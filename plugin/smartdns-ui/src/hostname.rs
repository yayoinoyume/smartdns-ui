/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with smartdns.  If not, see <http://www.gnu.org/licenses/>.
 */

//! Client hostname cache.
//!
//! Sources, in lookup priority order:
//!   1. manual map file (`smartdns-ui.hostname-map`), entries keyed by IP or MAC
//!   2. runtime observations (`note_client`): an IP whose MAC is known from a
//!      lease/manual entry - this bridges IPv6 clients (lease files are IPv4-only)
//!   3. dnsmasq lease file (`smartdns-ui.lease-file`), ip -> hostname
//!
//! When no source is configured (or files are unreadable) every lookup returns
//! None and callers fall back to the raw client IP, i.e. the feature is
//! silently off.

use crate::dns_log;
use crate::smartdns::*;

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

/// How often the source files are checked for changes. File IO is throttled so
/// that per-query lookups never touch the filesystem.
const RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// Cap for runtime observations to avoid unbounded memory growth. Mirrors the
/// mac_cache approach in data_server.rs: drop everything when full.
const RESOLVED_CAP: usize = 10000;

const ZERO_MAC: &str = "00:00:00:00:00:00";

/// Parse a single dnsmasq lease line: `<expiry_ts> <mac> <ip> <hostname> <clientid>`.
/// Returns (mac, ip, hostname); None for comment/short/placeholder (`*`) lines.
fn parse_lease_line(line: &str) -> Option<(String, String, String)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }

    let mac = fields[1];
    let ip = fields[2];
    let hostname = fields[3];
    if mac.is_empty() || ip.is_empty() || hostname.is_empty() || hostname == "*" {
        return None;
    }

    // A real address always contains '.' (IPv4) or ':' (IPv6). This rejects
    // garbage lines that happen to have 4+ fields: field count alone is not
    // enough, e.g. the comment "not a lease line" would otherwise be parsed
    // as ip="lease", hostname="line" and pollute the whole map.
    if !ip.contains('.') && !ip.contains(':') {
        return None;
    }

    Some((mac.to_string(), ip.to_string(), hostname.to_string()))
}

/// Parse the lease file content into (ip -> hostname, mac -> hostname).
fn parse_leases(content: &str) -> (HashMap<String, String>, HashMap<String, String>) {
    let mut ip_map = HashMap::new();
    let mut mac_map = HashMap::new();
    for line in content.lines() {
        if let Some((mac, ip, hostname)) = parse_lease_line(line) {
            ip_map.insert(ip, hostname.clone());
            mac_map.insert(mac.to_lowercase(), hostname);
        }
    }
    (ip_map, mac_map)
}

/// Parse one line of the manual map file: `<ip-or-mac> <name>`.
/// A key containing ":" is treated as a MAC (normalized to lowercase).
/// Returns None for comments, blank lines and lines with fewer than 2 fields.
fn parse_manual_line(line: &str) -> Option<(bool, String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut it = line.split_whitespace();
    let key = it.next()?;
    let name = it.next()?;
    if name.is_empty() {
        return None;
    }

    if key.contains(':') {
        Some((true, key.to_lowercase(), name.to_string()))
    } else {
        Some((false, key.to_string(), name.to_string()))
    }
}

/// Parse the manual map content into (ip -> name, mac -> name).
fn parse_manual(content: &str) -> (HashMap<String, String>, HashMap<String, String>) {
    let mut ip_map = HashMap::new();
    let mut mac_map = HashMap::new();
    for line in content.lines() {
        match parse_manual_line(line) {
            Some((true, mac, name)) => {
                mac_map.insert(mac, name);
            }
            Some((false, ip, name)) => {
                ip_map.insert(ip, name);
            }
            None => {}
        }
    }
    (ip_map, mac_map)
}

fn is_loopback_addr(addr: &str) -> bool {
    match addr.parse::<IpAddr>() {
        Ok(a) => a.is_loopback(),
        Err(_) => false,
    }
}

struct LeaseCacheInner {
    /// dnsmasq lease file path
    path: Option<String>,
    /// manual map file path
    manual_path: Option<String>,

    /// lease file: ip -> hostname, mac -> hostname
    ip_map: HashMap<String, String>,
    mac_map: HashMap<String, String>,
    /// manual map: ip -> name, mac -> name
    manual_ip_map: HashMap<String, String>,
    manual_mac_map: HashMap<String, String>,
    /// runtime observations: ip -> hostname, filled via note_client()
    resolved: HashMap<String, String>,

    last_check: Option<Instant>,
    lease_mtime: Option<SystemTime>,
    manual_mtime: Option<SystemTime>,
    failure_logged: bool,
    manual_failure_logged: bool,
}

pub struct LeaseHostnameCache {
    inner: Mutex<LeaseCacheInner>,
}

impl LeaseHostnameCache {
    fn new() -> Self {
        LeaseHostnameCache {
            inner: Mutex::new(LeaseCacheInner {
                path: None,
                manual_path: None,
                ip_map: HashMap::new(),
                mac_map: HashMap::new(),
                manual_ip_map: HashMap::new(),
                manual_mac_map: HashMap::new(),
                resolved: HashMap::new(),
                last_check: None,
                lease_mtime: None,
                manual_mtime: None,
                failure_logged: false,
                manual_failure_logged: false,
            }),
        }
    }

    /// Enable the cache with a lease file path. Re-enables after a previous
    /// failure and forces a reload on next lookup.
    pub fn set_path(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.path = Some(path.to_string());
        inner.ip_map.clear();
        inner.mac_map.clear();
        inner.lease_mtime = None;
        inner.failure_logged = false;
        inner.last_check = None;
    }

    /// Enable the optional manual map file, mirroring set_path().
    pub fn set_manual_path(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.manual_path = Some(path.to_string());
        inner.manual_ip_map.clear();
        inner.manual_mac_map.clear();
        inner.manual_mtime = None;
        inner.manual_failure_logged = false;
        inner.last_check = None;
    }

    /// Record a runtime observation: this IP was seen with this MAC. When the
    /// MAC maps to a hostname (lease or manual map), remember ip -> hostname so
    /// that IPv6 clients can be named through their MAC. Called once per DNS
    /// request; the fast path is memory-only, file IO stays throttled inside
    /// maybe_reload() like every other entry point.
    pub fn note_client(&self, ip: &str, mac: &str) {
        if mac == ZERO_MAC || ip.is_empty() {
            return;
        }

        self.maybe_reload();

        let mut inner = self.inner.lock().unwrap();
        let mac_lower = mac.to_lowercase();
        let name = inner
            .manual_mac_map
            .get(&mac_lower)
            .or_else(|| inner.mac_map.get(&mac_lower))
            .cloned();
        if let Some(name) = name {
            if inner.resolved.len() >= RESOLVED_CAP {
                inner.resolved.clear();
            }
            inner.resolved.insert(ip.to_string(), name);
        }
    }

    /// Lookup hostname by client IP.
    /// Priority: manual ip map > runtime observation > lease ip map.
    /// Returns None when nothing matches; callers fall back to the raw IP.
    pub fn get(&self, ip: &str) -> Option<String> {
        self.maybe_reload();
        let inner = self.inner.lock().unwrap();
        inner
            .manual_ip_map
            .get(ip)
            .or_else(|| inner.resolved.get(ip))
            .or_else(|| inner.ip_map.get(ip))
            .cloned()
    }

    /// Reverse lookup: every IP registered under `hostname`, merged from all
    /// sources and deduplicated. A single hostname may map to both an IPv4
    /// (lease/manual ip entry) and an IPv6 address (runtime MAC bridging),
    /// both are returned so a filter can match every row of that client.
    pub fn find_ips_by_hostname(&self, hostname: &str) -> Vec<String> {
        self.maybe_reload();
        let inner = self.inner.lock().unwrap();
        let mut ips: Vec<String> = Vec::new();
        for map in [
            &inner.manual_ip_map,
            &inner.resolved,
            &inner.ip_map,
        ] {
            for (ip, h) in map.iter() {
                if h.as_str() == hostname && !ips.contains(ip) {
                    ips.push(ip.clone());
                }
            }
        }
        ips
    }

    fn maybe_reload(&self) {
        // fast path: disabled or inside the throttle window
        {
            let inner = self.inner.lock().unwrap();
            if inner.path.is_none() && inner.manual_path.is_none() {
                return;
            }
            if let Some(last) = inner.last_check {
                if last.elapsed() < RELOAD_INTERVAL {
                    return;
                }
            }
        }

        // reload under one lock; re-check the throttle in case another thread
        // refreshed while we were waiting
        let mut inner = self.inner.lock().unwrap();
        if let Some(last) = inner.last_check {
            if last.elapsed() < RELOAD_INTERVAL {
                return;
            }
        }
        inner.last_check = Some(Instant::now());

        // dnsmasq lease file
        if let Some(path) = inner.path.clone() {
            let mtime = fs::metadata(&path).ok().and_then(|m| m.modified().ok());
            if mtime.is_some() && mtime == inner.lease_mtime {
                // unchanged
            } else {
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        let (ip_map, mac_map) = parse_leases(&content);
                        inner.ip_map = ip_map;
                        inner.mac_map = mac_map;
                        inner.lease_mtime = mtime;
                        inner.failure_logged = false;
                    }
                    Err(e) => {
                        inner.ip_map.clear();
                        inner.mac_map.clear();
                        inner.lease_mtime = None;
                        if !inner.failure_logged {
                            inner.failure_logged = true;
                            dns_log!(
                                LogLevel::INFO,
                                "lease file {} is not available, client hostname display disabled: {}",
                                path,
                                e.to_string()
                            );
                        }
                    }
                }
            }
        }

        // manual map file: same throttle/mtime mechanism as the lease file
        if let Some(path) = inner.manual_path.clone() {
            let mtime = fs::metadata(&path).ok().and_then(|m| m.modified().ok());
            if mtime.is_some() && mtime == inner.manual_mtime {
                // unchanged
            } else {
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        let (ip_map, mac_map) = parse_manual(&content);
                        inner.manual_ip_map = ip_map;
                        inner.manual_mac_map = mac_map;
                        inner.manual_mtime = mtime;
                        inner.manual_failure_logged = false;
                    }
                    Err(e) => {
                        inner.manual_ip_map.clear();
                        inner.manual_mac_map.clear();
                        inner.manual_mtime = None;
                        if !inner.manual_failure_logged {
                            inner.manual_failure_logged = true;
                            dns_log!(
                                LogLevel::INFO,
                                "hostname map file {} is not available, ignoring: {}",
                                path,
                                e.to_string()
                            );
                        }
                    }
                }
            }
        }

        // note: inner.resolved is runtime data (from note_client), it is
        // intentionally NOT cleared here
    }
}

pub fn lease_cache() -> &'static LeaseHostnameCache {
    static CACHE: OnceLock<LeaseHostnameCache> = OnceLock::new();
    CACHE.get_or_init(LeaseHostnameCache::new)
}

/// Final display value for a client: loopback queries come from the router
/// itself and are shown as "localhost", known clients show their hostname,
/// everything else keeps the raw IP.
pub fn display_name(ip: &str) -> String {
    if is_loopback_addr(ip) {
        return "localhost".to_string();
    }
    lease_cache().get(ip).unwrap_or_else(|| ip.to_string())
}

/// Replace the client field of domain log rows with hostnames where known.
/// Rows whose IP cannot be resolved keep the raw IP.
pub fn apply_to_domain_list(list: &mut [crate::db::DomainData]) {
    for d in list.iter_mut() {
        d.client = display_name(&d.client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lease_line() {
        // normal line
        assert_eq!(
            parse_lease_line(
                "1789665359 e0:70:ea:98:8a:53 192.168.2.102 MiWiFi-RD15-srv 01:e0:70:ea:98:8a:53"
            ),
            Some((
                "e0:70:ea:98:8a:53".to_string(),
                "192.168.2.102".to_string(),
                "MiWiFi-RD15-srv".to_string()
            ))
        );

        // too few fields
        assert_eq!(parse_lease_line("1789665359 e0:70:ea:98:8a:53"), None);
        assert_eq!(parse_lease_line("1789665359 e0:70:ea:98:8a:53 192.168.2.1"), None);

        // 占位主机名
        assert_eq!(
            parse_lease_line("1789665359 aa:bb:cc:dd:ee:ff 10.0.0.3 * 01:aabbccddee"),
            None
        );

        // too many words to be "short", but the ip field is not an address
        assert_eq!(parse_lease_line("not a lease line"), None);

        // empty / blank lines
        assert_eq!(parse_lease_line(""), None);
        assert_eq!(parse_lease_line("   "), None);
    }

    #[test]
    fn test_parse_leases() {
        let content = "\n\
            1789665359 aa:bb:cc:dd:ee:ff 10.0.0.2 phone 01:aabbccddee\n\
            1789665359 aa:bb:cc:dd:ee:10 10.0.0.3 * 01:aabbccddee10\n\
            not a lease line\n";
        let (ip_map, mac_map) = parse_leases(content);
        assert_eq!(ip_map.len(), 1);
        assert_eq!(ip_map.get("10.0.0.2"), Some(&"phone".to_string()));
        assert_eq!(ip_map.get("10.0.0.3"), None);
        assert_eq!(mac_map.get("aa:bb:cc:dd:ee:ff"), Some(&"phone".to_string()));
        assert_eq!(mac_map.len(), 1);
    }

    #[test]
    fn test_parse_manual_line() {
        // ip entry
        assert_eq!(
            parse_manual_line("192.168.2.27 客厅摄像头"),
            Some((false, "192.168.2.27".to_string(), "客厅摄像头".to_string()))
        );
        // mac entry, normalized to lowercase
        assert_eq!(
            parse_manual_line("0E:69:FA:C1:92:62 iPad"),
            Some((true, "0e:69:fa:c1:92:62".to_string(), "iPad".to_string()))
        );
        // comment / blank / too short
        assert_eq!(parse_manual_line("# comment"), None);
        assert_eq!(parse_manual_line(""), None);
        assert_eq!(parse_manual_line("only-key"), None);
    }

    #[test]
    fn test_parse_manual() {
        let content = "\n\
            # static devices\n\
            192.168.2.27 cam-livingroom\n\
            0e:69:fa:c1:92:62 random-mac-phone\n\
            badline\n";
        let (ip_map, mac_map) = parse_manual(content);
        assert_eq!(ip_map.get("192.168.2.27"), Some(&"cam-livingroom".to_string()));
        assert_eq!(
            mac_map.get("0e:69:fa:c1:92:62"),
            Some(&"random-mac-phone".to_string())
        );
        assert_eq!(ip_map.len(), 1);
        assert_eq!(mac_map.len(), 1);
    }

    #[test]
    fn test_is_loopback_addr() {
        assert!(is_loopback_addr("127.0.0.1"));
        assert!(is_loopback_addr("127.8.8.8"));
        assert!(is_loopback_addr("::1"));
        assert!(!is_loopback_addr("192.168.2.39"));
        assert!(!is_loopback_addr("fd00:6969:6969::b40"));
        // unparseable strings are simply not loopback
        assert!(!is_loopback_addr("API"));
        assert!(!is_loopback_addr(""));
    }
}
