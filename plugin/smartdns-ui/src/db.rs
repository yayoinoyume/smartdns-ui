/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use crate::dns_log;
use crate::smartdns;
use crate::smartdns::*;
use crate::utils;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::sync::Mutex;
use std::vec;

use chrono::Local;
use rusqlite::Transaction;
use rusqlite::{Connection, OpenFlags, Result};

pub struct DB {
    conn: Mutex<Option<Connection>>,
    version: i32,
    query_plan: bool,
}

#[derive(Debug, Clone)]
pub struct ClientData {
    pub id: u32,
    pub hostname: String,
    pub client_ip: String,
    pub mac: String,
    pub last_query_timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct ClientQueryCount {
    pub client_ip: String,
    pub count: u32,
    pub timestamp_start: u64,
    pub timestamp_end: u64,
}

#[derive(Debug, Clone)]
pub struct DomainQueryCount {
    pub domain: String,
    pub count: u32,
    pub timestamp_start: u64,
    pub timestamp_end: u64,
}

#[derive(Debug, Clone)]
pub struct HourlyQueryCountItem {
    pub hour: String,
    pub query_count: u32,
}

#[derive(Debug, Clone)]
pub struct HourlyQueryCount {
    pub query_timestamp: u64,
    pub hourly_query_count: Vec<HourlyQueryCountItem>,
}

#[derive(Debug, Clone)]
pub struct DailyQueryCountItem {
    pub day: String,
    pub query_count: u32,
}

#[derive(Debug, Clone)]
pub struct DailyQueryCount {
    pub query_timestamp: u64,
    pub daily_query_count: Vec<DailyQueryCountItem>,
}

#[derive(Debug, Clone)]
pub struct DomainGroupHourlyStat {
    pub domain_group: String,
    pub query_count: u32,
    pub cached_count: u32,
}

#[derive(Debug, Clone)]
pub struct HourlyDetailItem {
    pub hour: String,
    pub query_count: u32,
    pub cached_count: u32,
    pub blocked_count: u32,
    pub avg_query_time_cached: f64,
    pub avg_query_time_uncached: f64,
    pub groups: Vec<DomainGroupHourlyStat>,
}

#[derive(Debug, Clone)]
pub struct HourlyDetail {
    pub query_timestamp: u64,
    pub hourly_detail: Vec<HourlyDetailItem>,
}

/// `domain_hourly_detail` 表里 (小时, 域名分组) 的一行汇总。
///
/// 耗时存「求和 + 条数」，读取时相除得到平均值；这样重复汇总可直接覆盖（幂等）。
#[derive(Debug, Clone, Default)]
pub struct HourlyDetailGroupAgg {
    pub hour_timestamp: u64,
    pub domain_group: String,
    pub query_count: u64,
    pub cached_count: u64,
    pub blocked_count: u64,
    pub cached_time_sum: f64,
    pub cached_time_count: u64,
    pub uncached_time_sum: f64,
    pub uncached_time_count: u64,
}

const HOURLY_DETAIL_HOUR_MS: u64 = 3_600_000;

/// 每小时汇总时固定重算的已完成小时数（兜住明细延迟入库的情况）。
const HOURLY_DETAIL_RECHECK_HOURS: u64 = 3;

/// 读汇总表（只含已结束的完整小时）。抽成常量，便于 debug_query_plan 复用同一份 SQL。
const HOURLY_DETAIL_STORED_SQL: &str =
    "SELECT hour_timestamp, domain_group, query_count, cached_count, blocked_count, \
     cached_time_sum, cached_time_count, uncached_time_sum, uncached_time_count \
     FROM domain_hourly_detail WHERE hour_timestamp >= ?1 AND hour_timestamp < ?2";

/// 实时扫明细的 SQL。
const HOURLY_DETAIL_SCAN_SQL: &str =
    "SELECT timestamp, domain_group, is_cached, is_blocked, query_time \
     FROM domain WHERE timestamp >= ?1 AND timestamp < ?2";

/// 计算时间戳所属「本地小时」起点的毫秒值（UTC 纪元）。
///
/// 与 `insert_domain()` 维护 `domain_hourly_count` 的算法一致（加偏移 → 整点取整 → 减偏移）。
fn local_hour_start_ms(timestamp_ms: u64, local_offset_secs: i64) -> u64 {
    let offset_ms = local_offset_secs * 1000;
    let local = timestamp_ms as i64 + offset_ms;
    let hour_local = local - local.rem_euclid(HOURLY_DETAIL_HOUR_MS as i64);
    (hour_local - offset_ms) as u64
}

/// 用与旧实现完全相同的 strftime 表达式格式化小时字符串，保证输出一字不差。
fn format_local_hour(conn: &Connection, hour_timestamp: u64) -> Result<String, Box<dyn Error>> {
    let ret = conn.query_row(
        "SELECT strftime('%Y-%m-%d %H:00:00', datetime(?1 / 1000, 'unixepoch', 'localtime'))",
        [hour_timestamp as i64],
        |row| row.get::<_, Option<String>>(0),
    )?;

    Ok(ret.unwrap_or_default())
}

/// 扫描 `[start_ms, end_ms)` 内的查询明细，按 (本地小时, 域名分组) 汇总。
///
/// 返回 (汇总结果, 扫描到的明细行数)。异常行直接跳过，语义与旧实现一致。
fn collect_hourly_detail_aggs(
    conn: &Connection,
    start_ms: u64,
    end_ms: u64,
    local_offset_secs: i64,
) -> Result<(HashMap<(u64, String), HourlyDetailGroupAgg>, u64), Box<dyn Error>> {
    let mut aggs: HashMap<(u64, String), HourlyDetailGroupAgg> = HashMap::new();
    let mut scanned: u64 = 0;
    let scan_end = end_ms.min(i64::MAX as u64) as i64;

    let mut stmt = conn.prepare(HOURLY_DETAIL_SCAN_SQL)?;
    let mut rows = stmt.query(rusqlite::params![start_ms as i64, scan_end])?;

    while let Some(row) = rows.next()? {
        let timestamp: i64 = row.get(0)?;
        let domain_group: String = row.get(1)?;
        let is_cached: i64 = row.get::<_, Option<i64>>(2)?.unwrap_or(0);
        let is_blocked: i64 = row.get::<_, Option<i64>>(3)?.unwrap_or(0);
        let query_time: f64 = row.get::<_, Option<f64>>(4)?.unwrap_or(0.0);

        let hour_timestamp = local_hour_start_ms(timestamp.max(0) as u64, local_offset_secs);
        let agg = aggs
            .entry((hour_timestamp, domain_group))
            .or_insert_with_key(|key| HourlyDetailGroupAgg {
                hour_timestamp: key.0,
                domain_group: key.1.clone(),
                ..Default::default()
            });

        agg.query_count += 1;
        if is_cached != 0 {
            agg.cached_count += 1;
            agg.cached_time_sum += query_time;
            agg.cached_time_count += 1;
        } else {
            agg.uncached_time_sum += query_time;
            agg.uncached_time_count += 1;
        }
        if is_blocked != 0 {
            agg.blocked_count += 1;
        }
        scanned += 1;
    }

    Ok((aggs, scanned))
}

/// 把一批 (小时, 分组) 汇总追加到「按小时分组」的容器里。
fn push_hourly_detail_aggs(
    hours: &mut HashMap<u64, Vec<HourlyDetailGroupAgg>>,
    aggs: impl IntoIterator<Item = HourlyDetailGroupAgg>,
) {
    for agg in aggs {
        hours.entry(agg.hour_timestamp).or_default().push(agg);
    }
}

/// 计算 `get_hourly_detail()` 里必须实时扫明细的区间（不含「汇总表缺小时」的补算）。
///
/// 覆盖 `boundary_hour`（窗口起点所在的残段小时，半截、汇总表口径覆盖不到）和
/// `current_hour`（当前未结束的小时）；`window_start` 是窗口起点毫秒值。
/// 返回互不重叠的左闭右开区间，残段小时只会出现一次。
fn hourly_detail_live_ranges(
    boundary_hour: u64,
    current_hour: u64,
    window_start: u64,
) -> Vec<(u64, u64)> {
    if boundary_hour < current_hour {
        vec![
            (window_start, boundary_hour + HOURLY_DETAIL_HOUR_MS),
            (current_hour, u64::MAX),
        ]
    } else {
        vec![(window_start, u64::MAX)]
    }
}

/// 在 `[first_hour, to_hour)` 里找出汇总表没有、需要就地实时补算的完整小时。
/// 连续缺失合并成一个区间；表完整时返回空集合。
fn missing_hour_ranges(present: &HashSet<u64>, first_hour: u64, to_hour: u64) -> Vec<(u64, u64)> {
    let mut ret: Vec<(u64, u64)> = Vec::new();
    let mut hour = first_hour;
    while hour < to_hour {
        if present.contains(&hour) {
            hour += HOURLY_DETAIL_HOUR_MS;
            continue;
        }

        let start = hour;
        while hour < to_hour && !present.contains(&hour) {
            hour += HOURLY_DETAIL_HOUR_MS;
        }
        ret.push((start, hour));
    }

    ret
}

/// 汇总表是否存在（查 sqlite_master，开销可忽略）。
/// `open()` 补建失败时靠它整段跳过汇总表读取、退化为实时扫描，而不是报错。
fn hourly_detail_table_exists(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'domain_hourly_detail'",
        [],
        |_| Ok(()),
    )
    .is_ok()
}

/// 汇总表里 `[from_hour, to_hour)` 已有的小时集合。
fn stored_hours_in_range(
    conn: &Connection,
    from_hour: u64,
    to_hour: u64,
) -> Result<HashSet<u64>, Box<dyn Error>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT hour_timestamp FROM domain_hourly_detail \
         WHERE hour_timestamp >= ?1 AND hour_timestamp < ?2",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![from_hour as i64, to_hour as i64],
        |row| row.get::<_, i64>(0),
    )?;

    let mut ret = HashSet::new();
    for row in rows {
        ret.insert(row?.max(0) as u64);
    }

    Ok(ret)
}

/// 明细里 `[from_hour, to_hour)` 出现过数据的小时集合。
/// 与 `local_hour_start_ms()` 同一「本地整点」口径，走 idx_domain_timestamp 索引。
fn detail_hours_in_range(
    conn: &Connection,
    from_hour: u64,
    to_hour: u64,
    local_offset_secs: i64,
) -> Result<HashSet<u64>, Box<dyn Error>> {
    let offset_ms = local_offset_secs * 1000;
    let mut stmt = conn.prepare(
        "SELECT DISTINCT (timestamp + ?1) / ?2 * ?2 - ?1 AS hour \
         FROM domain WHERE timestamp >= ?3 AND timestamp < ?4",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![
            offset_ms,
            HOURLY_DETAIL_HOUR_MS as i64,
            from_hour as i64,
            to_hour as i64
        ],
        |row| row.get::<_, i64>(0),
    )?;

    let mut ret = HashSet::new();
    for row in rows {
        ret.insert(row?.max(0) as u64);
    }

    Ok(ret)
}


#[derive(Debug, Clone)]
pub struct DomainData {
    pub id: u64,
    pub timestamp: u64,
    pub domain: String,
    pub domain_type: u32,
    pub client: String,
    pub domain_group: String,
    pub reply_code: u16,
    pub query_time: i32,
    pub ping_time: f64,
    pub is_blocked: bool,
    pub is_cached: bool,
}

#[derive(Debug, Clone)]
pub struct QueryDomainListResult {
    pub domain_list: Vec<DomainData>,
    pub total_count: u64,
    pub step_by_cursor: bool,
}

#[derive(Debug, Clone)]
pub struct DomainListGetParamCursor {
    pub id: Option<u64>,
    pub total_count: u64,
    pub direction: String,
}

#[derive(Debug, Clone)]
pub struct QueryClientListResult {
    pub client_list: Vec<ClientData>,
    pub total_count: u64,
    pub step_by_cursor: bool,
}

#[derive(Debug, Clone)]
pub struct ClientListGetParamCursor {
    pub id: Option<u64>,
    pub total_count: u64,
    pub direction: String,
}

#[derive(Debug, Clone)]
pub struct ClientListGetParam {
    pub id: Option<u64>,
    pub order: Option<String>,
    pub page_num: u64,
    pub page_size: u64,
    pub client_ip: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub timestamp_before: Option<u64>,
    pub timestamp_after: Option<u64>,
    pub cursor: Option<ClientListGetParamCursor>,
}

impl ClientListGetParam {
    pub fn new() -> Self {
        ClientListGetParam {
            id: None,
            page_num: 1,
            order: None,
            page_size: 10,
            client_ip: None,
            mac: None,
            hostname: None,
            timestamp_before: None,
            timestamp_after: None,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainListGetParam {
    pub id: Option<u64>,
    pub order: Option<String>,
    pub page_num: u64,
    pub page_size: u64,
    pub domain: Option<String>,
    pub domain_filter_mode: Option<String>,
    pub domain_type: Option<u32>,
    pub client: Option<String>,
    /// Resolved client filter: every IP a hostname/localhost filter value
    /// expands to, matched with `client IN (...)`. Takes precedence over
    /// `client` when set.
    pub client_ips: Option<Vec<String>>,
    pub domain_group: Option<String>,
    pub reply_code: Option<u16>,
    pub timestamp_before: Option<u64>,
    pub timestamp_after: Option<u64>,
    pub is_blocked: Option<bool>,
    pub is_cached: Option<bool>,
    pub cursor: Option<DomainListGetParamCursor>,
}

impl DomainListGetParam {
    pub fn new() -> Self {
        DomainListGetParam {
            id: None,
            page_num: 1,
            order: None,
            page_size: 10,
            domain: None,
            domain_filter_mode: None,
            domain_type: None,
            client: None,
            client_ips: None,
            domain_group: None,
            reply_code: None,
            timestamp_before: None,
            timestamp_after: None,
            is_blocked: None,
            is_cached: None,
            cursor: None,
        }
    }
}

impl DB {
    pub fn new() -> Self {
        DB {
            conn: Mutex::new(None),
            version: 10000, /* x: major version, xx: minor version, xx: patch version */
            query_plan: std::env::var("SMARTDNS_DEBUG_SQL").is_ok(),
        }
    }

    fn create_table(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp BIGINT NOT NULL,
                domain TEXT NOT NULL,
                domain_type INTEGER NOT NULL,
                client TEXT NOT NULL,
                domain_group TEXT NOT NULL,
                reply_code INTEGER NOT NULL,
                query_time INTEGER NOT NULL,
                ping_time REAL NOT NULL,
                is_blocked INTEGER DEFAULT 0,
                is_cached INTEGER DEFAULT 0
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_timestamp ON domain (timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_client ON domain (client)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain_hourly_count (
                timestamp BIGINT PRIMARY KEY,
                count INTEGER DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain_daily_count (
                timestamp BIGINT PRIMARY KEY,
                count INTEGER DEFAULT 0
            );",
            [],
        )?;

        self.create_hourly_detail_table(conn)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS top_domain_list (
                domain TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0,
                timestamp_start BIGINT DEFAULT 0,
                timestamp_end BIGINT DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS top_client_list (
                client TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0,
                timestamp_start BIGINT DEFAULT 0,
                timestamp_end BIGINT DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "
        CREATE TABLE IF NOT EXISTS client (
            id INTEGER PRIMARY KEY,
            client_ip TEXT NOT NULL,
            mac TEXT NOT NULL,
            hostname TEXT NOT NULL,
            last_query_timestamp BIGINT NOT NULL,
            UNIQUE(client_ip, mac)
        )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_client_last_query_timestamp ON client (last_query_timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS status_data (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            [self.version],
        )?;

        Ok(())
    }

    /// 新建「按小时 + 域名分组」的汇总表（幂等，只 CREATE TABLE IF NOT EXISTS）。
    ///
    /// 必须在 `open()` 里单独补建：存量数据库不会走 `init_db()`/`create_table()`
    /// （只有库文件不存在时才会），否则老库上读不到汇总数据。
    fn create_hourly_detail_table(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain_hourly_detail (
                hour_timestamp BIGINT NOT NULL,
                domain_group TEXT NOT NULL,
                query_count INTEGER DEFAULT 0,
                cached_count INTEGER DEFAULT 0,
                blocked_count INTEGER DEFAULT 0,
                cached_time_sum REAL DEFAULT 0,
                cached_time_count INTEGER DEFAULT 0,
                uncached_time_sum REAL DEFAULT 0,
                uncached_time_count INTEGER DEFAULT 0,
                PRIMARY KEY (hour_timestamp, domain_group)
            )",
            [],
        )?;

        Ok(())
    }

    /// 尽力保证汇总表存在：失败只告警并返回 false，绝不影响插件启动 / 加载。
    fn ensure_hourly_detail_table_locked(&self, conn: &Connection) -> bool {
        if hourly_detail_table_exists(conn) {
            return true;
        }

        match self.create_hourly_detail_table(conn) {
            Ok(_) => true,
            Err(e) => {
                dns_log!(
                    LogLevel::WARN,
                    "create table domain_hourly_detail failed: {}, hourly-detail falls back to live scan",
                    e
                );
                false
            }
        }
    }

    /// 同 `ensure_hourly_detail_table_locked()`，但自己拿 `self.conn` 的锁
    /// （调用方必须没有持有该锁）。
    fn ensure_hourly_detail_table(&self) -> bool {
        let conn = self.conn.lock().unwrap();
        match conn.as_ref() {
            Some(conn) => self.ensure_hourly_detail_table_locked(conn),
            None => false,
        }
    }

    fn migrate_db(&self, _conn: &Connection) -> Result<(), Box<dyn Error>> {
        return Err(
            "Currently Not Support Migrate Database, Please Backup DB File, And Restart Server."
                .into(),
        );
    }

    fn init_db(&self, conn: &Connection) -> Result<(), Box<dyn Error>> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )",
            [],
        )?;

        let current_version: i32 = conn
            .query_row(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(self.version);

        if current_version >= self.version {
            self.create_table(conn)?;
        } else {
            self.migrate_db(conn)?;
        }

        Ok(())
    }

    pub fn open(&self, path: &str) -> Result<(), Box<dyn Error>> {
        let ruconn: std::result::Result<Connection, rusqlite::Error> =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE);
        let mut conn = self.conn.lock().unwrap();
        if let Err(_) = ruconn {
            let ruconn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            )?;

            let ret = self.init_db(&ruconn);
            if let Err(e) = ret {
                _ = ruconn.close();
                fs::remove_file(path)?;
                return Err(e);
            }

            *conn = Some(ruconn);
        } else {
            *conn = Some(ruconn.unwrap());
        }

        // 存量库不会走 init_db()/create_table()，这里补建汇总表（见 create_hourly_detail_table）。
        // 建表失败不能让插件起不来（这条路径还挂着主机名、日志和所有接口），所以只告警。
        if let Some(conn) = conn.as_ref() {
            self.ensure_hourly_detail_table_locked(conn);
        }

        conn.as_ref()
            .unwrap()
            .execute("PRAGMA synchronous = OFF", [])?;
        conn.as_ref()
            .unwrap()
            .execute("PRAGMA page_size  = 4096", [])?;
        conn.as_ref()
            .unwrap()
            .execute("PRAGMA cache_size = -8192", [])?;
        conn.as_ref()
            .unwrap()
            .execute("PRAGMA temp_store = MEMORY", [])?;

        let current_auto_vacuum: i32 =
            conn.as_ref()
                .unwrap()
                .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
        dns_log!(
            LogLevel::DEBUG,
            "Current auto_vacuum: {}",
            current_auto_vacuum
        );
        if current_auto_vacuum != 2 {
            dns_log!(LogLevel::INFO, "Set auto_vacuum to INCREMENTAL");
            conn.as_ref()
                .unwrap()
                .execute("PRAGMA auto_vacuum = INCREMENTAL", [])?;
            conn.as_ref().unwrap().execute("VACUUM", [])?;
        }

        conn.as_ref()
            .unwrap()
            .query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        conn.as_ref()
            .unwrap()
            .query_row("PRAGMA wal_autocheckpoint = 1000", [], |_| Ok(()))?;
        Ok(())
    }

    pub fn run_vacuum(&self, pages: Option<u32>) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        dns_log!(LogLevel::DEBUG, "Start incremental vacuum");

        conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))?;
        let vacuum_sql = if let Some(pages) = pages {
            format!("PRAGMA incremental_vacuum({})", pages)
        } else {
            "PRAGMA incremental_vacuum".to_string()
        };

        conn.query_row(&vacuum_sql, [], |_| Ok(()))?;
        conn.execute("PRAGMA shrink_memory", [])?;
        Ok(())
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt =
            conn.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)")?;
        let ret = stmt.execute(&[&key, &value]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(())
    }

    pub fn get_config_list(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let mut ret = HashMap::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn.prepare("SELECT key, value FROM config").unwrap();

        let rows = stmt.query_map([], |row| {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            Ok((key, value))
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.insert(row.0, row.1);
                }
            }
        }

        Ok(ret)
    }

    pub fn set_status_data(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt =
            conn.prepare("INSERT OR REPLACE INTO status_data (key, value) VALUES (?1, ?2)")?;
        let ret = stmt.execute(&[&key, &value]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(())
    }

    pub fn get_status_data_list(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let mut ret = HashMap::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let stmt = conn.prepare("SELECT key, value FROM status_data");
        if let Err(e) = stmt {
            return Err(Box::new(e));
        }
        let mut stmt = stmt.unwrap();

        let rows = stmt.query_map([], |row| {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            Ok((key, value))
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.insert(row.0, row.1);
                }
            }
        }

        Ok(ret)
    }

    pub fn debug_query_plan(&self, conn: &Connection, sql: String, sql_param: &Vec<String>) {
        if !self.query_plan {
            return;
        }

        let sqlplan = "EXPLAIN QUERY PLAN ".to_string() + &sql;
        let stmt = conn.prepare(sqlplan.as_str());
        if let Err(e) = stmt {
            dns_log!(LogLevel::DEBUG, "query plan sql error: {}", e);
            return;
        }

        let mut stmt = stmt.unwrap();
        let plan_rows = stmt.query_map(rusqlite::params_from_iter(sql_param.clone()), |row| {
            Ok(row.get::<_, String>(3)?)
        });

        if let Err(e) = plan_rows {
            dns_log!(LogLevel::DEBUG, "query plan error: {}", e);
            return;
        }

        let plan_rows = plan_rows.unwrap();
        dns_log!(LogLevel::NOTICE, "sql: {}", sql);
        for plan in plan_rows {
            if let Ok(plan) = plan {
                dns_log!(LogLevel::NOTICE, "plan: {}", plan);
            }
        }
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn
            .prepare("SELECT value FROM config WHERE key = ?")
            .unwrap();
        let rows = stmt.query_map(&[&key], |row| Ok(row.get(0)?));

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    return Ok(Some(row));
                }
            }
        }

        Ok(None)
    }

    pub fn update_domain_hourly_count(
        &self,
        tx: &Transaction<'_>,
        hourly_count: &HashMap<u64, u32>,
    ) -> Result<(), Box<dyn Error>> {
        let mut stmt = tx.prepare(
            "INSERT INTO domain_hourly_count (timestamp, count)
                 VALUES (
                    ?1,
                    ?2
                )
                ON CONFLICT(timestamp) DO UPDATE SET count = count + ?2;",
        )?;

        for (k, v) in hourly_count {
            stmt.execute(rusqlite::params![k, v])?;
        }
        stmt.finalize()?;
        Ok(())
    }

    pub fn update_domain_daily_count(
        &self,
        tx: &Transaction<'_>,
        daily_count: &HashMap<u64, u32>,
    ) -> Result<(), Box<dyn Error>> {
        let mut stmt = tx.prepare(
            "INSERT INTO domain_daily_count (timestamp, count)
                 VALUES (
                    ?1,
                    ?2
                )
                ON CONFLICT(timestamp) DO UPDATE SET count = count + ?2;",
        )?;

        for (k, v) in daily_count {
            stmt.execute(rusqlite::params![k, v])?;
        }
        stmt.finalize()?;
        Ok(())
    }

    pub fn insert_domain(&self, data: &Vec<DomainData>) -> Result<(), Box<dyn Error>> {
        let local_offset = Local::now().offset().local_minus_utc();
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let mut hourly_count = HashMap::new();
        let mut daily_count = HashMap::new();
        let conn = conn.as_mut().unwrap();

        let tx = conn.transaction()?;

        let mut stmt = tx.prepare(
            "INSERT INTO domain \
            (timestamp, domain, domain_type, client, domain_group, reply_code, query_time, ping_time, is_blocked, is_cached) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)")?;

        for d in data {
            let ret = stmt.execute(rusqlite::params![
                &d.timestamp.to_string(),
                &d.domain,
                &d.domain_type.to_string(),
                &d.client,
                &d.domain_group,
                &d.reply_code,
                &d.query_time,
                &d.ping_time,
                &(d.is_blocked as i32),
                &(d.is_cached as i32)
            ]);

            if let Err(e) = ret {
                stmt.finalize()?;
                tx.rollback()?;
                return Err(Box::new(e));
            }

            let localtimestamp = d.timestamp + local_offset as u64 * 1000;

            let hour_timestamp =
                localtimestamp - localtimestamp % 3600000 - local_offset as u64 * 1000;
            let day_timestamp =
                localtimestamp - localtimestamp % 86400000 - local_offset as u64 * 1000;

            hourly_count
                .entry(hour_timestamp)
                .and_modify(|v| *v += 1)
                .or_insert(1);
            daily_count
                .entry(day_timestamp)
                .and_modify(|v| *v += 1)
                .or_insert(1);
        }

        stmt.finalize()?;

        self.update_domain_hourly_count(&tx, &hourly_count)?;
        self.update_domain_daily_count(&tx, &daily_count)?;

        tx.commit()?;

        Ok(())
    }

    pub fn get_db_file_path(&self) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        if conn.is_none() {
            return None;
        }

        let conn = conn.as_ref().unwrap();
        conn.path().map(|v| v.to_string())
    }

    /// 取一个只读连接；数据库未打开时返回 `db is not open` 错误。
    fn readonly_conn_or_err(&self) -> Result<Connection, Box<dyn Error>> {
        match self.get_readonly_conn() {
            Some(conn) => Ok(conn),
            None => Err("db is not open".into()),
        }
    }

    pub fn get_readonly_conn(&self) -> Option<Connection> {
        let conn = self.conn.lock().unwrap();
        if conn.is_none() {
            return None;
        }

        let conn = conn.as_ref().unwrap();

        let read_conn = Connection::open_with_flags(
            conn.path().unwrap(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        );

        if let Err(_) = read_conn {
            return None;
        }

        Some(read_conn.unwrap())
    }

    /// # Returns
    ///
    /// A tuple containing:
    /// - `String`: The SQL WHERE clause.
    /// - `String`: The SQL ORDER BY clause.
    /// - `Vec<String>`: The parameters for the SQL query.
    pub fn get_domain_sql_where(
        param: Option<&DomainListGetParam>,
    ) -> Result<(String, String, Vec<String>), Box<dyn Error>> {
        let mut is_desc_order = true;
        let mut is_cursor_prev = false;
        let param = match param {
            Some(v) => v,
            None => return Ok((String::new(), String::new(), Vec::new())),
        };
        let mut order_timestamp_first = true;
        let mut cusor_with_timestamp = false;

        let mut sql_where = Vec::new();
        let mut sql_param: Vec<String> = Vec::new();
        let mut sql_order = String::new();

        if let Some(v) = &param.id {
            sql_where.push("id = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.order {
            if v.eq_ignore_ascii_case("asc") {
                is_cursor_prev = true;
            } else if v.eq_ignore_ascii_case("desc") {
                is_cursor_prev = false;
            } else {
                return Err("order param error".into());
            }
        }

        if let Some(v) = &param.cursor {
            if v.direction.eq_ignore_ascii_case("prev") {
                is_desc_order = !is_desc_order;
            } else if v.direction.eq_ignore_ascii_case("next") {
                // do nothing
            } else {
                return Err("cursor direction param error".into());
            }
        }

        if let Some(v) = &param.domain {
            if let Some(m) = &param.domain_filter_mode {
                match m.to_lowercase().as_str() {
                    "endswith" => {
                        sql_where.push("domain LIKE ?".to_string());
                        sql_param.push(format!("{}%", v));
                    }
                    "startswith" => {
                        sql_where.push("domain LIKE ?".to_string());
                        sql_param.push(format!("%{}", v));
                    }
                    "contains" => {
                        sql_where.push("domain LIKE ?".to_string());
                        sql_param.push(format!("%{}%", v));
                    }
                    "equals" => {
                        sql_where.push("domain = ?".to_string());
                        sql_param.push(v.to_string());
                    }
                    "notempty" => {
                        sql_where.push("domain IS NOT NULL AND domain <> ''".to_string());
                    }
                    _ => return Err("domain_filter_mode param error".into()),
                }
            } else {
                sql_where.push("domain = ?".to_string());
                sql_param.push(v.to_string());
                order_timestamp_first = false;
            }
        }

        if let Some(v) = &param.domain_type {
            sql_where.push("domain_type = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(ips) = &param.client_ips {
            if !ips.is_empty() {
                let placeholders = ips.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                sql_where.push(format!("client IN ({})", placeholders));
                for ip in ips {
                    sql_param.push(ip.clone());
                }
                order_timestamp_first = false;
            }
        } else if let Some(v) = &param.client {
            sql_where.push("client = ?".to_string());
            sql_param.push(v.clone());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.domain_group {
            sql_where.push("domain_group = ?".to_string());
            sql_param.push(v.clone());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.reply_code {
            sql_where.push("reply_code = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.timestamp_before {
            let mut use_cursor = false;
            if param.cursor.is_some() && (is_desc_order || is_cursor_prev) {
                let v = param.cursor.as_ref().unwrap().id;
                if let Some(v) = v {
                    sql_where.push("id < ?".to_string());
                    sql_param.push(v.to_string());
                    use_cursor = true;
                    order_timestamp_first = false;
                    cusor_with_timestamp = true;
                }
            }

            if use_cursor == false {
                sql_where.push("timestamp <= ?".to_string());
                sql_param.push(v.to_string());
            }
        }

        if let Some(v) = &param.timestamp_after {
            let mut use_cursor = false;
            if param.cursor.is_some() && (!is_desc_order || is_cursor_prev) {
                let v = param.cursor.as_ref().unwrap().id;
                if let Some(v) = v {
                    sql_where.push("id > ?".to_string());
                    sql_param.push(v.to_string());
                    use_cursor = true;
                    order_timestamp_first = false;
                    cusor_with_timestamp = true;
                }
            }

            if use_cursor == false {
                sql_where.push("timestamp >= ?".to_string());
                sql_param.push(v.to_string());
            }
        }

        if !cusor_with_timestamp {
            if let Some(v) = &param.cursor {
                if is_cursor_prev {
                    if let Some(id) = &v.id {
                        if is_desc_order {
                            sql_where.push("id > ?".to_string());
                        } else {
                            sql_where.push("id < ?".to_string());
                        }

                        sql_param.push(id.to_string());
                        order_timestamp_first = false;
                    }
                } else {
                    if let Some(id) = &v.id {
                        if is_desc_order {
                            sql_where.push("id < ?".to_string());
                        } else {
                            sql_where.push("id > ?".to_string());
                        }

                        sql_param.push(id.to_string());
                        order_timestamp_first = false;
                    }
                }
            }
        }

        if let Some(v) = &param.is_blocked {
            if *v {
                sql_where.push("is_blocked = 1".to_string());
            } else {
                sql_where.push("is_blocked = 0".to_string());
            }
            order_timestamp_first = false;
        }

        if let Some(v) = &param.is_cached {
            if *v {
                sql_where.push("is_cached = 1".to_string());
            } else {
                sql_where.push("is_cached = 0".to_string());
            }
            order_timestamp_first = false;
        }

        if is_cursor_prev {
            is_desc_order = !is_desc_order;
        }

        if is_desc_order {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY timestamp DESC, id DESC");
            } else {
                sql_order.push_str(" ORDER BY id DESC, timestamp DESC");
            }
        } else {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY timestamp ASC, id ASC");
            } else {
                sql_order.push_str(" ORDER BY id ASC, timestamp ASC");
            }
        }

        let sql_where = if sql_where.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", sql_where.join(" AND "))
        };

        Ok((sql_where, sql_order, sql_param))
    }

    pub fn get_domain_list_count(&self, param: Option<&DomainListGetParam>) -> u64 {
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return 0;
        }

        let conn = conn.as_ref().unwrap();
        let mut sql = String::new();
        let mut sql_param = Vec::new();
        sql.push_str("SELECT COUNT(*) FROM domain");
        if let Ok((sql_where, sql_order, mut ret_sql_param)) = Self::get_domain_sql_where(param) {
            sql.push_str(sql_where.as_str());
            sql.push_str(sql_order.as_str());
            sql_param.append(&mut ret_sql_param);
        }

        let mut stmt = conn.prepare(sql.as_str()).unwrap();
        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| Ok(row.get(0)?));

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    return row;
                }
            }
        }

        0
    }

    pub fn delete_domain_by_id(&self, id: u64) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute("DELETE FROM domain WHERE id = ?", &[&id]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn delete_domain_before_timestamp(&self, timestamp: u64) -> Result<u64, Box<dyn Error>> {
        let ret = {
            let conn = self.conn.lock().unwrap();
            if conn.as_ref().is_none() {
                return Err("db is not open".into());
            }

            let conn = conn.as_ref().unwrap();

            let ret = conn.execute("DELETE FROM domain WHERE timestamp <= ?", &[&timestamp]);

            if let Err(e) = ret {
                return Err(Box::new(e));
            }

            Ok(ret.unwrap() as u64)
        };

        self.run_vacuum(Some(50000))?;

        ret
    }

    pub fn refresh_client_top_list(&self, timestamp: u64) -> Result<(), Box<dyn Error>> {
        let timestamp_now = smartdns::get_utc_time_ms();
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_mut().unwrap();
        let sql = "SELECT client, count FROM top_client_list ORDER BY count DESC";
        self.debug_query_plan(&conn, sql.to_string(), &vec![]);

        let tx = conn.transaction()?;
        tx.execute("DELETE FROM top_client_list", [])?;
        tx.execute(
            "INSERT INTO top_client_list (client, count, timestamp_start, timestamp_end)
             SELECT 
                 client,
                 COUNT(*),
                 ?1,
                 ?2
             FROM domain
             WHERE timestamp >= ?1
             GROUP BY client
             ORDER BY COUNT(*) DESC
             LIMIT 20",
            rusqlite::params![timestamp, timestamp_now],
        )?;

        let mut client_count_list = Vec::new();

        let mut stmt = tx.prepare(sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(ClientQueryCount {
                client_ip: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: timestamp,
                timestamp_end: timestamp_now,
            })
        })?;

        for row in rows {
            client_count_list.push(row?);
        }

        stmt.finalize()?;
        tx.commit()?;

        Ok(())
    }

    pub fn get_client_top_list(&self, count: u32) -> Result<Vec<ClientQueryCount>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.readonly_conn_or_err()?;
        let mut stmt =
            conn.prepare("SELECT client, count, timestamp_start, timestamp_end FROM top_client_list ORDER BY count DESC LIMIT ?")?;
        let rows = stmt.query_map([count.to_string()], |row| {
            Ok(ClientQueryCount {
                client_ip: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: row.get(2)?,
                timestamp_end: row.get(3)?,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        Ok(ret)
    }

    pub fn delete_daily_query_count_before_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute(
            "DELETE FROM domain_daily_count WHERE timestamp <= ?",
            &[&timestamp],
        );

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_daily_query_count(&self, past_days: u32) -> Result<DailyQueryCount, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.readonly_conn_or_err()?;
        let seconds = 86400 * past_days - utils::seconds_until_next_hour() as u32;
        let mut stmt = conn.prepare(
            "SELECT \
                    strftime('%Y-%m-%d', datetime(timestamp / 1000, 'unixepoch', 'localtime')) AS date, timestamp, count \
                 FROM \
                    domain_daily_count \
                 WHERE \
                    timestamp >= strftime('%s', 'now') * 1000 - ? * 1000 \
                 ORDER BY \
                    timestamp DESC;\
                 ",
        )?;

        let rows = stmt.query_map([seconds.to_string()], |row| {
            Ok(DailyQueryCountItem {
                day: row.get(0)?,
                query_count: row.get(2)?,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        Ok(DailyQueryCount {
            query_timestamp: smartdns::get_utc_time_ms(),
            daily_query_count: ret,
        })
    }

    pub fn delete_hourly_query_count_before_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute(
            "DELETE FROM domain_hourly_count WHERE timestamp <= ?",
            &[&timestamp],
        );

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_hourly_query_count(
        &self,
        past_hours: u32,
    ) -> Result<HourlyQueryCount, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.readonly_conn_or_err()?;

        let query_start = std::time::Instant::now();
        let seconds = 3600 * past_hours - utils::seconds_until_next_hour() as u32;

        let sql = "SELECT \
                    strftime('%Y-%m-%d %H:00:00', datetime(timestamp / 1000, 'unixepoch', 'localtime')) AS hour, timestamp, count \
                 FROM \
                    domain_hourly_count \
                 WHERE \
                    timestamp >= strftime('%s', 'now') * 1000 - ? * 1000 \
                 ORDER BY \
                    timestamp DESC;\
                 ";
        self.debug_query_plan(&conn, sql.to_string(), &vec![seconds.to_string()]);
        let mut stmt = conn.prepare(sql)?;

        let rows = stmt.query_map([seconds.to_string()], |row| {
            Ok(HourlyQueryCountItem {
                hour: row.get(0)?,
                query_count: row.get(2)?,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        dns_log!(
            LogLevel::DEBUG,
            "hourly_query_count time: {}ms",
            query_start.elapsed().as_millis()
        );

        Ok(HourlyQueryCount {
            query_timestamp: smartdns::get_utc_time_ms(),
            hourly_query_count: ret,
        })
    }

    /// 按小时汇总最近 past_hours 小时的查询明细。
    ///
    /// 已完成的小时读 `domain_hourly_detail` 汇总表；窗口起点所在的「残段小时」（半截、
    /// 口径与整点汇总不同）、当前小时，以及汇总表缺失的完整小时仍实时扫明细。
    /// 汇总表不存在时整段退化为实时扫描，不报错；输出与旧的逐条扫描实现完全一致。
    pub fn get_hourly_detail(&self, past_hours: u32) -> Result<HourlyDetail, Box<dyn Error>> {
        let now_ms = smartdns::get_utc_time_ms();
        let local_offset = Local::now().offset().local_minus_utc() as i64;
        let current_hour = local_hour_start_ms(now_ms, local_offset);

        // 与旧实现的 strftime('%s','now') * 1000 对齐：窗口起点按秒截断。
        let now_sec_ms = now_ms / 1000 * 1000;
        let mut window_start = now_sec_ms
            .saturating_sub(HOURLY_DETAIL_HOUR_MS.saturating_mul(past_hours as u64));

        let conn = self.readonly_conn_or_err()?;

        // 汇总表可能保留 30 天，但旧实现只能看到明细保留期内的小时。
        // 用明细里最早的一条把窗口夹住，保证输出的小时范围与旧实现完全一致。
        let detail_min: Option<i64> =
            conn.query_row("SELECT MIN(timestamp) FROM domain", [], |row| row.get(0))?;
        let detail_min = match detail_min {
            Some(v) if v > 0 => v as u64,
            _ => {
                return Ok(HourlyDetail {
                    query_timestamp: now_ms,
                    hourly_detail: Vec::new(),
                });
            }
        };
        if detail_min > window_start {
            window_start = detail_min;
        }

        let boundary_hour = local_hour_start_ms(window_start, local_offset);
        let mut hours: HashMap<u64, Vec<HourlyDetailGroupAgg>> = HashMap::new();

        // 汇总表负责的区间：残段小时之后的第一个整点，直到当前小时（不含）。
        let stored_from = if boundary_hour < current_hour {
            boundary_hour.saturating_add(HOURLY_DETAIL_HOUR_MS)
        } else {
            current_hour
        };

        // 1) 已结束的完整小时：读汇总表（只读十几行到几十行）
        if hourly_detail_table_exists(&conn) && stored_from < current_hour {
            self.debug_query_plan(
                &conn,
                HOURLY_DETAIL_STORED_SQL.to_string(),
                &vec![stored_from.to_string(), current_hour.to_string()],
            );

            let mut stmt = conn.prepare(HOURLY_DETAIL_STORED_SQL)?;
            let rows = stmt.query_map(
                rusqlite::params![stored_from as i64, current_hour as i64],
                |row| {
                    let to_u64 = |v: Option<i64>| v.unwrap_or(0).max(0) as u64;
                    Ok(HourlyDetailGroupAgg {
                        hour_timestamp: row.get::<_, i64>(0)?.max(0) as u64,
                        domain_group: row.get(1)?,
                        query_count: to_u64(row.get::<_, Option<i64>>(2)?),
                        cached_count: to_u64(row.get::<_, Option<i64>>(3)?),
                        blocked_count: to_u64(row.get::<_, Option<i64>>(4)?),
                        cached_time_sum: row.get::<_, Option<f64>>(5)?.unwrap_or(0.0),
                        cached_time_count: to_u64(row.get::<_, Option<i64>>(6)?),
                        uncached_time_sum: row.get::<_, Option<f64>>(7)?.unwrap_or(0.0),
                        uncached_time_count: to_u64(row.get::<_, Option<i64>>(8)?),
                    })
                },
            )?;

            let aggs = rows.collect::<Result<Vec<HourlyDetailGroupAgg>, rusqlite::Error>>()?;
            push_hourly_detail_aggs(&mut hours, aggs);
        }

        // 2) 实时部分：残段小时 + 当前这个还没结束的小时
        for (start, end) in hourly_detail_live_ranges(boundary_hour, current_hour, window_start) {
            if start >= end {
                continue;
            }

            self.debug_query_plan(
                &conn,
                HOURLY_DETAIL_SCAN_SQL.to_string(),
                &vec![start.to_string(), end.to_string()],
            );

            let (aggs, _) = collect_hourly_detail_aggs(&conn, start, end, local_offset)?;
            push_hourly_detail_aggs(&mut hours, aggs.into_values());
        }

        // 3) 兜底：窗口内「明细里有数据、但汇总表里没有」的完整小时，就地实时补算，
        //    保证任何情况下都不缺柱子。汇总表完整时这里是空集合，不会有额外扫描。
        if stored_from < current_hour {
            let present: HashSet<u64> = hours.keys().copied().collect();
            let missing = missing_hour_ranges(&present, stored_from, current_hour);
            if !missing.is_empty() {
                let missing_hours: u64 = missing
                    .iter()
                    .map(|(start, end)| (end - start) / HOURLY_DETAIL_HOUR_MS)
                    .sum();
                let mut scanned: u64 = 0;
                for (start, end) in missing {
                    self.debug_query_plan(
                        &conn,
                        HOURLY_DETAIL_SCAN_SQL.to_string(),
                        &vec![start.to_string(), end.to_string()],
                    );

                    let (aggs, rows) =
                        collect_hourly_detail_aggs(&conn, start, end, local_offset)?;
                    scanned += rows;
                    push_hourly_detail_aggs(&mut hours, aggs.into_values());
                }

                dns_log!(
                    LogLevel::DEBUG,
                    "hourly detail fallback: {} missing hour(s), {} row(s) scanned live",
                    missing_hours,
                    scanned
                );
            }
        }

        // 4) 组装输出：小时倒序（与旧实现 ORDER BY hour DESC 一致），
        //    同一小时内按域名分组名升序（与旧实现 GROUP BY 的返回顺序一致）。
        let mut ordered: Vec<(u64, Vec<HourlyDetailGroupAgg>)> = hours.into_iter().collect();
        ordered.sort_by(|a, b| b.0.cmp(&a.0));

        let mut ret: Vec<HourlyDetailItem> = Vec::with_capacity(ordered.len());
        for (hour_timestamp, mut groups) in ordered {
            groups.sort_by(|a, b| a.domain_group.cmp(&b.domain_group));

            let mut item = HourlyDetailItem {
                hour: format_local_hour(&conn, hour_timestamp)?,
                query_count: 0,
                cached_count: 0,
                blocked_count: 0,
                avg_query_time_cached: 0.0,
                avg_query_time_uncached: 0.0,
                groups: Vec::new(),
            };
            let mut cached_time_sum = 0.0f64;
            let mut cached_time_count = 0u64;
            let mut uncached_time_sum = 0.0f64;
            let mut uncached_time_count = 0u64;

            for agg in groups {
                item.query_count = item.query_count.saturating_add(agg.query_count as u32);
                item.cached_count = item.cached_count.saturating_add(agg.cached_count as u32);
                item.blocked_count = item.blocked_count.saturating_add(agg.blocked_count as u32);
                cached_time_sum += agg.cached_time_sum;
                cached_time_count += agg.cached_time_count;
                uncached_time_sum += agg.uncached_time_sum;
                uncached_time_count += agg.uncached_time_count;

                item.groups.push(DomainGroupHourlyStat {
                    domain_group: agg.domain_group,
                    query_count: agg.query_count as u32,
                    cached_count: agg.cached_count as u32,
                });
            }

            if cached_time_count > 0 {
                item.avg_query_time_cached = cached_time_sum / cached_time_count as f64;
            }
            if uncached_time_count > 0 {
                item.avg_query_time_uncached = uncached_time_sum / uncached_time_count as f64;
            }

            ret.push(item);
        }

        Ok(HourlyDetail {
            query_timestamp: now_ms,
            hourly_detail: ret,
        })
    }

    /// 幂等写入小时汇总表：同一 (小时, 分组) 直接覆盖，不会累加。
    pub fn upsert_domain_hourly_detail(
        &self,
        aggs: &[HourlyDetailGroupAgg],
    ) -> Result<(), Box<dyn Error>> {
        if aggs.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }
        let conn = conn.as_mut().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO domain_hourly_detail \
                 (hour_timestamp, domain_group, query_count, cached_count, blocked_count, \
                  cached_time_sum, cached_time_count, uncached_time_sum, uncached_time_count) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(hour_timestamp, domain_group) DO UPDATE SET \
                  query_count = excluded.query_count, \
                  cached_count = excluded.cached_count, \
                  blocked_count = excluded.blocked_count, \
                  cached_time_sum = excluded.cached_time_sum, \
                  cached_time_count = excluded.cached_time_count, \
                  uncached_time_sum = excluded.uncached_time_sum, \
                  uncached_time_count = excluded.uncached_time_count",
            )?;

            for agg in aggs {
                stmt.execute(rusqlite::params![
                    agg.hour_timestamp as i64,
                    &agg.domain_group,
                    agg.query_count as i64,
                    agg.cached_count as i64,
                    agg.blocked_count as i64,
                    agg.cached_time_sum,
                    agg.cached_time_count as i64,
                    agg.uncached_time_sum,
                    agg.uncached_time_count as i64,
                ])?;
            }
        }
        tx.commit()?;

        Ok(())
    }

    /// 汇总 `[start_ms, end_ms)` 的明细并幂等落库，返回扫描到的明细行数。
    pub fn summarize_hourly_detail(
        &self,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<u64, Box<dyn Error>> {
        if start_ms >= end_ms {
            return Ok(0);
        }

        let local_offset = Local::now().offset().local_minus_utc() as i64;
        let (aggs, scanned) = {
            let conn = self.readonly_conn_or_err()?;
            collect_hourly_detail_aggs(&conn, start_ms, end_ms, local_offset)?
        };

        let mut rows: Vec<HourlyDetailGroupAgg> = aggs.into_values().collect();
        rows.sort_by(|a, b| {
            a.hour_timestamp
                .cmp(&b.hour_timestamp)
                .then_with(|| a.domain_group.cmp(&b.domain_group))
        });
        self.upsert_domain_hourly_detail(&rows)?;

        Ok(scanned)
    }

    /// 整点跑一次的小时汇总入口。
    ///
    /// 正常只重算最近 `HOURLY_DETAIL_RECHECK_HOURS` 个已完成小时（幂等覆盖）；首次运行、
    /// 重启或发现完整小时缺失时，按明细保留期整体回填。
    /// 只归档完整小时：当前小时和残段小时都是半截的，不由本函数负责（接口实时算）。
    pub fn refresh_hourly_detail(
        &self,
        now_ms: u64,
        retention_ms: u64,
    ) -> Result<u64, Box<dyn Error>> {
        // 表可能在 open() 时补建失败（例如那一刻被别的进程锁住），这里再补一次。
        // 还是建不出来就跳过本次汇总：接口会退化为实时扫描，功能不受影响。
        if !self.ensure_hourly_detail_table() {
            return Ok(0);
        }

        let local_offset = Local::now().offset().local_minus_utc() as i64;
        let current_hour = local_hour_start_ms(now_ms, local_offset);
        // 最旧的那格被保留期从中间切断，是残段小时、不由汇总表负责，
        // 所以回填起点取它的下一个整点（窗口内第一个完整小时）。
        let first_full_hour = local_hour_start_ms(now_ms.saturating_sub(retention_ms), local_offset)
            .saturating_add(HOURLY_DETAIL_HOUR_MS);
        if first_full_hour >= current_hour {
            return Ok(0);
        }

        let recheck_hour =
            current_hour.saturating_sub(HOURLY_DETAIL_RECHECK_HOURS * HOURLY_DETAIL_HOUR_MS);
        let covered = self.hourly_detail_hours_covered(first_full_hour, current_hour)?;
        let start_hour = if covered { recheck_hour } else { first_full_hour };
        if start_hour >= current_hour {
            return Ok(0);
        }

        self.summarize_hourly_detail(start_hour, current_hour)
    }

    /// 汇总表是否已把 `[first_hour, to_hour)` 内「明细里有数据的完整小时」全部归档。
    ///
    /// 比对集合而非 MIN/MAX，才能发现中间空洞；表完整时不会有任何写入。
    /// 代价是每小时一次 `idx_domain_timestamp` 索引扫描（宽度同明细保留期）。
    fn hourly_detail_hours_covered(
        &self,
        first_hour: u64,
        to_hour: u64,
    ) -> Result<bool, Box<dyn Error>> {
        let local_offset = Local::now().offset().local_minus_utc() as i64;
        let conn = self.readonly_conn_or_err()?;

        let needed = detail_hours_in_range(&conn, first_hour, to_hour, local_offset)?;
        if needed.is_empty() {
            return Ok(true);
        }

        let stored = stored_hours_in_range(&conn, first_hour, to_hour)?;
        Ok(needed.iter().all(|hour| stored.contains(hour)))
    }

    /// 清理 30 天以前的小时汇总（明细本身只有 24 小时，这里留宽一点方便以后扩展）。
    pub fn delete_hourly_detail_before_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }
        let conn = conn.as_ref().unwrap();

        let ret = conn.execute(
            "DELETE FROM domain_hourly_detail WHERE hour_timestamp <= ?",
            [timestamp as i64],
        )?;

        Ok(ret as u64)
    }

    pub fn refresh_domain_top_list(&self, timestamp: u64) -> Result<(), Box<dyn Error>> {
        let timestamp_now = smartdns::get_utc_time_ms();
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_mut().unwrap();
        let sql = "SELECT domain, count FROM top_domain_list ORDER BY count DESC";
        self.debug_query_plan(&conn, sql.to_string(), &vec![]);

        let tx = conn.transaction()?;
        tx.execute("DELETE FROM top_domain_list", [])?;
        tx.execute(
            "INSERT INTO top_domain_list (domain, count, timestamp_start, timestamp_end)
               SELECT 
               domain,
               COUNT(*),
               ?1,
               ?2
             FROM domain
             WHERE timestamp >= ?1
             GROUP BY domain
             ORDER BY COUNT(*) DESC
             LIMIT 20",
            rusqlite::params![timestamp, timestamp_now],
        )?;

        let mut domain_count_list = Vec::new();

        let mut stmt = tx.prepare(sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(DomainQueryCount {
                domain: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: timestamp,
                timestamp_end: timestamp_now,
            })
        })?;

        for row in rows {
            domain_count_list.push(row?);
        }
        stmt.finalize()?;
        tx.commit()?;

        Ok(())
    }

    pub fn get_domain_top_list(&self, count: u32) -> Result<Vec<DomainQueryCount>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.readonly_conn_or_err()?;

        let mut stmt = conn.prepare("SELECT domain, count, timestamp_start, timestamp_end FROM top_domain_list DESC LIMIT ?")?;
        let rows = stmt.query_map([count.to_string()], |row| {
            Ok(DomainQueryCount {
                domain: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: row.get(2)?,
                timestamp_end: row.get(3)?,
            })
        });

        if let Err(e) = rows {
            return Err(Box::new(e));
        }

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        Ok(ret)
    }

    pub fn get_domain_list(
        &self,
        param: Option<&DomainListGetParam>,
    ) -> Result<QueryDomainListResult, Box<dyn Error>> {
        let query_start = std::time::Instant::now();
        let mut cursor_reverse = false;

        let mut ret = QueryDomainListResult {
            domain_list: vec![],
            total_count: 0,
            step_by_cursor: false,
        };

        let conn = self.readonly_conn_or_err()?;

        let (sql_where, sql_order, mut sql_param) = Self::get_domain_sql_where(param)?;

        let mut sql = String::new();
        sql.push_str("SELECT id, timestamp, domain, domain_type, client, domain_group, reply_code, query_time, ping_time, is_blocked, is_cached FROM domain");

        sql.push_str(sql_where.as_str());
        sql.push_str(sql_order.as_str());

        if let Some(p) = param {
            let mut with_offset = true;
            if let Some(cursor) = &p.cursor {
                if cursor.id.is_some() {
                    sql.push_str(" LIMIT ?");
                    sql_param.push(p.page_size.to_string());
                    with_offset = false;
                }

                if cursor.direction.eq_ignore_ascii_case("prev") {
                    cursor_reverse = true;
                }
            }

            if with_offset {
                sql.push_str(" LIMIT ? OFFSET ?");
                sql_param.push(p.page_size.to_string());
                sql_param.push(((p.page_num - 1) * p.page_size).to_string());
            }
        }

        self.debug_query_plan(&conn, sql.clone(), &sql_param);
        let stmt = conn.prepare(&sql);

        if let Err(e) = stmt {
            dns_log!(LogLevel::ERROR, "get_domain_list error: {}", e);
            return Err("get_domain_list error".into());
        }

        let mut stmt = stmt?;

        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| {
            Ok(DomainData {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                domain: row.get(2)?,
                domain_type: row.get(3)?,
                client: row.get(4)?,
                domain_group: row.get(5)?,
                reply_code: row.get(6)?,
                query_time: row.get(7)?,
                ping_time: row.get(8)?,
                is_blocked: row.get(9)?,
                is_cached: row.get(10)?,
            })
        });

        if let Err(e) = rows {
            return Err(Box::new(e));
        }

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.domain_list.push(row);
                }
            }
        }

        if cursor_reverse {
            ret.domain_list.reverse();
        }

        if let Some(p) = param {
            if let Some(v) = &p.cursor {
                ret.total_count = v.total_count;
                ret.step_by_cursor = true;
            } else {
                let total_count = self.get_domain_list_count(param);
                ret.total_count = total_count;
            }
        }

        dns_log!(
            LogLevel::DEBUG,
            "domain_list time: {}ms",
            query_start.elapsed().as_millis()
        );
        Ok(ret)
    }

    pub fn insert_client(&self, client_data: &Vec<ClientData>) -> Result<(), Box<dyn Error>> {
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_mut().unwrap();
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare("INSERT INTO client (id, client_ip, mac, hostname, last_query_timestamp) VALUES (
            (SELECT MAX(rowid) FROM client) + 1,
            ?1, ?2, ?3, ?4)
            ON CONFLICT(client_ip, mac) DO UPDATE SET
                last_query_timestamp = excluded.last_query_timestamp,
                hostname = CASE WHEN excluded.hostname = '' THEN hostname ELSE excluded.hostname END;
            ")?;
        for d in client_data {
            let ret = stmt.execute(rusqlite::params![
                d.client_ip,
                d.mac,
                d.hostname,
                d.last_query_timestamp
            ]);

            if let Err(e) = ret {
                stmt.finalize()?;
                tx.rollback()?;
                return Err(Box::new(e));
            }
        }
        stmt.finalize()?;
        tx.commit()?;

        Ok(())
    }

    pub fn get_client_list_count(&self, param: Option<&ClientListGetParam>) -> u64 {
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return 0;
        }

        let conn = conn.as_ref().unwrap();
        let mut sql = String::new();
        let mut sql_param = Vec::new();
        sql.push_str("SELECT COUNT(*) FROM client");
        if let Ok((sql_where, sql_order, mut ret_sql_param)) = Self::get_client_sql_where(param) {
            sql.push_str(sql_where.as_str());
            sql.push_str(sql_order.as_str());
            sql_param.append(&mut ret_sql_param);
        }

        let mut stmt = conn.prepare(sql.as_str()).unwrap();
        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| Ok(row.get(0)?));

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    return row;
                }
            }
        }

        0
    }

    fn get_client_sql_where(
        param: Option<&ClientListGetParam>,
    ) -> Result<(String, String, Vec<String>), Box<dyn Error>> {
        let mut is_desc_order = true;
        let param = match param {
            Some(v) => v,
            None => return Ok((String::new(), String::new(), Vec::new())),
        };
        let mut order_timestamp_first = false;

        let mut sql_where: Vec<String> = Vec::new();
        let mut sql_param: Vec<String> = Vec::new();
        let mut sql_order = String::new();

        if let Some(v) = &param.id {
            sql_where.push("id = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.order {
            if v.eq_ignore_ascii_case("asc") {
                is_desc_order = false;
            } else if v.eq_ignore_ascii_case("desc") {
                is_desc_order = true;
            } else {
                return Err("order param error".into());
            }
        }


        if let Some(v) = &param.client_ip {
            sql_where.push("client_ip = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.mac {
            sql_where.push("mac = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.hostname {
            sql_where.push("hostname = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.timestamp_before {
            sql_where.push("last_query_timestamp <= ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = true;
        }

        if let Some(v) = &param.timestamp_after {
            sql_where.push("last_query_timestamp >= ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = true;
        }

        if order_timestamp_first {
            if is_desc_order {
                sql_order.push_str(" ORDER BY last_query_timestamp DESC, id DESC");
            } else {
                sql_order.push_str(" ORDER BY last_query_timestamp ASC, id ASC");
            }
        } else {
            if is_desc_order {
                sql_order.push_str(" ORDER BY id DESC, last_query_timestamp DESC");
            } else {
                sql_order.push_str(" ORDER BY id ASC, last_query_timestamp ASC");
            }
        };

        let sql_where = if sql_where.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", sql_where.join(" AND "))
        };

        Ok((sql_where, sql_order, sql_param))
    }

    /// Fetch all persisted (client_ip, mac) pairs for the hostname cache warmup.
    /// Only pairs with a real MAC are returned so runtime observations are usable.
    pub fn get_client_ip_mac_pairs(&self) -> Result<Vec<(String, String)>, Box<dyn Error>> {
        let conn = self.readonly_conn_or_err()?;

        let mut stmt = conn.prepare(
            "SELECT client_ip, mac FROM client \
             WHERE mac != '00:00:00:00:00:00' AND client_ip != ''",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut pairs = Vec::new();
        for row in rows {
            pairs.push(row?);
        }
        Ok(pairs)
    }

    /// Rows of the client table whose hostname column is still empty, used by
    /// the one-shot hostname backfill at startup.
    pub fn get_client_rows_without_hostname(
        &self,
    ) -> Result<Vec<(u32, String, String)>, Box<dyn Error>> {
        let conn = self.readonly_conn_or_err()?;

        let mut stmt = conn.prepare("SELECT id, client_ip, mac FROM client WHERE hostname = ''")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Batch-update the hostname column in one transaction (startup backfill
    /// only; regular per-query upserts never touch existing hostnames).
    pub fn update_client_hostnames(&self, updates: &[(u32, String)]) -> Result<(), Box<dyn Error>> {
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }
        let conn = conn.as_mut().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare("UPDATE client SET hostname = ?2 WHERE id = ?1")?;
            for (id, name) in updates {
                stmt.execute(rusqlite::params![id, name])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_client_list(
        &self,
        param: Option<&ClientListGetParam>,
    ) -> Result<QueryClientListResult, Box<dyn Error>> {
        let query_start = std::time::Instant::now();

        let mut ret = QueryClientListResult {
            client_list: vec![],
            total_count: 0,
            step_by_cursor: false,
        };

        let conn = self.readonly_conn_or_err()?;

        let (mut sql_where, sql_order, mut sql_param) = Self::get_client_sql_where(param)?;

        let mut sql = String::new();
        sql.push_str("SELECT id, client_ip, mac, hostname, last_query_timestamp FROM client");

        if let Some(p) = param {
            let page_size = p.page_size as u64;
            let page_num = p.page_num as u64;
            let offset = (page_num - 1) * page_size;

            let use_timestamp_sort =
                p.timestamp_before.is_some() || p.timestamp_after.is_some();

            if use_timestamp_sort {
                sql.push_str(&sql_where);
                sql.push_str(&sql_order);
                sql.push_str(" LIMIT ? OFFSET ?");
                sql_param.push(page_size.to_string());
                sql_param.push(offset.to_string());
            } else {
                if page_num > 1 {

                    let mut anchor_sql = sql.clone();
                    anchor_sql.push_str(&sql_where);
                    anchor_sql.push_str(&sql_order);
                    anchor_sql.push_str(" LIMIT 1 OFFSET ?");

                    let mut anchor_param = sql_param.clone();
                    anchor_param.push(offset.to_string());

                    self.debug_query_plan(&conn, anchor_sql.clone(), &anchor_param);
                    let mut stmt = conn.prepare(&anchor_sql)?;
                    let mut rows = stmt.query(rusqlite::params_from_iter(anchor_param))?;
                    if let Some(row) = rows.next()? {
                        let anchor_id: i64 = row.get(0)?;
                        let is_desc = match &p.order {
                            Some(o) => !o.eq_ignore_ascii_case("asc"),
                            None => true,
                        };

                        let cond = if is_desc { "id <= ?" } else { "id >= ?" };

                        if sql_where.is_empty() {
                            sql_where = format!(" WHERE {}", cond);
                        } else {
                            sql_where.push_str(" AND ");
                            sql_where.push_str(cond);
                        }

                        sql_param.push(anchor_id.to_string());
                    }
                }

                sql.push_str(&sql_where);
                sql.push_str(&sql_order);  //push ORDER after WHERE !important
                sql.push_str(" LIMIT ?");  //push LIMIT after ORDER !important

                sql_param.push(page_size.to_string());
            }
        }

        self.debug_query_plan(&conn, sql.clone(), &sql_param);
        let stmt = conn.prepare(&sql);
        if let Err(e) = stmt {
            dns_log!(LogLevel::ERROR, "get_client_list error: {}", e);
            return Err("get_client_list error".into());
        }
        let mut stmt = stmt?;

        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| {
            Ok(ClientData {
                id: row.get(0)?,
                client_ip: row.get(1)?,
                mac: row.get(2)?,
                hostname: row.get(3)?,
                last_query_timestamp: row.get(4)?,
            })
        });

        if let Err(e) = rows {
            return Err(Box::new(e));
        }

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.client_list.push(row);
                }
            }
        }

        if let Some(_p) = param {
            ret.total_count = self.get_client_list_count(param);
        }

        dns_log!(
            LogLevel::DEBUG,
            "client_list time: {}ms",
            query_start.elapsed().as_millis()
        );
        Ok(ret)
    }

    pub fn delete_client_by_id(&self, id: u64) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute("DELETE FROM client WHERE id = ?", &[&id]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_db_size(&self) -> u64 {
        let db_file = self.get_db_file_path();
        let mut total_size = 0;
        if db_file.is_none() {
            return 0;
        }

        let db_file = db_file.unwrap();
        let wal_file = db_file.clone() + "-wal";

        let metadata = fs::metadata(db_file);
        if let Err(_) = metadata {
            return 0;
        }
        total_size += metadata.unwrap().len();

        let wal_metadata = fs::metadata(wal_file);
        if let Ok(wal_metadata) = wal_metadata {
            let wal_size = wal_metadata.len();
            total_size += wal_size;
        }

        total_size
    }

    pub fn close(&self) {
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return;
        }

        if let Some(t) = conn.take() {
            let _ = t.close();
        }
    }
}

impl Drop for DB {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = HOURLY_DETAIL_HOUR_MS;

    #[test]
    fn local_hour_start_ms_rounds_down_to_local_hour() {
        // 整点（UTC 偏移 0）
        assert_eq!(local_hour_start_ms(10 * HOUR, 0), 10 * HOUR);
        // 非整点（UTC 偏移 0）
        assert_eq!(local_hour_start_ms(10 * HOUR + 1_234_567, 0), 10 * HOUR);
        // 非整小时偏移（+5:30）：本地时间比整点早 30 分钟，落在上一个 UTC 小时
        assert_eq!(
            local_hour_start_ms(10 * HOUR + 1_234_567, 19_800),
            9 * HOUR + 1_800_000
        );
        // 负偏移（-5:00，与 +5:00 等价地按整点分桶）
        assert_eq!(local_hour_start_ms(10 * HOUR + 1_234_567, -18_000), 10 * HOUR);
        // 纪元起点 + 正偏移不能下溢
        assert_eq!(local_hour_start_ms(0, 28_800), 0);
        // 一个固定的真实时间戳（跨天场景）
        assert_eq!(
            local_hour_start_ms(1_700_000_000_000, 28_800),
            1_699_999_200_000
        );
    }

    #[test]
    fn local_hour_start_ms_invariants() {
        // 前提：时间戳是真实的「毫秒级 unix 时间」（远大于任何时区偏移）。
        // 时间戳小于偏移量的情况（1970 年前后）不在这个函数的使用范围内。
        for ts in [10 * HOUR, 10 * HOUR + 1_234_567, 1_700_000_000_000] {
            for off in [0i64, 28_800, 19_800, -18_000, -28_800] {
                let hour = local_hour_start_ms(ts, off);
                let off_ms = off * 1000;
                // 不晚于时间戳，且同一小时内
                assert!(hour <= ts, "ts={} off={}", ts, off);
                assert!(ts - hour < HOUR, "ts={} off={}", ts, off);
                // 加上偏移后一定是整点，说明分桶口径是「本地整点」
                assert_eq!(
                    (hour as i64 + off_ms).rem_euclid(HOUR as i64),
                    0,
                    "ts={} off={}",
                    ts,
                    off
                );
            }
        }
    }

    #[test]
    fn live_ranges_tile_window_with_stored_range() {
        let boundary = 100 * HOUR;
        let current = 103 * HOUR;
        let window_start = boundary + 1_000;

        let ranges = hourly_detail_live_ranges(boundary, current, window_start);
        assert_eq!(
            ranges,
            vec![(window_start, boundary + HOUR), (current, u64::MAX)]
        );

        // 实时区间 + 汇总表区间（[boundary+HOUR, current)）必须无缝、无重叠地覆盖窗口
        let mut all = ranges;
        all.push((boundary + HOUR, current));
        all.sort();

        assert_eq!(all[0].0, window_start);
        for pair in all.windows(2) {
            assert_eq!(pair[0].1, pair[1].0, "gap or overlap in {:?}", all);
        }
        assert_eq!(all.last().unwrap().1, u64::MAX);
    }

    #[test]
    fn live_ranges_collapse_when_window_inside_current_hour() {
        let current = 100 * HOUR;
        let window_start = current + 60_000;

        assert_eq!(
            hourly_detail_live_ranges(current, current, window_start),
            vec![(window_start, u64::MAX)]
        );
    }

    #[test]
    fn missing_hour_ranges_coalesces_gaps() {
        let first = 100 * HOUR;
        let to = 106 * HOUR;
        let present: HashSet<u64> = [first, first + 2 * HOUR, first + 5 * HOUR]
            .into_iter()
            .collect();

        assert_eq!(
            missing_hour_ranges(&present, first, to),
            vec![
                (first + HOUR, first + 2 * HOUR),
                (first + 3 * HOUR, first + 5 * HOUR),
            ]
        );

        // 表完整时没有任何补算区间
        let all: HashSet<u64> = (0..6).map(|i| first + i * HOUR).collect();
        assert!(missing_hour_ranges(&all, first, to).is_empty());
    }

    #[test]
    fn live_and_missing_ranges_tile_window_without_stored_holes() {
        // 场景：4 个完整小时里只有第 1、3 个在汇总表中
        let boundary = 100 * HOUR;
        let current = 104 * HOUR;
        let window_start = boundary + 42_000;
        let stored_from = boundary + HOUR;
        let present: HashSet<u64> = [stored_from, stored_from + 2 * HOUR].into_iter().collect();

        let mut all: Vec<(u64, u64)> = missing_hour_ranges(&present, stored_from, current);
        all.extend(hourly_detail_live_ranges(boundary, current, window_start));
        all.extend(present.iter().map(|hour| (*hour, *hour + HOUR)));
        all.sort();

        assert_eq!(all[0].0, window_start);
        for pair in all.windows(2) {
            assert_eq!(pair[0].1, pair[1].0, "gap or overlap in {:?}", all);
        }
        assert_eq!(all.last().unwrap().1, u64::MAX);
        // 残段小时只被算一次
        assert_eq!(all.iter().filter(|(s, _)| *s == window_start).count(), 1);
    }

    #[test]
    fn upsert_hourly_detail_is_idempotent() {
        let db = DB {
            conn: Mutex::new(Some(Connection::open_in_memory().unwrap())),
            version: 10000,
            query_plan: false,
        };
        {
            let guard = db.conn.lock().unwrap();
            db.create_hourly_detail_table(guard.as_ref().unwrap())
                .unwrap();
        }

        let aggs = vec![HourlyDetailGroupAgg {
            hour_timestamp: 100 * HOUR,
            domain_group: "default".to_string(),
            query_count: 10,
            cached_count: 4,
            blocked_count: 1,
            cached_time_sum: 12.0,
            cached_time_count: 4,
            uncached_time_sum: 30.0,
            uncached_time_count: 6,
        }];

        // 同一个小时重复汇总（重启 / 重跑整点任务）必须覆盖，不能累加
        db.upsert_domain_hourly_detail(&aggs).unwrap();
        db.upsert_domain_hourly_detail(&aggs).unwrap();

        let guard = db.conn.lock().unwrap();
        let conn = guard.as_ref().unwrap();

        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM domain_hourly_detail", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 1, "same (hour, group) must be overwritten, not appended");

        let (query_count, cached_count, cached_sum, cached_cnt, blocked): (i64, i64, f64, i64, i64) =
            conn.query_row(
                "SELECT query_count, cached_count, cached_time_sum, cached_time_count, blocked_count \
                 FROM domain_hourly_detail WHERE hour_timestamp = ?1 AND domain_group = ?2",
                rusqlite::params![(100 * HOUR) as i64, "default"],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();

        assert_eq!((query_count, cached_count, cached_cnt, blocked), (10, 4, 4, 1));
        assert_eq!(cached_sum, 12.0);
    }
}
