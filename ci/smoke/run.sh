#!/bin/sh
# 冒烟测试：真实 smartdns 主程序 + 待测插件，容器内跑完整链路
#
# 用法（容器内）：sh /w/run.sh
# 需要 /w/main.smartdns（主程序）与 /w/smartdns_ui.so（待测插件）
# 依赖（容器内先装好）：apk add --no-cache bind-tools libgcc iproute2 sqlite zlib
#
# 断言，全部通过才算成功：
#   1. 主程序启动后日志出现插件加载并启动
#   2. lease-file 配置被插件读到
#   3. DNS 解析可用
#   4. 进程全程存活（插件没把主程序带崩）
#   5. client 表里真的落下了租约文件里的主机名（功能端到端生效）
set -e

W=/w
DATA=/var/lib/smartdns
LEASES=/etc/smartdns/leases/dnsmasq.leases
LOG=/var/log/smartdns.log
CONF=/etc/smartdns/smartdns.conf
PORT=5300
WANT=smoke-host

fail() { echo "SMOKE FAIL: $*"; exit 1; }
ok()   { echo "  [ok] $*"; }

[ -f "$W/main.smartdns" ]  || fail "缺少 $W/main.smartdns"
[ -f "$W/smartdns_ui.so" ] || fail "缺少 $W/smartdns_ui.so"

# ---- 0. 布置 ----
mkdir -p /usr/sbin /usr/lib /usr/share/smartdns/wwwroot /etc/smartdns/leases "$DATA"
cp "$W/main.smartdns"  /usr/sbin/smartdns
cp "$W/smartdns_ui.so" /usr/lib/smartdns_ui.so
chmod +x /usr/sbin/smartdns

# 查询必须从非回环地址发出，否则插件会把客户端显示成 localhost，
# 而不是租约文件里的名字（这是特性，不是 bug）。
IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7}')
[ -n "$IP" ] || fail "拿不到本机非回环 IP"
echo "本机 IP = $IP"

# dnsmasq 租约格式：<到期时间戳> <MAC> <IP> <主机名> <client-id>
echo "1900000000 aa:bb:cc:dd:ee:ff $IP $WANT 01:aa:bb:cc:dd:ee:ff" > "$LEASES"

cat > "$CONF" <<EOF
server-name smoke
bind [::]:$PORT
log-level info
log-file $LOG
cache-size 0
speed-check-mode none
server 223.5.5.5
plugin smartdns_ui.so
smartdns-ui.www-root /usr/share/smartdns/wwwroot
smartdns-ui.ip http://127.0.0.1:6080
smartdns-ui.max-query-log-age 86400
smartdns-ui.lease-file $LEASES
data-dir $DATA
EOF

# ---- 1. 启动 ----
/usr/sbin/smartdns -f -c "$CONF" -p /var/run/smartdns.pid >/tmp/stdout.log 2>&1 &
SRV=$!
echo "smartdns pid=$SRV"

i=0
while [ $i -lt 30 ]; do
    kill -0 $SRV 2>/dev/null || { echo "--- 日志 ---"; cat "$LOG" 2>/dev/null; fail "主程序启动后立刻退出"; }
    [ -f "$LOG" ] && grep -q "start smartdns-ui server" "$LOG" && break
    i=$((i+1)); sleep 1
done
grep -q "start smartdns-ui server" "$LOG" \
    || { echo "--- 日志 ---"; cat "$LOG"; fail "插件没启动（日志无 start smartdns-ui server）"; }
ok "插件已 dlopen 并启动"

# ---- 2. lease-file 生效 ----
grep -q "client hostname display enabled with lease file" "$LOG" \
    || { echo "--- 日志 ---"; cat "$LOG"; fail "lease-file 配置没生效"; }
ok "lease-file 配置生效"

# ---- 3. 解析可用 ----
i=0; RESOLVED=0
while [ $i -lt 15 ]; do
    if dig +short -p $PORT @$IP www.baidu.com >/tmp/ns.log 2>&1 && [ -s /tmp/ns.log ]; then RESOLVED=1; break; fi
    i=$((i+1)); sleep 1
done
[ $RESOLVED -eq 1 ] || { echo "--- 日志尾部 ---"; tail -30 "$LOG"; fail "DNS 解析不通"; }
ok "DNS 解析正常"

# ---- 4. 进程存活 ----
kill -0 $SRV 2>/dev/null || { echo "--- 日志尾部 ---"; tail -30 "$LOG"; fail "查询过程中进程崩溃"; }
ok "进程存活，插件没把主程序带崩"

# ---- 5. 功能端到端 ----
# 客户端行只在"距首次出现 > 3 秒"时才写库，所以必须持续查询把批次推起来。
DB="$DATA/smartdns.db"
i=0; FOUND=0
while [ $i -lt 25 ]; do
    dig +short -p $PORT @$IP www.baidu.com >/dev/null 2>&1 || true
    n=$(sqlite3 "$DB" "select count(*) from client where hostname='$WANT';" 2>/dev/null || echo 0)
    if [ "$n" -ge 1 ] 2>/dev/null; then FOUND=1; break; fi
    i=$((i+1)); sleep 1
done
if [ $FOUND -ne 1 ]; then
    echo "--- client 表实际内容 ---"
    sqlite3 -header "$DB" "select * from client;" 2>&1 | head -5
    echo "--- 日志里 hostname 相关 ---"
    grep -i "hostname" "$LOG" | head -5
    fail "client 表里没有出现主机名 $WANT（功能未生效）"
fi
ok "client 表里查到 $WANT —— 客户端主机名功能端到端生效"

kill $SRV 2>/dev/null || true
echo "SMOKE PASS"
