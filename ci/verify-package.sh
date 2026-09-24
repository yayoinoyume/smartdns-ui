#!/bin/sh
# 发布包真机验证：在目标架构的容器里，把 release 包当作真实安装包装一遍并跑起来
#
# 用法（容器内）：sh /ci/verify-package.sh <包.tar.gz 路径>
# 退出码 0 = 全部断言通过
#
# 断言：
#   1. 包能解压、目录结构符合预期
#   2. 二进制能在本架构运行（打印版本）
#   3. 主程序能启动且不死
#   4. 插件被主程序 dlopen 并启动
#   5. 租约文件被插件读取
#   6. DNS 静态解析可用（不依赖外网）
#   7. 插件 HTTP/WebUI 能返回 200
set -e

PKG="$1"
[ -f "$PKG" ] || { echo "FAIL: 找不到包 $PKG"; exit 1; }

ok()   { echo "  [ok] $*"; }
fail() { echo "  [FAIL] $*"; exit 1; }

echo "═══ 环境 ═══"
echo "  架构: $(uname -m)   系统: $(cat /etc/alpine-release 2>/dev/null || echo unknown)"

echo "═══ 1. 解压发布包 ═══"
mkdir -p /work
tar xzf "$PKG" -C /work
BASE=/work/smartdns
[ -d "$BASE" ] || fail "包内没有 smartdns/ 目录"
ok "解压成功"

echo "═══ 2. 按包内布局安装 ═══"
mkdir -p /usr/local/lib /usr/sbin /usr/share/smartdns /etc/smartdns /var/lib/smartdns /var/log
cp -a "$BASE/usr/local/lib/smartdns" /usr/local/lib/
ln -sf /usr/local/lib/smartdns/run-smartdns /usr/sbin/smartdns
cp -a "$BASE/usr/share/smartdns/wwwroot" /usr/share/smartdns/
ok "已安装主程序 + 插件 + WebUI"

echo "═══ 3. 二进制自检 ═══"
/usr/sbin/smartdns -v 2>&1 | head -2 || fail "二进制无法运行"
ok "二进制可在本架构执行"

echo "═══ 4. 准备配置 ═══"
PORT=5300
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -n "$IP" ] || IP=127.0.0.1
echo "9000000000 aa:bb:cc:dd:ee:ff $IP verify-host 01:aa:bb:cc:dd:ee:ff" > /etc/smartdns/leases
cat > /etc/smartdns/smartdns.conf <<EOF
server-name verify
bind [::]:$PORT
log-level info
log-file /var/log/smartdns.log
cache-size 0
speed-check-mode none
server 223.5.5.5
address /offline-check.local/1.2.3.4
plugin /usr/local/lib/smartdns/smartdns_ui.so
smartdns-ui.www-root /usr/share/smartdns/wwwroot
smartdns-ui.ip http://127.0.0.1:6080
smartdns-ui.lease-file /etc/smartdns/leases
data-dir /var/lib/smartdns
EOF
ok "配置就绪（插件已启用）"

echo "═══ 5. 启动主程序 ═══"
/usr/local/lib/smartdns/run-smartdns -f -c /etc/smartdns/smartdns.conf -p /var/run/smartdns.pid >/tmp/out.log 2>&1 &
SRV=$!
i=0
while [ $i -lt 25 ]; do
    kill -0 $SRV 2>/dev/null || { cat /var/log/smartdns.log 2>/dev/null | tail -30; fail "主程序启动后退出"; }
    grep -q "start smartdns-ui server" /var/log/smartdns.log 2>/dev/null && break
    i=$((i+1)); sleep 1
done
kill -0 $SRV 2>/dev/null || fail "主程序死掉了"
ok "主程序存活"

echo "═══ 6. 断言 ═══"
grep -q "start smartdns-ui server" /var/log/smartdns.log \
    || { tail -30 /var/log/smartdns.log; fail "插件没有被加载"; }
ok "插件已 dlopen 并启动"

grep -q "client hostname display enabled" /var/log/smartdns.log \
    || fail "租约文件配置没生效"
ok "租约文件已生效"

nslookup -port=$PORT offline-check.local 127.0.0.1 >/dev/null 2>&1 \
    || { nslookup -port=$PORT offline-check.local 127.0.0.1; fail "DNS 静态解析失败"; }
ok "DNS 解析正常（离线域名）"

if nslookup -port=$PORT www.baidu.com 127.0.0.1 >/dev/null 2>&1; then
    ok "外网 DNS 解析正常"
else
    echo "  [warn] 外网解析不通（runner 网络限制，不计为包的问题）"
fi

wget -q -O /tmp/index.html http://127.0.0.1:6080/ 2>/dev/null \
    || fail "WebUI HTTP 服务无响应"
[ -s /tmp/index.html ] || fail "WebUI 返回空内容"
ok "WebUI HTTP 返回内容（$(wc -c < /tmp/index.html) 字节）"

kill $SRV 2>/dev/null || true
sleep 1
echo
echo "✅ 该架构包验证通过"
