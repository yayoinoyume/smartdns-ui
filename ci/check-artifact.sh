#!/bin/sh
# 产物检查：确认编出来的 smartdns_ui.so 能不能安全地装到目标设备上
#
# 用法：sh ci/check-artifact.sh <smartdns_ui.so> [目标符号表]
#       目标符号表默认 ci/router-symbols.txt（从生产路由器主程序导出）
#
# 四类检查：
#   1. 架构/文件类型正确（ELF 64-bit x86-64 共享对象）
#   2. 动态依赖干净（只允许 libc.so / libgcc_s.so.1，不允许 glibc、不明显多出东西）
#   3. 插件该导出的 6 个入口函数都在
#   4. 插件向主程序索要的符号，目标设备的主程序必须全都有
#      —— 这条最值钱：主程序用 RTLD_LAZY 加载插件，
#         符号缺失不会在加载时报错，而是等到调用时直接崩。
set -e

SO=${1:-plugin/smartdns-ui/target/smartdns_ui.so}
SYMS=${2:-ci/router-symbols.txt}

fail() { echo "CHECK FAIL: $*"; exit 1; }
ok()   { echo "  [ok] $*"; }
warn() { echo "  [warn] $*"; }

[ -f "$SO" ]   || fail "找不到产物 $SO"
[ -f "$SYMS" ] || fail "找不到目标符号表 $SYMS"

echo "检查 $SO ($(stat -c%s "$SO" 2>/dev/null || wc -c <"$SO") 字节)"

# ---------- 1. 文件类型 ----------
FILEOUT=$(file -b "$SO")
echo "  file: $FILEOUT"
echo "$FILEOUT" | grep -q "ELF 64-bit"        || fail "不是 ELF 64-bit"
echo "$FILEOUT" | grep -qi "x86-64"           || fail "不是 x86-64 架构"
echo "$FILEOUT" | grep -qi "shared object"    || fail "不是共享对象"
ok "架构与文件类型正确"

# ---------- 2. 动态依赖 ----------
NEEDED=$(readelf -d "$SO" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | sort -u)
echo "  NEEDED: $(echo $NEEDED | tr '\n' ' ')"
for lib in $NEEDED; do
    case "$lib" in
        libc.so|libgcc_s.so.1) ;;
        *) fail "多出一个动态依赖: $lib（目标设备上可能没有）" ;;
    esac
done
echo "$NEEDED" | grep -q '^libc\.so$' || fail "没有链接 libc.so（工具链不对？）"
ok "动态依赖干净：只有 libc.so / libgcc_s.so.1"

# RPATH/RUNPATH 指向构建机路径的话，换台机器就找不到库
if readelf -d "$SO" | grep -qE '\((RPATH|RUNPATH)\)'; then
    warn "产物带 RPATH/RUNPATH：$(readelf -d "$SO" | grep -E '\((RPATH|RUNPATH)\)')"
fi

# ---------- 3. 插件入口函数 ----------
EXPORTS=$(nm -D --defined-only "$SO" | awk '$2 ~ /^[TtWw]$/ {print $3}' | sort -u)
echo "  导出函数: $(echo $EXPORTS | tr '\n' ' ')"
MISSING=""
for f in dns_plugin_api_version dns_plugin_init dns_plugin_exit \
         dns_request_complete dns_server_log dns_server_audit_log; do
    echo "$EXPORTS" | grep -qx "$f" || MISSING="$MISSING $f"
done
[ -z "$MISSING" ] || fail "缺少插件入口函数:$MISSING"
ok "6 个插件入口函数齐全"

# ---------- 4. 符号兼容性 ----------
# 插件向主程序索要的就是 dns_* / smartdns_* / conf_* 这几类
needs=$(nm -D -u "$SO" | awk '{print $NF}' | grep -E '^_?(dns_|smartdns_|conf_)' | sed 's/^_*//' | sort -u)
sed 's/^_*//' "$SYMS" | sed '/^$/d' | sort -u > /tmp/_have.txt
echo "$needs" > /tmp/_need.txt
n_need=$(wc -l < /tmp/_need.txt)
missing_syms=$(comm -23 /tmp/_need.txt /tmp/_have.txt)
if [ -n "$missing_syms" ]; then
    echo "--- 目标主程序里没有这些符号 ---"
    echo "$missing_syms"
    echo "--- 目标符号表: $SYMS ---"
    fail "插件索要了目标设备主程序没有的符号（装上去会在调用时崩溃）"
fi
ok "插件需要的 $n_need 个主程序符号，目标设备全都有"

echo "CHECK PASS"
