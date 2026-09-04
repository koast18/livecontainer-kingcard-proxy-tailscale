#!/usr/bin/env python3
"""Static regression checks for Tailscale crash and isolation guardrails."""
from pathlib import Path

manager = Path("Tweak/Sources/LCTailscaleManager.m").read_text(encoding="utf-8")
config = Path("Tweak/Sources/LCProxyConfig.m").read_text(encoding="utf-8")
king = Path("Tweak/Sources/LCProxyKing.m").read_text(encoding="utf-8")
server = Path("Tweak/Sources/LCProxyServer.m").read_text(encoding="utf-8")
core = Path("Tweak/Sources/KPKIngCore.c").read_text(encoding="utf-8")
header = Path("Tweak/Sources/KPKIngCore.h").read_text(encoding="utf-8")

assert "char buf[1024 * 1024]" not in manager
assert "char pbuf[1024 * 1024]" not in manager
assert "LCTailscaleJSONInitialCapacity" in manager
assert "LCTailscaleJSONMaximumCapacity" in manager
assert "rc == ERANGE" in manager
assert "memchr(buffer.bytes, '\\0', capacity)" in manager
assert "stateDirectoryForSettings" in manager
assert "instanceIdentifier" in manager
assert "return [base stringByAppendingPathComponent:[self instanceIdentifier]];" in manager
assert "hostnameForSettings" in manager
assert "finishStartForGeneration" in manager
assert "tailscaleForceDerpOnly" in manager
assert "finalGenerationOK = self.generation == generation" in manager
assert "Tailscale 上游代理配置失败" in manager
assert "@synchronized (self)" in manager
for getter in ("proxyPassword", "lastError", "authURL", "backendState"):
    marker = f"- (NSString *){getter} {{"
    start = manager.index(marker)
    body = manager[start:manager.index("\n}", start) + 2]
    assert f"self.{getter}" not in body, f"{getter} must not recursively lock itself"

assert "kp_http_get_via_socks5" in header
assert "kp_http_get_via_socks5" in core
assert "reply[1] != 0x02" in core, "SOCKS5 username/password negotiation missing"
assert "reply[1] != 0x00" in core, "SOCKS5 authentication or CONNECT success check missing"
assert "kp_http_get_via_socks5" in server
assert "Tailscale 未连接或 SOCKS5 服务未就绪" in server
assert "return port;\n    return port;" not in core

assert "runtimeApplyLock" in config
assert "[self.runtimeApplyLock lock];" in config
assert "port = forwarderPort > 0 ? forwarderPort : 1;" in config
assert "@synchronized (self)" in king
assert "if ([weakSelf isRunning])" in king

print("tailscale safety static checks OK")
