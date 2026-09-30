#!/usr/bin/env python3
"""
scope_guard.py — Claude Code PreToolUse hook for authorized bug bounty work.

Purpose
-------
Enforce (not just steer) that offensive-security tooling only ever runs against
hosts the user has confirmed are in scope. Pairs with the `authorized-bug-bounty`
skill and a `SCOPE.md` file in the project root.

Design
------
- Only gates commands that actually invoke a network / recon / exploitation tool
  (curl, nmap, ffuf, sqlmap, ...). Ordinary dev commands (ls, cat, git, python)
  pass straight through, so this never gets in the way of normal work.
- When a gated tool IS present, every host/IP/URL in the command must match an
  in-scope entry in SCOPE.md. Any target that is not in scope -> DENY.
- FAIL CLOSED: if SCOPE.md is missing/empty, or a gated command references a host
  we cannot confirm, the action is denied. Safer default for this use case.
- A small denylist of inherently-harmful tooling (stress/DoS, high-concurrency
  flooding) is refused regardless of scope.

This is a guardrail, not a sandbox. It stops accidental and casual out-of-scope
testing and raises the bar substantially; it can be evaded by deliberate
obfuscation (e.g. pre-resolving a domain to a raw IP). For hard containment, pair
it with network-level controls (a VPN/allowlist that can only reach scoped hosts).

Hook I/O contract (Claude Code):
  stdin  : JSON with { tool_name, tool_input: { command | url }, ... }
  stdout : JSON with hookSpecificOutput.permissionDecision = allow|deny|ask
  exit 0 : decision honored via stdout
"""

import ipaddress
import json
import os
import re
import sys

# --- configuration ---------------------------------------------------------

# Tools whose invocation means "this command talks to a target". Only when one
# of these appears do we extract hosts and enforce scope.
NETWORK_TOOLS = {
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet",
    "nmap", "masscan", "rustscan", "zmap",
    "ping", "hping3", "traceroute", "mtr",
    "dig", "host", "nslookup", "dnsrecon", "dnsenum", "fierce", "amass",
    "subfinder", "assetfinder", "httpx", "httprobe", "waybackurls", "gau",
    "nikto", "wpscan", "joomscan", "whatweb", "wafw00f",
    "ffuf", "gobuster", "feroxbuster", "dirb", "dirbuster", "wfuzz", "dirsearch",
    "sqlmap", "nosqlmap", "commix", "xsstrike", "dalfox",
    "hydra", "medusa", "patator", "crackmapexec", "nxc",
    "msfconsole", "msfvenom", "searchsploit",
    "openssl",  # s_client etc.
}

# Inherently harmful / prohibited regardless of scope (DoS, flooding, mass).
DENY_PATTERNS = [
    (re.compile(r"\bhping3\b.*(--flood|--faster)"), "DoS/flood tooling (hping3 flood)"),
    (re.compile(r"\b(slowloris|goldeneye|hulk|loic|hoic|t50|mhddos)\b", re.I), "Denial-of-service tooling"),
    (re.compile(r"\bab\b.*-c\s*([5-9]\d{2,}|\d{4,})"), "High-concurrency load/flood (ab -c very high)"),
    (re.compile(r"\bnmap\b.*(-T5|--min-rate\s*(\d{4,}))"), "Aggressive nmap timing/rate (potential DoS) — lower it and confirm ROE"),
    (re.compile(r":\(\)\s*\{\s*:\|\s*:\s*&\s*\}\s*;\s*:"), "Fork bomb"),
]

# Hosts that are always allowed (local lab / loopback). Private ranges are NOT
# auto-allowed because internal targets are frequently explicitly out of scope.
ALWAYS_ALLOW_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

# Hosts needed for the user's own tooling/workflow (package installs, git).
# These are allow-listed so the guard never blocks legitimate dev/ops traffic.
INFRA_ALLOW_SUFFIXES = (
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "pypi.org", "pythonhosted.org", "npmjs.org", "npmjs.com",
    "crates.io", "rubygems.org", "golang.org", "go.dev", "sum.golang.org",
    "debian.org", "ubuntu.com", "archlinux.org", "alpinelinux.org",
    "docker.io", "docker.com", "ghcr.io", "quay.io",
    "cloudflare.com", "letsencrypt.org",
)

HOST_RE = re.compile(
    r"(?:https?|ftp|ftps|ws|wss)://([^/\s:'\"\\]+)"          # URL host
    r"|(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])"          # bare IPv4
    r"|(?<![\w.@-])((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?![\w-])"  # bare domain
)


# --- helpers ---------------------------------------------------------------

def decision(kind: str, reason: str):
    """kind in {allow, deny, ask}. Emit hook JSON and exit."""
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": kind,
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def project_dir() -> str:
    return os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()


def _is_cidr(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
        return "/" in text
    except ValueError:
        return False


def load_scope():
    """Return (in_scope_patterns, out_of_scope_patterns, found)."""
    path = os.path.join(project_dir(), "SCOPE.md")
    if not os.path.isfile(path):
        return [], [], False
    in_scope, out_scope = [], []
    section = None
    in_comment = False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()

                # Track (possibly multi-line) HTML comments and skip their body,
                # so template example lines never become real scope entries.
                if in_comment:
                    if "-->" in line:
                        in_comment = False
                    continue
                if "<!--" in line and "-->" not in line:
                    in_comment = True
                    continue
                if "<!--" in line and "-->" in line:
                    line = re.sub(r"<!--.*?-->", "", line).strip()

                low = line.lower()
                if low.startswith("#"):
                    if "out" in low and "scope" in low:
                        section = "out"
                    elif "scope" in low or "asset" in low or "target" in low:
                        section = "in"
                    else:
                        section = None
                    continue
                if not line or line[0] not in "-*+":
                    continue

                # Drop exactly one leading bullet marker, keep the rest intact
                # (so "*.example.com" keeps its wildcard).
                entry = line[1:].strip().strip("`").strip()
                # Cut a trailing annotation: 2+ spaces, a tab, or an inline "#".
                entry = re.split(r"\s{2,}|\t|\s#", entry)[0].strip()
                if not entry:
                    continue
                entry = re.sub(r"^\w+://", "", entry, flags=re.I)  # strip scheme
                # Strip a URL path, but never mangle a CIDR's "/24".
                if "/" in entry and not _is_cidr(entry):
                    entry = entry.split("/")[0]
                token = entry.split()[0].strip().lower() if entry.split() else ""
                if not token:
                    continue
                (out_scope if section == "out" else in_scope).append(token)
    except OSError:
        return [], [], False
    return in_scope, out_scope, True


def host_matches(host: str, pattern: str) -> bool:
    host = host.lower().strip(".")
    pattern = pattern.lower().strip(".")
    if not host or not pattern:
        return False
    # CIDR / IP range
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    # exact IP
    try:
        ipaddress.ip_address(pattern)
        return host == pattern
    except ValueError:
        pass
    # wildcard domain: *.example.com matches sub.example.com AND example.com
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    # plain domain: exact match only (no implicit subdomain coverage)
    return host == pattern


def extract_hosts(text: str):
    hosts = set()
    for m in HOST_RE.finditer(text):
        h = m.group(1) or m.group(2) or m.group(3)
        if h:
            hosts.add(h.strip().lower().rstrip("."))
    return hosts


def command_uses_network_tool(command: str) -> bool:
    # Tokenize loosely; check each word (and basename) against the tool set.
    for tok in re.findall(r"[A-Za-z0-9_./-]+", command):
        name = tok.rsplit("/", 1)[-1]
        if name in NETWORK_TOOLS:
            return True
    return False


def is_infra_host(host: str) -> bool:
    if host in ALWAYS_ALLOW_HOSTS:
        return True
    return any(host == s or host.endswith("." + s) for s in INFRA_ALLOW_SUFFIXES)


# --- main ------------------------------------------------------------------

def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Can't parse input -> fail closed with an ask so nothing silently runs.
        decision("ask", "scope_guard: could not parse hook input; review manually.")

    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input", {}) or {}

    # Assemble the text we need to inspect per tool.
    if tool == "Bash":
        command = tool_input.get("command", "") or ""
    elif tool in ("WebFetch", "WebSearch"):
        command = tool_input.get("url", "") or tool_input.get("query", "") or ""
    else:
        decision("allow", "scope_guard: tool not gated.")

    # 1) Hard denylist (harmful regardless of scope).
    for rx, why in DENY_PATTERNS:
        if rx.search(command):
            decision("deny", f"Blocked by scope_guard: {why}. This is prohibited regardless of authorization.")

    # 2) For Bash: only enforce scope when a network/recon tool is invoked.
    if tool == "Bash" and not command_uses_network_tool(command):
        decision("allow", "scope_guard: no network/recon tool in command.")

    hosts = extract_hosts(command)
    # Drop infra/loopback hosts from enforcement.
    target_hosts = {h for h in hosts if not is_infra_host(h)}

    if not target_hosts:
        decision("allow", "scope_guard: no external target host referenced.")

    in_scope, out_scope, found = load_scope()

    if not found:
        decision(
            "deny",
            "Blocked by scope_guard: no SCOPE.md found, so authorization/scope is "
            "unconfirmed. Run /bounty (or create SCOPE.md) to record the authorized "
            f"program and in-scope assets before testing {', '.join(sorted(target_hosts))}.",
        )

    if not in_scope:
        decision(
            "deny",
            "Blocked by scope_guard: SCOPE.md has no in-scope assets listed. "
            "Add the confirmed in-scope hosts before running against "
            f"{', '.join(sorted(target_hosts))}.",
        )

    # 3) Check each target: explicit out-of-scope wins; else must match in-scope.
    for host in sorted(target_hosts):
        if any(host_matches(host, p) for p in out_scope):
            decision("deny", f"Blocked by scope_guard: {host} is explicitly OUT OF SCOPE in SCOPE.md.")
        if not any(host_matches(host, p) for p in in_scope):
            decision(
                "deny",
                f"Blocked by scope_guard: {host} is not in the confirmed in-scope list "
                "in SCOPE.md. Add it to scope (with written authorization) or target an "
                "in-scope asset.",
            )

    decision("allow", f"scope_guard: target(s) {', '.join(sorted(target_hosts))} confirmed in scope.")


if __name__ == "__main__":
    main()
