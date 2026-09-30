# Claude Bounty

A Claude Code setup that steers **and enforces** authorized-only bug bounty /
penetration-testing work. It keeps offensive tooling inside a written,
confirmed scope and refuses anything against systems you aren't authorized to
test.

## What's in here

| Piece | Path | Role |
|-------|------|------|
| **Skill** | `.claude/skills/authorized-bug-bounty/SKILL.md` | Steers Claude: requires authorization + scope before any testing, keeps work in-scope and non-destructive, focuses on good reports. |
| **Hook** | `.claude/hooks/scope_guard.py` | Enforces it: a `PreToolUse` guard that blocks recon/attack tooling against out-of-scope hosts. Fails closed. |
| **Settings** | `.claude/settings.json` | Registers the hook on `Bash`, `WebFetch`, `WebSearch`. |
| **Scope file** | `SCOPE.md` | Source of truth for the hook — your authorized program and in-scope assets. |
| **Command** | `.claude/commands/bounty.md` | `/bounty` runs the authorization checklist and fills in `SCOPE.md`. |

## How it works

1. Run `/bounty` at the start of an engagement. Claude walks the authorization
   checklist and writes your confirmed scope into `SCOPE.md`.
2. From then on, any time Claude tries to run a network/recon tool (curl, nmap,
   ffuf, sqlmap, …) the `scope_guard.py` hook:
   - lets ordinary dev commands (ls, cat, git, python) through untouched;
   - extracts every host/IP/URL the command targets;
   - **allows** only hosts that match an in-scope entry in `SCOPE.md`;
   - **denies** anything explicitly out-of-scope, unconfirmed, or when
     `SCOPE.md` is missing (fail-closed);
   - **denies** inherently harmful tooling (DoS/flooding, fork bombs) regardless
     of scope.

## Scope syntax (`SCOPE.md`)

Under **In-Scope Assets**, one entry per line:

```
example.com            # exact host
*.example.com          # example.com and any subdomain
203.0.113.0/24         # IPv4 CIDR range
198.51.100.23          # single IP
```

Entries under **Out-of-Scope** always win over in-scope matches.

## Important limitation — read this

This is a **guardrail, not a sandbox.** It stops accidental and casual
out-of-scope testing and raises the bar a lot, but it inspects command text, so
a determined user can evade it (e.g. pre-resolving a domain to a raw IP, heavy
obfuscation). For hard containment, pair it with **network-level controls** — a
VPN or firewall allowlist that can only reach your scoped hosts.

**Use this only for testing you are authorized to perform.** Unauthorized access
to computer systems is illegal.

## Testing the guard

```bash
# should ALLOW (in-scope, assuming example.com is in SCOPE.md)
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}' \
  | CLAUDE_PROJECT_DIR="$PWD" python3 .claude/hooks/scope_guard.py

# should DENY (not in scope)
echo '{"tool_name":"Bash","tool_input":{"command":"nmap scanme.nmap.org"}}' \
  | CLAUDE_PROJECT_DIR="$PWD" python3 .claude/hooks/scope_guard.py

# should ALLOW (no network tool)
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | CLAUDE_PROJECT_DIR="$PWD" python3 .claude/hooks/scope_guard.py
```
