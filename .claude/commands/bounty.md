---
description: Start or update an authorized security assessment engagement — runs the authorization checklist and populates SCOPE.md.
---

You are starting an **authorized security assessment engagement**. Follow the
`authorized-bug-bounty` skill. Your job right now is to establish and record
scope before any assessment happens.

Do this:

1. Check whether `SCOPE.md` exists and is filled in (not the example template).
2. Ask the user for anything missing, one concise round of questions:
   - Authorization source (platform / signed agreement / self-owned) and program link
   - Exact in-scope assets (domains, wildcards, IP ranges)
   - Explicit out-of-scope assets
   - Rules of engagement: rate limits, prohibited techniques, test accounts,
     required identifiers, disclosure channel
3. Write the confirmed details into `SCOPE.md` using its existing structure.
   Under **In-Scope Assets**, list one host/wildcard/CIDR per line — this is what
   the `scope_guard.py` hook reads to allow or block tooling.
4. Do NOT infer scope from a domain name and do NOT accept "just trust me"
   without a program link or agreement. If authorization can't be confirmed, leave the
   in-scope list empty (the hook will keep everything blocked) and say so.
5. Once SCOPE.md is accurate, confirm the scope back to the user in a short
   summary and tell them the guard is now active.

$ARGUMENTS
