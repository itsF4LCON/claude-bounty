# Engagement Scope

> This file is the source of truth for the `scope_guard.py` hook. It only permits
> network/recon tooling against hosts listed under **In-Scope Assets**. Keep it
> accurate and honest — do not add a host here unless you have written
> authorization to test it.
>
> Delete the example entries below and fill in your real engagement. If this file
> is missing or has no in-scope assets, the hook fails closed and blocks all
> recon/attack tooling.

## Program / Authorization

- **Platform / source:** <!-- HackerOne | Bugcrowd | Intigriti | YesWeHack | private VDP | signed pentest SOW | self-owned -->
- **Program name / URL:** <!-- link to the program policy or ROE document -->
- **Authorization confirmed:** <!-- yes/no + date -->
- **Engagement window:** <!-- start – end dates, if time-boxed -->

## In-Scope Assets

<!-- One host, domain, wildcard, or CIDR per line. Supported forms:
       example.com           exact host
       *.example.com         example.com AND any subdomain
       203.0.113.0/24        IPv4 CIDR range
       198.51.100.23         single IP
     Only these get network/recon tooling. Everything else is blocked. -->

- example.com
- *.example.com
- 203.0.113.0/24

## Out-of-Scope

<!-- Explicitly forbidden even if they'd otherwise match an in-scope pattern.
     These always win. -->

- blog.example.com
- *.internal.example.com

## Rules of Engagement

- **Rate limits:** <!-- e.g. max N req/s; no aggressive scanning -->
- **Prohibited techniques:** <!-- commonly: DoS, social engineering, physical, automated mass-scanning, third-party/shared infra -->
- **Test accounts:** <!-- credentials / how to provision -->
- **Required identifiers:** <!-- e.g. X-Bug-Bounty header, specific user-agent -->
- **Disclosure:** <!-- report channel, embargo/timeline -->

## Notes

<!-- Anything scope-relevant: known fragile endpoints, do-not-touch data, contacts. -->
