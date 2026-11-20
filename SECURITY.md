# Security Policy

## Supported versions

Only the latest release of winpcapy receives security fixes.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Report them
privately with GitHub's
[private vulnerability reporting](https://github.com/orweis/winpcapy/security/advisories/new)
("Report a vulnerability" in the repository's Security tab). Include the
affected version, your platform (Windows/Npcap or libpcap version) and steps
to reproduce.

Vulnerabilities in the capture driver itself should be reported to the
[Npcap project](https://npcap.com/) or to [libpcap](https://www.tcpdump.org/).

## Hardening recommendations

- Use Npcap (WinPcap has been unmaintained since 2013) and keep it up to date.
- Install Npcap with "Restrict Npcap driver's access to Administrators only".
- Only open devices in promiscuous mode when you need to.
- Treat captured packets as untrusted input in your callbacks.
