#!/usr/bin/env python3
"""
pentrix-phish: a suspicious URL analyzer.

Scores a URL against a set of phishing heuristics and prints a
risk verdict. Built for learning and portfolio purposes; the score
is a hint, not a verdict on guilt.

Usage:
    python3 phish.py URL
    python3 phish.py -f urls.txt
    python3 phish.py --json URL

Exit codes:
    0 - analysis completed (any verdict)
    1 - invalid usage (bad arguments, unreadable input file)
    2 - URL could not be parsed / is malformed
"""

import argparse
import json
import re
import sys
from urllib.parse import urlparse

# ------------------------------------------------------------------
# Heuristic weights (points added when a heuristic triggers)
# ------------------------------------------------------------------
W_PUNYCODE = 20          # xn-- prefix in the host (IDN homograph risk)
W_AT_SIGN = 25           # @ in URL (credential / host-confusion trick)
W_IP_HOST = 25           # host is a raw IP literal
W_NONSTD_PORT = 10       # port other than 80/443 (or default for scheme)
W_MANY_SUBDOMAINS = 10   # more than 3 subdomains
W_KEYWORD = 10           # per suspicious keyword found (capped)
W_KEYWORD_CAP = 30       # cap so one URL cannot max out on keywords alone
W_LONG_URL = 10          # total URL length over 100 characters
W_HYPHEN_HEAVY = 15      # 3+ hyphens in the registered domain (lookalike)
W_NO_HTTPS = 10          # scheme is not https
W_SHORTENER = 20         # known URL-shortener host

URL_LENGTH_THRESHOLD = 100
SUBDOMAIN_THRESHOLD = 3
HYPHEN_THRESHOLD = 3

SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "account", "update",
    "paypal", "bank", "signin", "confirm", "free", "bonus",
)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "shorturl.at",
    "cutt.ly", "rb.gy", "s.id", "tiny.cc",
}

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def parse_url(raw):
    """Parse a raw URL string. Returns a ParsedResult or raises ValueError."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty URL")
    # Add a scheme when the user pastes a bare host; without one,
    # urlparse cannot tell host from path.
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError("could not determine a hostname")
    return parsed


def is_ip_literal(host):
    """True when the host is a raw IPv4 (or plausible IPv6) literal."""
    if not host:
        return False
    if IPV4_RE.match(host):
        return all(0 <= int(octet) <= 255 for octet in host.split("."))
    if ":" in host and IPV6_RE.match(host):
        return True
    return False


def host_parts(host):
    """Split a hostname into labels, e.g. 'a.b.example.com' -> list."""
    return [p for p in (host or "").lower().split(".") if p]


def check_punycode(raw, parsed, findings):
    """Punycode (xn--) in the host suggests an IDN homograph trick."""
    if "xn--" in (parsed.hostname or "").lower():
        findings.append({
            "name": "punycode",
            "points": W_PUNYCODE,
            "detail": "Host contains 'xn--' (punycode/IDN). Real brands rarely do this; "
                      "it is a classic homograph trick.",
        })


def check_at_sign(raw, parsed, findings):
    """An @ sign lets 'user@realhost' hide the true destination."""
    if "@" in raw:
        findings.append({
            "name": "at_sign",
            "points": W_AT_SIGN,
            "detail": "'@' found in the URL. Everything before it is treated as "
                      "credentials, so attackers use it to disguise the real host.",
        })


def check_ip_host(raw, parsed, findings):
    """Legit services use domain names; raw IPs in links are suspicious."""
    if is_ip_literal(parsed.hostname):
        findings.append({
            "name": "ip_host",
            "points": W_IP_HOST,
            "detail": "Host is a raw IP address (%s). Legitimate sites almost "
                      "always use a domain name." % parsed.hostname,
        })


def check_nonstandard_port(raw, parsed, findings):
    """Ports other than 80/443 are unusual for public web links."""
    port = parsed.port
    if port is None:
        return
    default = {"http": 80, "https": 443}.get(parsed.scheme.lower())
    if default is not None and port != default:
        findings.append({
            "name": "nonstandard_port",
            "points": W_NONSTD_PORT,
            "detail": "Non-standard port %d for %s (normally %d)." % (port, parsed.scheme, default),
        })


def check_many_subdomains(raw, parsed, findings):
    """Long subdomain chains (a.b.c.d.example.com) are used to pad URLs."""
    labels = host_parts(parsed.hostname)
    # For 'a.b.example.com', subdomains are everything before the last two labels.
    subdomain_count = max(0, len(labels) - 2)
    if subdomain_count > SUBDOMAIN_THRESHOLD:
        findings.append({
            "name": "many_subdomains",
            "points": W_MANY_SUBDOMAINS,
            "detail": "%d subdomains (over the %d threshold). Attackers stack "
                      "subdomains so the real domain sits far from the brand name." % (
                          subdomain_count, SUBDOMAIN_THRESHOLD),
        })


def check_keywords(raw, parsed, findings):
    """Lure words (login, verify, paypal, bank...) push urgency or trust."""
    haystack = raw.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in haystack]
    if hits:
        points = min(len(hits) * W_KEYWORD, W_KEYWORD_CAP)
        findings.append({
            "name": "suspicious_keywords",
            "points": points,
            "detail": "Suspicious keywords found: %s. Phishing pages use them to "
                      "look official or create urgency." % ", ".join(hits),
        })


def check_long_url(raw, parsed, findings):
    """Very long URLs are often padded to hide the real destination."""
    if len(raw) > URL_LENGTH_THRESHOLD:
        findings.append({
            "name": "long_url",
            "points": W_LONG_URL,
            "detail": "URL is %d characters (over %d). Long URLs help hide the "
                      "real host from a quick glance." % (len(raw), URL_LENGTH_THRESHOLD),
        })


def check_hyphen_heavy(raw, parsed, findings):
    """Lookalike domains stack hyphens: 'pay-pal-secure-login.com'."""
    host = (parsed.hostname or "").lower()
    hyphens = host.count("-")
    if hyphens >= HYPHEN_THRESHOLD:
        findings.append({
            "name": "hyphen_heavy",
            "points": W_HYPHEN_HEAVY,
            "detail": "%d hyphens in '%s'. Legit brands rarely hyphenate this "
                      "much; phishers glue brand names to lures with dashes." % (hyphens, host),
        })


def check_no_https(raw, parsed, findings):
    """Plain http means the connection is not encrypted."""
    if parsed.scheme.lower() != "https":
        findings.append({
            "name": "no_https",
            "points": W_NO_HTTPS,
            "detail": "URL uses '%s' instead of HTTPS. Credentials sent over it "
                      "can be read in transit." % (parsed.scheme or "no scheme"),
        })


def check_shortener(raw, parsed, findings):
    """URL shorteners hide the final destination from the victim."""
    host = (parsed.hostname or "").lower()
    if host in URL_SHORTENERS or any(host.endswith("." + s) for s in URL_SHORTENERS):
        findings.append({
            "name": "url_shortener",
            "points": W_SHORTENER,
            "detail": "Host '%s' is a known URL shortener. The link hides where "
                      "it really goes." % host,
        })


HEURISTICS = (
    check_punycode,
    check_at_sign,
    check_ip_host,
    check_nonstandard_port,
    check_many_subdomains,
    check_keywords,
    check_long_url,
    check_hyphen_heavy,
    check_no_https,
    check_shortener,
)


def analyze(raw):
    """Run every heuristic against one URL. Returns an analysis dict."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty URL")
    parsed = parse_url(raw)
    findings = []
    for heuristic in HEURISTICS:
        heuristic(raw, parsed, findings)
    score = min(100, sum(f["points"] for f in findings))
    if score >= 60:
        verdict = "HIGH"
    elif score >= 30:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"
    return {
        "url": raw,
        "host": parsed.hostname,
        "score": score,
        "verdict": verdict,
        "findings": findings,
    }


def format_human(analysis):
    """Render one analysis as readable plain text."""
    lines = []
    lines.append("URL:     %s" % analysis["url"])
    lines.append("Host:    %s" % analysis["host"])
    lines.append("Score:   %d/100" % analysis["score"])
    lines.append("Verdict: %s risk" % analysis["verdict"])
    if analysis["findings"]:
        lines.append("")
        lines.append("Triggered heuristics:")
        for f in analysis["findings"]:
            lines.append("  [+%2d] %s" % (f["points"], f["name"]))
            lines.append("         %s" % f["detail"])
    else:
        lines.append("")
        lines.append("No heuristics triggered. Nothing suspicious found.")
    return "\n".join(lines)


def iter_urls(args):
    """Yield URL strings from the positional arg and/or the -f file."""
    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
        except OSError as exc:
            print("error: cannot read file '%s': %s" % (args.file, exc), file=sys.stderr)
            sys.exit(1)
    if not urls:
        print("error: no URL given. Pass a URL or use -f <file>.", file=sys.stderr)
        print("Try: python3 phish.py --help", file=sys.stderr)
        sys.exit(1)
    return urls


def main(argv=None):
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="phish.py",
        description="Analyze a URL for phishing signs and print a risk score (0-100). "
                    "Heuristics only: a LOW score does not prove safety, and a HIGH "
                    "score does not prove malice.",
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="the URL to analyze (a bare host like example.com is accepted)",
    )
    parser.add_argument(
        "-f", "--file",
        metavar="FILE",
        default=None,
        help="read URLs from FILE, one per line (lines starting with # are ignored); "
             "can be combined with a positional URL",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of human-readable text",
    )
    args = parser.parse_args(argv)

    had_malformed = False
    results = []
    for url in iter_urls(args):
        try:
            results.append(analyze(url))
        except ValueError as exc:
            print("error: skipping malformed URL '%s': %s" % (url, exc), file=sys.stderr)
            had_malformed = True

    if not results:
        # Nothing analyzable was supplied.
        sys.exit(2 if had_malformed else 1)

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        print("\n\n".join(format_human(r) for r in results))

    sys.exit(2 if had_malformed else 0)


if __name__ == "__main__":
    main()
