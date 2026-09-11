"""Regression tests for two real bugs found running against a live Squid
instance (2026-08-28 smoke test), both in proxy/squid.conf.template.
Neither is the kind of thing a pure Python unit test of the helper *logic*
can catch -- both are about Squid's own ACL/protocol semantics -- so these
tests check the config's text/structure directly instead.

1. Every external_acl_type FORMAT string was missing an explicit %DATA
   macro. Squid always appends %DATA to an external_acl_type FORMAT unless
   it's already present (documented Squid behavior), so every helper was
   receiving one more field on the wire than its registered field_count
   expected -- every line was rejected as malformed, and every real request
   fell through to `ssl_bump terminate step2 all`. Fails closed (nothing
   loads) but the entire SNI/authz decision layer never worked at all.

2. `http_access allow step1`/`step2`, left bare, also grants access to the
   real *decrypted* HTTP request that follows a bump decision -- Squid's
   at_step state doesn't reset after step2 is reached. This bypassed
   authz_allowed entirely for every bump-mode request (any Crunchyroll show,
   approved or not) -- fails OPEN, the more serious direction. Fixed by
   qualifying both with CONNECT, which only matches during the tunnel/
   negotiation phase.

proxy/basic_auth_helper.py (and the auth_param basic percent-encoding
regression that used to be tested here) was removed 2026-08-30 along with
the rest of Squid's explicit-proxy-with-login model -- see RoadMap.md's
"Squid: explicit-proxy-with-login -> transparent intercept" section. Squid
now runs in native intercept mode with no per-request login at all, so
there is nothing left for that helper (or these tests) to cover.
"""
from __future__ import annotations

import re
from pathlib import Path

import authz_helper
import sni_helper
import squid_helper

TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "proxy" / "squid.conf.template"


def _expected_field_count(acl_name: str) -> int:
    """How many fields Squid will actually send on the wire for the named
    external_acl_type: its FORMAT line's %macro count, plus 1 for the
    implicit %DATA Squid appends unless %DATA is already present."""
    text = TEMPLATE_PATH.read_text()
    # `external_acl_type NAME options... \` then `FORMAT... \` then the helper
    # command line -- two backslash-continued lines.
    pattern = re.compile(
        rf"external_acl_type\s+{re.escape(acl_name)}\s+.*?\\\s*\n(.*?)\\\s*\n",
        re.DOTALL,
    )
    match = pattern.search(text)
    assert match, f"could not find external_acl_type {acl_name!r} in {TEMPLATE_PATH}"
    format_line = match.group(1)
    macros = re.findall(r"%\S+", format_line)
    assert macros, f"no %macros found for {acl_name}: {format_line!r}"
    return len(macros) if "%DATA" in macros else len(macros) + 1


def _captured_field_count(monkeypatch, call) -> int:
    captured: dict = {}

    def fake_run(name, field_count, handler, **kwargs):
        captured["field_count"] = field_count
        return 0

    # sni_helper and authz_helper both `import squid_helper` -- same cached
    # module object, so patching it here intercepts either's main().
    monkeypatch.setattr(squid_helper, "run", fake_run)
    call()
    assert "field_count" in captured, "squid_helper.run was never called"
    return captured["field_count"]


def test_sni_helper_field_count_matches_squid_conf_template(monkeypatch):
    for mode, acl_name in [
        ("bump", "sni_bump_check"),
        ("trusted", "sni_trusted_check"),
        ("splice", "sni_splice_check"),
        ("block_page", "sni_block_page_check"),
    ]:
        monkeypatch.setattr("sys.argv", ["sni_helper.py", mode])
        actual = _captured_field_count(monkeypatch, sni_helper.main)
        expected = _expected_field_count(acl_name)
        assert actual == expected, (
            f"sni_helper.py {mode}: registered field_count={actual} but "
            f"squid.conf.template's {acl_name} FORMAT actually sends {expected} fields"
        )


def test_authz_helper_field_count_matches_squid_conf_template(monkeypatch):
    actual = _captured_field_count(monkeypatch, authz_helper.main)
    expected = _expected_field_count("authz_check")
    assert actual == expected, (
        f"authz_helper.py: registered field_count={actual} but "
        f"squid.conf.template's authz_check FORMAT actually sends {expected} fields"
    )


def test_step_acls_in_http_access_are_qualified_with_connect():
    """Regression for a real, security-relevant bug found in live testing:
    a bare `http_access allow step2` (or step1) also grants access to the
    real *decrypted* HTTP request that follows a bump decision -- Squid's
    at_step state doesn't reset after step2 is reached, so that request is
    still evaluated as "at step2" too. This let an authenticated user reach
    ANY bump-mode content (any Crunchyroll show, approved or not) without
    ever being checked by authz_allowed. Confirmed against a real Squid
    instance and fixed by requiring CONNECT alongside step1/step2, which
    only ever matches during the tunnel/negotiation phase (the decrypted
    inner request's method is GET/POST/etc., never CONNECT). This test
    can't reproduce Squid's own ACL semantics, but it stops the fix from
    being silently reverted to a bare `allow step1`/`allow step2` line.
    """
    text = TEMPLATE_PATH.read_text()
    for line in text.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"http_access\s+allow\s+step[12]", stripped):
            raise AssertionError(
                f"{stripped!r} must be qualified with CONNECT "
                f"(e.g. 'http_access allow CONNECT step1') -- see "
                f"docs/review-2026-08-28.md for why a bare step1/step2 "
                f"bypasses authz_allowed entirely."
            )


def test_no_proxy_auth_left_in_intercept_mode():
    """Regression guard for RoadMap.md's Squid intercept-mode migration
    (2026-08-30): an intercepted connection has no CONNECT handshake for
    Squid to challenge with a 407, so auth_param basic/proxy_auth must never
    creep back in -- if it did, every intercepted connection would be denied
    outright (fails closed, but silently breaks the entire bump-tier
    feature)."""
    text = TEMPLATE_PATH.read_text()
    assert "auth_param basic" not in text
    assert "proxy_auth" not in text


def test_ports_are_intercept_mode_not_explicit_proxy():
    """Regression guard: the old explicit-proxy `http_port 3128 ssl-bump`
    must not come back -- it's fundamentally incompatible with NAT-redirected
    traffic (no CONNECT is ever sent for an intercepted HTTPS connection).

    `http_port 127.0.0.1:3128` (added 2026-08-30, confirmed live against a
    real Squid binary) is NOT that port coming back -- it's a deliberate,
    loopback-only, non-intercept port that exists purely so Squid has a
    "normal" address to build its own internal URLs from (built-in icons
    for e.g. FTP listings); without it, an intercept-only Squid FATALs at
    startup with "mimeLoadIcon: cannot parse internal URL" before ever
    opening the real intercept listeners. It's never reachable from
    outside the container and never carries real traffic, so the
    meaningful guard is "no *explicit ssl-bump proxy* on 3128", not "the
    digits 3128 never appear in the file" -- see docs/review-2026-08-28.md
    equivalent write-up in RoadMap.md's live-verification section."""
    text = TEMPLATE_PATH.read_text()
    assert re.search(r"^http_port\s+3129\s+intercept\s*$", text, re.MULTILINE)
    assert re.search(r"^https_port\s+3130\s+intercept\s+ssl-bump\b", text, re.MULTILINE)
    assert not re.search(r"^http_port\s+3128\s+ssl-bump\b", text, re.MULTILINE)
    assert re.search(r"^http_port\s+127\.0\.0\.1:3128\s*$", text, re.MULTILINE)


def test_ssl_bump_catchall_is_still_terminate_not_splice():
    """Guards a deliberate deviation from RoadMap.md's changes-needed
    checklist: that checklist lists flipping `ssl_bump terminate step2 all`
    to `splice` as part of this item, but also flags (in the same breath)
    that whether the SNI-layer helpers still pull their own weight "needs a
    closer look... not assumed here." Closer look: flipping it now, before
    the AdGuard hard-deny integration exists (a separate, not-yet-started
    checklist item) to actually be the domain-level gate, would make
    block_page_mode='terminate' (the default) silently splice unconfigured/
    unassigned domains through unfiltered instead of denying them -- a real
    regression, not a no-op. See squid.conf.template's own comment on this
    line. Revisit together with the AdGuard item."""
    text = TEMPLATE_PATH.read_text()
    assert re.search(r"^ssl_bump\s+terminate\s+step2\s+all\s*$", text, re.MULTILINE), (
        "the ssl_bump catch-all must stay 'terminate' until the AdGuard "
        "hard-deny integration exists -- see the comment above this rule "
        "in squid.conf.template"
    )
    assert not re.search(r"^ssl_bump\s+splice\s+step2\s+all\s*$", text, re.MULTILINE)


def test_http_access_catchall_is_still_deny_not_allow():
    """Companion guard to the ssl_bump catch-all test above, for the same
    reason: plain HTTP (intercept, no ssl_bump) falls straight through to
    the final http_access line with no other check in front of it, so it
    must stay deny-by-default until AdGuard is actually the authoritative
    domain-level gate."""
    text = TEMPLATE_PATH.read_text()
    lines = [l.strip() for l in text.splitlines() if l.strip().startswith("http_access")]
    assert lines[-1] == "http_access deny all", (
        f"expected the final http_access rule to be 'http_access deny all', got {lines[-1]!r}"
    )


def test_alt_svc_response_header_is_stripped_for_bumped_connections():
    """RoadMap.md finding #2 (QUIC fallback UX): controller/adguard_sync.py's
    build_ech_strip_rules() (item 17) already withholds the DNS HTTPS
    record's alpn="h3" hint for every bump-mode domain, but that alone was
    confirmed live 2026-09-11 NOT to stop Chrome's ERR_QUIC_PROTOCOL_ERROR
    -- Chrome also caches h3 support from a real Alt-Svc response header,
    independent of DNS. reply_header_access denies that header specifically
    for any transaction Squid actually decrypted (ssl::bumped is false for
    spliced/raw-relayed traffic, which Squid never HTTP-parses at all), so
    a fresh browser profile behind this proxy can never learn h3 support
    for a bump-mode domain through either channel."""
    text = TEMPLATE_PATH.read_text()
    assert re.search(r"^acl\s+bumped\s+ssl::bumped\s*$", text, re.MULTILINE), (
        "expected an `acl bumped ssl::bumped` line -- see squid.conf.template's "
        "RESPONSE HEADER HYGIENE section"
    )
    assert re.search(r"^reply_header_access\s+Alt-Svc\s+deny\s+bumped\s*$", text, re.MULTILINE), (
        "expected `reply_header_access Alt-Svc deny bumped` -- see squid.conf.template's "
        "RESPONSE HEADER HYGIENE section"
    )


def test_host_verify_strict_is_off_for_intercept_mode():
    """RoadMap.md finding #6 (2026-09-10): with Squid's stricter host
    verification, an intercepted connection to a large multi-IP CDN gets
    killed with `SECURITY ALERT: Host header forgery detected` +
    NONE_NONE/409 whenever the client's connected IP isn't in Squid's own
    fresh re-resolution of the SNI name -- which is most of the time for a
    short-TTL CDN pool. `host_verify_strict off` makes Squid treat the
    intercepted destination as authoritative instead. It must sit BEFORE
    the ssl_bump chain (it governs how the intercepted destination is
    established, which happens first)."""
    text = TEMPLATE_PATH.read_text()
    m = re.search(r"^host_verify_strict\s+off\s*$", text, re.MULTILINE)
    assert m, "host_verify_strict off must be set -- see the comment block above it in squid.conf.template"
    first_ssl_bump = text.index("ssl_bump ")
    assert m.start() < first_ssl_bump, "host_verify_strict must be configured before the ssl_bump rules"
