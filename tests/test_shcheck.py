import base64
import http.client
import io
import json
import urllib.error
import urllib.request
from unittest.mock import patch, MagicMock

import pytest

from shcheck import shcheck
from shcheck.shcheck import Scanner


# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------

HTTPS_URL = "https://example.com"
HTTP_URL = "http://example.com"

# A representative set of security headers used across multiple tests
SAMPLE_HEADERS = [
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Strict-Transport-Security", "max-age=31536000"),
    ("Referrer-Policy", "no-referrer"),
]


def make_scanner(*extra_args, target=HTTPS_URL):
    """Build a Scanner through the real option parser.

    Going through parse_options() instead of hand-rolling a namespace keeps the
    tests in sync with the CLI: a new option with a default is picked up here
    automatically.
    """
    options, _targets = Scanner.parse_options(["shcheck.py", *extra_args, target])
    return Scanner(options)


def _mock_response(headers, url):
    mock = MagicMock()
    mock.getheaders.return_value = headers
    mock.geturl.return_value = url
    return mock


def _run_main(extra_args, targets_and_headers):
    """Run main() over one or more targets; return (stdout, stderr).

    targets_and_headers is a list of (url, headers) pairs; urlopen returns the
    matching mocked responses in order.
    """
    mocks = [_mock_response(hdrs, url) for url, hdrs in targets_and_headers]
    urls = [url for url, _ in targets_and_headers]
    out, err = io.StringIO(), io.StringIO()
    with (
        patch("sys.stdout", out),
        patch("sys.stderr", err),
        patch("urllib.request.urlopen", side_effect=mocks),
    ):
        shcheck.main(["shcheck.py"] + extra_args + urls)
    return out.getvalue(), err.getvalue()


def _run_failing_main(extra_args, side_effect, url=HTTPS_URL):
    """Run main() against a target whose request raises; return (stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with (
        patch("sys.stdout", out),
        patch("sys.stderr", err),
        patch("urllib.request.urlopen", side_effect=side_effect),
    ):
        shcheck.main(["shcheck.py"] + extra_args + [url])
    return out.getvalue(), err.getvalue()


def _run_json(extra_args, headers, url=HTTPS_URL):
    """Run main() with -j against a single target and return parsed JSON output."""
    out, _err = _run_main(["-j"] + extra_args, [(url, headers)])
    return json.loads(out)


def _run_json_multi(extra_args, targets_and_headers):
    """Run main() with -j against multiple targets and return parsed JSON output."""
    out, _err = _run_main(["-j"] + extra_args, targets_and_headers)
    return json.loads(out)


def _run_normal(extra_args, headers, url=HTTPS_URL):
    """Run main() without -j and return captured stdout."""
    out, _err = _run_main(["--colours", "none"] + extra_args, [(url, headers)])
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_no_args_return_help():
    with patch("sys.stdout", io.StringIO()):
        with pytest.raises(SystemExit) as exc:
            shcheck.main(["shcheck.py"])
    assert exc.value.code == 12


def test_parse_options_normalizes_and_deduplicates_targets():
    _options, targets = Scanner.parse_options(
        ["shcheck.py", "example.com", "https://example.com", "192.168.1.1"]
    )
    assert targets == ["https://example.com", "http://192.168.1.1"]


def test_parse_options_all_flag_enables_extra_checks():
    options, _targets = Scanner.parse_options(["shcheck.py", "-A", HTTPS_URL])
    assert options.information
    assert options.cache_control
    assert options.show_deprecated


def test_parse_options_json_output_implies_quiet_without_output_file():
    options, _targets = Scanner.parse_options(["shcheck.py", "-j", HTTPS_URL])
    assert options.quiet


def test_parse_options_quiet_ignored_for_plain_terminal_output():
    options, _targets = Scanner.parse_options(["shcheck.py", "-q", HTTPS_URL])
    assert not options.quiet


# ---------------------------------------------------------------------------
# append_port
# ---------------------------------------------------------------------------


def test_append_port_with_trailing_slash():
    assert (
        shcheck.append_port("http://example.com/", "8080") == "http://example.com:8080/"
    )


def test_append_port_without_trailing_slash():
    assert (
        shcheck.append_port("http://example.com", "8080") == "http://example.com:8080"
    )


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------


def test_normalize_bare_ip_adds_http():
    assert shcheck.normalize("192.168.1.1") == "http://192.168.1.1"


def test_normalize_bare_domain_adds_https():
    assert shcheck.normalize("github.com") == "https://github.com"


def test_normalize_bare_domain_with_path_adds_https():
    assert (
        shcheck.normalize("github.com/santoru/shcheck")
        == "https://github.com/santoru/shcheck"
    )


def test_normalize_https_url_unchanged():
    assert shcheck.normalize("https://example.com") == "https://example.com"


def test_normalize_http_url_unchanged():
    assert shcheck.normalize("http://example.com") == "http://example.com"


# ---------------------------------------------------------------------------
# parse_headers
# ---------------------------------------------------------------------------


def test_parse_headers_lowercases_keys():
    result = shcheck.parse_headers(
        [("X-Frame-Options", "DENY"), ("Content-Type", "text/html")]
    )
    assert "x-frame-options" in result
    assert result["x-frame-options"] == "DENY"
    assert "content-type" in result


def test_parse_headers_preserves_values():
    result = shcheck.parse_headers(
        [("Strict-Transport-Security", "max-age=31536000; includeSubDomains")]
    )
    assert result["strict-transport-security"] == "max-age=31536000; includeSubDomains"


# ---------------------------------------------------------------------------
# Raw request capture
# ---------------------------------------------------------------------------


def test_raw_request_reproduces_the_wire_format():
    request = urllib.request.Request(
        "https://example.com/a?b=1", headers=Scanner.CLIENT_HEADERS
    )
    request.get_method = lambda: "HEAD"
    raw = shcheck.raw_request(request).decode("latin-1")

    assert raw.startswith("HEAD /a?b=1 HTTP/1.1\r\n")
    assert "Host: example.com\r\n" in raw
    # do_open() forces this, and putrequest() adds the default encoding
    assert "Connection: close\r\n" in raw
    assert "Accept-Encoding: identity\r\n" in raw
    assert raw.endswith("\r\n\r\n")


@pytest.mark.xfail(
    strict=True,
    reason="raw_request() does not reproduce putrequest()'s `url = url or '/'` "
    "rule, so a target with no path is captured as 'HEAD  HTTP/1.1'",
)
def test_raw_request_uses_slash_for_an_empty_selector():
    request = urllib.request.Request(HTTPS_URL)
    request.get_method = lambda: "HEAD"
    assert shcheck.raw_request(request).startswith(b"HEAD / HTTP/1.1\r\n")


def test_raw_request_rejects_non_bytes_body():
    request = urllib.request.Request("https://example.com", data=io.BytesIO(b"x"))
    with pytest.raises(TypeError):
        shcheck.raw_request(request)


# ---------------------------------------------------------------------------
# Scanner header tables
# ---------------------------------------------------------------------------


def test_cache_headers_contains_last_modified():
    # Regression: missing comma caused 'Last-Modified' and 'Expires' to concatenate
    assert "Last-Modified" in Scanner.CACHE_HEADERS
    assert "Expires" in Scanner.CACHE_HEADERS
    assert "Last-ModifiedExpires" not in Scanner.CACHE_HEADERS


def test_upgrade_insecure_requests_is_string():
    # Regression: value was int 1 instead of str '1'
    assert isinstance(Scanner.CLIENT_HEADERS["Upgrade-Insecure-Requests"], str)


def test_policy_headers_are_a_subset_of_security_headers():
    assert Scanner.POLICY_HEADERS <= set(Scanner.SECURITY_HEADERS)


def test_deprecated_headers_are_not_also_security_headers():
    assert not set(Scanner.DEPRECATED_HEADERS) & set(Scanner.SECURITY_HEADERS)


def test_every_security_header_severity_is_a_known_theme_colour():
    # analyze_headers() feeds these straight into colorize() as the alert name
    for theme in Scanner.THEMES.values():
        assert set(Scanner.SECURITY_HEADERS.values()) <= set(theme)


# ---------------------------------------------------------------------------
# colorize
# ---------------------------------------------------------------------------


def test_colorize_none_mode_returns_plain_string():
    scanner = make_scanner("--colours", "none")
    assert scanner.colorize("hello", "error") == "hello"


def test_colorize_unknown_alert_returns_plain_string():
    scanner = make_scanner("--colours", "dark")
    assert scanner.colorize("hello", "unknown_alert") == "hello"


def test_colorize_dark_error_contains_ansi():
    result = make_scanner("--colours", "dark").colorize("hello", "error")
    assert "\033[91m" in result
    assert "hello" in result
    assert "\033[0m" in result


def test_colorize_dark_ok_contains_ansi():
    assert "\033[92m" in make_scanner("--colours", "dark").colorize("hello", "ok")


def test_colorize_light_warning_differs_from_dark():
    dark_result = make_scanner("--colours", "dark").colorize("hello", "warning")
    light_result = make_scanner("--colours", "light").colorize("hello", "warning")
    assert dark_result != light_result


def test_colorize_all_highlights_every_keyword_occurrence():
    scanner = make_scanner("--colours", "dark")
    result = scanner.colorize_all(
        "script-src 'self'; style-src 'self'", "error", ["self"]
    )
    assert result.count("\033[91mself\033[0m") == 2


def test_colorize_all_none_mode_returns_plain_string():
    scanner = make_scanner("--colours", "none")
    value = "script-src 'self'"
    assert scanner.colorize_all(value, "error", ["self"]) == value


# ---------------------------------------------------------------------------
# check_target (mocked network)
# ---------------------------------------------------------------------------


def test_check_target_success():
    scanner = make_scanner()
    mock = _mock_response([("Content-Type", "text/html")], HTTP_URL)
    with patch("urllib.request.urlopen", return_value=mock):
        rurl, headers, raw_req, raw_resp = scanner.check_target(HTTP_URL)
    assert rurl == HTTP_URL
    assert headers == {"content-type": "text/html"}
    # raw capture is off unless -r was passed
    assert raw_req is None
    assert raw_resp is None


def test_check_target_captures_raw_exchange_with_flag():
    scanner = make_scanner("-r")
    url = HTTP_URL + "/index.html"
    mock = _mock_response([("Content-Type", "text/html")], url)
    mock.version = 11
    mock.status = 200
    mock.reason = "OK"
    mock.headers.items.return_value = [("Content-Type", "text/html")]
    mock.isclosed.return_value = True
    with patch("urllib.request.urlopen", return_value=mock):
        _rurl, _headers, raw_req, raw_resp = scanner.check_target(url)
    assert raw_req.startswith(b"HEAD /index.html HTTP/1.1\r\n")
    assert b"User-Agent: Mozilla/5.0" in raw_req
    assert raw_resp.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Type: text/html\r\n" in raw_resp


def test_check_target_unreachable_returns_nones():
    scanner = make_scanner()
    with patch(
        "urllib.request.urlopen", side_effect=urllib.error.URLError("unreachable")
    ):
        result = scanner.check_target("http://unreachable.invalid")
    assert result == (None, None, None, None)


def test_check_target_4xx_uses_the_error_response():
    scanner = make_scanner()
    # A real HTTPError wraps the response body object, and header access is
    # delegated to it, so the fp has to answer getheaders().
    fp = _mock_response([("Server", "nginx")], HTTP_URL)
    http_error = urllib.error.HTTPError(HTTP_URL, 403, "Forbidden", {}, fp)
    with patch("urllib.request.urlopen", side_effect=http_error):
        rurl, headers, _raw_req, _raw_resp = scanner.check_target(HTTP_URL)
    assert rurl == HTTP_URL
    assert headers == {"server": "nginx"}


def test_check_target_5xx_returns_nones():
    scanner = make_scanner()
    http_error = urllib.error.HTTPError(HTTP_URL, 500, "Server Error", {}, None)
    with patch("urllib.request.urlopen", side_effect=http_error):
        result = scanner.check_target(HTTP_URL)
    assert result == (None, None, None, None)


def test_check_target_normalizes_a_bare_target():
    scanner = make_scanner()
    mock = _mock_response([], HTTPS_URL)
    with patch("urllib.request.urlopen", return_value=mock) as urlopen:
        scanner.check_target("example.com")
    assert urlopen.call_args[0][0].full_url == HTTPS_URL


def test_check_target_uses_the_requested_method():
    scanner = make_scanner("-g")
    mock = _mock_response([], HTTP_URL)
    with patch("urllib.request.urlopen", return_value=mock) as urlopen:
        scanner.check_target(HTTP_URL)
    assert urlopen.call_args[0][0].get_method() == "GET"


# ---------------------------------------------------------------------------
# JSON output — structure and content
# ---------------------------------------------------------------------------


def test_json_output_is_valid_json():
    data = _run_json([], SAMPLE_HEADERS)
    assert isinstance(data, dict)


def test_json_output_structure():
    data = _run_json([], SAMPLE_HEADERS)
    assert HTTPS_URL in data
    assert isinstance(data[HTTPS_URL]["present"], dict)
    assert isinstance(data[HTTPS_URL]["missing"], list)
    assert isinstance(data[HTTPS_URL]["unsafe"], dict)


def test_json_present_headers_match_response():
    present = _run_json([], SAMPLE_HEADERS)[HTTPS_URL]["present"]
    assert present.get("X-Frame-Options") == "DENY"
    assert present.get("X-Content-Type-Options") == "nosniff"
    assert present.get("Strict-Transport-Security") == "max-age=31536000"
    assert present.get("Referrer-Policy") == "no-referrer"


def test_json_missing_headers_vs_present():
    # Both assertions share a single run to avoid duplicate main() calls
    missing = _run_json([], SAMPLE_HEADERS)[HTTPS_URL]["missing"]
    # Headers in the response must not appear as missing
    assert "X-Frame-Options" not in missing
    assert "Strict-Transport-Security" not in missing
    assert "Referrer-Policy" not in missing
    # Headers absent from the response must appear as missing
    assert "Permissions-Policy" in missing
    assert "Content-Security-Policy" in missing
    assert "Cross-Origin-Opener-Policy" in missing


def test_json_no_headers_all_security_headers_missing():
    missing = set(_run_json([], [])[HTTPS_URL]["missing"])
    assert missing == set(Scanner.SECURITY_HEADERS)


def test_json_hsts_excluded_for_http_target():
    data = _run_json([], [], HTTP_URL)
    assert "Strict-Transport-Security" not in data[HTTP_URL]["missing"]


def test_json_hsts_missing_for_https_target():
    assert "Strict-Transport-Security" in _run_json([], [])[HTTPS_URL]["missing"]


def test_json_hsts_max_age_zero_is_unsafe_not_present():
    data = _run_json([], [("Strict-Transport-Security", "max-age=0")])[HTTPS_URL]
    assert data["unsafe"]["Strict-Transport-Security"] == "max-age=0"
    assert "Strict-Transport-Security" not in data["present"]
    assert "Strict-Transport-Security" not in data["missing"]


def test_json_policy_header_with_unsafe_value_is_flagged_unsafe():
    csp = "default-src 'self'; script-src 'unsafe-inline'"
    data = _run_json([], [("Content-Security-Policy", csp)])[HTTPS_URL]
    assert data["unsafe"]["Content-Security-Policy"] == csp
    assert "Content-Security-Policy" not in data["present"]
    assert "Content-Security-Policy" not in data["missing"]


def test_json_policy_header_with_safe_value_is_present():
    csp = "default-src https://cdn.example.com"
    data = _run_json([], [("Content-Security-Policy", csp)])[HTTPS_URL]
    assert data["present"]["Content-Security-Policy"] == csp
    assert "Content-Security-Policy" not in data["unsafe"]


# ---------------------------------------------------------------------------
# JSON output — deprecated headers
# ---------------------------------------------------------------------------
# Deprecated headers are reported only when the target actually sends them;
# unlike security headers, their absence is the desired state and is never
# reported as missing.


def test_json_deprecated_headers_never_reported_as_missing():
    missing = _run_json(["-k"], [])[HTTPS_URL]["missing"]
    for header in Scanner.DEPRECATED_HEADERS:
        assert header not in missing


def test_json_no_deprecated_key_without_flag():
    data = _run_json([], [("X-XSS-Protection", "0")])
    assert "deprecated" not in data[HTTPS_URL]


def test_json_deprecated_headers_reported_with_flag():
    data = _run_json(["-k"], [("X-XSS-Protection", "0")])
    assert data[HTTPS_URL]["deprecated"] == {"X-XSS-Protection": "0"}


def test_json_deprecated_key_is_empty_when_flag_set_but_none_found():
    # An empty dict means "the check ran and found nothing"
    assert _run_json(["-k"], [])[HTTPS_URL]["deprecated"] == {}


def test_json_deprecated_header_with_bad_value_is_also_unsafe():
    value = "1; mode=block"
    data = _run_json(["-k"], [("X-XSS-Protection", value)])[HTTPS_URL]
    assert data["deprecated"]["X-XSS-Protection"] == value
    assert data["unsafe"]["X-XSS-Protection"] == value


def test_json_deprecated_header_with_recommended_value_is_not_unsafe():
    data = _run_json(["-k"], [("X-XSS-Protection", "0")])[HTTPS_URL]
    assert "X-XSS-Protection" not in data["unsafe"]


# ---------------------------------------------------------------------------
# JSON output — optional checks
# ---------------------------------------------------------------------------


def test_json_information_disclosure_with_flag():
    headers = SAMPLE_HEADERS + [("Server", "Apache/2.4"), ("X-Powered-By", "PHP/8.0")]
    disclosure = _run_json(["-i"], headers)[HTTPS_URL]["information_disclosure"]
    assert disclosure["Server"] == "Apache/2.4"
    assert disclosure["X-Powered-By"] == "PHP/8.0"


def test_json_no_information_disclosure_without_flag():
    headers = SAMPLE_HEADERS + [("Server", "Apache/2.4")]
    assert "information_disclosure" not in _run_json([], headers)[HTTPS_URL]


def test_json_information_disclosure_key_is_empty_when_none_found():
    assert _run_json(["-i"], SAMPLE_HEADERS)[HTTPS_URL]["information_disclosure"] == {}


def test_json_caching_headers_with_flag():
    headers = SAMPLE_HEADERS + [("Cache-Control", "no-store"), ("ETag", '"abc123"')]
    caching = _run_json(["-x"], headers)[HTTPS_URL]["caching"]
    assert caching["Cache-Control"] == "no-store"
    assert caching["ETag"] == '"abc123"'


def test_json_no_caching_headers_without_flag():
    headers = SAMPLE_HEADERS + [("Cache-Control", "no-store")]
    assert "caching" not in _run_json([], headers)[HTTPS_URL]


def test_json_all_flag_enables_every_optional_section():
    data = _run_json(["-A"], SAMPLE_HEADERS)[HTTPS_URL]
    assert "information_disclosure" in data
    assert "caching" in data
    assert "deprecated" in data


def test_json_raw_capture_is_base64_encoded():
    url = HTTPS_URL + "/index.html"
    mock = _mock_response(SAMPLE_HEADERS, url)
    mock.version = 11
    mock.status = 200
    mock.reason = "OK"
    mock.headers.items.return_value = SAMPLE_HEADERS
    mock.isclosed.return_value = True
    out = io.StringIO()
    with (
        patch("sys.stdout", out),
        patch("urllib.request.urlopen", return_value=mock),
    ):
        shcheck.main(["shcheck.py", "-j", "-r", url])
    data = json.loads(out.getvalue())[url]
    assert base64.b64decode(data["request"]).startswith(
        b"HEAD /index.html HTTP/1.1\r\n"
    )
    assert base64.b64decode(data["response"]).startswith(b"HTTP/1.1 200 OK\r\n")


# ---------------------------------------------------------------------------
# Per-target isolation
# ---------------------------------------------------------------------------


def test_security_headers_table_not_mutated_across_targets():
    # Regression: sec_headers.pop() used to permanently drop X-Frame-Options for
    # all subsequent targets whenever a target had CSP with frame-ancestors.
    second_url = "https://other.example.com"
    data = _run_json_multi(
        [],
        [
            (
                HTTPS_URL,
                [
                    (
                        "Content-Security-Policy",
                        "default-src https://cdn.example.com; frame-ancestors 'none'",
                    )
                ],
            ),
            (second_url, []),
        ],
    )
    # frame-ancestors covers X-Frame-Options for the first target only
    assert "X-Frame-Options" not in data[HTTPS_URL]["missing"]
    assert "X-Frame-Options" in data[second_url]["missing"]
    # ...and the shared table itself must be untouched
    assert "X-Frame-Options" in Scanner.SECURITY_HEADERS


def test_information_disclosure_preserved_per_target():
    """information_disclosure must be nested under each URL, not as a shared
    top-level key that later targets silently overwrite."""
    first_url = "https://first.example.com"
    second_url = "https://second.example.com"
    data = _run_json_multi(
        ["-i"],
        [
            (first_url, [("Server", "Apache/2.4")]),
            (second_url, [("Server", "nginx/1.18")]),
        ],
    )
    assert data[first_url]["information_disclosure"]["Server"] == "Apache/2.4"
    assert data[second_url]["information_disclosure"]["Server"] == "nginx/1.18"


def test_caching_preserved_per_target():
    """caching must be nested under each URL, not as a shared top-level key
    that later targets silently overwrite."""
    first_url = "https://first.example.com"
    second_url = "https://second.example.com"
    data = _run_json_multi(
        ["-x"],
        [
            (first_url, [("Cache-Control", "no-store")]),
            (second_url, [("Cache-Control", "max-age=3600")]),
        ],
    )
    assert data[first_url]["caching"]["Cache-Control"] == "no-store"
    assert data[second_url]["caching"]["Cache-Control"] == "max-age=3600"


# ---------------------------------------------------------------------------
# JSON vs normal output consistency
# ---------------------------------------------------------------------------


def test_json_and_normal_output_consistent():
    """JSON and normal text output must agree on which headers are present/missing
    and on the summary counts. Both modes are run once and compared."""
    data = _run_json([], SAMPLE_HEADERS)[HTTPS_URL]
    normal = _run_normal([], SAMPLE_HEADERS)

    # Every header reported as present in JSON must appear as present in normal output
    for header in data["present"]:
        assert f"Header {header} is present" in normal

    # Every header reported as missing in JSON must appear as missing in normal output
    for header in data["missing"]:
        assert f"Security header missing: {header}" in normal

    # Summary counts must match
    assert (
        "[+] {} security header(s) present and safe".format(len(data["present"]))
        in normal
    )
    assert (
        "[-] {} security header(s) present but unsafe".format(len(data["unsafe"]))
        in normal
    )
    assert "[-] {} security header(s) missing".format(len(data["missing"])) in normal


# ---------------------------------------------------------------------------
# Output file
# ---------------------------------------------------------------------------


def test_output_file_is_written_without_ansi_codes(tmp_path):
    out_path = tmp_path / "report.txt"
    _run_main(["--colours", "dark", "-o", str(out_path)], [(HTTPS_URL, SAMPLE_HEADERS)])
    content = out_path.read_text(encoding="utf-8")
    assert "Header X-Frame-Options is present" in content
    assert "\033[" not in content


def test_json_output_file_receives_the_json(tmp_path):
    out_path = tmp_path / "report.json"
    _run_main(["-j", "-o", str(out_path)], [(HTTPS_URL, SAMPLE_HEADERS)])
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data[HTTPS_URL]["present"]["X-Frame-Options"] == "DENY"


# ---------------------------------------------------------------------------
# Error reporting
# ---------------------------------------------------------------------------
# Diagnostics belong on stderr: printing them to stdout would corrupt the JSON
# document in -j mode. Note that -j on its own implies --quiet (see
# parse_options), which suppresses diagnostics entirely; -o keeps them on.


def test_unknown_protocol_error_goes_to_stderr():
    out, err = _run_failing_main([], http.client.UnknownProtocol("HTTP/2"))
    assert "Unknown protocol" in err
    assert "Unknown protocol" not in out


def test_no_response_error_goes_to_stderr():
    _out, err = _run_failing_main([], http.client.UnknownProtocol("HTTP/2"))
    assert "Couldn't read a response from the server." in err


def test_unreachable_target_error_goes_to_stderr():
    _out, err = _run_failing_main([], urllib.error.URLError("unreachable"))
    assert "seems to be unreachable" in err


def test_certificate_error_suggests_the_d_flag():
    _out, err = _run_failing_main(
        [], urllib.error.URLError("CERTIFICATE_VERIFY_FAILED")
    )
    assert "Certificate validation error" in err
    assert '"-d" option' in err


def test_errors_reach_stderr_in_json_mode_when_not_quiet(tmp_path):
    out_path = tmp_path / "report.json"
    stdout, err = _run_failing_main(
        ["-j", "-o", str(out_path)], http.client.UnknownProtocol("HTTP/2")
    )
    assert "Unknown protocol" in err
    assert "Unknown protocol" not in stdout
    # The JSON document stays clean: the failed target is simply absent
    assert json.loads(out_path.read_text(encoding="utf-8")) == {}


def test_json_mode_stdout_stays_parseable_when_a_target_fails():
    stdout, _err = _run_failing_main(["-j"], http.client.UnknownProtocol("HTTP/2"))
    assert json.loads(stdout) == {}


@pytest.mark.xfail(
    strict=True,
    reason="print_error() calls colorize() without the alert argument, so an "
    "error outside the ValueError/HTTPError/URLError branches raises TypeError",
)
def test_generic_error_is_reported_rather_than_raised():
    _out, err = _run_failing_main([], TimeoutError("timed out"))
    assert "timed out" in err


def test_quiet_suppresses_stdout(tmp_path):
    # -q is only honoured when the output goes somewhere else
    out_path = tmp_path / "report.txt"
    out, _err = _run_main(["-q", "-o", str(out_path)], [(HTTPS_URL, SAMPLE_HEADERS)])
    assert out == ""
    assert "Header X-Frame-Options is present" in out_path.read_text(encoding="utf-8")
