import http.client
import io
import json
import sys
import urllib.error
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from shcheck import shcheck


# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------

HTTPS_URL = 'https://example.com'
HTTP_URL = 'http://example.com'

# A representative set of security headers used across multiple tests
SAMPLE_HEADERS = [
    ('X-Frame-Options', 'DENY'),
    ('X-Content-Type-Options', 'nosniff'),
    ('Strict-Transport-Security', 'max-age=31536000'),
    ('Referrer-Policy', 'no-referrer'),
]


def make_options(**kwargs):
    defaults = dict(
        json_output=False,
        colours='none',
        ssldisabled=False,
        usemethod='HEAD',
        proxy=None,
        no_follow=False,
        output_handle=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _mock_response(headers, url):
    mock = MagicMock()
    mock.getheaders.return_value = headers
    mock.geturl.return_value = url
    return mock


def _run_json(extra_args, headers, url):
    """Run main() with -j and return parsed JSON output."""
    mock = _mock_response(headers, url)
    captured = io.StringIO()
    with patch('sys.argv', ['shcheck.py', '-j'] + extra_args + [url]), \
         patch('sys.stdout', captured), \
         patch('urllib.request.urlopen', return_value=mock):
        shcheck.main()
    return json.loads(captured.getvalue())


def _run_normal(extra_args, headers, url):
    """Run main() without -j and return captured stdout."""
    mock = _mock_response(headers, url)
    captured = io.StringIO()
    with patch('sys.argv', ['shcheck.py', '--colours', 'none'] + extra_args + [url]), \
         patch('sys.stdout', captured), \
         patch('urllib.request.urlopen', return_value=mock):
        shcheck.main()
    return captured.getvalue()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_no_args_return_help():
    with patch('sys.argv', ['shcheck.py']):
        with pytest.raises(SystemExit) as exc:
            shcheck.main()
    assert exc.value.code == 12


# ---------------------------------------------------------------------------
# append_port
# ---------------------------------------------------------------------------

def test_append_port_with_trailing_slash():
    assert shcheck.append_port('http://example.com/', '8080') == 'http://example.com:8080/'

def test_append_port_without_trailing_slash():
    assert shcheck.append_port('http://example.com', '8080') == 'http://example.com:8080'


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------

def test_normalize_bare_ip_adds_http():
    assert shcheck.normalize('192.168.1.1') == 'http://192.168.1.1'

def test_normalize_bare_domain_adds_https():
    assert shcheck.normalize('github.com') == 'https://github.com'

def test_normalize_bare_domain_with_path_adds_https():
    assert shcheck.normalize('github.com/santoru/shcheck') == 'https://github.com/santoru/shcheck'

def test_normalize_https_url_unchanged():
    assert shcheck.normalize('https://example.com') == 'https://example.com'

def test_normalize_http_url_unchanged():
    assert shcheck.normalize('http://example.com') == 'http://example.com'


# ---------------------------------------------------------------------------
# parse_headers
# ---------------------------------------------------------------------------

def test_parse_headers_lowercases_keys():
    result = shcheck.parse_headers([('X-Frame-Options', 'DENY'), ('Content-Type', 'text/html')])
    assert 'x-frame-options' in result
    assert result['x-frame-options'] == 'DENY'
    assert 'content-type' in result

def test_parse_headers_preserves_values():
    result = shcheck.parse_headers([('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')])
    assert result['strict-transport-security'] == 'max-age=31536000; includeSubDomains'


# ---------------------------------------------------------------------------
# colorize
# ---------------------------------------------------------------------------

def test_colorize_none_mode_returns_plain_string():
    shcheck.options = make_options(colours='none')
    assert shcheck.colorize('hello', 'error') == 'hello'

def test_colorize_unknown_alert_returns_plain_string():
    shcheck.options = make_options(colours='none')
    assert shcheck.colorize('hello', 'unknown_alert') == 'hello'

def test_colorize_dark_error_contains_ansi():
    shcheck.options = make_options(colours='dark')
    result = shcheck.colorize('hello', 'error')
    assert '\033[91m' in result
    assert 'hello' in result
    assert '\033[0m' in result

def test_colorize_dark_ok_contains_ansi():
    shcheck.options = make_options(colours='dark')
    result = shcheck.colorize('hello', 'ok')
    assert '\033[92m' in result

def test_colorize_light_warning_differs_from_dark():
    shcheck.options = make_options(colours='dark')
    dark_result = shcheck.colorize('hello', 'warning')
    shcheck.options = make_options(colours='light')
    light_result = shcheck.colorize('hello', 'warning')
    assert dark_result != light_result


# ---------------------------------------------------------------------------
# Regression tests for fixed bugs
# ---------------------------------------------------------------------------

def test_cache_headers_contains_last_modified():
    # Regression: missing comma caused 'Last-Modified' and 'Expires' to concatenate
    assert 'Last-Modified' in shcheck.cache_headers
    assert 'Expires' in shcheck.cache_headers
    assert 'Last-ModifiedExpires' not in shcheck.cache_headers

def test_upgrade_insecure_requests_is_string():
    # Regression: value was int 1 instead of str '1'
    assert isinstance(shcheck.client_headers['Upgrade-Insecure-Requests'], str)

def test_sec_headers_not_mutated_across_targets():
    # Regression: sec_headers.pop() used to permanently drop X-Frame-Options for
    # all subsequent targets whenever a target had CSP with frame-ancestors.
    headers_with_csp = [('Content-Security-Policy', "default-src 'self'; frame-ancestors 'self'")]
    headers_without_xfo = []
    second_url = 'https://other.example.com'

    mock1 = _mock_response(headers_with_csp, HTTPS_URL)
    mock2 = _mock_response(headers_without_xfo, second_url)

    captured = io.StringIO()
    with patch('sys.argv', ['shcheck.py', '-j', HTTPS_URL, second_url]), \
         patch('sys.stdout', captured), \
         patch('urllib.request.urlopen', side_effect=[mock1, mock2]):
        shcheck.main()

    data = json.loads(captured.getvalue())
    # X-Frame-Options must still be checked on the second target
    assert 'X-Frame-Options' in data[second_url]['missing']


# ---------------------------------------------------------------------------
# check_target (mocked network)
# ---------------------------------------------------------------------------

def test_check_target_success():
    shcheck.options = make_options()
    mock = _mock_response([('Content-Type', 'text/html')], HTTP_URL)
    with patch('urllib.request.urlopen', return_value=mock):
        result = shcheck.check_target(HTTP_URL)
    assert result is mock

def test_check_target_unreachable_returns_none():
    shcheck.options = make_options()
    with patch('urllib.request.urlopen', side_effect=urllib.error.URLError('unreachable')):
        result = shcheck.check_target('http://unreachable.invalid')
    assert result is None

def test_check_target_4xx_returns_error_response():
    shcheck.options = make_options()
    http_error = urllib.error.HTTPError(HTTP_URL, 403, 'Forbidden', {}, None)
    with patch('urllib.request.urlopen', side_effect=http_error):
        result = shcheck.check_target(HTTP_URL)
    assert result is http_error

def test_check_target_5xx_returns_none():
    shcheck.options = make_options()
    http_error = urllib.error.HTTPError(HTTP_URL, 500, 'Server Error', {}, None)
    with patch('urllib.request.urlopen', side_effect=http_error):
        result = shcheck.check_target(HTTP_URL)
    assert result is None


# ---------------------------------------------------------------------------
# JSON output — structure and content
# ---------------------------------------------------------------------------

def test_json_output_is_valid_json():
    data = _run_json([], SAMPLE_HEADERS, HTTPS_URL)
    assert isinstance(data, dict)

def test_json_output_structure():
    data = _run_json([], SAMPLE_HEADERS, HTTPS_URL)
    assert HTTPS_URL in data
    assert 'present' in data[HTTPS_URL]
    assert 'missing' in data[HTTPS_URL]
    assert isinstance(data[HTTPS_URL]['present'], dict)
    assert isinstance(data[HTTPS_URL]['missing'], list)

def test_json_present_headers_match_response():
    data = _run_json([], SAMPLE_HEADERS, HTTPS_URL)
    present = data[HTTPS_URL]['present']
    assert present.get('X-Frame-Options') == 'DENY'
    assert present.get('X-Content-Type-Options') == 'nosniff'
    assert present.get('Strict-Transport-Security') == 'max-age=31536000'
    assert present.get('Referrer-Policy') == 'no-referrer'

def test_json_missing_headers_vs_present():
    # Both assertions share a single run to avoid duplicate main() calls
    data = _run_json([], SAMPLE_HEADERS, HTTPS_URL)
    missing = data[HTTPS_URL]['missing']
    # Headers in the response must not appear as missing
    assert 'X-Frame-Options' not in missing
    assert 'Strict-Transport-Security' not in missing
    assert 'Referrer-Policy' not in missing
    # Headers absent from the response must appear as missing
    assert 'Permissions-Policy' in missing
    assert 'Content-Security-Policy' in missing
    assert 'Cross-Origin-Opener-Policy' in missing

def test_json_no_headers_all_non_deprecated_missing():
    data = _run_json([], [], HTTPS_URL)
    missing = set(data[HTTPS_URL]['missing'])
    expected = {h for h, v in shcheck.sec_headers.items() if v != 'deprecated'}
    assert missing == expected

def test_json_deprecated_headers_excluded_by_default():
    data = _run_json([], [], HTTPS_URL)
    missing = data[HTTPS_URL]['missing']
    for header, severity in shcheck.sec_headers.items():
        if severity == 'deprecated':
            assert header not in missing

def test_json_deprecated_headers_included_with_flag():
    data = _run_json(['-k'], [], HTTPS_URL)
    missing = data[HTTPS_URL]['missing']
    for header, severity in shcheck.sec_headers.items():
        if severity == 'deprecated':
            assert header in missing

def test_json_hsts_excluded_for_http_target():
    data = _run_json([], [], HTTP_URL)
    assert 'Strict-Transport-Security' not in data[HTTP_URL]['missing']

def test_json_hsts_missing_for_https_target():
    data = _run_json([], [], HTTPS_URL)
    assert 'Strict-Transport-Security' in data[HTTPS_URL]['missing']

def test_json_information_disclosure_with_flag():
    headers = SAMPLE_HEADERS + [('Server', 'Apache/2.4'), ('X-Powered-By', 'PHP/8.0')]
    data = _run_json(['-i'], headers, HTTPS_URL)
    assert 'information_disclosure' in data[HTTPS_URL]
    assert data[HTTPS_URL]['information_disclosure']['Server'] == 'Apache/2.4'
    assert data[HTTPS_URL]['information_disclosure']['X-Powered-By'] == 'PHP/8.0'

def test_json_no_information_disclosure_without_flag():
    headers = SAMPLE_HEADERS + [('Server', 'Apache/2.4')]
    data = _run_json([], headers, HTTPS_URL)
    assert 'information_disclosure' not in data[HTTPS_URL]

def test_json_caching_headers_with_flag():
    headers = SAMPLE_HEADERS + [('Cache-Control', 'no-store'), ('ETag', '"abc123"')]
    data = _run_json(['-x'], headers, HTTPS_URL)
    assert 'caching' in data[HTTPS_URL]
    assert data[HTTPS_URL]['caching']['Cache-Control'] == 'no-store'
    assert data[HTTPS_URL]['caching']['ETag'] == '"abc123"'

def test_json_no_caching_headers_without_flag():
    headers = SAMPLE_HEADERS + [('Cache-Control', 'no-store')]
    data = _run_json([], headers, HTTPS_URL)
    assert 'caching' not in data[HTTPS_URL]


# ---------------------------------------------------------------------------
# JSON vs normal output consistency
# ---------------------------------------------------------------------------

def test_json_and_normal_output_consistent():
    """JSON and normal text output must agree on which headers are present/missing
    and on the summary counts. Both modes are run once and compared."""
    data = _run_json([], SAMPLE_HEADERS, HTTPS_URL)
    normal = _run_normal([], SAMPLE_HEADERS, HTTPS_URL)

    # Every header reported as present in JSON must appear as present in normal output
    for header in data[HTTPS_URL]['present']:
        assert f'Header {header} is present' in normal or f'header {header} is set' in normal

    # Every header reported as missing in JSON must appear as missing in normal output
    for header in data[HTTPS_URL]['missing']:
        assert f'Security header missing: {header}' in normal

    # Summary counts must match
    assert f"{len(data[HTTPS_URL]['present'])} security header(s) present" in normal
    assert f"{len(data[HTTPS_URL]['missing'])} security header(s) missing" in normal


# ---------------------------------------------------------------------------
# Bug confirmations (tests currently FAIL — fixed by upcoming patches)
# ---------------------------------------------------------------------------

def _run_json_multi(extra_args, targets_and_headers):
    """Run main() with -j against multiple targets. targets_and_headers is a list
    of (url, headers) pairs; urlopen responses are returned in order."""
    mocks = [_mock_response(hdrs, url) for url, hdrs in targets_and_headers]
    urls = [url for url, _ in targets_and_headers]
    captured = io.StringIO()
    with patch('sys.argv', ['shcheck.py', '-j'] + extra_args + urls), \
         patch('sys.stdout', captured), \
         patch('urllib.request.urlopen', side_effect=mocks):
        shcheck.main()
    return json.loads(captured.getvalue())


# Bug #1 — information_disclosure and caching overwrite each other across targets

def test_bug1_information_disclosure_preserved_per_target():
    """information_disclosure must be nested under each URL, not as a shared
    top-level key that later targets silently overwrite."""
    first_url = 'https://first.example.com'
    second_url = 'https://second.example.com'
    data = _run_json_multi(
        ['-i'],
        [
            (first_url,  [('Server', 'Apache/2.4')]),
            (second_url, [('Server', 'nginx/1.18')]),
        ]
    )
    assert data[first_url]['information_disclosure']['Server'] == 'Apache/2.4'
    assert data[second_url]['information_disclosure']['Server'] == 'nginx/1.18'


def test_bug1_caching_preserved_per_target():
    """caching must be nested under each URL, not as a shared top-level key
    that later targets silently overwrite."""
    first_url = 'https://first.example.com'
    second_url = 'https://second.example.com'
    data = _run_json_multi(
        ['-x'],
        [
            (first_url,  [('Cache-Control', 'no-store')]),
            (second_url, [('Cache-Control', 'max-age=3600')]),
        ]
    )
    assert data[first_url]['caching']['Cache-Control'] == 'no-store'
    assert data[second_url]['caching']['Cache-Control'] == 'max-age=3600'


# Bug #2 — print() calls in check_target are swallowed by stdout redirect under -j

def test_bug2_unknown_protocol_error_visible_in_json_mode():
    """'Unknown protocol' error must reach stderr even in -j mode."""
    captured_stderr = io.StringIO()
    with patch('sys.argv', ['shcheck.py', '-j', HTTPS_URL]), \
         patch('sys.stdout', io.StringIO()), \
         patch('sys.stderr', captured_stderr), \
         patch('urllib.request.urlopen',
               side_effect=http.client.UnknownProtocol('HTTP/2')):
        shcheck.main()
    assert 'Unknown protocol' in captured_stderr.getvalue()


def test_bug2_no_response_error_visible_in_json_mode():
    """'Couldn't read a response from server.' must reach stderr even in -j mode."""
    captured_stderr = io.StringIO()
    with patch('sys.argv', ['shcheck.py', '-j', HTTPS_URL]), \
         patch('sys.stdout', io.StringIO()), \
         patch('sys.stderr', captured_stderr), \
         patch('urllib.request.urlopen',
               side_effect=http.client.UnknownProtocol('HTTP/2')):
        shcheck.main()
    assert "Couldn't read a response from server." in captured_stderr.getvalue()


# ---------------------------------------------------------------------------
# Output file (-o)
# ---------------------------------------------------------------------------

def _run_with_output_file(extra_args, headers, url, path):
    """Run main() with -o <path> and return (captured stdout, file contents)."""
    stdout = _run_normal(['-o', str(path)] + extra_args, headers, url)
    return stdout, path.read_text(encoding='utf-8')


def test_output_file_contains_information_disclosure(tmp_path):
    """With -i -o, information disclosure findings must be written to the output file,
    not only printed to stdout."""
    headers = SAMPLE_HEADERS + [('Server', 'Apache/2.4')]
    _, written = _run_with_output_file(['-i'], headers, HTTPS_URL, tmp_path / 'out.txt')
    assert ('[!] Possible information disclosure: '
            'header Server is present! (Value: Apache/2.4)\n') in written


def test_output_file_contains_csp_directives(tmp_path):
    """The per-directive CSP breakdown from parse_csp() must be written to the output file."""
    headers = SAMPLE_HEADERS + [('Content-Security-Policy', "default-src 'self'; img-src *")]
    _, written = _run_with_output_file([], headers, HTTPS_URL, tmp_path / 'out.txt')
    assert "Value:\n\tdefault-src: 'self'\n\timg-src: *\n" in written


def test_output_file_mirrors_stdout_after_banner(tmp_path):
    """Everything printed after the banner must also land in the output file, so no
    log line can be missed; covers CSP, information disclosure and caching output."""
    headers = SAMPLE_HEADERS + [
        ('Content-Security-Policy', "default-src 'self'"),
        ('Server', 'Apache/2.4'),
        ('Cache-Control', 'no-store'),
    ]
    stdout, written = _run_with_output_file(['-i', '-x'], headers, HTTPS_URL,
                                            tmp_path / 'out.txt')
    assert written
    assert stdout.endswith(written)


def test_run_without_output_file_leaves_previous_output_file_untouched(tmp_path):
    """A run without -o after a run with -o must not write to the previous run's
    file handle: the second run must succeed and the first file must be unchanged
    (the handle lives on options, which main() rebuilds on every run)."""
    path = tmp_path / 'out.txt'
    _, first_written = _run_with_output_file([], SAMPLE_HEADERS, HTTPS_URL, path)
    stdout = _run_normal(['-i'], SAMPLE_HEADERS + [('Server', 'Apache/2.4')], HTTPS_URL)
    assert 'security header(s) present' in stdout
    # ensure file handle is closed and file is not overwritten by a following run
    assert path.read_text(encoding='utf-8') == first_written
