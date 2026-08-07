#!/usr/bin/env python3

# shcheck - Security headers check!
# Copyright (C) 2019-2021  santoru
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import urllib.request
import urllib.error
import http.client
import socket
import sys
import ssl
import json
import argparse
import re
import shutil
import functools
import base64


def _strip_ansi_codes(string):
    return re.sub(r"\x1b\[[0-9;]*m", "", string)


def parse_headers(hdrs):
    return {x.lower(): y for x, y in hdrs}


def append_port(target, port):
    if target[-1:] == "/":
        return target[:-1] + ":" + port + "/"
    return target + ":" + port


def normalize(target):
    try:
        socket.inet_aton(target)
        target = "http://" + target
    except (ValueError, socket.error):
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
    return target


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def _handle_redirect(self, req, fp, code, msg, headers):
        url = req.get_full_url()
        resp = urllib.response.addinfourl(fp, headers, url)
        resp.status = code
        resp.code = code
        return resp

    http_error_301 = _handle_redirect
    http_error_302 = _handle_redirect
    http_error_303 = _handle_redirect
    http_error_307 = _handle_redirect
    http_error_308 = _handle_redirect


def _effective_headers(req, connection_close=True):
    """Reproduce the header dict AbstractHTTPHandler.do_open() builds."""
    headers = dict(req.unredirected_hdrs)
    headers.update({k: v for k, v in req.headers.items() if k not in headers})
    if connection_close:
        # do_open() forces this; it is never stored on the Request.
        headers["Connection"] = "close"
    headers = {name.title(): val for name, val in headers.items()}
    if req._tunnel_host:
        # do_open() moves this onto the CONNECT, so it is not in the request.
        headers.pop("Proxy-Authorization", None)
    return headers


def raw_request(req, *, http_version="1.1", connection_close=True):
    """Bytes urllib.request would put on the wire for `req`.

    Pass a Request that has already been through an opener; do_request_()
    adds Host, User-agent and Content-length by mutating it in place.
    """
    headers = _effective_headers(req, connection_close)
    lower = {k.lower() for k in headers}

    # http.client.putrequest() prepends these when the caller omitted them.
    leading = []
    if "host" not in lower:
        host = req.host or ""
        leading.append(("Host", host))
    if "accept-encoding" not in lower:
        leading.append(("Accept-Encoding", "identity"))

    lines = ["%s %s HTTP/%s" % (req.get_method(), req.selector, http_version)]
    for name, value in leading + list(headers.items()):
        lines.append("%s: %s" % (name, value))

    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

    body = req.data
    if body is None:
        body = b""
    elif isinstance(body, (bytes, bytearray, memoryview)):
        body = bytes(body)
    else:
        # file object or iterable: consuming it here would break the send
        raise TypeError(
            "req.data is %s; only bytes-like bodies can be reconstructed"
            % type(body).__name__
        )

    if "transfer-encoding" in lower and body:
        body = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)

    return head + body


def raw_response(resp, body=None):
    """Bytes that produced `resp`.

    `body` should be what you got from resp.read(); it is read here only if
    the response is still open. For a chunked response the returned body is
    the decoded form -- chunk framing is discarded by http.client and cannot
    be recovered.
    """
    # Accepts an HTTPResponse or an HTTPError (which exposes the same
    # status/reason/headers, but no version -- assume 1.1 there).
    version = {9: "0.9", 10: "1.0", 11: "1.1"}.get(
        getattr(resp, "version", None), "1.1"
    )
    lines = ["HTTP/%s %s %s" % (version, resp.status, resp.reason)]
    for name, value in resp.headers.items():
        lines.append("%s: %s" % (name, value))
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

    if body is None:
        closed = getattr(resp, "isclosed", lambda: resp.closed)()
        body = b"" if closed else resp.read()
    return head + body


class Scanner:
    # Colour themes.
    THEMES = {
        "dark": {
            "ok": "\033[92m",
            "info": "\033[94m",
            "warning": "\033[93m",
            "error": "\033[91m",
        },
        "light": {
            "ok": "\033[92m",
            "info": "\033[94m",
            "warning": "\033[95m",
            "error": "\033[91m",
        },
    }

    # Client headers to send to the server during the request.
    CLIENT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml, application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US;q=0.8,en;q=0.3",
        "Upgrade-Insecure-Requests": "1",
    }

    # Security headers that should be enabled.
    SECURITY_HEADERS = {
        "Content-Security-Policy": "warning",
        "Cross-Origin-Embedder-Policy": "warning",
        "Cross-Origin-Opener-Policy": "warning",
        "Cross-Origin-Resource-Policy": "warning",
        "Permissions-Policy": "info",
        "Referrer-Policy": "warning",
        "Strict-Transport-Security": "error",
        "X-Content-Type-Options": "warning",
        "X-Frame-Options": "warning",
    }

    # Security headers that use a policy syntax.
    POLICY_HEADERS = {
        "Content-Security-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Permissions-Policy",
        "Referrer-Policy",
    }

    # Deprecated security headers that should no longer be used.
    DEPRECATED_HEADERS = {
        "Expect-CT": "",
        "X-Permitted-Cross-Domain-Policies": "none",
        "X-XSS-Protection": "0",
    }

    # Potential information disclosure headers.
    INFORMATION_HEADERS = {
        "Server",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Powered-By",
    }

    # Cache control headers.
    CACHE_HEADERS = {
        "Cache-Control",
        "ETag",
        "Expires",
        "Last-Modified",
        "Pragma",
    }

    def __init__(self, options):
        self.options = options
        self.theme = self.THEMES.get(self.options.colours, self.THEMES["dark"])
        self.output_file = None

        # Build the URL opener.
        if self.options.proxy:
            proxyhnd = urllib.request.ProxyHandler(
                {
                    "http": self.options.proxy,
                    "https": self.options.proxy,
                }
            )
        else:
            proxyhnd = urllib.request.ProxyHandler()
        if self.options.ssldisabled:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sslhnd = urllib.request.HTTPSHandler(context=ctx)
        else:
            sslhnd = urllib.request.HTTPSHandler()
        if self.options.no_follow:
            self.opener = urllib.request.build_opener(
                NoRedirectHandler(), proxyhnd, sslhnd
            )
        else:
            self.opener = urllib.request.build_opener(proxyhnd, sslhnd)

    def __enter__(self):
        self.open_output_file()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close_output_file()
        return False

    def open_output_file(self):
        filename = self.options.output_file
        if filename:
            self.output_file = open(filename, "w", encoding="utf-8")

    def close_output_file(self):
        if self.output_file is not None:
            try:
                self.output_file.flush()
                self.output_file.close()
            finally:
                self.output_file = None

    def log(self, string):
        if self.output_file is not None and not self.options.json_output:
            self.output_file.write(_strip_ansi_codes(string) + "\n")
        if not self.options.quiet:
            print(string)

    def banner(self):
        self.log("")
        self.log("======================================================")
        self.log(" > shcheck.py - santoru ..............................")
        self.log("------------------------------------------------------")
        self.log(" Simple tool to check security headers on a webserver ")
        self.log("======================================================")
        self.log("")

    def colorize(self, string, alert):
        if self.options.colours == "none" or alert not in self.theme:
            return string
        return self.theme[alert] + string + "\033[0m"

    def colorize_all(self, string, alert, keywords):
        if (
            self.options.colours == "none"
            or alert not in self.theme
            or not string
            or not keywords
        ):
            return string
        lstring = string.lower()
        c = self.theme[alert]
        for k in keywords:
            r = c + k + "\033[0m"
            p = lstring.find(k)
            while p >= 0:
                q = p + len(k)
                lstring = lstring[:p] + r + lstring[q:]
                string = string[:p] + r + string[q:]
                p = lstring.find(k, p + len(r))
        return string

    def print_error(self, target, e):
        if not self.options.quiet:
            if isinstance(e, ValueError):
                sys.stderr.write("Unknown URL type\n")

            elif isinstance(e, urllib.error.HTTPError):
                sys.stderr.write(
                    "[!] URL Returned an HTTP error: {}\n".format(
                        self.colorize(str(e.code), "error")
                    )
                )

            elif isinstance(e, urllib.error.URLError):
                if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
                    sys.stderr.write(
                        "SSL: Certificate validation error.\n"
                        'If you want to ignore it run the program with the "-d" option.\n'
                    )
                else:
                    sys.stderr.write(
                        "Target host {} seems to be unreachable ({})\n".format(
                            target, e.reason
                        )
                    )

            else:
                sys.stderr.write("{}\n".format(self.colorize(str(e))))

    def check_target(self, target, req_headers=None):
        response = None
        target = normalize(target)
        usemethod = self.options.usemethod
        request = urllib.request.Request(
            target, headers=req_headers or self.CLIENT_HEADERS
        )
        request.get_method = lambda: usemethod

        try:
            response = urllib.request.urlopen(request, timeout=10)
        except http.client.UnknownProtocol as e:
            if not self.options.quiet:
                sys.stderr.write(
                    "Unknown protocol: {}. Are you using a proxy? Try disabling it\n".format(
                        e
                    )
                )

        except Exception as e:
            self.print_error(target, e)
            if hasattr(e, "code") and e.code >= 400 and e.code < 500:
                response = e
            else:
                return None, None, None, None

        if response is not None:
            r_req, r_resp = None, None
            if self.options.capture:
                r_req = raw_request(request)
                r_resp = raw_response(response)
                if not self.options.quiet:
                    self.log("---")
                    self.log("HTTP Request:")
                    for line in r_req.decode("utf-8").splitlines():
                        self.log("\t" + line)
                    self.log("---")
                    self.log("HTTP Response:")
                    for line in r_resp.decode("utf-8").splitlines():
                        self.log("\t" + line)
                    self.log("---")
            return (
                response.geturl(),
                parse_headers(response.getheaders()),
                r_req,
                r_resp,
            )

        if not self.options.quiet:
            sys.stderr.write("Couldn't read a response from the server.\n")
        return None, None, None, None

    def analyze_headers(self, rUrl, headers):
        safe = 0
        unsafe = 0
        missing = 0
        leaks = 0
        deprecated = 0
        json_results = {}
        json_unsafe = {}
        json_results["present"] = {}
        json_results["missing"] = []
        json_results["unsafe"] = json_unsafe

        information = self.options.information
        cache_control = self.options.cache_control
        show_deprecated = self.options.show_deprecated
        if information:
            json_information_disclosure = {}
            json_results["information_disclosure"] = json_information_disclosure
        if show_deprecated:
            json_deprecated = {}
            json_results["deprecated"] = json_deprecated
        if cache_control:
            json_caching = {}
            json_results["caching"] = json_caching

        # Before analyzing, remove X-Frame-Options if there's CSP with frame-ancestors directive.
        target_sec_headers = dict(self.SECURITY_HEADERS)
        if "frame-ancestors" in headers.get("content-security-policy", "").lower():
            target_sec_headers.pop("X-Frame-Options", None)
            headers.pop("x-frame-options", None)

        # Analyze each security header.
        for safeh in target_sec_headers:
            lsafeh = safeh.lower()

            # If header is found...
            if lsafeh in headers:
                value = headers.get(lsafeh)
                lvalue = value.strip().lower().replace(" ", "")

                # Taking care of special headers that could have bad values:

                # Parse policy headers.
                if safeh in self.POLICY_HEADERS:
                    is_unsafe = False
                    unsafe_keywords = ["unsafe", "self"]
                    for keyword in unsafe_keywords:
                        if keyword in lvalue:
                            is_unsafe = True
                    if is_unsafe:
                        self.log(
                            "[!] Header {} is present but potentially unsafe!".format(
                                self.colorize(safeh, "warning")
                            )
                        )
                        self.log("Value:")
                        pvalue = self.colorize_all(value, "error", unsafe_keywords)
                        for line in pvalue.split(";"):
                            if line.strip():
                                self.log("\t" + line.strip() + ";")
                        json_unsafe[safeh] = value
                        unsafe += 1
                        continue

                # Check for max-age=0 in HSTS.
                elif lsafeh == "strict-transport-security" and "max-age=0" in lvalue:
                    self.log(
                        "[!] Insecure header {} is set! (Value: {})".format(
                            self.colorize(safeh, "warning"),
                            self.colorize(value, "error"),
                        )
                    )
                    json_unsafe[safeh] = value
                    unsafe += 1
                    continue

                # X-Frame-Options with ALLOW-FROM is deprecated.
                elif (
                    lsafeh == "x-frame-options"
                    and show_deprecated
                    and "allow-from" in lvalue
                ):
                    self.log(
                        "[!] Deprecated security header {} is present! (Value: {})".format(
                            self.colorize(safeh, "warning"),
                            self.colorize(value, "error"),
                        )
                    )
                    json_unsafe[safeh] = value
                    deprecated += 1
                    continue

                # Printing generic message if not specified above.
                self.log(
                    "[*] Header {} is present! (Value: {})".format(
                        self.colorize(safeh, "ok"), value
                    )
                )
                safe += 1
                json_results["present"][safeh] = value

            # If header is not found...
            else:
                # HSTS works obviously only on HTTPS.
                if lsafeh == "strict-transport-security" and not rUrl.startswith(
                    "https://"
                ):
                    continue

                # Printing generic message if not specified above.
                missing += 1
                json_results["missing"].append(safeh)
                self.log(
                    "[!] Security header missing: {}".format(
                        self.colorize(safeh, self.SECURITY_HEADERS.get(safeh))
                    )
                )

        # Report the use of deprecated security headers.
        # An empty dictionary represents the check was enabled but no results were found.
        for deph, goodval in self.DEPRECATED_HEADERS.items():
            ldeph = deph.lower()
            if ldeph in headers:
                value = headers.get(ldeph)
                if show_deprecated:
                    deprecated += 1
                    json_deprecated[deph] = value
                lvalue = value.strip().lower().replace(" ", "")
                if goodval and goodval in lvalue:
                    if show_deprecated:
                        self.log(
                            "[!] Deprecated security header {} is present! (Value: {})".format(
                                self.colorize(deph, "info"), value
                            )
                        )
                else:
                    self.log(
                        "[!] Deprecated security header {} is present! (Value: {})".format(
                            self.colorize(deph, "error"), value
                        )
                    )
                    unsafe += 1
                    json_unsafe[deph] = value

        # Report possible information disclosure headers.
        # These will need to be reviewed manually, since the value matters, not just its presence.
        if information:
            for infoh in self.INFORMATION_HEADERS:
                linfoh = infoh.lower()
                if linfoh in headers:
                    leaks += 1
                    value = headers.get(linfoh)
                    json_information_disclosure[infoh] = value
                    self.log(
                        "[!] Possible information disclosure: header {} is present! (Value: {})".format(
                            self.colorize(infoh, "warning"), value
                        )
                    )

        # Show cache control headers.
        if cache_control:
            for cacheh in self.CACHE_HEADERS:
                lcacheh = cacheh.lower()
                if lcacheh in headers:
                    value = headers.get(lcacheh)
                    json_caching[cacheh] = value
                    self.log(
                        "[!] Cache control header {} is present! (Value: {})".format(
                            self.colorize(cacheh, "info"), value
                        )
                    )

        self.log("-------------------------------------------------------")
        self.log(
            "[!] Headers analysis results for {}".format(self.colorize(rUrl, "info"))
        )
        self.log(
            "[+] {} security header(s) present and safe".format(
                self.colorize(str(safe), "ok" if safe else "error")
            )
        )
        self.log(
            "[-] {} security header(s) present but unsafe".format(
                self.colorize(str(unsafe), "error" if unsafe else "ok")
            )
        )
        self.log(
            "[-] {} security header(s) missing".format(
                self.colorize(str(missing), "error" if missing else "ok")
            )
        )
        if show_deprecated:
            self.log(
                "[-] {} deprecated security header(s) found".format(
                    self.colorize(str(deprecated), "info" if deprecated else "ok")
                )
            )
        if information:
            self.log(
                "[-] {} potential information disclosure header(s) found".format(
                    self.colorize(str(leaks), "info" if leaks else "ok")
                )
            )
        self.log("")

        return json_results

    @staticmethod
    def parse_options(argv):
        # Create an argument parser and give it more room if it fits the terminal size.
        term_width = shutil.get_terminal_size().columns
        parser = argparse.ArgumentParser(
            prog=argv[0],
            usage="%(prog)s [options] <targets...>",
            formatter_class=functools.partial(
                argparse.HelpFormatter,
                max_help_position=min(48, max(24, term_width // 3)),
                width=min(term_width - 2, 110),
            ),
        )

        # Register the command line arguments and options.
        parser.add_argument(
            "targets", nargs="*", metavar="target", help="target URL(s) to check"
        )
        parser.add_argument(
            "-p",
            "--port",
            dest="port",
            help="set a custom port to connect to",
            metavar="PORT",
        )
        parser.add_argument(
            "-c",
            "--cookie",
            dest="cookie",
            help="set cookies for the request",
            metavar="COOKIE_STRING",
        )
        parser.add_argument(
            "-a",
            "--add-header",
            dest="custom_headers",
            help="add headers for the request e.g. 'Header: value'",
            metavar="HEADER_STRING",
            action="append",
        )
        parser.add_argument(
            "-o",
            "--output",
            dest="output_file",
            default=False,
            help="save the output to this file",
            metavar="OUTPUT_FILE",
        )
        parser.add_argument(
            "-q",
            "--quiet",
            dest="quiet",
            default=False,
            help="suppress terminal output",
            action="store_true",
        )
        parser.add_argument(
            "-d",
            "--disable-ssl-check",
            dest="ssldisabled",
            default=False,
            help="disable SSL/TLS certificate validation",
            action="store_true",
        )
        parser.add_argument(
            "-m",
            "--use-method",
            dest="usemethod",
            default="HEAD",
            choices=["HEAD", "GET", "POST", "PUT", "DELETE", "TRACE"],
            help="use a specified method",
        )
        parser.add_argument(
            "-g",
            "--use-get-method",
            dest="usemethod",
            help="alias for -m GET",
            action="store_const",
            const="GET",
        )
        parser.add_argument(
            "-j",
            "--json-output",
            dest="json_output",
            default=False,
            help="print the output in JSON format",
            action="store_true",
        )
        parser.add_argument(
            "-i",
            "--information",
            dest="information",
            default=False,
            help="display information headers",
            action="store_true",
        )
        parser.add_argument(
            "-x",
            "--caching",
            dest="cache_control",
            default=False,
            help="display caching headers",
            action="store_true",
        )
        parser.add_argument(
            "-k",
            "--deprecated",
            dest="show_deprecated",
            default=False,
            help="display deprecated headers",
            action="store_true",
        )
        parser.add_argument(
            "-A",
            "--all",
            dest="all",
            default=False,
            help="display all supported checks (-i -x -k)",
            action="store_true",
        )
        parser.add_argument(
            "-r",
            "--raw",
            dest="capture",
            default=False,
            help="capture raw HTTP request and response",
            action="store_true",
        )
        parser.add_argument(
            "--proxy",
            dest="proxy",
            help="set a proxy (Ex: http://127.0.0.1:8080)",
            metavar="PROXY_URL",
        )
        parser.add_argument(
            "--hfile",
            dest="hfile",
            help="load a list of hosts from a flat file",
            metavar="PATH_TO_FILE",
        )
        parser.add_argument(
            "--colours",
            "--colors",
            dest="colours",
            help="set up a colour profile [dark/light/none]",
            default="dark",
        )
        parser.add_argument(
            "--no-follow",
            dest="no_follow",
            default=False,
            help="do not follow HTTP redirects (return 3xx response)",
            action="store_true",
        )

        # Parse the command line.
        args = parser.parse_args(argv[1:])
        targets = args.targets

        # Validate the format of the headers.
        custom_headers = args.custom_headers
        if custom_headers is not None:
            for header in custom_headers:
                header_split = header.split(": ", 1)
                if len(header_split) != 2:
                    sys.stderr.write(
                        "[!] Header strings must be of the format 'Header: value'\n"
                    )
                    sys.exit(1)

        # Add targets from a text file if requested.
        if len(targets) < 1 and args.hfile is None:
            parser.print_help()
            sys.exit(12)
        if args.hfile is not None:
            with open(args.hfile) as f:
                targets.extend(f.read().splitlines())

        # Normalize all targets.
        targets = [normalize(t) for t in targets]

        # Hardwire the port if requested.
        port = args.port
        if port is not None:
            targets = [append_port(t, port) for t in targets]

        # Remove duplicate targets without losing the original order.
        targets = list(dict.fromkeys(targets))

        # Alias for "all extra checks".
        if args.all:
            args.information = True
            args.cache_control = True
            args.show_deprecated = True

        # The --quiet flag is ignored (or forced) when nonsensical not to do so.
        if not (args.json_output or args.output_file):
            args.quiet = False
        else:
            args.quiet = args.quiet or (args.json_output and not args.output_file)

        # Return the processed options and list of targets.
        return args, targets

    def run(self, targets):
        cookie = self.options.cookie
        custom_headers = self.options.custom_headers
        output_file = self.options.output_file

        # Print banner.
        self.banner()

        # Set cookie if provided.
        req_headers = dict(self.CLIENT_HEADERS)
        if cookie is not None:
            req_headers["Cookie"] = cookie

        # Set custom headers if provided.
        if custom_headers is not None:
            for header in custom_headers:
                header_split = header.split(": ", 1)
                req_headers[header_split[0]] = header_split[1]

        # Scan all targets in order.
        json_out = {}
        for target in targets:
            self.log(
                "[*] Analyzing headers of {}".format(self.colorize(target, "info"))
            )

            # Check if target is valid.
            rUrl, headers, r_req, r_resp = self.check_target(target, req_headers)
            if not rUrl:
                continue
            if rUrl != target:
                self.log("[*] Effective URL: {}".format(self.colorize(rUrl, "info")))

            # Analyze the headers.
            json_out[rUrl] = self.analyze_headers(rUrl, headers)
            if r_req:
                json_out[rUrl]["request"] = base64.b64encode(r_req).decode()
            if r_resp:
                json_out[rUrl]["response"] = base64.b64encode(r_resp).decode()

        # Write the JSON output if requested.
        if self.options.json_output:
            if output_file:
                json.dump(json_out, self.output_file)
            else:
                print(json.dumps(json_out))


def main(argv):
    options, targets = Scanner.parse_options(argv)
    with Scanner(options) as scanner:
        scanner.run(targets)


if __name__ == "__main__":
    main(sys.argv)
