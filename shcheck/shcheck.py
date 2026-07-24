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
import urllib.parse
import http.client
import socket
import sys
import ssl
import json
import argparse
import re


def _make_colours(warning):
    class _C:
        OKBLUE  = '\033[94m'
        OKGREEN = '\033[92m'
        FAIL    = '\033[91m'
        ENDC    = '\033[0m'
        WARNING = warning
    return _C

darkcolours  = _make_colours('\033[93m')
lightcolours = _make_colours('\033[95m')


def _strip_ansi_codes(string):
    return re.sub(r'\x1b\[[0-9;]*m', '', string)


# log - prints unless JSON output is set
def log(string, output_file=None):
    if options.json_output:
        return
    if output_file:
        output_file.write(_strip_ansi_codes(string) + "\n")
    print(string)


# Client headers to send to the server during the request.
client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)\
 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,\
 application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US;q=0.8,en;q=0.3',
    'Upgrade-Insecure-Requests': '1'
 }


# Security headers that should be enabled
sec_headers = {
    'X-XSS-Protection': 'deprecated',
    'X-Frame-Options': 'warning',
    'X-Content-Type-Options': 'warning',
    'Strict-Transport-Security': 'error',
    'Content-Security-Policy': 'warning',
    'X-Permitted-Cross-Domain-Policies': 'deprecated',
    'Referrer-Policy': 'warning',
    'Expect-CT': 'deprecated',
    'Permissions-Policy': 'warning',
    'Cross-Origin-Embedder-Policy': 'warning',
    'Cross-Origin-Resource-Policy': 'warning',
    'Cross-Origin-Opener-Policy': 'warning'
}

information_headers = {
    'X-Powered-By',
    'Server',
    'X-AspNet-Version',
    'X-AspNetMvc-Version'
}

cache_headers = {
    'Cache-Control',
    'Pragma',
    'Last-Modified',
    'Expires',
    'ETag'
}

options = None


def banner():
    log("")
    log("======================================================")
    log(" > shcheck.py - santoru ..............................")
    log("------------------------------------------------------")
    log(" Simple tool to check security headers on a webserver ")
    log("======================================================")
    log("")


def colorize(string, alert):
    bcolors = darkcolours
    if options.colours == "light":
        bcolors = lightcolours
    elif options.colours == "none":
        return string
    color = {
        'error':    bcolors.FAIL + string + bcolors.ENDC,
        'warning':  bcolors.WARNING + string + bcolors.ENDC,
        'ok':       bcolors.OKGREEN + string + bcolors.ENDC,
        'info':     bcolors.OKBLUE + string + bcolors.ENDC,
        'deprecated': string # No color for deprecated headers or not-an-issue ones
    }
    return color[alert] if alert in color else string


def parse_headers(hdrs):
    return {x.lower(): y for x, y in hdrs}


def append_port(target, port):
    if target[-1:] == '/':
        return target[:-1] + ':' + port + '/'
    return target + ':' + port


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


def build_opener(proxy, ssldisabled, nofollow=False):
    proxyhnd = urllib.request.ProxyHandler()
    sslhnd = urllib.request.HTTPSHandler()
    if proxy:
        proxyhnd = urllib.request.ProxyHandler({
            'http':  proxy,
            'https': proxy
        })
    if ssldisabled:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sslhnd = urllib.request.HTTPSHandler(context=ctx)

    if nofollow:
        opener = urllib.request.build_opener(NoRedirectHandler(), proxyhnd, sslhnd)
    else:
        opener = urllib.request.build_opener(proxyhnd, sslhnd)
    urllib.request.install_opener(opener)


def normalize(target):
    try:
        socket.inet_aton(target)
        target = 'http://' + target
    except (ValueError, socket.error):
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
    return target


def print_error(target, e):
    if isinstance(e, ValueError):
        sys.stderr.write("Unknown url type\n")

    elif isinstance(e, urllib.error.HTTPError):
        sys.stderr.write("[!] URL Returned an HTTP error: {}\n".format(
              colorize(str(e.code), 'error')))

    elif isinstance(e, urllib.error.URLError):
        if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
            sys.stderr.write(
                "SSL: Certificate validation error.\n"
                "If you want to ignore it run the program with the \"-d\" option.\n"
            )
        else:
            sys.stderr.write("Target host {} seems to be unreachable ({})\n".format(target, e.reason))

    else:
        sys.stderr.write("{}\n".format(str(e)))


def check_target(target, req_headers=None, usemethod='HEAD'):
    '''
    Normalize the target URL and perform an HTTP request, returning the
    response object, or None if the target is unreachable.
    '''
    response = None

    target = normalize(target)

    request = urllib.request.Request(target, headers=req_headers or client_headers)
    request.get_method = lambda: usemethod

    try:
        response = urllib.request.urlopen(request, timeout=10)

    # Handling issues with HTTP/2
    except http.client.UnknownProtocol as e:
        sys.stderr.write("Unknown protocol: {}. Are you using a proxy? Try disabling it\n".format(e))
    except Exception as e:
        print_error(target, e)
        if hasattr(e, 'code') and e.code >= 400 and e.code < 500:
            response = e
        else:
            return None

    if response is not None:
        return response
    sys.stderr.write("Couldn't read a response from server.\n")
    return None


def report(target, safe, unsafe, output_file):
    log("-------------------------------------------------------", output_file)
    log("[!] Analyzing headers for {}".format(colorize(target, 'info')), output_file)
    log("[+] {} security header(s) present".format(colorize(str(safe), 'ok')), output_file)
    log("[-] {} security header(s) missing".format(
            colorize(str(unsafe), 'error')),
        output_file=output_file)
    log("", output_file)


def parse_csp(csp):
    unsafe_operators = ['unsafe-inline', 'unsafe-eval', 'unsafe-hashes', 'wasm-unsafe-eval', 'self']
    log("Value:")
    policy_directive = csp.split(";")
    for policy in policy_directive:
        elements = policy.lstrip().split(" ", 1)

        values = elements[1].replace("*", colorize("*", 'warning')) if len(elements) > 1 else ""
        for x in unsafe_operators:
            values = values.replace(x, colorize(x, 'error'))
        log("\t" + colorize(elements[0], 'info') + (": " + values if values != "" else ""))


def parse_options():
    parser = argparse.ArgumentParser(
        prog=sys.argv[0],
        usage="%(prog)s [options] <target>",
    )

    parser.add_argument("targets", nargs="*", metavar="target",
                        help="Target URL(s) to check")
    parser.add_argument("-p", "--port", dest="port",
                        help="Set a custom port to connect to",
                        metavar="PORT")
    parser.add_argument("-c", "--cookie", dest="cookie",
                        help="Set cookies for the request",
                        metavar="COOKIE_STRING")
    parser.add_argument("-a", "--add-header", dest="custom_headers",
                        help="Add headers for the request e.g. 'Header: value'",
                        metavar="HEADER_STRING", action="append")
    parser.add_argument("-o" , "--output", dest="output_file", default=False,
                        help="Save the output to this file",
                        metavar="OUTPUT_FILE")
    parser.add_argument('-d', "--disable-ssl-check", dest="ssldisabled",
                        default=False,
                        help="Disable SSL/TLS certificate validation",
                        action="store_true")
    parser.add_argument('-g', "--use-get-method", dest="useget",
                        default=False, help="Use GET method instead HEAD method",
                        action="store_true")
    parser.add_argument('-m', "--use-method", dest="usemethod", default='HEAD',
                        choices=["HEAD", "GET", "POST", "PUT", "DELETE", "TRACE"],
                        help="Use a specified method")
    parser.add_argument("-j", "--json-output", dest="json_output",
                        default=False, help="Print the output in JSON format",
                        action="store_true")
    parser.add_argument("-i", "--information", dest="information", default=False,
                        help="Display information headers",
                        action="store_true")
    parser.add_argument("-x", "--caching", dest="cache_control", default=False,
                        help="Display caching headers",
                        action="store_true")
    parser.add_argument("-k", "--deprecated", dest="show_deprecated", default=False,
                        help="Display deprecated headers",
                        action="store_true")
    parser.add_argument("--proxy", dest="proxy",
                        help="Set a proxy (Ex: http://127.0.0.1:8080)",
                        metavar="PROXY_URL")
    parser.add_argument("--hfile", dest="hfile",
                        help="Load a list of hosts from a flat file",
                        metavar="PATH_TO_FILE")
    parser.add_argument("--colours", "--colors", dest="colours",
                        help="Set up a colour profile [dark/light/none]",
                        default="dark")
    parser.add_argument("--no-follow", dest="no_follow", default=False,
                        help="Do not follow HTTP redirects (return 3xx response)",
                        action="store_true")

    args = parser.parse_args()
    if args.useget:
        args.usemethod = 'GET'
    targets = args.targets

    if len(targets) < 1 and args.hfile is None:
        parser.print_help()
        sys.exit(12)

    return args, targets


def main():
    # Getting options
    global options
    options, targets = parse_options()

    port = options.port
    cookie = options.cookie
    custom_headers = options.custom_headers
    information = options.information
    cache_control = options.cache_control
    show_deprecated = options.show_deprecated
    hfile = options.hfile
    json_output = options.json_output
    output_file = options.output_file

    banner()
    req_headers = dict(client_headers)
    if cookie is not None:
        req_headers.update({'Cookie': cookie})

    # Set custom headers if provided
    if custom_headers is not None:
        for header in custom_headers:
            # Split supplied string of format 'Header: value'
            header_split = header.split(': ')
            # Add to existing headers using header name and header value
            try:
                req_headers.update({header_split[0]: header_split[1]})
            except IndexError:
                s = "[!] Header strings must be of the format 'Header: value'"
                print(s)
                raise SystemExit(1)

    if hfile is not None:
        with open(hfile) as f:
            targets = f.read().splitlines()

    build_opener(options.proxy, options.ssldisabled, options.no_follow)

    if output_file:
        # open and clear file to append logs
        output_file = open(output_file, "w", encoding="utf-8")

    json_out = {}
    for target in targets:
        json_headers = {}
        if port is not None:
            target = append_port(target, port)

        safe = 0
        unsafe = 0

        log("[*] Analyzing headers of {}".format(colorize(target, 'info')),
            output_file=output_file)

        # Check if target is valid
        response = check_target(target, req_headers, usemethod=options.usemethod)
        if not response:
            continue
        rUrl = response.geturl()
        json_results = {}

        log("[*] Effective URL: {}".format(colorize(rUrl, 'info')),
            output_file=output_file)
        headers = parse_headers(response.getheaders())
        json_headers[rUrl] = json_results
        json_results["present"] = {}
        json_results["missing"] = []

        # Before parsing, remove X-Frame-Options if there's CSP with frame-ancestors directive
        target_sec_headers = dict(sec_headers)
        if "content-security-policy" in headers and "frame-ancestors" in headers.get("content-security-policy").lower():
            target_sec_headers.pop("X-Frame-Options", None)
            headers.pop('x-frame-options', None)

        for safeh in target_sec_headers:
            lsafeh = safeh.lower()
            if lsafeh in headers:
                safe += 1
                json_results["present"][safeh] = headers.get(lsafeh)

                # Taking care of special headers that could have bad values

                # Parse CSP headers
                if lsafeh == 'content-security-policy':
                    log("[*] Header {} is present!".format(
                            colorize(safeh, 'ok')),
                        output_file=output_file)
                    parse_csp(headers.get(lsafeh))

                # X-XSS-Protection Should be enabled
                elif lsafeh == 'x-xss-protection' and headers.get(lsafeh) == '0':
                    log("[*] Header {} is present! (Value: {})".format(
                            colorize(safeh, 'ok'),
                            colorize(headers.get(lsafeh), 'warning')),
                        output_file=output_file)

                # unsafe-url policy is more insecure compared to the default/unset value
                elif lsafeh == 'referrer-policy' and headers.get(lsafeh) == 'unsafe-url':
                    log("[!] Insecure header {} is set! (Value: {})".format(
                            colorize(safeh, 'warning'),
                            colorize(headers.get(lsafeh), 'error')),
                        output_file=output_file)

                # check for max-age=0 in HSTS
                elif lsafeh == 'strict-transport-security' and "max-age=0" in headers.get(lsafeh):
                    log("[!] Insecure header {} is set! (Value: {})".format(
                            colorize(safeh, 'warning'),
                            colorize(headers.get(lsafeh), 'error')),
                        output_file=output_file)

                # Printing generic message if not specified above
                else:
                    log("[*] Header {} is present! (Value: {})".format(
                            colorize(safeh, 'ok'),
                            headers.get(lsafeh)),
                        output_file=output_file)
            else:
                unsafe += 1
                json_results["missing"].append(safeh)
                # HSTS works obviously only on HTTPS
                if lsafeh == 'strict-transport-security' and not rUrl.startswith('https://'):
                    unsafe -= 1
                    json_results["missing"].remove(safeh)
                    continue
                # Hide deprecated
                if not show_deprecated and target_sec_headers.get(safeh) == "deprecated":
                    unsafe -= 1
                    json_results["missing"].remove(safeh)
                    continue
                log('[!] Security header missing: {}'.format(
                        colorize(safeh, sec_headers.get(safeh))),
                    output_file=output_file)

        if information:
            json_results["information_disclosure"] = {}
            i_chk = False
            log("", output_file=output_file)
            for infoh in information_headers:
                linfoh = infoh.lower()
                if linfoh in headers:
                    json_results["information_disclosure"][infoh] = headers.get(linfoh)
                    i_chk = True
                    log("[!] Possible information disclosure: "
                        "header {} is present! (Value: {})".format(
                            colorize(infoh, 'warning'),
                            headers.get(linfoh),
                        output_file=output_file))
            if not i_chk:
                log("[*] No information disclosure headers detected",
                output_file=output_file)

        if cache_control:
            json_results["caching"] = {}
            c_chk = False
            log("", output_file=output_file)
            for cacheh in cache_headers:
                lcacheh = cacheh.lower()
                if lcacheh in headers:
                    json_results["caching"][cacheh] = headers.get(lcacheh)
                    c_chk = True
                    log("[!] Cache control header {} is present! "
                        "(Value: {})".format(
                            colorize(cacheh, 'info'),
                            headers.get(lcacheh)),
                        output_file=output_file)
            if not c_chk:
                log("[*] No caching headers detected",
                    output_file=output_file)

        report(rUrl, safe, unsafe, output_file)
        json_out.update(json_headers)

    if json_output:
        print(json.dumps(json_out))

    if output_file:
        if json_output:
            output_file.write(json.dumps(json_out, indent=4))
        output_file.close()


if __name__ == "__main__":
    main()
