#!/usr/bin/env python

# shcheck - Security Headers checks!
# Copyright (C) 2017  m3liot
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


import urllib2
import socket
import sys
import ssl
from optparse import OptionParser

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Client headers to send to the server during the request.
client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0)\
Gecko/20100101 Firefox/53.0',
    'Accept': 'text/html,application/xhtml+xml,\
application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US;q=0.8,en;q=0.3',
    'Upgrade-Insecure-Requests': 1
 }


# Security headers that should be enabled
sec_headers = {
    'X-XSS-Protection': 'warning',
    'X-Frame-Options': 'warning',
    'X-Content-Type-Options': 'warning',
    'Strict-Transport-Security': 'error',
    'Public-Key-Pins': 'none',
    'Content-Security-Policy': 'warning',
    'X-Permitted-Cross-Domain-Policies': 'warning',
    'Referrer-Policy': 'warning'

}

information_headers = {
    'X-Powered-By',
    'Server'
}

cache_headers = {
    'Cache-Control',
    'Pragma',
    'Last-Modified'
    'Expires',
    'ETag'
}

headers = {}


def banner():
    print
    print "======================================================="
    print " > shcheck.py - m3liot................................."
    print "-------------------------------------------------------"
    print " Simple tool to check security headers on a webserver "
    print "======================================================="
    print


def colorize(string, alert):
    if alert == 'error':
        return bcolors.FAIL + string + bcolors.ENDC
    elif alert == 'warning':
        return bcolors.WARNING + string + bcolors.ENDC
    elif alert == 'ok':
        return bcolors.OKGREEN + string + bcolors.ENDC
    elif alert == 'info':
        return bcolors.OKBLUE + string + bcolors.ENDC
        return string
    return string


def parse_headers(hdrs):
    for header in hdrs:
        htype = header.split(':')[0].strip()
        hvalue = header.split(':')[1].strip()
        headers.update({htype: hvalue})


def append_port(target, port):
    if target[-1:] == '/':
        return target[:-1] + ':' + port + '/'
    return target + ':' + port + '/'


def check_target(target, ssldisabled, useget):
    '''
    Just put a protocol to a valid IP and check if connection works,
    returning HEAD response
    '''
    response = None

    try:
        if (socket.inet_aton(target)):
            target = 'http://' + target
    except (ValueError, socket.error):
        pass

    try:

        if useget:
            method = 'GET'
        else:
            method = 'HEAD'

        request = urllib2.Request(target, headers=client_headers)
        request.get_method = lambda: method

        if ssldisabled:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            response = urllib2.urlopen(request, timeout=10, context=context)
        else:
            response = urllib2.urlopen(request, timeout=10)

    except ValueError:
        print "Unknown url type"
        sys.exit(5)
    except urllib2.HTTPError as e:
        print "[!] URL Returned an HTTP error: {}".format(
            colorize(str(e.code), 'error'))
        response = e
    except urllib2.URLError, e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
            print "SSL: Certificate validation error.\nIf you want to \
ignore it run the program with the \"-d\" option."
        else:
            print "Target host seems to be unreachable"
        sys.exit(4)

    if response is not None:
        return response
    print "Couldn't read a response from server."
    sys.exit(3)


def check_https(target):
    '''
    Check if target support HTTPS for Strict-Transport-Security
    '''
    return target.startswith('https://')


def report(target, safe, unsafe):
    print "-------------------------------------------------------"
    print "[!] Headers analyzed for {}".format(colorize(target, 'info'))
    print "[+] There are {} security headers".format(colorize(str(safe), 'ok'))
    print "[-] There are not {} security headers".format(
        colorize(str(unsafe), 'error'))
    print


def main(options, args):
    # Getting options
    port = options.port
    cookie = options.cookie
    information = options.information
    ssldisabled = options.ssldisabled
    useget = options.useget
    cache_control = options.cache_control

    banner()
    targets = args                                                                 

    # Set a custom port if provided
    if port is not None:
        target = append_port(target, port)

    # Set cookies for the request
    if cookie is not None:
        client_headers.update({'Cookie': cookie})

    for target in targets:
        safe = 0
        unsafe = 0

        # Check if target is valid
        response = check_target(target, ssldisabled, useget)
        rUrl = response.geturl()

        print "[*] Analyzing headers of {}".format(colorize(target, 'info'))
        print "[*] Effective URL: {}".format(colorize(rUrl, 'info'))
        parse_headers(response.info().headers)

        for safeh in sec_headers:
            if safeh in headers:
                safe += 1

                # Taking care of special headers that could have bad values

                # X-XSS-Protection Should be enabled
                if safeh == 'X-XSS-Protection' and headers.get(safeh) == '0':
                    print "[*] Header {} is present! (Value: {})".format(
                            colorize(safeh, 'ok'),
                            colorize(headers.get(safeh), 'warning'))

                # Printing generic message if not specified above
                else:
                    print "[*] Header {} is present! (Value: {})".format(
                            colorize(safeh, 'ok'),
                            headers.get(safeh))
            else:
                unsafe += 1

                # HSTS works obviously only on HTTPS
                if safeh == 'Strict-Transport-Security' and not check_https(rUrl):
                    unsafe -= 1
                    continue
                print '[!] Missing security header: {}'.format(
                    colorize(safeh, sec_headers.get(safeh)))

        if information:
            i_chk = False
            print
            for infoh in information_headers:
                if infoh in headers:
                    i_chk = True
                    print "[!] Possible information disclosure: \
header {} is present! (Value: {})".format(
                            colorize(infoh, 'warning'),
                            headers.get(infoh))
            if not i_chk:
                print "[*] No information disclosure headers detected"

        if cache_control:
            c_chk = False
            print
            for cacheh in cache_headers:
                if cacheh in headers:
                    c_chk = True
                    print "[!] Cache control header {} is present! \
Value: {})".format(
                            colorize(cacheh, 'info'),
                            headers.get(cacheh))
            if not c_chk:
                print "[*] No caching headers detected"

        report(rUrl, safe, unsafe)


if __name__ == "__main__":

    parser = OptionParser("Usage: %prog [options] <target>", prog=sys.argv[0])

    parser.add_option("-p", "--port", dest="port",
                      help="Set a custom port to connect to", metavar="PORT")
    parser.add_option("-c", "--cookie", dest="cookie",
                      help="Set cookies for the request", metavar="COOKIE_STRING")
    parser.add_option('-d', "--disable-ssl-check", dest="ssldisabled",
                      default=False, help="Disable SSL/TLS certificate validation",
                      action="store_true")
    parser.add_option('-g', "--use-get-method", dest="useget",
                      default=False, help="Use GET method instead HEAD method",
                      action="store_true")
    parser.add_option("-i", "--information", dest="information", default=False,
                      help="Display information headers",
                      action="store_true")
    parser.add_option("-x", "--caching", dest="cache_control", default=False,
                      help="Display caching headers",
                      action="store_true")
    
    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(1)
    main(options, args)
