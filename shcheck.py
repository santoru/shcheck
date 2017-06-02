#!/usr/bin/env python

import urllib2
import socket
import sys
from optparse import OptionParser

parser = OptionParser("Usage: %prog [options] <target>", prog=sys.argv[0])
parser.add_option("-p", "--port", dest="port",
                  help="Set a custom port to connect to", metavar="PORT")
parser.add_option("-i", "--information", dest="information", default=False,
                  help="Display present information headers",
                  action="store_true")
(options, args) = parser.parse_args()


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


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
headers = {}


def banner():
    print
    print "======================================================="
    print " > safetycheck.py by @m3liot..........................."
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


def check_target(target):
    '''
    Just put a protocol to a valid IP and check if connection works
    '''

    try:
        if (socket.inet_aton(target)):
            target = 'http://' + target
    except (ValueError, socket.error):
        pass

    try:
        request = urllib2.Request(target)
        request.get_method = lambda: 'HEAD'
        response = urllib2.urlopen(request, timeout=10)
    except ValueError:
        print "Unknown url type"
        sys.exit(5)
    except urllib2.URLError:
        print "Target host seems to be unreachable"
        sys.exit(4)
    return response


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


def main(argv):
    if len(argv) < 2:
        parser.print_help()
        sys.exit(1)

    # Getting options
    port = options.port
    information = options.information

    banner()
    target = argv[1]
    safe = 0
    unsafe = 0

    if port is not None:
        target = append_port(target, port)

    # Check if target is valid
    response = check_target(target)
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
        chk = False
        print
        for infoh in information_headers:
            if infoh in headers:
                chk = True
                print "[!] Possible information disclosure: \
header {} is present! (Value: {})".format(
                        colorize(infoh, 'warning'),
                        headers.get(infoh))
        if not chk:
            print "[*] No information disclosure headers detected"

    report(target, safe, unsafe)


if __name__ == "__main__":
    main(sys.argv)
