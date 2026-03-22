#!/usr/bin/env python3
#
# mkdns.py - generates output for input to nsupdate
#  making it easy to update dynamic dns
#
# created March 22, 2026 by Robert Patrick;
#  based on 2012 Perl script, mkdns
#  ported in partnership with AI
#
# mkdns.py is a Python 3.12+ port of mkdns.pl
#
# accepts input list of hostnames with IPv4 or IPv6 addresses
#  supported formats: special inventory, basic csv, host=ip
#   appends a domain suffix to hostnames, if needed
#    generating both forward and reverse updates
#
# requires only Python 3.12+ stdlib (ipaddress, argparse, subprocess)
#
### This is free and unencumbered software released into the public domain.
###
### Anyone is free to copy, modify, publish, use, compile, sell, or
### distribute this software, either in source code form or as a compiled
### binary, for any purpose, commercial or non-commercial, and by any
### means.
###
### In jurisdictions that recognize copyright laws, the author or authors
### of this software dedicate any and all copyright interest in the
### software to the public domain. We make this dedication for the benefit
### of the public at large and to the detriment of our heirs and
### successors. We intend this dedication to be an overt act of
### relinquishment in perpetuity of all present and future rights to this
### software under copyright law.
###
### THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
### EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
### MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
### IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
### OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
### ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
### OTHER DEALINGS IN THE SOFTWARE.
#
#
# Example usage:
#
# echo "site,bldg,hostname,1.2.3.4,other.info" | mkdns.py | nsupdate
#
# echo "hostname,1.2.3.4" | mkdns.py --nsupdate
#
# mkdns.py < list | nsupdate
#
# mkdns.py --ns < list
#
# mkdns.py --ns --host "foo=1.2.3.4" --host "bar=2.3.4.5"
#
# mkdns.py --ns "foo=1.2.3.4" "bar,2.3.4.5"
#
# rmdns.py --ns "foo=1.2.3.4"

import os
import re
import sys
import shlex
import subprocess
import ipaddress
import argparse
from pathlib import Path

VERSION = '2026.03.22-py'

DNS_SERVER = 'authoritative-dns-server-name-or-ip'  # send dynamic dns updates to this server
DOMAIN     = 'example.com'                           # default domain suffix if none present for hostnames
NSUPDATE   = '/usr/bin/nsupdate -v -t 30'            # location and args for nsupdate
TTL        = 3600


def check_ip(hostname: str, ip_address: str) -> tuple:
    """Validate IP address, handle swapped host/IP order, compute reverse PTR.

    Returns (hostname, ip_str, reverse_ip, version) where ip_str uses
    expanded notation (matching Net::IP ->ip() output) and reverse_ip has
    a trailing dot.  Returns ('', '', '', None) on failure.
    """
    ip_obj = None

    # Try ip_address first; if invalid, try swapping with hostname
    for h, candidate in [(hostname, ip_address), (ip_address, hostname)]:
        try:
            ip_obj = ipaddress.ip_address(candidate.strip())
            hostname, ip_address = h, candidate
            break
        except ValueError:
            continue

    if ip_obj is None:
        return ('', '', '', None)

    # Use exploded form to match Net::IP's ->ip() output:
    #   IPv4: '1.2.3.4'  (identical to str())
    #   IPv6: '2001:0db8:0000:0000:0000:0000:0000:0001'
    ip_str = ip_obj.exploded

    # reverse_pointer omits trailing dot; Net::IP->reverse_ip() includes it
    reverse_ip = ip_obj.reverse_pointer + '.'

    return (hostname.strip(), ip_str, reverse_ip, ip_obj.version)


def output(string: str, state: dict) -> None:
    if state['debug'] or not state['nsupdate_fh']:
        sys.stdout.write(string)
    if state['nsupdate_fh'] and not state['testmode']:
        state['nsupdate_fh'].write(string)


def process_input(line: str, state: dict, counter: int) -> None:
    line = str(line).rstrip('\n')
    line = re.sub(r'^[!#].*', '', line)   # strip comment lines starting with ! or #
    line = re.sub(r'#.*',     '', line)   # strip inline # comments
    line = line.strip()
    line = re.sub(r'\s+',  ' ', line)    # collapse whitespace
    line = re.sub(r',\s',  ',', line)    # comma+space  → comma
    line = re.sub(r'\s,',  ',', line)    # space+comma  → comma

    if not line:
        return

    if ',' not in line:
        # no comma: convert first = or | or spaces to commas
        line = re.sub(r'\s',  ',', line)           # spaces      → commas
        line = re.sub(r'=',   ',', line, count=1)  # first =     → comma
        line = re.sub(r'\|',  ',', line, count=1)  # first |     → comma

    field_count = line.count(',')
    if not field_count:
        return

    if field_count <= 2:
        # basic csv: hostname,ip[,extra]
        parts = line.split(',', 2)
        hostname, ip = parts[0], parts[1]
    elif field_count >= 3:
        # inventory format: site,bldg,hostname,ip[,extra]
        parts = line.split(',', 4)
        hostname, ip = parts[2], parts[3]
    else:
        sys.stderr.write(f"{state['scriptname']}: illegal record at {counter}\n")
        return

    hostname, ip, reverse_ip, ip_version = check_ip(hostname, ip)
    if not ip:
        sys.stderr.write(f"{state['scriptname']}: illegal ip address input at {counter}\n")
        return

    if state['drop_suffix']:
        hostname = hostname.split('.')[0]
        hostname = (hostname + '.' + state['domain'] + '.').lower()
    else:
        if '.' not in hostname:
            hostname = hostname + '.' + state['domain']
        hostname = hostname.lower()

    record_type = 'a' if ip_version == 4 else 'aaaa'
    ttl = state['ttl']

    if state['do_a']:
        if state['del_any_a']:
            output(f"update delete {hostname} {record_type}\n", state)
        if not state['remove_records']:
            output(f"update add {hostname} {ttl} {record_type} {ip}\n", state)
        if state['debug'] >= 2 or (state['debug'] and not state['nsupdate_fh']):
            output("show\n", state)
        output("send\n", state)

    if state['do_ptr']:
        output(f"update delete {reverse_ip}\n", state)
        if not state['remove_records']:
            output(f"update add {reverse_ip} {ttl} ptr {hostname}\n", state)
        if state['debug'] >= 2 or (state['debug'] and not state['nsupdate_fh']):
            output("show\n", state)
        output("send\n", state)


def print_version(scriptname: str) -> None:
    print(f"{scriptname} version {VERSION}")


def print_usage(scriptname: str, dns_server: str, domain: str) -> None:
    print(f"""\
This software is especially flammable and comes with ABSOLUTELY NO WARRANTY.
You're likely to crash and burn, corrupting customer DNS data, so stop now!
Danger ahead.  Proceed at your own risk.

This script is designed for automating updates to Dynamic DNS records.

Usage:
{scriptname} [OPTIONS] --host "host1=1.2.3.4" --host "host2=2001:db8::123"
{scriptname} [OPTIONS] "host1=1.2.3.4" "host2=2001:db8::123" "host3,4.5.6.7"

  or pipe input via STDIN

{scriptname} < input.file

Options
 -d, --debug        display increasingly verbose debug output
 -t, --test         enables test mode, negates output to nsupdate
 -n, --nsupdate     enables direct nsupdate access
 --server=SERVER    define server for DDNS update (default = {dns_server})
 --domain=DOMAIN    define default domain (default = {domain})

 -dd, --dropdomain  discards domain suffixes, forces default domain
 -noa               avoid updating A or AAAA forward records
 -noptr             avoid updating PTR reverse records

 -nodeletea         allows multiple addresses per A or AAAA record

 -remove            enable removal mode, deleting DDNS records
""")


def build_parser(scriptname: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=scriptname, add_help=False)

    parser.add_argument('-d', '--debug', action='count', default=0)
    # Bug fix vs Perl: -t/--test were documented but only --testmode was registered
    parser.add_argument('-t', '--test', '--testmode', dest='testmode',
                        action='store_true', default=False)
    parser.add_argument('-n', '--ns', '--nsupdate', dest='use_nsupdate',
                        action='store_true', default=False)
    parser.add_argument('--server',  default=DNS_SERVER)
    parser.add_argument('--domain',  default=DOMAIN)
    parser.add_argument('-dd', '--dropdomain', dest='drop_suffix',
                        action='store_true', default=False)
    parser.add_argument('--remove', dest='remove_records',
                        action='store_true', default=False)

    # PTR record control (mirrors Perl's --ptr! / --noptr)
    parser.add_argument('--noptr', dest='do_ptr', action='store_false')
    parser.add_argument('--ptr',   dest='do_ptr', action='store_true')
    parser.set_defaults(do_ptr=True)

    # A/AAAA record control (mirrors Perl's --a|--aaaa! / --noa)
    parser.add_argument('--noa', '--noaaaa', dest='do_a', action='store_false')
    parser.add_argument('--a',   '--aaaa',   dest='do_a', action='store_true')
    parser.set_defaults(do_a=True)

    # delete-before-add control (mirrors Perl's --deletea! / --nodeletea)
    parser.add_argument('--nodeletea', dest='del_any_a', action='store_false')
    parser.add_argument('--deletea',   dest='del_any_a', action='store_true')
    parser.set_defaults(del_any_a=True)

    # --host accepts "hostname=ip" or "hostname,ip" strings (same as Perl -host)
    parser.add_argument('--host', action='append', default=[], metavar='HOST=IP')

    parser.add_argument('-h', '--help', dest='show_help',
                        action='store_true', default=False)
    parser.add_argument('--version', action='version',
                        version=f'{scriptname} version {VERSION}')

    # positional: bare host=ip or host,ip arguments on the command line
    parser.add_argument('hosts', nargs='*', metavar='HOST')

    return parser


def main() -> None:
    scriptname = Path(sys.argv[0]).name
    parser = build_parser(scriptname)
    opts = parser.parse_args()

    if opts.show_help:
        print_usage(scriptname, DNS_SERVER, DOMAIN)
        sys.exit(0)

    # Auto-enable remove mode when invoked as rmdns (or rmdns.py)
    remove_records = opts.remove_records or bool(re.search(r'rmdns', scriptname))

    nsupdate_proc = None
    nsupdate_fh   = None

    if opts.use_nsupdate:
        exec_path = shlex.split(NSUPDATE)[0]
        if os.path.isfile(exec_path) and os.access(exec_path, os.X_OK):
            if opts.debug:
                sys.stderr.write(
                    "\n*** calling nsupdate directly, "
                    "do not pipe this output to nsupdate manually ***\n\n"
                )
            nsupdate_proc = subprocess.Popen(
                shlex.split(NSUPDATE), stdin=subprocess.PIPE, text=True
            )
            nsupdate_fh = nsupdate_proc.stdin
        else:
            sys.stderr.write(f"{scriptname}: error accessing file ({NSUPDATE})\n")
            sys.exit(255)

    state = {
        'debug':          opts.debug,
        'testmode':       opts.testmode,
        'nsupdate_fh':    nsupdate_fh,
        'domain':         opts.domain,
        'drop_suffix':    opts.drop_suffix,
        'remove_records': remove_records,
        'do_ptr':         opts.do_ptr,
        'do_a':           opts.do_a,
        'del_any_a':      opts.del_any_a,
        'ttl':            TTL,
        'scriptname':     scriptname,
    }

    if opts.debug >= 3:
        print("*** begin show cli input ***")
        print(f" debug       = {state['debug']}")
        print(f" test mode   = {state['testmode']}")
        print(f" nsupdate    = {opts.use_nsupdate}")
        print(f" server      = {opts.server}")
        print(f" domain      = {state['domain']}")
        print(f" drop domain = {state['drop_suffix']}")
        print(f" remove mode = {state['remove_records']}")
        print(f" delete a    = {state['del_any_a']}")
        print(f" do ptr      = {state['do_ptr']}")
        print(f" do a        = {state['do_a']}")
        for arg in opts.hosts:
            print(f" extra: {arg}")
        print("*** end show cli input ***")

    output(f"server {opts.server}\n", state)

    counter = 0

    if opts.hosts or opts.host:
        for arg in opts.hosts:
            counter += 1
            process_input(arg, state, counter)
        for host_entry in opts.host:
            counter += 1
            process_input(host_entry, state, counter)
    else:
        for line in sys.stdin:
            counter += 1
            process_input(line, state, counter)

    if nsupdate_fh:
        try:
            nsupdate_fh.close()
            nsupdate_proc.wait()
            if nsupdate_proc.returncode:
                sys.stderr.write(
                    f"{scriptname}: error encountered while running "
                    f"nsupdate ({nsupdate_proc.returncode})\n"
                )
        except Exception:
            pass


if __name__ == '__main__':
    main()
