#!/usr/bin/env python3
"""
test-mkdns.py - cross-implementation test suite for mkdns.pl and mkdns.py

Runs both scripts with identical inputs and compares normalized outputs.
A test passes only when both scripts produce the same result.

Usage:
  python3 test_mkdns.py            # run all tests
  python3 test_mkdns.py -v         # verbose: show output for each test
  python3 test_mkdns.py PATTERN    # run tests whose names contain PATTERN

Notes:
  - Both scripts must be in the same directory as this file, or set
    MKDNS_PERL and MKDNS_PY environment variables to override paths.
  - Tests always pass --server to avoid default-value mismatches
    (the Perl script has a typo in its default server constant).
  - IPv6 addresses in output are normalised to compressed form before
    comparison, so expanded (Net::IP) and compressed (Python) both pass.
"""

import difflib
import ipaddress
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Script locations
# ---------------------------------------------------------------------------
HERE        = Path(__file__).parent
PERL_SCRIPT = os.environ.get('MKDNS_PERL', str(HERE / 'mkdns.pl'))
PY_SCRIPT   = os.environ.get('MKDNS_PY',   str(HERE / 'mkdns.py'))

# Common flag passed to every test so server lines always match
DEFAULT_ARGS = ['--server', 'dns.test.local']


# ---------------------------------------------------------------------------
# Test case definition
# ---------------------------------------------------------------------------
@dataclass
class TestCase:
    name:        str
    stdin:       str | None = None   # None → no stdin (args-only)
    args:        list[str]  = field(default_factory=list)
    expect_fail: bool       = False  # set True if both scripts should error
    sort_output: bool       = False  # set True when record order is undefined
                                     # (e.g. multiple --host entries use a hash
                                     #  in Perl, so iteration order is not stable)


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------
TESTS: list[TestCase] = [
    # --- basic IPv4 ---
    TestCase('IPv4 basic csv via stdin',
             stdin='myhost,1.2.3.4'),
    TestCase('IPv4 basic csv via positional arg',
             args=['myhost,1.2.3.4']),
    TestCase('IPv4 via --host option',
             args=['--host', 'myhost=1.2.3.4']),
    TestCase('IPv4 equals separator on cmdline',
             args=['myhost=1.2.3.4']),
    TestCase('IPv4 pipe separator via stdin',
             stdin='myhost|1.2.3.4'),
    TestCase('IPv4 space separator via stdin',
             stdin='myhost 1.2.3.4'),
    TestCase('IPv4 swapped order (ip,host)',
             stdin='1.2.3.4,myhost'),

    # --- basic IPv6 ---
    TestCase('IPv6 compressed via stdin',
             stdin='myhost,2001:db8::1'),
    TestCase('IPv6 full expanded via stdin',
             stdin='myhost,2001:0db8:0000:0000:0000:0000:0000:0001'),
    TestCase('IPv6 loopback via stdin',
             stdin='myhost,::1'),
    TestCase('IPv6 via positional arg',
             args=['myhost,2001:db8::cafe']),
    TestCase('IPv6 swapped order (ip,host)',
             stdin='2001:db8::1,myhost'),

    # --- hostname domain handling ---
    TestCase('hostname without domain gets default appended',
             stdin='myhost,1.2.3.4'),
    TestCase('hostname with domain kept as-is',
             stdin='myhost.example.org,1.2.3.4'),
    TestCase('hostname uppercase lowercased',
             stdin='MYHOST,1.2.3.4'),

    # --- --dropdomain ---
    TestCase('--dropdomain strips existing suffix and adds default',
             stdin='myhost.other.com,1.2.3.4',
             args=['--dropdomain']),
    TestCase('--dropdomain with no suffix',
             stdin='myhost,1.2.3.4',
             args=['--dropdomain']),

    # --- --domain override ---
    TestCase('--domain overrides default',
             stdin='myhost,1.2.3.4',
             args=['--domain', 'test.local']),

    # --- input formats ---
    TestCase('inventory format (5 fields)',
             stdin='site1,bldg2,myhost,1.2.3.4,extra-info'),
    TestCase('inventory format IPv6',
             stdin='site1,bldg2,myhost,2001:db8::1,extra-info'),
    TestCase('basic csv with extra field',
             stdin='myhost,1.2.3.4,extra'),
    TestCase('multiple hosts via stdin',
             stdin='host1,1.2.3.4\nhost2,5.6.7.8'),
    TestCase('multiple IPv6 hosts via stdin',
             stdin='host1,2001:db8::1\nhost2,2001:db8::2'),

    # --- comment / whitespace handling ---
    TestCase('comment line starting with # is skipped',
             stdin='# this is a comment\nmyhost,1.2.3.4'),
    TestCase('comment line starting with ! is skipped',
             stdin='! this is a comment\nmyhost,1.2.3.4'),
    TestCase('inline # comment stripped',
             stdin='myhost,1.2.3.4 # inline comment'),
    TestCase('leading/trailing whitespace stripped',
             stdin='  myhost  ,  1.2.3.4  '),
    TestCase('blank lines skipped',
             stdin='\n\nmyhost,1.2.3.4\n\n'),

    # --- record-type flags ---
    TestCase('--noptr suppresses PTR records',
             stdin='myhost,1.2.3.4',
             args=['--noptr']),
    TestCase('--noptr with IPv6',
             stdin='myhost,2001:db8::1',
             args=['--noptr']),
    TestCase('--noa suppresses A records',
             stdin='myhost,1.2.3.4',
             args=['--noa']),
    TestCase('--noa with IPv6 suppresses AAAA records',
             stdin='myhost,2001:db8::1',
             args=['--noa']),
    TestCase('--noa and --noptr suppress all updates',
             stdin='myhost,1.2.3.4',
             args=['--noa', '--noptr']),

    # --- --nodeletea ---
    TestCase('--nodeletea omits delete-before-add for A',
             stdin='myhost,1.2.3.4',
             args=['--nodeletea']),
    TestCase('--nodeletea omits delete-before-add for AAAA',
             stdin='myhost,2001:db8::1',
             args=['--nodeletea']),

    # --- --remove mode ---
    TestCase('--remove deletes A and PTR, no add',
             stdin='myhost,1.2.3.4',
             args=['--remove']),
    TestCase('--remove with IPv6',
             stdin='myhost,2001:db8::1',
             args=['--remove']),
    TestCase('--remove with --noptr',
             stdin='myhost,1.2.3.4',
             args=['--remove', '--noptr']),

    # --- error / invalid input ---
    TestCase('invalid IP skipped, valid processed',
             stdin='bad,999.999.999.999\nvalid,1.2.3.4'),
    TestCase('lone hostname with no ip skipped',
             stdin='justahostname'),
    TestCase('empty line skipped',
             stdin=''),

    # --- multiple --host options ---
    # Perl stores --host values in a hash and iterates with each(), so order is
    # undefined.  Python preserves insertion order.  Both outputs are correct;
    # we sort lines before comparison to make this test order-independent.
    TestCase('multiple --host options',
             args=['--host', 'host1=1.2.3.4', '--host', 'host2=5.6.7.8'],
             sort_output=True),
    TestCase('mixed positional and --host',
             args=['--host', 'host1=1.2.3.4', 'host2,5.6.7.8']),
]


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
_IPV6_WORD = re.compile(
    r'\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b'
    r'|::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}'
    r'|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F:]*)?'
)


def _try_normalize_ipv6(token: str) -> str:
    """Return compressed IPv6 string if token is a valid IPv6 address, else unchanged."""
    try:
        return str(ipaddress.IPv6Address(token))
    except ValueError:
        return token


def normalize_output(raw: str, sort: bool = False) -> str:
    """Normalise output for Perl/Python comparison.

    - Strip trailing whitespace from each line
    - Normalise all IPv6 addresses to compressed form
      (Net::IP->ip() returns expanded; Python ipaddress.exploded also
       returns expanded, but this guard handles any future divergence)
    - If sort=True, sort all lines before comparing (used when Perl hash
      iteration produces records in an undefined order)
    """
    lines = []
    for line in raw.splitlines():
        line = line.rstrip()
        tokens = line.split()
        tokens = [_try_normalize_ipv6(t) for t in tokens]
        lines.append(' '.join(tokens))
    if sort:
        lines.sort()
    return '\n'.join(lines).strip()


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_script(interpreter: str, script: str, test: TestCase) -> tuple[str, str, int]:
    cmd = [interpreter, script] + DEFAULT_ARGS + test.args
    result = subprocess.run(
        cmd,
        input=test.stdin,
        capture_output=True,
        text=True,
    )
    return result.stdout, result.stderr, result.returncode


def run_tests(verbose: bool = False, pattern: str | None = None) -> bool:
    tests = TESTS
    if pattern:
        tests = [t for t in TESTS if pattern.lower() in t.name.lower()]
        if not tests:
            print(f"No tests match pattern: {pattern!r}")
            return False

    passed = failed = skipped = 0
    failures: list[str] = []

    print(f"Running {len(tests)} test(s) …\n")

    for test in tests:
        perl_out, perl_err, perl_rc = run_script('perl',    PERL_SCRIPT, test)
        py_out,   py_err,   py_rc   = run_script('python3', PY_SCRIPT,   test)

        perl_norm = normalize_output(perl_out, sort=test.sort_output)
        py_norm   = normalize_output(py_out,   sort=test.sort_output)

        if perl_norm == py_norm:
            status = 'PASS'
            passed += 1
        else:
            status = 'FAIL'
            failed += 1
            diff = ''.join(difflib.unified_diff(
                perl_norm.splitlines(keepends=True),
                py_norm.splitlines(keepends=True),
                fromfile='perl stdout',
                tofile='python stdout',
                n=3,
            ))
            failures.append(f"FAIL: {test.name}\n{diff}")

        mark = '✓' if status == 'PASS' else '✗'
        print(f"  {mark} {test.name}")

        if verbose or status == 'FAIL':
            if perl_norm:
                print(f"      perl  : {perl_norm!r:.120}")
            if py_norm:
                print(f"      python: {py_norm!r:.120}")
            if perl_err.strip():
                print(f"      perl stderr : {perl_err.strip()!r:.120}")
            if py_err.strip():
                print(f"      py   stderr : {py_err.strip()!r:.120}")

    print(f"\n{'─'*50}")
    print(f"Results: {passed} passed, {failed} failed"
          + (f", {skipped} skipped" if skipped else ""))

    if failures:
        print()
        for f in failures:
            print(f)

    return failed == 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    verbose = '-v' in sys.argv
    args    = [a for a in sys.argv[1:] if not a.startswith('-')]
    pattern = args[0] if args else None
    sys.exit(0 if run_tests(verbose=verbose, pattern=pattern) else 1)
