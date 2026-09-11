#!/usr/bin/env python3
"""
script by claudi ai for hacksmarter lab https://www.hacksmarter.org/courses/27b0ac4a-5e03-4e43-afae-7c730b7b6263
smtp_userenum.py -- single-session SMTP user enumeration for Postfix

Idea: hold ONE TCP connection open and push every name through it, instead of
opening a fresh connection per name (which trips Postfix's per-client
connection-rate limit -- anvil -- and gets you dropped with 421 4.7.x).

Reality check: Postfix also has smtpd_hard_error_limit (default 20). Every 550
to an invalid recipient counts as an "error", so the server WILL force-close the
session with 421 after ~20 rejects, even on a single connection. So the correct
design is: keep the session open, and when the server makes us reconnect, back
off briefly and RESUME from the exact name we were on. For 500 names that's
~25 reconnects instead of 500 -- far under the connection-rate limit.

Methods:
  VRFY  (default) -- one command per name. Postfix: 250/252 = valid, 550 = unknown.
  RCPT  (fallback) -- MAIL FROM once, then RCPT TO:<name@domain> per name.
                      Use this if VRFY is disabled (502) or neutered (252 for all).

PIPELINING: when advertised (it is, in your banner), we send a batch of commands
without waiting, then read the replies. That removes per-command round-trips.

Authorised testing / CTF use only.
"""

import argparse
import socket
import ssl
import sys
import time


class Dropped(Exception):
    """Server closed the session (421 or connection reset)."""


class SMTPSession:
    def __init__(self, host, port, timeout, helo, use_starttls):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.helo = helo
        self.use_starttls = use_starttls
        self.sock = None
        self.rfile = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.rfile = self.sock.makefile("rb")
        self._read_reply()                       # 220 banner
        self._cmd(f"EHLO {self.helo}")
        if self.use_starttls:
            code, _ = self._cmd("STARTTLS")
            if code != 220:
                raise RuntimeError(f"STARTTLS refused ({code})")
            ctx = ssl._create_unverified_context()
            self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)
            self.rfile = self.sock.makefile("rb")
            self._cmd(f"EHLO {self.helo}")        # must re-EHLO after TLS

    def start_rcpt(self, mail_from):
        code, _ = self._cmd(f"MAIL FROM:<{mail_from}>")
        if code // 100 != 2:
            raise RuntimeError(f"MAIL FROM rejected ({code}) -- try another --mail-from")

    def _read_reply(self):
        """Read one full (possibly multiline) SMTP reply -> (code, [lines])."""
        lines = []
        while True:
            raw = self.rfile.readline()
            if not raw:
                raise Dropped("connection closed by server")
            line = raw.decode(errors="replace").rstrip("\r\n")
            lines.append(line)
            if len(line) >= 4 and line[3] == " ":   # final line of the reply
                try:
                    return int(line[:3]), lines
                except ValueError:
                    raise Dropped(f"malformed reply: {line!r}")

    def _cmd(self, line):
        self.sock.sendall((line + "\r\n").encode())
        return self._read_reply()

    def send_batch(self, lines):
        """Pipelined send: fire all commands, don't wait between them."""
        payload = "".join(l + "\r\n" for l in lines).encode()
        self.sock.sendall(payload)

    def close(self):
        try:
            if self.sock:
                self.sock.sendall(b"QUIT\r\n")
        except OSError:
            pass
        finally:
            try:
                self.sock.close()
            except (OSError, AttributeError):
                pass


def load_names(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [n.strip() for n in f if n.strip() and not n.startswith("#")]


def is_valid(code, method):
    if method == "vrfy":
        return code in (250, 252)
    return code == 250          # rcpt


def build_line(name, method, domain):
    addr = f"{name}@{domain}" if domain else name
    if method == "vrfy":
        return f"VRFY {addr}"
    return f"RCPT TO:<{addr}>"


def main():
    ap = argparse.ArgumentParser(description="Single-session Postfix user enumeration")
    ap.add_argument("target")
    ap.add_argument("userlist")
    ap.add_argument("-p", "--port", type=int, default=25)
    ap.add_argument("-m", "--method", choices=["vrfy", "rcpt"], default="vrfy")
    ap.add_argument("-d", "--domain", default="", help="append @domain (needed for rcpt)")
    ap.add_argument("--mail-from", default="probe@example.com", help="rcpt mode envelope sender")
    ap.add_argument("-b", "--batch", type=int, default=10, help="pipelined commands per send (1 = no pipelining)")
    ap.add_argument("--backoff", type=float, default=1.0, help="sleep on reconnect (stay under connection-rate limit)")
    ap.add_argument("--helo", default="probe.local")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--starttls", action="store_true")
    ap.add_argument("-o", "--out", default="", help="write valid users to file")
    args = ap.parse_args()

    if args.method == "rcpt" and not args.domain:
        print("[!] rcpt mode usually needs -d/--domain", file=sys.stderr)

    names = load_names(args.userlist)
    total = len(names)
    print(f"[*] {total} names against {args.target}:{args.port} via {args.method.upper()} "
          f"(batch={args.batch})")

    valid = []
    out = open(args.out, "w", encoding="utf-8") if args.out else None
    reconnects = 0
    codes_seen = {}
    t0 = time.time()

    sess = None
    i = 0
    try:
        while i < total:
            if sess is None:
                if reconnects:
                    time.sleep(args.backoff)
                sess = SMTPSession(args.target, args.port, args.timeout, args.helo, args.starttls)
                sess.connect()
                if args.method == "rcpt":
                    sess.start_rcpt(args.mail_from)

            batch = names[i:i + args.batch]
            lines = [build_line(n, args.method, args.domain) for n in batch]

            try:
                if args.batch > 1:
                    sess.send_batch(lines)
                    for j, name in enumerate(batch):
                        code, _ = sess._read_reply()
                        codes_seen[code] = codes_seen.get(code, 0) + 1
                        if code == 421:                 # limit hit: this name unprocessed
                            raise Dropped(f"421 at {name}")
                        if is_valid(code, args.method):
                            valid.append(name)
                            print(f"[+] {name}  ({code})")
                            if out:
                                out.write(name + "\n"); out.flush()
                    i += len(batch)                     # whole batch done
                else:
                    for name in batch:
                        code, _ = sess._cmd(lines[0] if False else build_line(name, args.method, args.domain))
                        codes_seen[code] = codes_seen.get(code, 0) + 1
                        if code == 421:
                            raise Dropped(f"421 at {name}")
                        if is_valid(code, args.method):
                            valid.append(name)
                            print(f"[+] {name}  ({code})")
                            if out:
                                out.write(name + "\n"); out.flush()
                        i += 1
            except Dropped as e:
                # resume from the exact name that got 421 / where the socket died
                # j counts fully-answered replies in this batch when pipelining
                answered = j if (args.batch > 1 and "j" in dir()) else 0
                i += answered
                reconnects += 1
                sys.stdout.write(f"\r[~] server dropped ({e}); reconnecting "
                                 f"#{reconnects}, resume at {i}/{total}\n")
                try:
                    sess.close()
                except Exception:
                    pass
                sess = None
            sys.stdout.write(f"\r[.] progress {min(i, total)}/{total}   ")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[!] interrupted")
    finally:
        if sess:
            sess.close()
        if out:
            out.close()

    dt = time.time() - t0
    print(f"\n[*] done: {len(valid)} valid / {total} in {dt:.1f}s, "
          f"{reconnects} reconnects")
    print(f"[*] reply codes: {dict(sorted(codes_seen.items()))}")
    if args.method == "vrfy" and codes_seen.get(252, 0) >= total * 0.9:
        print("[!] almost everything returned 252 -- VRFY looks neutered; retry with -m rcpt")
    if valid:
        print("[*] valid users:")
        for v in valid:
            print("   ", v)


if __name__ == "__main__":
    main()
