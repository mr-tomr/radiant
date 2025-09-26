#!/usr/bin/env python3
"""
cmc_fuzzer.py
Lightweight fuzzing client for NCR CMC/DCS plaintext port (8089).
Designed for authorized testing only.

Usage examples:
  python3 cmc_fuzzer.py --host 192.168.1.241 --port 8089 --mode smart --count 200
  python3 cmc_fuzzer.py --host 192.168.1.241 --payload-file payloads.txt --count 50
"""

import argparse
import socket
import threading
import time
import random
import string
import os
from datetime import datetime

DEFAULT_HOST = "192.168.1.241"
DEFAULT_PORT = 8089
DEFAULT_TIMEOUT = 5.0
LOG_DIR = "cmc_fuzzer_logs"

# Base template observed from your nc output
BASE_TEMPLATE = "<cmcsys:myNodeNumber={node} myNodeName={name} mySiteId={site}|nodeIsProxy={proxy}<:EOM:>"

# Some example seeds derived from netcat screenshot
SEED_PAYLOADS = [
    BASE_TEMPLATE.format(node=0, name="ME0732ARSMT999", site=1107714, proxy="False"),
    BASE_TEMPLATE.format(node=1, name="ME0732ARSMT001", site=1107714, proxy="True"),
    "<heartbeat><EOM:>",
    "PING<:EOM:>",
    "HELLO<:EOM:>",
]

# Mutators
def mutate_truncate(s):
    if not s: return s
    cut = random.randint(1, max(1, len(s)//2))
    return s[:len(s)-cut]

def mutate_repeat(s):
    # repeat a random chunk
    if not s: return s
    i = random.randint(0, max(0, len(s)-1))
    j = random.randint(i+1, len(s))
    chunk = s[i:j]
    times = random.randint(2, 8)
    return s[:i] + (chunk * times) + s[j:]

def mutate_flipbytes(s):
    b = bytearray(s.encode(errors="ignore"))
    if not b: return s
    idx = random.randrange(len(b))
    b[idx] = b[idx] ^ random.getrandbits(8)
    return b.decode(errors="replace")

def mutate_insert_random(s):
    insert = ''.join(random.choices(string.printable, k=random.randint(1,20)))
    pos = random.randint(0, len(s))
    return s[:pos] + insert + s[pos:]

def mutate_change_numbers(s):
    return ''.join(str(random.randint(0,9999)) if ch.isdigit() else ch for ch in s)

MUTATORS = [
    mutate_truncate,
    mutate_repeat,
    mutate_flipbytes,
    mutate_insert_random,
    mutate_change_numbers,
]

# Utility to make a mutated payload from a seed
def generate_mutation(seed):
    s = seed
    # randomly apply 1-3 mutators
    for _ in range(random.randint(1,3)):
        mut = random.choice(MUTATORS)
        s = mut(s)
    # occasionally append garbage bytes
    if random.random() < 0.15:
        s += ''.join(chr(random.randint(1,127)) for _ in range(random.randint(1,10)))
    return s

# Fuzz worker
def fuzz_worker(host, port, payloads, timeout, delay, iterations, thread_id, logf, verbose):
    for i in range(iterations):
        # pick payload source: seed, generated, or user-provided
        choice = random.random()
        if choice < 0.35:
            payload = random.choice(SEED_PAYLOADS)
        elif choice < 0.7:
            payload = random.choice(payloads) if payloads else random.choice(SEED_PAYLOADS)
        else:
            payload = generate_mutation(random.choice(SEED_PAYLOADS))
        # ensure EOM marker present (common in observed output)
        if "<:EOM:>" not in payload:
            payload = payload + "<:EOM:>"
        ts = datetime.utcnow().isoformat() + "Z"
        log_entry_header = f"[{ts}] [T{thread_id}] Iter {i+1}/{iterations} -> len={len(payload)}"
        if verbose:
            print(log_entry_header)
            print("  ->", payload)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                s.sendall(payload.encode(errors="ignore"))
                # read response until timeout or close
                resp = b""
                start = time.time()
                while True:
                    try:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                    except socket.timeout:
                        break
                    # small safety cap
                    if time.time() - start > (timeout + 2):
                        break
                resp_text = resp.decode(errors="replace")
                out = f"{log_entry_header}\nREQUEST: {payload}\nRESPONSE: {resp_text}\n\n"
                logf.write(out)
                logf.flush()
                if verbose:
                    print("  <-", resp_text.replace("\n", "\\n"))
        except Exception as e:
            out = f"{log_entry_header}\nREQUEST: {payload}\nERROR: {repr(e)}\n\n"
            logf.write(out)
            logf.flush()
            if verbose:
                print("  !!", repr(e))
        time.sleep(delay)

def ensure_log_dir():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

def main():
    parser = argparse.ArgumentParser(description="CMC/DCS plaintext port (8089) fuzzer")
    parser.add_argument("--host", "-H", default=DEFAULT_HOST, help="target host")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help="target port")
    parser.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help="socket timeout seconds")
    parser.add_argument("--delay", "-d", type=float, default=0.2, help="delay between requests (s)")
    parser.add_argument("--threads", type=int, default=2, help="concurrent worker threads")
    parser.add_argument("--count", "-c", type=int, default=100, help="total iterations per thread")
    parser.add_argument("--payload-file", "-f", help="file with custom payloads (one per line)")
    parser.add_argument("--mode", choices=["smart","mutate","dict"], default="mutate", help="fuzzing strategy")
    parser.add_argument("--verbose", action="store_true", help="print progress to stdout")
    args = parser.parse_args()

    # build payload list
    payloads = []
    if args.payload_file:
        try:
            with open(args.payload_file, "r", encoding="utf-8", errors="ignore") as pf:
                for ln in pf:
                    ln = ln.strip()
                    if ln:
                        payloads.append(ln)
        except Exception as e:
            print(f"[!] Could not read payload file: {e}")
            return

    # add seeds by default
    payloads.extend(SEED_PAYLOADS)

    ensure_log_dir()
    logfile_name = os.path.join(LOG_DIR, f"cmc_fuzz_{args.host}_{args.port}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.log")
    with open(logfile_name, "a", encoding="utf-8", errors="ignore") as logf:
        header = f"=== CMC Fuzz session {datetime.utcnow().isoformat()}Z target={args.host}:{args.port} threads={args.threads} per-thread={args.count} mode={args.mode}\n"
        logf.write(header + "\n")
        print(f"[+] Logging to {logfile_name}")

        threads = []
        for tid in range(args.threads):
            t = threading.Thread(target=fuzz_worker,
                                 args=(args.host, args.port, payloads, args.timeout, args.delay, args.count, tid+1, logf, args.verbose),
                                 daemon=True)
            threads.append(t)
            t.start()

        try:
            # wait for threads
            while any(t.is_alive() for t in threads):
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("[*] Interrupted by user, waiting for threads to finish...")
            # threads are daemon; they'll exit when program exits
        print("[+] Fuzzing finished.")

if __name__ == "__main__":
    main()
