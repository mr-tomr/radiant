#!/usr/bin/env python3
"""
cmc_fuzzer_full.py
Full CMC/DCS plaintext (8089) fuzzer with fingerprint targeting and summary.

Usage examples:
  python3 cmc_fuzzer_full.py --host 192.168.1.241 --port 8089 --threads 2 --count 200 --verbose
  python3 cmc_fuzzer_full.py --host 192.168.1.241 --payload-file my_payloads.txt --count 50
  python3 cmc_fuzzer_full.py --host 192.168.1.241 --crash-detect --crash-threshold 10

AUTHORIZED USE ONLY: Run this only against systems you are authorized to test.
"""

import argparse
import socket
import threading
import time
import random
import string
import os
from datetime import datetime
from collections import defaultdict

# -----------------------------
# Config / defaults
# -----------------------------
DEFAULT_HOST = "192.168.1.241"
DEFAULT_PORT = 8089
DEFAULT_TIMEOUT = 5.0
LOG_DIR = "cmc_fuzzer_logs"

# Thread-safe counters & lock
counters = defaultdict(int)
counters_lock = threading.Lock()

# For simple crash detection / service-down flag
service_state = {"down": False}
service_state_lock = threading.Lock()

# Base template observed from your nc output
BASE_TEMPLATE = "<cmcsys:myNodeNumber={node} myNodeName={name} mySiteId={site}|nodeIsProxy={proxy}<:EOM:>"

# Fingerprint strings (from your nmap/netcat output)
FINGERPRINT_STRINGS = [
    "DNSStatusRequestTCP", "DNSVersionBindReqTCP", "FourOhFourRequest", "GenericLines",
    "GetRequest", "HTTPOptions", "Help", "Kerberos", "LPDString", "NULL",
    "RPCCheck", "RTSPRequest", "SMBProgNeg", "SSLSessionReq", "TLSSessionReq",
    "TerminalServerCookie", "X11Probe"
]

# Seeds (include fingerprint payloads)
SEED_PAYLOADS = [
    BASE_TEMPLATE.format(node=0, name="ME0732ARSMT999", site=1107714, proxy="False"),
    BASE_TEMPLATE.format(node=1, name="ME0732ARSMT001", site=1107714, proxy="True"),
    "<heartbeat><:EOM:>",
    "PING<:EOM:>",
    "HELLO<:EOM:>",
] + [f"{s}<:EOM:>" for s in FINGERPRINT_STRINGS]

# -----------------------------
# Mutators
# -----------------------------
def mutate_truncate(s):
    if not s: return s
    cut = random.randint(1, max(1, len(s)//2))
    return s[:len(s)-cut]

def mutate_repeat(s):
    if not s: return s
    i = random.randint(0, max(0, len(s)-2))
    j = random.randint(i+1, len(s))
    chunk = s[i:j]
    times = random.randint(2, 8)
    return s[:i] + (chunk * times) + s[j:]

def mutate_flipbytes(s):
    try:
        b = bytearray(s.encode('utf-8', errors='ignore'))
        if not b:
            return s
        idx = random.randrange(len(b))
        b[idx] = b[idx] ^ random.getrandbits(8)
        return b.decode('utf-8', errors='replace')
    except Exception:
        return s

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

def generate_mutation(seed):
    s = seed
    # apply 1-3 random mutators
    for _ in range(random.randint(1,3)):
        mut = random.choice(MUTATORS)
        s = mut(s)
    # occasionally append random bytes
    if random.random() < 0.15:
        s += ''.join(chr(random.randint(1,127)) for _ in range(random.randint(1,10)))
    return s

# -----------------------------
# Structured-field generator (puts fingerprints into cmcsys fields)
# -----------------------------
def generate_field_fuzz(node=0, name="ME0732ARSMT999", site=1107714):
    out = []
    for fp in FINGERPRINT_STRINGS:
        # fingerprint as its own message (already added to seeds but keep for structured)
        out.append(f"<cmcsys:myNodeNumber={node} myNodeName={name} mySiteId={site} fingerprint={fp}|nodeIsProxy=False<:EOM:>")
        # fingerprint appended to nodeName to test parsing
        out.append(f"<cmcsys:myNodeNumber={node} myNodeName={name}-{fp} mySiteId={site}|nodeIsProxy=False<:EOM:>")
    return out

# -----------------------------
# Logging utilities
# -----------------------------
def ensure_log_dir():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

def make_logfile(host, port):
    safe = host.replace(":", "_")
    fname = f"cmc_fuzz_{safe}_{port}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.log"
    return os.path.join(LOG_DIR, fname)

# -----------------------------
# Fuzz worker
# -----------------------------
def fuzz_worker(host, port, payloads, timeout, delay, iterations, thread_id, logf, verbose, crash_detect, crash_threshold):
    consecutive_errors = 0
    for i in range(iterations):
        # choose payload strategy
        choice = random.random()
        if choice < 0.25:
            payload = random.choice(SEED_PAYLOADS)
        elif choice < 0.5:
            # custom payloads (user-provided or extended)
            payload = random.choice(payloads) if payloads else random.choice(SEED_PAYLOADS)
        elif choice < 0.8:
            # mutated seed
            payload = generate_mutation(random.choice(SEED_PAYLOADS))
        else:
            # structured field fuzz
            payload = random.choice(generate_field_fuzz())

        # ensure EOM marker
        if "<:EOM:>" not in payload:
            payload = payload + "<:EOM:>"

        ts = datetime.utcnow().isoformat() + "Z"
        header = f"[{ts}] [T{thread_id}] Iter {i+1}/{iterations} len={len(payload)}"
        if verbose:
            print(header)
            print("  ->", payload)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                s.sendall(payload.encode('utf-8', errors='ignore'))

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
                    if time.time() - start > (timeout + 2):
                        break

                resp_text = resp.decode('utf-8', errors='replace')
                out = f"{header}\nREQUEST: {payload}\nRESPONSE: {resp_text}\n\n"
                logf.write(out)
                logf.flush()
                with counters_lock:
                    counters['requests'] += 1
                    counters['responses'] += 1
                consecutive_errors = 0
                # mark service up if it was down
                with service_state_lock:
                    if service_state.get("down"):
                        service_state["down"] = False
                        logf.write(f"[{datetime.utcnow().isoformat()}] SERVICE_UP detected by T{thread_id}\n")
                        logf.flush()
                if verbose:
                    print("  <-", resp_text.replace("\n", "\\n"))

        except Exception as e:
            out = f"{header}\nREQUEST: {payload}\nERROR: {repr(e)}\n\n"
            logf.write(out)
            logf.flush()
            with counters_lock:
                counters['requests'] += 1
                counters['errors'] += 1
            consecutive_errors += 1
            if verbose:
                print("  !!", repr(e))

            # crash detection logic: mark service down when threshold exceeded
            if crash_detect and consecutive_errors >= crash_threshold:
                with service_state_lock:
                    if not service_state.get("down"):
                        service_state["down"] = True
                        notice = f"[{datetime.utcnow().isoformat()}] SERVICE_DOWN detected by T{thread_id} after {consecutive_errors} consecutive errors\n"
                        logf.write(notice)
                        logf.flush()
                        if verbose:
                            print(notice.strip())

        # polite delay between requests
        time.sleep(delay)

# -----------------------------
# Periodic progress printer (optional)
# -----------------------------
def progress_printer(interval, logfile, stop_event):
    while not stop_event.is_set():
        time.sleep(interval)
        with counters_lock:
            reqs = counters.get('requests', 0)
            resps = counters.get('responses', 0)
            errs = counters.get('errors', 0)
        with service_state_lock:
            down = service_state.get("down", False)
        summary = f"[{datetime.utcnow().isoformat()}] PROGRESS: requests={reqs} responses={resps} errors={errs} service_down={down}"
        try:
            with open(logfile, "a", encoding="utf-8", errors="ignore") as lf:
                lf.write(summary + "\n")
        except Exception:
            pass
        print(summary)

# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="CMC/DCS plaintext port (8089) fuzzer - full version")
    parser.add_argument("--host", "-H", default=DEFAULT_HOST, help="target host")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help="target port")
    parser.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help="socket timeout seconds")
    parser.add_argument("--delay", "-d", type=float, default=0.2, help="delay between requests (s)")
    parser.add_argument("--threads", type=int, default=2, help="concurrent worker threads")
    parser.add_argument("--count", "-c", type=int, default=100, help="iterations per thread")
    parser.add_argument("--payload-file", "-f", help="file with custom payloads (one per line)")
    parser.add_argument("--verbose", action="store_true", help="print progress to stdout")
    parser.add_argument("--progress-interval", type=int, default=0, help="print progress every N seconds (0 = disabled)")
    parser.add_argument("--crash-detect", action="store_true", help="enable simple crash detection (consecutive errors)")
    parser.add_argument("--crash-threshold", type=int, default=15, help="consecutive errors threshold for crash-detect")
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

    # always include seeds + structured field fuzz
    payloads.extend(SEED_PAYLOADS)
    payloads.extend(generate_field_fuzz())

    ensure_log_dir()
    logfile_name = make_logfile(args.host, args.port)
    with open(logfile_name, "a", encoding="utf-8", errors="ignore") as logf:
        header = f"=== CMC Fuzz session {datetime.utcnow().isoformat()}Z target={args.host}:{args.port} threads={args.threads} per-thread={args.count} delay={args.delay} mode=full\n"
        logf.write(header + "\n")
        logf.flush()
        print(f"[+] Logging to {logfile_name}")

        # start optional progress printer
        stop_event = threading.Event()
        progress_thread = None
        if args.progress_interval and args.progress_interval > 0:
            progress_thread = threading.Thread(target=progress_printer, args=(args.progress_interval, logfile_name, stop_event), daemon=True)
            progress_thread.start()

        # spawn workers
        threads = []
        for tid in range(args.threads):
            t = threading.Thread(target=fuzz_worker,
                                 args=(args.host, args.port, payloads, args.timeout, args.delay, args.count, tid+1, logf, args.verbose, args.crash_detect, args.crash_threshold),
                                 daemon=True)
            threads.append(t)
            t.start()

        try:
            while any(t.is_alive() for t in threads):
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("[*] Interrupted by user, waiting for threads to finish...")
            # allow threads to exit

        # stop progress printer
        if progress_thread:
            stop_event.set()
            progress_thread.join(timeout=2)

        # final summary
        with counters_lock:
            reqs = counters.get('requests', 0)
            resps = counters.get('responses', 0)
            errs = counters.get('errors', 0)
        with service_state_lock:
            down = service_state.get("down", False)

        summary = (
            f"\n=== Fuzz session summary ===\n"
            f"Target: {args.host}:{args.port}\n"
            f"Threads: {args.threads}\n"
            f"Per-thread iterations: {args.count}\n"
            f"Total requests attempted: {reqs}\n"
            f"Total successful responses logged: {resps}\n"
            f"Total errors: {errs}\n"
            f"Service_down_flag: {down}\n"
            f"Logfile: {logfile_name}\n"
            "===========================\n"
        )
        print(summary)
        logf.write(summary + "\n")
        logf.flush()

        # audible bell
        try:
            print("\a")
        except Exception:
            pass

        print("[+] Fuzzing finished.")

if __name__ == "__main__":
    main()
