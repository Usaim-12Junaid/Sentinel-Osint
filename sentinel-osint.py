#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║              SentinelOSINT v1.0.0                        ║
║      Professional OSINT Reconnaissance Framework         ║
║                                                          ║
║  Author : SentinelOSINT Project                          ║
║  Usage  : For authorized security testing ONLY           ║
╚══════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────
# IMPORTS 1. Imports (Line 16-27)
# Bahar ki libraries load karna — requests=internet, bs4=html padhna, gradio=GUI, json=file save
# ─────────────────────────────────────────────────────────

from gradio_client import file
import requests
from bs4 import BeautifulSoup
import random
import time
import json
import os
import io
import re
from datetime import datetime
from urllib.parse import quote_plus, urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import gradio as gr

# ─────────────────────────────────────────────────────────
# CONSTANTS & CONFIGURATION 2. Constants & Configuration (Line 42-85)
#USER_AGENTS = 10 alag alag browsers ke naam — Google ko lagta hai real user hai
#RISK_MAP = file types ka khatra level — .env=CRITICAL, .pdf=LOW
# ─────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════╗
║              SentinelOSINT v1.0.0                        ║
║      Professional OSINT Reconnaissance Framework         ║
║                                                          ║
║   Launching Web Interface on http://127.0.0.1:7860       ║
╚══════════════════════════════════════════════════════════╝
"""

# Rotating User-Agent pool to evade bot detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Risk classification map — used for scoring discovered files
RISK_MAP = {
    "CRITICAL": [
        "env", "sql", "conf", "config", "ini", "key", "pem",
        "bak", "backup", "db", "sqlite", "sh", "bash_history",
        "htpasswd", "passwd", "shadow", "secret", "credentials",
        "private", "id_rsa", "id_dsa",
    ],
    "HIGH": [
        "log", "xml", "json", "yaml", "yml", "php", "asp",
        "aspx", "jsp", "py", "rb", "java", "go",
    ],
    "MEDIUM": [
        "xlsx", "xls", "docx", "doc", "csv", "pptx", "ppt",
        "mdb", "accdb",
    ],
    "LOW": [
        "pdf", "txt", "rtf", "odt", "ods",
    ],
}

# Search engine internal domains to exclude from results
SE_DOMAINS = [
    "google.com", "bing.com", "duckduckgo.com", "microsoft.com",
    "yahoo.com", "baidu.com", "yandex.com", "ask.com",
]

RESULTS_FILE = "scan_results.json"
PDF_DOWNLOAD_LIMIT_MB = 3  # Max MB to download per PDF for metadata
MAX_VERIFY_WORKERS = 8     # Concurrent threads for link verification


# ─────────────────────────────────────────────────────────
# PHASE 0 — UTILITY FUNCTIONS Utility Functions (Line 92-140)
#get_random_headers() → Har request ke sath random browser naam bhejta hai
#classify_risk() → URL dekh kar risk level decide karta hai (CRITICAL/HIGH/MEDIUM/LOW)
#sanitize_domain() → "https://example.com/" → "example.com" clean karta ha
# ─────────────────────────────────────────────────────────

def get_random_headers() -> dict:
    """
    Build a randomized HTTP header set.
    Rotating User-Agents is the primary anti-bot measure here.
    """
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "no-cache",
    }


def classify_risk(url: str) -> str:
    """
    Determine risk level by matching the URL's file extension
    against the RISK_MAP. Returns 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'.
    """
    url_lower = url.lower().split("?")[0]  # Strip query params before checking ext
    ext = url_lower.rsplit(".", 1)[-1] if "." in url_lower else ""

    for level, extensions in RISK_MAP.items():
        if ext in extensions:
            return level
    return "LOW"


def sanitize_domain(raw_domain: str) -> str:
    """Strip protocol and trailing slashes from a domain string."""
    domain = raw_domain.strip()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.rstrip("/").split("/")[0]  # Keep only the TLD+domain part
    return domain


def is_valid_url(url: str) -> bool:
    """Basic URL sanity check."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────
# PHASE 2 — MULTI-ENGINE DORKING . Dorking Engine — Phase 2 (Line 148-290)
#dork_google() → Google par search karta hai: "site:example.com filetype:pdf"
#dork_bing() → Same cheez Bing par — Google block kare toh yeh backup hai
#dork_duckduckgo() → DuckDuckGo par — sabse zyada friendly, block nahi karta
#Teeno mein: 2-4 second ruk jaata hai taake IP block na ho
# ─────────────────────────────────────────────────────────

def dork_google(domain: str, file_type: str, log) -> set:
    """
    Google dorking via scraping the HTML search page.
    Dork query format: site:<domain> filetype:<ext>
    Anti-bot: Random UA + randomized 2-4 second delay.
    """
    query = f"site:{domain} filetype:{file_type}"
    url = f"https://www.google.com/search?q={quote_plus(query)}&num=50&hl=en"

    try:
        # Time delay is our primary anti-bot courtesy measure
        time.sleep(random.uniform(2.0, 4.0))
        response = requests.get(url, headers=get_random_headers(), timeout=15)

        if response.status_code != 200:
            log(f"  [Google] ⚠ Status {response.status_code} — likely blocked. Skipping Google for .{file_type}.")
            return set()

        soup = BeautifulSoup(response.text, "html.parser")
        links = set()

        # Google wraps real URLs in /url?q= redirect format
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith("/url?q="):
                real_url = unquote(href.split("/url?q=")[1].split("&")[0])
                if domain in real_url and is_valid_url(real_url):
                    if not any(se in real_url for se in SE_DOMAINS):
                        links.add(real_url)
            elif href.startswith("http") and domain in href:
                if not any(se in href for se in SE_DOMAINS):
                    links.add(href)

        log(f"  [Google] ✓ Found {len(links)} candidates for .{file_type}")
        return links

    except requests.exceptions.Timeout:
        log("  [Google] ✗ Request timed out.")
        return set()
    except Exception as e:
        log(f"  [Google] ✗ Error: {e}")
        return set()


def dork_bing(domain: str, file_type: str, log) -> set:
    """
    Bing dorking via scraping HTML search results.
    Bing is generally less aggressive with bot-blocking than Google.
    """
    query = f"site:{domain} filetype:{file_type}"
    url = f"https://www.bing.com/search?q={quote_plus(query)}&count=50"

    try:
        time.sleep(random.uniform(2.0, 3.5))
        response = requests.get(url, headers=get_random_headers(), timeout=15)

        if response.status_code != 200:
            log(f"  [Bing] ⚠ Status {response.status_code}.")
            return set()

        soup = BeautifulSoup(response.text, "html.parser")
        links = set()

        # Bing places result links inside <li class="b_algo"> containers
        for result in soup.select("li.b_algo"):
            a_tag = result.find("a", href=True)
            if a_tag:
                href = a_tag["href"]
                if href.startswith("http") and domain in href:
                    if not any(se in href for se in SE_DOMAINS):
                        links.add(href)

        # Fallback: scan all <a> tags if structured parsing yields nothing
        if not links:
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if href.startswith("http") and domain in href:
                    if not any(se in href for se in SE_DOMAINS):
                        links.add(href)

        log(f"  [Bing] ✓ Found {len(links)} candidates for .{file_type}")
        return links

    except requests.exceptions.Timeout:
        log("  [Bing] ✗ Request timed out.")
        return set()
    except Exception as e:
        log(f"  [Bing] ✗ Error: {e}")
        return set()


def dork_duckduckgo(domain: str, file_type: str, log) -> set:
    """
    DuckDuckGo dorking using the non-JS HTML frontend (html.duckduckgo.com).
    DDG's HTML version is the most scraper-friendly of the three engines.
    """
    query = f"site:{domain} filetype:{file_type}"
    url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"

    try:
        time.sleep(random.uniform(1.5, 3.0))
        response = requests.get(url, headers=get_random_headers(), timeout=15)

        if response.status_code != 200:
            log(f"  [DuckDuckGo] ⚠ Status {response.status_code}.")
            return set()

        soup = BeautifulSoup(response.text, "html.parser")
        links = set()

        # DDG HTML result anchors use class="result__a"
        for a_tag in soup.select("a.result__a"):
            href = a_tag.get("href", "")
            if href.startswith("http") and domain in href:
                links.add(href)

        # DDG also uses a redirect via ?uddg= parameter
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if "uddg=" in href:
                parsed_params = parse_qs(urlparse(href).query)
                if "uddg" in parsed_params:
                    actual_url = unquote(parsed_params["uddg"][0])
                    if domain in actual_url and is_valid_url(actual_url):
                        links.add(actual_url)

        log(f"  [DuckDuckGo] ✓ Found {len(links)} candidates for .{file_type}")
        return links

    except requests.exceptions.Timeout:
        log("  [DuckDuckGo] ✗ Request timed out.")
        return set()
    except Exception as e:
        log(f"  [DuckDuckGo] ✗ Error: {e}")
        return set()


# ─────────────────────────────────────────────────────────
# PHASE 3A — LINK VERIFICATION 
#verify_single_link() → Ek link check karta hai — zinda hai ya nahi (HTTP 200)
#batch_verify_links() → 8 links ek saath check karta hai — time bachata ha
# ─────────────────────────────────────────────────────────

def verify_single_link(url: str):
    """
    Send a HEAD request to check if a URL returns HTTP 200.
    HEAD is used instead of GET to avoid downloading the full file body.
    Returns a tuple: (url, is_live: bool, status_code)
    """
    try:
        time.sleep(random.uniform(0.3, 1.0))  # Polite delay between checks
        response = requests.head(
            url,
            headers=get_random_headers(),
            timeout=10,
            allow_redirects=True,
        )
        return url, (response.status_code == 200), response.status_code
    except requests.exceptions.Timeout:
        return url, False, "TIMEOUT"
    except requests.exceptions.SSLError:
        return url, False, "SSL_ERROR"
    except requests.exceptions.ConnectionError:
        return url, False, "CONN_ERROR"
    except Exception as e:
        return url, False, str(e)[:40]


def batch_verify_links(urls: set, log) -> list:
    """
    Verify all raw URLs concurrently using a thread pool.
    MAX_VERIFY_WORKERS controls parallelism.
    Returns a list of live (HTTP 200) URLs only.
    """
    if not urls:
        return []

    log(f"\n[Phase 3 – Verification] Checking {len(urls)} link(s) for live status...")
    live_links = []

    with ThreadPoolExecutor(max_workers=MAX_VERIFY_WORKERS) as executor:
        futures = {executor.submit(verify_single_link, url): url for url in urls}
        for future in as_completed(futures):
            url, is_live, status = future.result()
            if is_live:
                live_links.append(url)
                log(f"  ✅ LIVE  [{status}] {url}")
            else:
                log(f"  ❌ DEAD  [{status}] {url}")

    log(f"\n  → {len(live_links)} live link(s) confirmed out of {len(urls)} checked.")
    return live_links


# ─────────────────────────────────────────────────────────
# PHASE 3B — PDF METADATA EXTRACTION
# ─────────────────────────────────────────────────────────

def extract_pdf_metadata(url: str, log) -> dict:
    """
    Download a PDF (up to PDF_DOWNLOAD_LIMIT_MB) and extract
    internal metadata fields: Author, Creator, Producer, etc.

    Tries PyPDF2 first, then pikepdf as fallback.
    This metadata can reveal internal software, usernames, or
    organizational details — hence the 'intelligence' value.
    """
    metadata = {}

    try:
        log(f"  [Metadata] Extracting from: {url}")
        response = requests.get(
            url,
            headers=get_random_headers(),
            timeout=25,
            stream=True,
        )

        if response.status_code != 200:
            return {"error": f"Download failed (HTTP {response.status_code})"}

        # Stream only up to the size limit to be bandwidth-conscious
        limit_bytes = PDF_DOWNLOAD_LIMIT_MB * 1024 * 1024
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) >= limit_bytes:
                log(f"  [Metadata] ⚠ Truncated download at {PDF_DOWNLOAD_LIMIT_MB}MB")
                break

        # --- Try PyPDF2 first ---
        try:
            import PyPDF2
            reader = PyPDF2.PdfReader(io.BytesIO(content))
            info = reader.metadata

            if info:
                metadata = {
                    "Author":       str(info.get("/Author",       "N/A")),
                    "Creator":      str(info.get("/Creator",      "N/A")),
                    "Producer":     str(info.get("/Producer",     "N/A")),
                    "CreationDate": str(info.get("/CreationDate", "N/A")),
                    "ModDate":      str(info.get("/ModDate",      "N/A")),
                    "Title":        str(info.get("/Title",        "N/A")),
                    "Subject":      str(info.get("/Subject",      "N/A")),
                    "Pages":        len(reader.pages),
                    "library_used": "PyPDF2",
                }
            else:
                metadata = {"info": "PDF opened but no metadata fields found.", "library_used": "PyPDF2"}

            return metadata

        except ImportError:
            pass  # PyPDF2 not installed, try pikepdf

        # --- Fallback: pikepdf ---
        try:
            import pikepdf
            pdf = pikepdf.open(io.BytesIO(content))
            docinfo = pdf.docinfo
            metadata = {
                "Author":       str(docinfo.get("/Author",       "N/A")),
                "Creator":      str(docinfo.get("/Creator",      "N/A")),
                "Producer":     str(docinfo.get("/Producer",     "N/A")),
                "CreationDate": str(docinfo.get("/CreationDate", "N/A")),
                "Title":        str(docinfo.get("/Title",        "N/A")),
                "library_used": "pikepdf",
            }
            pdf.close()
            return metadata

        except ImportError:
            return {"error": "No PDF library found. Run: pip install PyPDF2"}

    except requests.exceptions.Timeout:
        return {"error": "Download timed out"}
    except Exception as e:
        return {"error": str(e)[:120]}


# ─────────────────────────────────────────────────────────
# PHASE 4 — RISK CLASSIFICATION & REPORT BUILDING
# ─────────────────────────────────────────────────────────

def build_scan_report(domain: str, file_type: str, live_links: list, metadata_map: dict) -> tuple:
    """
    Build a structured scan report dict for one file type.
    Returns (report_dict, critical_count).
    """
    classified_links = []
    critical_count = 0

    for url in live_links:
        risk = classify_risk(url)
        if risk == "CRITICAL":
            critical_count += 1

        entry = {
            "url": url,
            "risk_score": risk,
        }

        # Attach PDF metadata if it was extracted for this URL
        if url in metadata_map:
            entry["pdf_metadata"] = metadata_map[url]

        classified_links.append(entry)

    # Sort so CRITICAL links appear first in the report
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    classified_links.sort(key=lambda x: risk_order.get(x["risk_score"], 9))

    report = {
        "scan_id":         datetime.now().strftime("%Y%m%d_%H%M%S_%f"),
        "timestamp":       datetime.now().isoformat(),
        "target_domain":   domain,
        "file_type":       f".{file_type}",
        "total_live_links": len(live_links),
        "critical_leaks":  critical_count,
        "links":           classified_links,
    }

    return report, critical_count


# ─────────────────────────────────────────────────────────
# PHASE 5 — DATA PERSISTENCE
# ─────────────────────────────────────────────────────────

def load_existing_results() -> list:
    """Load previous scan results from scan_results.json."""
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            # File may be corrupt or empty; start fresh
            return []
    return []


def save_scan_report(report: dict) -> bool:
    """
    Append one scan report to scan_results.json.
    The file grows as a JSON array with each call.
    """
    all_results = load_existing_results()
    all_results.append(report)

    try:
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=4, ensure_ascii=False)
        return True
    except IOError as e:
        print(f"[SentinelOSINT] ✗ Could not write {RESULTS_FILE}: {e}")
        return False


# ─────────────────────────────────────────────────────────
# MAIN SCAN ORCHESTRATOR
# ─────────────────────────────────────────────────────────

def run_scan(domain_raw: str, file_types_raw: str, selected_engines: list):
    """
    Orchestrates the full 5-phase scan pipeline.

    Called by Gradio on button click.
    Returns: (log_text, critical_count_str, summary_table_rows)
    """

    # ── Shared state ──────────────────────────────────────
    log_lines = []
    all_reports = []
    total_critical = 0

    def log(msg: str):
        """Append a message to the log buffer and print to console."""
        log_lines.append(msg)
        print(msg)

    # ── Input Validation ──────────────────────────────────
    domain = sanitize_domain(domain_raw)
    if not domain:
        return "❌ Please enter a valid target domain (e.g., example.com).", "0", []

    file_types = [
        ft.strip().lstrip(".").lower()
        for ft in re.split(r"[,\s]+", file_types_raw)
        if ft.strip()
    ]
    if not file_types:
        return "❌ Please enter at least one file extension.", "0", []

    if not selected_engines:
        return "❌ Please select at least one search engine.", "0", []

    # ── Phase 1 Header ────────────────────────────────────
    log("=" * 62)
    log("  SentinelOSINT v1.0.0 — Scan Initiated")
    log("=" * 62)
    log(f"  Target Domain   : {domain}")
    log(f"  File Extensions : {', '.join('.' + ft for ft in file_types)}")
    log(f"  Search Engines  : {', '.join(selected_engines)}")
    log(f"  Start Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 62)

    # ── Per-Extension Loop ────────────────────────────────
    for file_type in file_types:

        log(f"\n{'─'*60}")
        log(f"[Phase 2] Dorking for .{file_type} across {len(selected_engines)} engine(s)...")
        log(f"{'─'*60}")

        raw_links = set()

        # Run each selected search engine sequentially
        # (Sequential here because parallel requests to multiple SEs
        #  greatly increases detection probability)
        if "Google" in selected_engines:
            raw_links |= dork_google(domain, file_type, log)

        if "Bing" in selected_engines:
            raw_links |= dork_bing(domain, file_type, log)

        if "DuckDuckGo" in selected_engines:
            raw_links |= dork_duckduckgo(domain, file_type, log)

        log(f"\n  [Deduplication] {len(raw_links)} unique candidate URL(s) after merging engine results.")

        if not raw_links:
            log(f"  [!] No results for .{file_type}. Possible reasons:")
            log("      • Search engine blocked the dork query (CAPTCHA)")
            log("      • No indexed files of this type exist for the target")
            log("      • Target domain has low search engine footprint")
            continue

        # ── Phase 3A: Verify ──────────────────────────────
        live_links = batch_verify_links(raw_links, log)

        if not live_links:
            log(f"  [!] No live links found for .{file_type}.")
            continue

        # ── Phase 3B: PDF Metadata ────────────────────────
        metadata_map = {}
        if file_type == "pdf" and live_links:
            log(f"\n[Phase 3 – Metadata] Extracting metadata from PDF(s)...")
            # Limit metadata extraction to the first 5 PDFs to stay time-efficient
            for pdf_url in live_links[:5]:
                meta = extract_pdf_metadata(pdf_url, log)
                metadata_map[pdf_url] = meta
                if "error" not in meta:
                    log(f"    Author   : {meta.get('Author', 'N/A')}")
                    log(f"    Creator  : {meta.get('Creator', 'N/A')}")
                    log(f"    Producer : {meta.get('Producer', 'N/A')}")

        # ── Phase 4: Risk Classification ──────────────────
        report, critical_count = build_scan_report(domain, file_type, live_links, metadata_map)
        total_critical += critical_count
        all_reports.append(report)

        log(f"\n[Phase 4 – Risk] .{file_type} summary:")
        log(f"  Live Links     : {len(live_links)}")
        log(f"  Critical Leaks : {critical_count}")

        for entry in report["links"]:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(entry["risk_score"], "⚪")
            log(f"  {icon} [{entry['risk_score']:8s}] {entry['url']}")
            if "pdf_metadata" in entry and "error" not in entry["pdf_metadata"]:
                log(f"              └─ Author: {entry['pdf_metadata'].get('Author','N/A')} | Creator: {entry['pdf_metadata'].get('Creator','N/A')}")

        # ── Phase 5: Persist ──────────────────────────────
        saved = save_scan_report(report)
        if saved:
            log(f"\n[Phase 5 – Persist] ✅ Report saved → {RESULTS_FILE}")
        else:
            log(f"\n[Phase 5 – Persist] ✗ Could not write to {RESULTS_FILE}")

    # ── Final Summary ─────────────────────────────────────
    log(f"\n{'='*62}")
    log("  SentinelOSINT — Scan Complete")
    log(f"  Total Critical Leaks : {total_critical}")
    log(f"  Report File          : {os.path.abspath(RESULTS_FILE)}")
    log(f"  End Time             : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"{'='*62}")

    # ── Build Gradio Outputs ──────────────────────────────
    results_text = "\n".join(log_lines)

    # Summary table rows: [URL, File Type, Risk, Has Metadata]
    table_rows = []
    for report in all_reports:
        for entry in report["links"]:
            has_meta = "✅ Yes" if "pdf_metadata" in entry and "error" not in entry.get("pdf_metadata", {}) else "—"
            table_rows.append([
                entry["url"],
                report["file_type"],
                entry["risk_score"],
                has_meta,
            ])

    if not table_rows and not any(r["total_live_links"] > 0 for r in all_reports):
        results_text += "\n\n[TIP] No live files found. Try:\n"
        results_text += "  • Using a VPN to bypass search engine CAPTCHA blocks\n"
        results_text += "  • Scanning less common file types (.bak, .conf, .sql)\n"
        results_text += "  • Running the scan again after a few minutes\n"

    return results_text, str(total_critical), table_rows


# ─────────────────────────────────────────────────────────
# GRADIO GUI
# ─────────────────────────────────────────────────────────

CUSTOM_CSS = """
    /* Global font */
    * { font-family: 'JetBrains Mono', 'Fira Code', monospace; }

    /* Page background */
    .gradio-container { background: #0d0d1a !important; }

    /* Header box */
    .sentinel-header {
        background: linear-gradient(135deg, #0d0d1a 0%, #1a0a2e 100%);
        border: 1px solid #ff3333;
        border-radius: 12px;
        padding: 24px;
        text-align: center;
        margin-bottom: 8px;
    }

    /* Scan button */
    .scan-btn button {
        background: linear-gradient(135deg, #cc0000, #ff4444) !important;
        color: white !important;
        font-weight: 700 !important;
        font-size: 1.1em !important;
        border-radius: 8px !important;
        border: none !important;
        letter-spacing: 1px;
    }
    .scan-btn button:hover {
        background: linear-gradient(135deg, #ff4444, #ff6666) !important;
        transform: translateY(-1px);
        box-shadow: 0 4px 20px rgba(255,50,50,0.4) !important;
    }

    /* Textbox log */
    textarea { background: #0a0a14 !important; color: #00ff88 !important; font-size: 0.82em !important; }

    /* Critical counter */
    .critical-counter .output-class {
        font-size: 2.5em !important;
        font-weight: 900 !important;
        color: #ff3333 !important;
        text-align: center !important;
    }

    /* Disclaimer box */
    .disclaimer {
        background: rgba(255,50,50,0.08);
        border: 1px solid rgba(255,50,50,0.3);
        border-radius: 8px;
        padding: 10px 14px;
        margin-top: 10px;
    }
    """

def create_interface() -> gr.Blocks:
    """Build and return the Gradio Blocks interface."""

    with gr.Blocks(title="SentinelOSINT") as demo:

        # ── Header ────────────────────────────────────────
        gr.HTML("""
        <div class="sentinel-header">
            <h1 style="color:#ff3333; font-size:2.4em; font-weight:900; margin:0; letter-spacing:2px;">
                🛡️ SentinelOSINT
            </h1>
            <p style="color:#aaa; margin:6px 0 0; font-size:1em; letter-spacing:1px;">
                Professional OSINT Reconnaissance Framework &nbsp;|&nbsp; v1.0.0
            </p>
            <p style="color:#555; font-size:0.78em; margin:8px 0 0;">
                Multi-Engine Dorking &nbsp;·&nbsp; Live Verification &nbsp;·&nbsp;
                PDF Metadata &nbsp;·&nbsp; Risk Classification &nbsp;·&nbsp; JSON Logging
            </p>
        </div>
        """)

        with gr.Row(equal_height=False):

            # ── LEFT COLUMN — Controls ─────────────────────
            with gr.Column(scale=1, min_width=300):

                gr.HTML("<h3 style='color:#ff3333; margin-bottom:4px;'>⚙️ Target Configuration</h3>")

                domain_input = gr.Textbox(
                    label="🎯 Target Domain",
                    placeholder="example.com",
                    info="Domain only — no http:// needed",
                )

                file_types_input = gr.Textbox(
                    label="📁 File Extensions",
                    value="pdf, env, sql, docx, xlsx, conf, log, bak",
                    info="Comma or space separated (e.g. pdf, sql, env)",
                )

                engines_input = gr.CheckboxGroup(
                    label="🔍 Dorking Engines",
                    choices=["Google", "Bing", "DuckDuckGo"],
                    value=["Google", "Bing", "DuckDuckGo"],
                    info="Select one or more search engines",
                )

                scan_btn = gr.Button(
                    "🚀  LAUNCH RECON SCAN",
                    variant="primary",
                    elem_classes=["scan-btn"],
                    size="lg",
                )

                gr.HTML("""
                <div class="disclaimer">
                    <p style="color:#ff6666; font-size:0.82em; margin:0;">
                    ⚠️ <strong>Legal Notice:</strong>
                    Use SentinelOSINT ONLY on domains you own or have explicit written
                    authorization to test. Unauthorized scanning may violate computer
                    crime laws in your jurisdiction.
                    </p>
                </div>
                """)

                gr.HTML("""
                <div style="margin-top:14px; padding:10px; background:#0a0a14;
                            border-radius:8px; border:1px solid #222;">
                    <p style="color:#666; font-size:0.78em; margin:0; line-height:1.7;">
                    <strong style="color:#ff3333;">Risk Levels:</strong><br>
                    🔴 CRITICAL &nbsp;— .env .sql .conf .key .bak .db<br>
                    🟠 HIGH &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;— .log .xml .json .yaml .php<br>
                    🟡 MEDIUM &nbsp;&nbsp;&nbsp;— .xlsx .docx .csv .xls<br>
                    🟢 LOW &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;— .pdf .txt .rtf
                    </p>
                </div>
                """)

            # ── RIGHT COLUMN — Output ──────────────────────
            with gr.Column(scale=2):

                gr.HTML("<h3 style='color:#ff3333; margin-bottom:4px;'>📊 Intelligence Report</h3>")

                with gr.Row():
                    with gr.Column(scale=1):
                        critical_output = gr.Label(
                            label="🔴 Total Critical Leaks",
                            value="0",
                            elem_classes=["critical-counter"],
                        )
                    with gr.Column(scale=3):
                        gr.HTML("""
                        <div style="padding:10px; background:#0a0a14; border-radius:8px;
                                    border:1px solid #1a1a2e; height:100%; box-sizing:border-box;">
                            <p style="color:#666; font-size:0.8em; margin:0; line-height:1.8;">
                            <strong style="color:#aaa;">Output Files</strong><br>
                            📄 <code style="color:#00ff88;">scan_results.json</code> — Full JSON report<br>
                            📋 Scan log visible below in real-time
                            </p>
                        </div>
                        """)

                results_output = gr.Textbox(
                    label="📋 Scan Log",
                    lines=22,
                    placeholder="Scan log will appear here after launching the recon...\n\nNote: Scanning may take 1-3 minutes depending on extensions and engines selected.",
                    interactive=False,
                )

                summary_table = gr.Dataframe(
                    headers=["URL", "File Type", "Risk Level", "PDF Metadata"],
                    label="📑 Summary Table — Live Findings",
                    interactive=False,
                    wrap=True,
                )

        # ── Footer ────────────────────────────────────────
        gr.HTML("""
        <div style="text-align:center; margin-top:16px; color:#333; font-size:0.78em;">
            SentinelOSINT v1.0.0 &nbsp;|&nbsp; For authorized security testing only &nbsp;|&nbsp;
            Results persisted in scan_results.json
        </div>
        """)

        # ── Wire Up ────────────────────────────────────────
        scan_btn.click(
            fn=run_scan,
            inputs=[domain_input, file_types_input, engines_input],
            outputs=[results_output, critical_output, summary_table],
        )

    return demo


# ─────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(BANNER)
    demo = create_interface()
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        inbrowser=True,
        show_error=True,
        css=CUSTOM_CSS,
    )
