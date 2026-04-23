# 🛡️ SentinelOSINT v1.0.0
### Professional OSINT Reconnaissance Framework

> **Legal Notice:** Use SentinelOSINT **only** on domains you own or have explicit written authorization to test. Unauthorized scanning may violate computer crime laws in your jurisdiction.

---

## 📐 Architecture Overview

```
Phase 1 → Input & Configuration     (Gradio GUI)
Phase 2 → Multi-Engine Dorking      (Google + Bing + DuckDuckGo)
Phase 3 → Validation & Intelligence (Live-check + PDF Metadata)
Phase 4 → Risk Classification       (CRITICAL / HIGH / MEDIUM / LOW)
Phase 5 → Persistence & Dashboard   (scan_results.json + Summary Table)
```

---

## ⚡ Quick Start

### 1. Prerequisites
- Python **3.8 or higher**
- pip

### 2. Install Dependencies

```bash
# Clone or download the project folder, then:
cd SentinelOSINT
pip install -r requirements.txt
```

### 3. Run

```bash
python sentinel_osint.py
```

The browser will open automatically at **http://127.0.0.1:7860**

---

## 🖥️ Interface Guide

| Field | Description |
|---|---|
| **Target Domain** | Enter `example.com` (no `http://`) |
| **File Extensions** | Comma-separated: `pdf, env, sql, docx, bak` |
| **Dorking Engines** | Select Google, Bing, DuckDuckGo (or all three) |
| **Launch Recon Scan** | Starts the full 5-phase pipeline |

### Output Panels
- **Scan Log** — Real-time phase-by-phase log with live/dead link status
- **Critical Leaks Counter** — Total CRITICAL-risk files found
- **Summary Table** — Sortable table with URL, file type, risk level, metadata flag

---

## 🔍 Dorking Engine Details

| Engine | Dork Format | Notes |
|---|---|---|
| Google | `site:domain filetype:ext` | Most indexed; most likely to block scrapers |
| Bing | `site:domain filetype:ext` | Less aggressive blocking; good fallback |
| DuckDuckGo | `site:domain filetype:ext` | HTML frontend; most scraper-friendly |

**Anti-bot measures implemented:**
- Random `User-Agent` rotation from a pool of 10 real browser UAs
- Randomized time delays between requests (1.5–4 seconds)
- Sequential engine queries (not parallel) to reduce detection fingerprint

---

## ⚠️ Risk Classification

| Level | Extensions |
|---|---|
| 🔴 **CRITICAL** | `.env` `.sql` `.conf` `.config` `.key` `.pem` `.bak` `.backup` `.db` `.sqlite` `.sh` `.htpasswd` `.passwd` `.id_rsa` |
| 🟠 **HIGH** | `.log` `.xml` `.json` `.yaml` `.yml` `.php` `.asp` `.aspx` `.jsp` |
| 🟡 **MEDIUM** | `.xlsx` `.xls` `.docx` `.doc` `.csv` `.pptx` `.mdb` |
| 🟢 **LOW** | `.pdf` `.txt` `.rtf` `.odt` |

---

## 🧠 PDF Metadata Extraction

When `.pdf` is included in the scan, SentinelOSINT downloads each PDF (up to **3 MB**) and extracts:

- `Author` — Who wrote/submitted it
- `Creator` — Application that created it (e.g., "Microsoft Word 2010")
- `Producer` — PDF converter used (e.g., "Adobe Distiller")
- `CreationDate` / `ModDate`
- `Title` / `Subject`
- `Pages`

This intelligence appears in both the scan log and the `scan_results.json` report.

**Library used:** `PyPDF2` (primary) → `pikepdf` (fallback)

---

## 💾 Output: scan_results.json

Every scan appends to `scan_results.json` in the same folder. Example entry:

```json
{
    "scan_id": "20240415_143022_123456",
    "timestamp": "2024-04-15T14:30:22.123456",
    "target_domain": "example.com",
    "file_type": ".pdf",
    "total_live_links": 3,
    "critical_leaks": 0,
    "links": [
        {
            "url": "https://example.com/files/report.pdf",
            "risk_score": "LOW",
            "pdf_metadata": {
                "Author": "John Smith",
                "Creator": "Microsoft Word 2016",
                "Producer": "Adobe PDF Library 15.0",
                "CreationDate": "D:20230101120000Z",
                "Pages": 12,
                "library_used": "PyPDF2"
            }
        }
    ]
}
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---|---|
| **No results found** | Search engines blocked the query. Use a VPN and retry after a few minutes. |
| **Google always blocked** | Use Bing + DuckDuckGo only. Google is most aggressive with CAPTCHA. |
| **PDF metadata shows N/A** | The PDF has no embedded metadata (common in scanned/protected PDFs). |
| **`ModuleNotFoundError: PyPDF2`** | Run `pip install PyPDF2` |
| **Port 7860 already in use** | Change `server_port=7860` in the last line of `sentinel_osint.py` |

---

## 📁 Project Structure

```
SentinelOSINT/
├── sentinel_osint.py     ← Main application (run this)
├── requirements.txt      ← Python dependencies
├── README.md             ← This file
└── scan_results.json     ← Auto-created on first scan
```

---

## 🔧 Extending SentinelOSINT

**Add a new search engine:**
```python
# In sentinel_osint.py, create a new function:
def dork_yahoo(domain, file_type, log):
    query = f"site:{domain} filetype:{file_type}"
    url = f"https://search.yahoo.com/search?p={quote_plus(query)}"
    # ... scraping logic ...

# Then add "Yahoo" to the engines_input choices in create_interface()
# And call dork_yahoo() inside run_scan() when selected
```

**Add Office document metadata extraction:**
```python
# pip install python-docx openpyxl
# Follow the same pattern as extract_pdf_metadata()
```

---

*SentinelOSINT v1.0.0 — For authorized security testing only.*
