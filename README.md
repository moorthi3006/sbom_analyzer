# SBOM Analyzer — Software Supply Chain Risk Scorer

Enterprise-style modular application for analyzing Software Bill of Materials (SBOM), assessing supply chain security risks, and generating actionable security reports.

## Features

- **SBOM Parsing** — Import JSON (CycloneDX) and CSV SBOM files
- **Vulnerability Scanning** — CVE detection with CVSS scoring and severity classification
- **License Analysis** — Compatibility checking and conflict detection
- **Maintenance Analysis** — Outdated library detection and maintenance risk assessment
- **Dependency Graph** — Tree and graph visualization with NetworkX
- **Risk Scoring** — Composite risk engine: CVSS + License + Maintenance + Depth
- **PDF Reports** — Enterprise security assessment reports via ReportLab
- **Dashboard Analytics** — Real-time charts, cards, and trend analysis

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| Backend | Python, Flask, SQLAlchemy, SQLite |
| Analysis | NetworkX, Pandas, Matplotlib, ReportLab |
| Frontend | HTML, CSS, JavaScript, Bootstrap 5, Chart.js |

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**

Username: `admin`

Password: `admin123`

## License

Built for cybersecurity hackathon demonstration purposes.