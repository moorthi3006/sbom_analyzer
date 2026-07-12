# SBOM Analyzer — Software Supply Chain Risk Scorer

Hackathon-ready application for analysing Software Bills of Materials (SBOMs), highlighting supply-chain risks, and generating actionable security reports.

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

```powershell
pip install -r requirements.txt
$env:ADMIN_PASSWORD = "choose-a-strong-demo-password"
$env:SECRET_KEY = "a-long-random-secret"
python app.py
```

Open **http://127.0.0.1:5000**

Sign in as `admin` with the `ADMIN_PASSWORD` you set above. The app does not ship a usable default password.

## Dataset and demo scope

The supplied `original datasets/vulnerability_db.json` is loaded automatically. Findings are matched by package **and affected version**. Unknown packages are shown without fabricated CVEs. This makes the demo results traceable; connect an OSV/NVD feed for continuously updated production coverage.

## Validation

```powershell
python -m unittest discover -s tests -v
```

## License

Built for cybersecurity hackathon demonstration purposes.
