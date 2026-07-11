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

Open **http://127.0.0.1:5000** and log in:

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin123` |

## Project Structure

```
sbom_analyzer/
├── app.py                  # Application entry point
├── config.py               # Configuration settings
├── requirements.txt        # Python dependencies
├── database.db             # SQLite database (auto-created)
├── sample_data/            # Sample SBOM and license files
├── uploads/                # Uploaded SBOM files
├── reports/                # Generated PDF reports
├── graphs/                 # Dependency graph images
├── backend/
│   ├── models/             # SQLAlchemy database models
│   ├── services/           # Business logic modules
│   ├── routes/             # Flask blueprints
│   └── utils/              # Helpers and seed data
├── templates/              # Jinja2 HTML templates
└── static/                 # CSS, JS, images
```

## Pages

1. **Login** — Authentication
2. **Dashboard** — Risk overview, charts, recent scans
3. **Upload SBOM** — JSON/CSV file import
4. **Applications** — Application inventory with risk scores
5. **Dependency Explorer** — Tree and graph views
6. **Vulnerabilities** — CVE list with filtering
7. **License Analysis** — Compatibility matrix and conflicts
8. **Maintenance** — Outdated library tracking
9. **Reports** — PDF generation and download
10. **Settings** — Profile and system configuration

## Risk Score Formula

```
Risk Score = CVSS Score + License Penalty + Maintenance Penalty + Dependency Depth Weight
```

| Level | Threshold |
|-------|-----------|
| Low | < 25 |
| Medium | 25–50 |
| High | 50–75 |
| Critical | ≥ 75 |

## Sample Data

The application seeds realistic data on first run:

- 10 enterprise applications
- 500+ dependencies
- 200+ CVEs
- License compatibility matrix

Sample SBOM files are available in `sample_data/` for testing uploads.

## License

Built for cybersecurity hackathon demonstration purposes.
