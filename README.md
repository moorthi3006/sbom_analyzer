
sbom-risk-analyzer/
│
├── backend/
│   ├── api/
│   │     ├── routes.py
│   │     └── upload.py
│   │
│   ├── services/
│   │     ├── parser.py
│   │     ├── vulnerability_service.py
│   │     ├── dependency_graph.py
│   │     ├── license_checker.py
│   │     ├── maintenance_checker.py
│   │     ├── risk_score.py
│   │     └── report_generator.py
│   │
│   ├── models/
│   │     └── schemas.py
│   │
│   ├── utils/
│   │     └── helpers.py
│   │
│   └── main.py
│
├── frontend/
│   ├── Dashboard
│   ├── Upload Page
│   ├── Graph View
│   ├── Reports
│   └── Components
│
├── data/
│   ├── applications.json
│   ├── sbom_dependencies.csv
│   ├── vulnerability_db.json
│   └── license_rules.json
│
├── reports/
│
├── docs/
│
├── requirements.txt
│
└── README.md# sbom_analyzer
