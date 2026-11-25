# 🛡️ Production Web Application Security Scanner & Audit Platform

A fully functional, asynchronous web application security audit engine, REST API, interactive Streamlit dashboard, and ReportLab PDF report generator built strictly with Python.

---

## 🌟 Architectural Features

- **🐍 Core Async Engine**: `httpx` and `BeautifulSoup` driven crawler capable of BFS domain link extraction, URL normalization, depth/page capping, and header inspection.
- **🔍 Security Rule Engine**: Modular rule suite evaluating:
  - **HTTP Security Headers**: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.
  - **Cookie Security Flags**: `Secure`, `HttpOnly`, and `SameSite` flags.
  - **TLS & Transport Encryption**: HTTPS enforcement & unencrypted traffic analysis.
  - **Information Disclosure**: Server header version leakage, sensitive HTML comment exposure (`TODO`, `password`, `key`), and sensitive path exposures (`.env`, `.git/HEAD`, `robots.txt`, `wp-config.php`, `backup.sql`).
  - **CORS Policies**: Insecure wildcard origins with credentials allowed.
- **📊 Risk Engine**: A heuristic Security Health Score (0.0 to 100.0). Each distinct rule deducts points once at its highest observed severity, even if it appears on multiple pages or cookies. The report retains every finding. This score reflects the checks performed, not a comprehensive security assessment or a CVSS score.
- **⚡ FastAPI Backend REST API**: Clean RESTful endpoints for starting, monitoring, listing, deleting scans, and downloading executive PDF reports.
- **🗄️ Database ORM**: SQLite database managed via SQLAlchemy models with clean relational mapping.
- **📈 Streamlit Dashboard**: Ultra-modern, dark-themed interactive UI with real-time stats, scan controls, vulnerability expanders, and PDF generator download buttons.
- **📄 ReportLab PDF Reporter**: Executive security assessment report generation with badges, tables, evidence snippets, and remediation steps.
- **🧪 Built-in Vulnerable Target Server**: `tests/mock_target_app.py` for immediate local end-to-end testing without external target setup.

---

## 🚀 Quick Start Guide

### 1. Installation & Environment Setup
Ensure Python 3.10+ is installed.

```bash
# Clone or navigate to the repository directory
cd d:\SEM-2\PythonProject

# Install required Python dependencies
pip install -r requirements.txt
```

### 2. Start Built-in Vulnerable Test App (Optional Target)
Run the local test target server in a separate terminal window:
```bash
python tests/mock_target_app.py
# Listens on http://127.0.0.1:8888
```

### 3. Launch FastAPI Backend API
Start the backend scanner server:
```bash
uvicorn app.main:app --reload --port 8000
# API Docs available at http://127.0.0.1:8000/docs
```

### 4. Launch Streamlit Dashboard Frontend
Start the interactive Streamlit UI:
```bash
streamlit run frontend/dashboard.py
# Dashboard opens automatically at http://localhost:8501
```

---

## 🧪 Running Automated Tests

Execute unit, crawler, rule, and API tests with pytest:
```bash
pytest -v tests/
```

---

## 🐳 Docker Deployment

To launch the complete application stack (Backend API + Streamlit Dashboard) in Docker:

```bash
docker compose up --build
```
- Streamlit Dashboard: `http://localhost:8501`
- FastAPI REST API: `http://localhost:8000/docs`
