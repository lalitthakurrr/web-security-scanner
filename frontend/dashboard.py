import os

import pandas as pd
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000/api").rstrip("/")
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

st.set_page_config(page_title="Security Scanner", page_icon="◈", layout="wide")
st.markdown("""
<style>
    .stApp { background: #f6f7f5; color: #17251f; }
    [data-testid="stSidebar"] { background: #172c24; }
    [data-testid="stSidebar"] * { color: #eef5f0; }
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] { color: #b5c9bd; }
    [data-testid="stSidebar"] [data-testid="stAlert"] * { color: #213a2a; }
    .block-container { max-width: 1320px; padding-top: 2.4rem; padding-bottom: 4rem; }
    h1, h2, h3 { letter-spacing: -0.035em; color: #17251f; }
    h1 { font-size: 2.2rem !important; }
    h2 { font-size: 1.45rem !important; }
    h3 { font-size: 1.05rem !important; }
    p, label, [data-testid="stCaptionContainer"] { line-height: 1.5; }
    [data-testid="stMetric"] { background: white; border: 1px solid #e1e8e2; border-radius: 10px; padding: 18px; }
    [data-testid="stMetricLabel"] { color: #66776d; }
    [data-testid="stMetricValue"] { font-size: 1.65rem; }
    [data-testid="stTabs"] [data-baseweb="tab-list"] { gap: 1.5rem; border-bottom: 1px solid #dce5de; }
    [data-testid="stTabs"] [data-baseweb="tab"] { padding: 0.7rem 0; color: #586a5e; font-weight: 600; }
    [data-testid="stTabs"] [aria-selected="true"] { color: #206547; }
    [data-testid="stExpander"] { background: white; border: 1px solid #e1e8e2; border-radius: 8px; }
    .stButton button, .stDownloadButton button { border-radius: 7px; font-weight: 600; }
    .eyebrow { color: #3f7c59; text-transform: uppercase; letter-spacing: .14em; font-size: .72rem; font-weight: 700; margin-bottom: .4rem; }
    .intro { color: #617169; font-size: 1rem; max-width: 700px; margin-bottom: 1.5rem; }
    .sidebar-title { font-size: 1.22rem; font-weight: 700; letter-spacing: -.03em; margin: .25rem 0; }
    .sidebar-note { color: #b5c9bd !important; font-size: .85rem; line-height: 1.6; }
    hr { border-color: #e1e8e2; }
</style>
""", unsafe_allow_html=True)


def api(method, path, **kwargs):
    try:
        response = requests.request(method, f"{API_BASE_URL}{path}", timeout=15, **kwargs)
        if not response.ok:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            st.error(f"Request failed ({response.status_code}): {detail}")
            return None
        return response
    except requests.RequestException as exc:
        st.error(f"Couldn't reach the scanner service: {exc}")
        return None


def score(scan):
    value = scan.get("security_score")
    return f"{value:.1f}" if scan.get("status") == "completed" and value is not None else "—"


def scan_label(scan):
    return f"#{scan['id']}  ·  {scan['target_url']}  ·  {scan['status'].title()}"


def scan_table(scans):
    return pd.DataFrame([{
        "ID": s["id"], "Target": s["target_url"], "Status": s["status"].title(),
        "Score / 100": score(s), "Findings": s.get("total_findings", 0),
        "Pages": s.get("total_urls_crawled", 0), "Started": (s.get("start_time") or "")[:16].replace("T", " "),
    } for s in scans])


try:
    online = requests.get(f"{API_BASE_URL}/health", timeout=3).ok
except requests.RequestException:
    online = False

with st.sidebar:
    st.markdown('<div class="eyebrow">Security workspace</div><div class="sidebar-title">◈ &nbsp;Scanner</div>', unsafe_allow_html=True)
    st.markdown('<p class="sidebar-note">A clearer view of your web security checks.</p>', unsafe_allow_html=True)
    st.divider()
    if online:
        st.success("Scanner connected")
    else:
        st.error("Scanner offline")
        st.caption("Start the backend and refresh this page.")
        if st.button("Retry connection", use_container_width=True):
            st.rerun()
    st.markdown('<p class="sidebar-note">Scores are based on the checks performed and are not a complete security assessment.</p>', unsafe_allow_html=True)

st.markdown('<div class="eyebrow">Web security</div>', unsafe_allow_html=True)
st.title("Security scanner")
st.markdown('<p class="intro">Run a scan, review what needs attention, and track changes over time.</p>', unsafe_allow_html=True)

new_tab, history_tab, report_tab, playground_tab, compare_tab = st.tabs(
    ["New scan", "Scan history", "Report", "Playground", "Compare"]
)

with new_tab:
    st.subheader("Start a scan")
    st.caption("Enter a site you are authorized to assess. The scanner checks pages, headers, cookies and common exposures.")
    left, right = st.columns([2, 1], gap="large")
    with left:
        target_url = st.text_input("Website URL", placeholder="https://example.com", help="Include https:// when available.")
        with st.expander("Notifications"):
            webhook_url = st.text_input("Webhook URL", placeholder="https://…", help="Optional URL for scan alerts.")
        st.caption("Tip: start with a small page limit for a quick overview.")
    with right:
        st.markdown("#### Scan settings")
        max_pages = st.slider("Maximum pages", 5, 100, 30, help="Maximum number of pages the crawler will visit.")
        max_depth = st.slider("Crawl depth", 1, 5, 3, help="How many links away from the starting page to follow.")
        interval = st.selectbox("Repeat scan", [0, 1, 6, 12, 24, 48], format_func=lambda x: "No schedule" if x == 0 else f"Every {x} hours")
    action, _ = st.columns([1, 3])
    with action:
        start = st.button("Start scan", type="primary", use_container_width=True, disabled=not online)
    if start:
        if not target_url.strip():
            st.warning("Enter a website URL to start.")
        else:
            response = api("POST", "/scans", json={"target_url": target_url.strip(), "max_depth": max_depth, "max_pages": max_pages, "webhook_url": webhook_url.strip() or None})
            if response is not None:
                st.session_state["selected_scan_id"] = response.json()["id"]
                st.session_state["report_selection"] = response.json()["id"]
                st.success(f"Scan #{response.json()['id']} started. Open Scan history to check its progress or Report to view it.")
    if interval:
        if st.button("Create recurring schedule", disabled=not online):
            if not target_url.strip():
                st.warning("Enter a website URL to create a schedule.")
            else:
                response = api("POST", "/schedules", json={"target_url": target_url.strip(), "interval_hours": interval, "max_depth": max_depth, "max_pages": max_pages})
                if response is not None:
                    st.success(f"Scheduled every {interval} hours. Manage it in Scan history.")

scans = []
if online:
    response = api("GET", "/scans")
    if response is not None:
        scans = response.json()

with history_tab:
    heading, refresh = st.columns([5, 1])
    with heading:
        st.subheader("Scan history")
        st.caption("Choose a scan to inspect its findings. Times are shown as returned by the scanner.")
    with refresh:
        if st.button("Refresh", use_container_width=True):
            st.rerun()
    if not online:
        st.info("Connect the scanner to view history.")
    elif not scans:
        st.info("No scans yet. Start one from the New scan tab.")
    else:
        if any(s["status"] in ("pending", "crawling", "scanning") for s in scans):
            st.info("A scan is in progress. Select Refresh to update its status.")
        st.dataframe(scan_table(scans), hide_index=True, use_container_width=True)
        options = {s["id"]: s for s in scans}
        ids = list(options)
        current = st.session_state.get("selected_scan_id")
        selected = st.selectbox("Choose a scan", ids, index=ids.index(current) if current in ids else 0, format_func=lambda i: scan_label(options[i]), key="history_selection")
        view, delete = st.columns([1, 3])
        with view:
            if st.button("View report", type="primary", use_container_width=True):
                st.session_state["selected_scan_id"] = selected
                st.session_state["report_selection"] = selected
                st.success("Selected. Open the Report tab to view it.")
        with delete:
            with st.popover("Delete scan"):
                st.write(f"Permanently delete scan #{selected} and its findings?")
                if st.button("Confirm delete", key="delete_scan"):
                    result = api("DELETE", f"/scans/{selected}")
                    if result is not None:
                        if st.session_state.get("selected_scan_id") == selected:
                            st.session_state.pop("selected_scan_id", None)
                        st.rerun()
    if online:
        st.divider()
        st.subheader("Recurring schedules")
        result = api("GET", "/schedules")
        schedules = result.json() if result is not None else []
        if schedules:
            st.dataframe(pd.DataFrame(schedules)[["id", "target_url", "interval_hours", "is_active", "last_run", "next_run"]].rename(columns={"id": "ID", "target_url": "Target", "interval_hours": "Interval (hours)", "is_active": "Active", "last_run": "Last run", "next_run": "Next run"}), hide_index=True, use_container_width=True)
            schedule_id = st.selectbox("Choose a schedule", [s["id"] for s in schedules], format_func=lambda i: f"#{i}")
            with st.popover("Cancel schedule"):
                st.write(f"Cancel schedule #{schedule_id}?")
                if st.button("Confirm cancellation"):
                    if api("DELETE", f"/schedules/{schedule_id}") is not None:
                        st.rerun()
        elif result is not None:
            st.caption("No recurring scans scheduled.")

with report_tab:
    st.subheader("Scan report")
    if not online:
        st.info("Connect the scanner to view reports.")
    elif not scans:
        st.info("Run a scan to see its report here.")
    else:
        options = {s["id"]: s for s in scans}
        ids = list(options)
        current = st.session_state.get("selected_scan_id")
        selected = st.selectbox("Scan", ids, index=ids.index(current) if current in ids else 0, format_func=lambda i: scan_label(options[i]), key="report_selection")
        result = api("GET", f"/scans/{selected}")
        if result is not None:
            scan = result.json()
            st.caption(scan["target_url"])
            metrics = st.columns(4)
            metrics[0].metric("Status", scan["status"].title())
            metrics[1].metric("Score", f"{score(scan)} / 100" if score(scan) != "—" else "—")
            metrics[2].metric("Findings", scan.get("total_findings", 0))
            metrics[3].metric("Pages", scan.get("total_urls_crawled", 0))
            if scan["status"] == "failed":
                st.error(scan.get("error_message") or "The scan failed. Try again.")
            elif scan["status"] != "completed":
                st.info("This scan is still running. Refresh the page to see the latest results.")
            else:
                st.caption("The score is a heuristic based on the checks performed; each rule is counted once at its highest severity.")
                findings = scan.get("findings", [])
                main, aside = st.columns([3, 1], gap="large")
                with main:
                    st.subheader("Findings")
                    if not findings:
                        st.success("No findings from the checks performed.")
                    else:
                        available = [s for s in SEVERITIES if any(f["severity"].upper() == s for f in findings)]
                        selected_severities = st.multiselect("Filter by severity", available, default=available)
                        filtered = [f for f in findings if f["severity"].upper() in selected_severities]
                        st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
                        for f in filtered:
                            with st.expander(f"{f['severity'].upper()}  ·  {f['title']}"):
                                st.caption(f"{f['category']}  ·  {f.get('cwe_id') or 'No CWE'}")
                                st.write(f"**URL:** {f['url']}")
                                st.write(f["description"])
                                st.markdown("**Evidence**")
                                st.code(f.get("evidence") or "Not available", language=None)
                                st.markdown("**Recommended action**")
                                st.write(f["remediation"])
                    crawled = scan.get("crawled_urls", [])
                    if crawled:
                        with st.expander(f"Pages checked ({len(crawled)})"):
                            st.dataframe(pd.DataFrame(crawled)[["url", "status_code", "content_type", "response_time_ms"]].rename(columns={"url": "URL", "status_code": "Status", "content_type": "Content type", "response_time_ms": "Response (ms)"}), hide_index=True, use_container_width=True)
                with aside:
                    st.subheader("Severity")
                    for severity in SEVERITIES:
                        st.write(f"{severity.title()}  ·  **{scan.get(severity.lower() + '_count', 0)}**")
                    st.divider()
                    if st.button("Prepare PDF report", use_container_width=True):
                        pdf = api("GET", f"/scans/{selected}/report")
                        if pdf is not None:
                            st.session_state["pdf_report"] = (selected, pdf.content)
                    pdf_report = st.session_state.get("pdf_report")
                    if pdf_report and pdf_report[0] == selected:
                        st.download_button("Download PDF", pdf_report[1], file_name=f"security-report-{selected}.pdf", mime="application/pdf", use_container_width=True)

with playground_tab:
    st.subheader("Practice in the playground")
    st.write("The included local target contains intentional security weaknesses, so you can explore the scanner safely.")
    st.markdown("**1. Start the target**")
    st.code("python tests/mock_target_app.py", language="bash")
    st.markdown("**2. Run a scan**")
    st.write("Enter `http://127.0.0.1:8888` in New scan. The target includes insecure headers, a test cookie and fake exposed files.")

with compare_tab:
    st.subheader("Compare scans")
    st.caption("Review changes between two completed scans of the same target.")
    completed = [s for s in scans if s.get("status") == "completed"]
    if len(completed) < 2:
        st.info("Complete at least two scans to compare results.")
    else:
        opts = {s["id"]: s for s in completed}
        ids = list(opts)
        a, b = st.columns(2)
        with a:
            base = st.selectbox("Baseline", ids, index=1, format_func=lambda i: scan_label(opts[i]), key="compare_base")
        with b:
            target = st.selectbox("Compare with", ids, format_func=lambda i: scan_label(opts[i]), key="compare_target")
        if base == target:
            st.warning("Choose two different scans.")
        elif opts[base]["target_url"] != opts[target]["target_url"]:
            st.warning("These scans have different target URLs; their results may not be directly comparable.")
        if st.button("Compare results", type="primary", disabled=base == target):
            result = api("GET", "/scans/diff", params={"base_scan_id": base, "target_scan_id": target})
            if result is not None:
                st.session_state["active_diff"] = (base, target, result.json())
        saved = st.session_state.get("active_diff")
        if saved and saved[:2] == (base, target):
            diff = saved[2]
            cols = st.columns(4)
            cols[0].metric("Baseline score", f"{diff['base_score']:.1f}")
            cols[1].metric("New score", f"{diff['target_score']:.1f}")
            cols[2].metric("Score change", f"{diff['score_delta']:+.1f}")
            cols[3].metric("New findings", diff.get("total_new", 0))
            for label, key in [("Resolved", "fixed_findings"), ("New", "new_findings"), ("Still present", "persistent_findings")]:
                items = diff.get(key, [])
                with st.expander(f"{label} ({len(items)})", expanded=bool(items) and label == "New"):
                    if not items:
                        st.caption("None.")
                    for finding in items:
                        st.write(f"**{finding['severity']} · {finding['title']}**")
                        st.caption(finding["url"])
