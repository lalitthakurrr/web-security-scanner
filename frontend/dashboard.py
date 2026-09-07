import sys
import os
import re
import time
import requests
import streamlit as st
import pandas as pd

# Ensure app module is in Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# API Base URL
API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000/api")

# Streamlit Page Config
st.set_page_config(
    page_title="Web Application Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark Glassmorphic & Modern Security Palette)
st.markdown("""
<style>
    .main {
        background-color: #0B0F19;
        color: #F8FAFC;
    }
    .stMetric {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 15px;
        border-radius: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .severity-badge-critical {
        background-color: #DC2626; color: white; padding: 4px 8px; border-radius: 6px; font-weight: bold;
    }
    .severity-badge-high {
        background-color: #EA580C; color: white; padding: 4px 8px; border-radius: 6px; font-weight: bold;
    }
    .severity-badge-medium {
        background-color: #D97706; color: white; padding: 4px 8px; border-radius: 6px; font-weight: bold;
    }
    .severity-badge-low {
        background-color: #2563EB; color: white; padding: 4px 8px; border-radius: 6px; font-weight: bold;
    }
    .severity-badge-info {
        background-color: #64748B; color: white; padding: 4px 8px; border-radius: 6px; font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar Navigation Header
st.sidebar.markdown("# 🛡️ Security Scanner")
st.sidebar.caption("Enterprise Web Vulnerability & Audit Engine")

# Check API Health with Retry Logic & Detailed Diagnostics
def check_api_connection():
    last_error = None
    for attempt in range(2):
        try:
            r = requests.get(f"{API_BASE_URL}/health", timeout=8)
            if r.status_code == 200:
                return True, None
        except Exception as e:
            last_error = str(e)
            if attempt == 0:
                time.sleep(1)
    return False, last_error

api_online, api_error = check_api_connection()
if api_online:
    st.sidebar.success("Backend API: ONLINE 🟢")
else:
    st.sidebar.error("Backend API: OFFLINE 🔴")
    if api_error:
        with st.sidebar.expander("Diagnostics / Connection Details", expanded=False):
            st.caption(f"Target: `{API_BASE_URL}/health`")
            st.code(api_error, language="text")
    if st.sidebar.button("🔄 Recheck Connection", use_container_width=True):
        st.rerun()

# Main Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🚀 New Security Audit",
    "📊 Active & Past Scans",
    "🔍 Detailed Audit Report",
    "🎯 Target Playground",
    "🔄 Scan Diff & Comparison"
])

# ==========================================
# TAB 1: NEW SECURITY AUDIT
# ==========================================
with tab1:
    st.header("Initiate Web Application Security Scan")
    st.write("Perform asynchronous domain crawling, HTTP header checks, TLS configuration analysis, cookie flag audits, and sensitive path exposure discovery.")

    col_input, col_config = st.columns([2, 1])

    with col_input:
        target_url = st.text_input(
            "Target URL",
            placeholder="http://127.0.0.1:8888",
            help="Enter target protocol and hostname (e.g. http://127.0.0.1:8888)"
        )
        webhook_url = st.text_input(
            "Alert Webhook URL (Optional)",
            placeholder="https://hooks.slack.com/services/...",
            help="Optional Slack/Discord/Custom webhook URL to receive instant security alerts"
        )

    with col_config:
        max_depth = st.slider("Crawl Depth Limit", min_value=1, max_value=5, value=3)
        max_pages = st.slider("Max Crawl Pages Limit", min_value=5, max_value=100, value=30)
        interval_hours = st.selectbox("Recurring Schedule Interval", [0, 1, 6, 12, 24, 48], index=0, help="Select interval to create a recurring background schedule")

    btn_col1, btn_col2 = st.columns(2)

    with btn_col1:
        if st.button("▶ START INSTANT SCAN", type="primary", use_container_width=True):
            if not target_url:
                st.warning("⚠️ Please specify a target URL first.")
            elif not api_online:
                st.error("❌ Cannot launch scan: Backend API is offline.")
            else:
                # --- Client-side URL pre-validation ---
                raw = target_url.strip()
                # Temporarily prepend scheme for parsing if missing
                check_url = raw if raw.startswith(("http://", "https://")) else "http://" + raw
                from urllib.parse import urlparse as _urlparse
                _parsed = _urlparse(check_url)
                _hostname = _parsed.hostname or ""
                _local = {"localhost", "127.0.0.1", "::1"}

                _validation_error = None
                if not _hostname:
                    _validation_error = f"'{raw}' is not a valid URL — no hostname found."
                elif _hostname not in _local and "." not in _hostname:
                    _validation_error = (
                        f"'{_hostname}' is not a valid domain name. "
                        "Domains must contain a dot (e.g. google.com, upgrad.com). "
                        "Random words are not valid targets."
                    )
                elif not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-.]*[a-zA-Z0-9]$", _hostname) and _hostname not in _local:
                    _validation_error = f"'{_hostname}' contains illegal characters for a domain name."

                if _validation_error:
                    st.error(f"❌ Invalid Target URL\n\n{_validation_error}")
                else:
                    try:
                        payload = {
                            "target_url": raw,
                            "max_depth": max_depth,
                            "max_pages": max_pages,
                            "webhook_url": webhook_url.strip() if webhook_url else None
                        }
                        res = requests.post(f"{API_BASE_URL}/scans", json=payload)
                        if res.status_code == 202:
                            scan_data = res.json()
                            st.success(f"✅ Scan #{scan_data['id']} launched for `{raw}`! Check 'Active & Past Scans' tab.")
                            st.session_state["selected_scan_id"] = scan_data['id']
                        else:
                            # Show the backend's validation message cleanly
                            try:
                                err_detail = res.json().get("detail", res.text)
                            except Exception:
                                err_detail = res.text
                            st.error(f"❌ Scan rejected\n\n{err_detail}")
                    except Exception as e:
                        st.error(f"❌ Error connecting to backend API: {e}")

    with btn_col2:
        if interval_hours > 0:
            if st.button("⏰ SCHEDULE RECURRING SCAN", use_container_width=True):
                if not target_url:
                    st.warning("⚠️ Please specify a target URL first.")
                elif not api_online:
                    st.error("❌ Cannot schedule scan: Backend API is offline.")
                else:
                    try:
                        payload = {
                            "target_url": target_url.strip(),
                            "interval_hours": interval_hours,
                            "max_depth": max_depth,
                            "max_pages": max_pages
                        }
                        res = requests.post(f"{API_BASE_URL}/schedules", json=payload)
                        if res.status_code == 201:
                            st.success(f"✅ Recurring scan scheduled every {interval_hours} hours for `{target_url}`!")
                        else:
                            try:
                                err_detail = res.json().get("detail", res.text)
                            except Exception:
                                err_detail = res.text
                            st.error(f"❌ Schedule rejected\n\n{err_detail}")
                    except Exception as e:
                        st.error(f"❌ Error scheduling scan: {e}")

# ==========================================
# TAB 2: ACTIVE & PAST SCANS
# ==========================================
with tab2:
    st.header("Security Scan History & Schedules")

    if not api_online:
        st.info("Connect to backend API to view history.")
    else:
        try:
            res = requests.get(f"{API_BASE_URL}/scans")
            if res.status_code == 200:
                scans = res.json()
                if not scans:
                    st.info("No security scans executed yet. Launch a new scan in Tab 1!")
                else:
                    # Check if any scan is currently in progress to auto-trigger background refresh
                    running_scans = [s for s in scans if s.get("status") in ["pending", "crawling", "scanning"]]
                    if running_scans:
                        st.info(f"⏳ {len(running_scans)} scan(s) currently active... Auto-refreshing in 5s.")
                        # Use a state counter to limit refresh frequency without blocking the thread
                        if "refresh_counter" not in st.session_state:
                            st.session_state["refresh_counter"] = 0
                        st.session_state["refresh_counter"] += 1
                        time.sleep(5)
                        st.rerun()

                    df = pd.DataFrame(scans)
                    df_display = df[[
                        "id", "target_url", "status", "security_score",
                        "total_findings", "total_urls_crawled", "start_time", "duration_seconds"
                    ]].copy()

                    df_display.columns = [
                        "ID", "Target URL", "Status", "Score",
                        "Findings", "Pages Crawled", "Start Time", "Duration (s)"
                    ]

                    st.dataframe(df_display, use_container_width=True)

                    st.markdown("---")
                    col_sel, col_del = st.columns([3, 1])
                    scan_ids = [s["id"] for s in scans]
                    with col_sel:
                        selected_id = st.selectbox(
                            "Select Scan for Detailed Inspection",
                            scan_ids,
                            index=0 if "selected_scan_id" not in st.session_state or st.session_state["selected_scan_id"] not in scan_ids
                                  else scan_ids.index(st.session_state["selected_scan_id"])
                        )

                    with col_del:
                        st.write("")
                        st.write("")
                        if st.button("🗑️ DELETE SELECTED SCAN", type="secondary", use_container_width=True):
                            del_res = requests.delete(f"{API_BASE_URL}/scans/{selected_id}")
                            if del_res.status_code == 204:
                                st.success(f"Scan #{selected_id} deleted!")
                                if st.session_state.get("selected_scan_id") == selected_id:
                                    st.session_state["selected_scan_id"] = None
                                st.rerun()
                            else:
                                st.error(f"Failed to delete scan #{selected_id}")

                    if st.button("🔍 INSPECT AUDIT REPORT DETAIL", type="primary", use_container_width=True):
                        st.session_state["selected_scan_id"] = selected_id
                        st.rerun()
                    
                    if st.session_state.get("selected_scan_id") == selected_id:
                        st.info("✅ Scan selected! Please click the '🔍 Detailed Audit Report' tab at the top of the screen to view the results.")

            # Active Recurring Schedules
            st.markdown("---")
            st.subheader("⏰ Configured Recurring Scan Schedules")
            sched_res = requests.get(f"{API_BASE_URL}/schedules")
            if sched_res.status_code == 200:
                schedules = sched_res.json()
                if schedules:
                    sdf = pd.DataFrame(schedules)
                    st.dataframe(sdf[["id", "target_url", "interval_hours", "is_active", "last_run", "next_run"]], use_container_width=True)
                    
                    sc_col1, sc_col2 = st.columns([3, 1])
                    with sc_col1:
                        del_sched_id = st.selectbox("Select Schedule ID to Cancel", [s["id"] for s in schedules])
                    with sc_col2:
                        st.write("")
                        st.write("")
                        if st.button("❌ CANCEL SCHEDULE", use_container_width=True):
                            del_sc_res = requests.delete(f"{API_BASE_URL}/schedules/{del_sched_id}")
                            if del_sc_res.status_code == 204:
                                st.success(f"Schedule #{del_sched_id} cancelled successfully!")
                                st.rerun()
                            else:
                                st.error(f"Failed to cancel schedule #{del_sched_id}")
                else:
                    st.caption("No active recurring schedules configured.")

        except Exception as e:
            st.error(f"Error retrieving scans: {e}")

# ==========================================
# TAB 3: DETAILED AUDIT REPORT
# ==========================================
with tab3:
    st.header("Vulnerability Audit & Analytical Deep-Dive")

    selected_scan_id = st.session_state.get("selected_scan_id")

    if not selected_scan_id or not api_online:
        st.info("Select a scan from 'Active & Past Scans' tab to inspect details.")
    else:
        try:
            res = requests.get(f"{API_BASE_URL}/scans/{selected_scan_id}")
            if res.status_code == 200:
                scan = res.json()
                findings = scan.get("findings", [])

                # Top Metrics Bar
                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("Target Host", scan["target_url"])
                m2.metric("Scan Status", scan["status"].upper())
                m3.metric("Security Score", f"{scan['security_score']:.1f} / 100")
                m4.metric("Total Findings", scan["total_findings"])
                m5.metric("Crawled URLs", scan["total_urls_crawled"])

                st.markdown("---")

                col_left, col_right = st.columns([3, 1])

                with col_left:
                    st.subheader("Vulnerability Findings")
                    
                    if not findings:
                        st.success("🎉 No security vulnerabilities detected for this target!")
                    else:
                        # Severity Filter
                        severities = list(set(f["severity"].upper() for f in findings))
                        selected_sev = st.multiselect("Filter by Severity", severities, default=severities)

                        filtered_findings = [f for f in findings if f["severity"].upper() in selected_sev]

                        for idx, f in enumerate(filtered_findings, 1):
                            with st.expander(f"#{idx} [{f['severity'].upper()}] {f['title']} - {f['url']}"):
                                st.markdown(f"**Category:** {f['category']} | **CWE:** {f['cwe_id'] or 'N/A'}")
                                st.markdown(f"**Description:** {f['description']}")
                                st.markdown("**Evidence:**")
                                st.code(f['evidence'] or "N/A", language="text")
                                st.markdown(f"**Remediation:** {f['remediation']}")

                    # Crawled URLs Table
                    crawled_list = scan.get("crawled_urls", [])
                    if crawled_list:
                        st.markdown("---")
                        with st.expander(f"🌐 Crawled Endpoints & Response Times ({len(crawled_list)} URLs)"):
                            cdf = pd.DataFrame(crawled_list)
                            st.dataframe(cdf[["url", "status_code", "content_type", "response_time_ms"]], use_container_width=True)

                with col_right:
                    st.subheader("Executive Actions")
                    if scan["status"] == "completed":
                        report_url = f"{API_BASE_URL}/scans/{scan['id']}/report"
                        try:
                            rep_res = requests.get(report_url)
                            if rep_res.status_code == 200:
                                st.download_button(
                                    label="📄 DOWNLOAD PDF REPORT",
                                    data=rep_res.content,
                                    file_name=f"Security_Report_Scan_{scan['id']}.pdf",
                                    mime="application/pdf",
                                    use_container_width=True
                                )
                        except Exception as ex:
                            st.error(f"Error fetching PDF: {ex}")

                    st.markdown("### Severity Distribution")
                    sev_summary = {
                        "Critical": scan["critical_count"],
                        "High": scan["high_count"],
                        "Medium": scan["medium_count"],
                        "Low": scan["low_count"],
                        "Info": scan["info_count"]
                    }
                    st.bar_chart(pd.DataFrame.from_dict(sev_summary, orient='index', columns=['Count']))

        except Exception as e:
            st.error(f"Error fetching scan detail: {e}")

# ==========================================
# TAB 4: TARGET PLAYGROUND (VULNERABLE MOCK SERVER)
# ==========================================
with tab4:
    st.header("Built-in Vulnerable Target Playground")
    st.write("Launch a local deliberately misconfigured web application to safely test and demonstrate scanner capabilities live.")

    st.markdown("""
    The playground environment contains intentional security flaws:
    - ❌ Missing CSP, HSTS, X-Frame-Options, and Referrer-Policy headers
    - ❌ Insecure Session Cookie (Missing `HttpOnly`, `Secure`, and `SameSite` flags)
    - ❌ Exposed `.env` file containing fake database credentials
    - ❌ Exposed `.git/HEAD` repository metadata
    - ❌ HTML developer comment leaking internal admin credentials
    """)

    st.info("The target server runs locally on **`http://127.0.0.1:8888`**.")
    st.code("python tests/mock_target_app.py", language="bash")

# ==========================================
# TAB 5: SCAN DIFF & COMPARISON
# ==========================================
with tab5:
    st.header("🔄 Historical Scan Comparison & Diff Engine")
    st.write("Compare two security scans of a domain to evaluate security score deltas, newly introduced risks, and resolved vulnerabilities.")

    if not api_online:
        st.info("Connect to backend API to perform comparison.")
    else:
        try:
            scans_res = requests.get(f"{API_BASE_URL}/scans")
            if scans_res.status_code == 200:
                scans = scans_res.json()
                completed_scans = [s for s in scans if s.get("status") == "completed"]

                if len(completed_scans) < 2:
                    st.info("Execute at least 2 completed security scans to enable side-by-side diff comparison!")
                    if len(scans) >= 2:
                        st.caption("Note: Scans must be in 'completed' status to perform comparison. Wait for active scans to finish.")
                else:
                    # Safely extract labels without crashing on missing dates or duplicate values
                    scan_opts = {}
                    for s in completed_scans:
                        st_time = str(s.get('start_time', ''))[:16] if s.get('start_time') else "N/A"
                        score_val = s.get('security_score')
                        score_str = f"{score_val:.1f}" if score_val is not None else "100.0"
                        label = f"Scan #{s['id']} - {s.get('target_url', '')} (Score: {score_str} | {st_time})"
                        scan_opts[label] = s['id']

                    labels_list = list(scan_opts.keys())

                    col_base, col_target = st.columns(2)
                    with col_base:
                        base_label = st.selectbox(
                            "Select Baseline Scan (Scan A)",
                            labels_list,
                            index=min(1, len(labels_list) - 1)
                        )
                        base_id = scan_opts[base_label]

                    with col_target:
                        target_label = st.selectbox(
                            "Select Comparison Scan (Scan B)",
                            labels_list,
                            index=0
                        )
                        target_id = scan_opts[target_label]

                    if st.button("🔍 COMPARE SCANS NOW", type="primary", use_container_width=True):
                        with st.spinner("Fetching scan diff..."):
                            diff_res = requests.get(f"{API_BASE_URL}/scans/diff?base_scan_id={base_id}&target_scan_id={target_id}")
                            if diff_res.status_code == 200:
                                st.session_state["active_diff"] = diff_res.json()
                            else:
                                st.error(f"Failed to fetch scan comparison (HTTP {diff_res.status_code}): {diff_res.text}")

                    active_diff = st.session_state.get("active_diff")
                    if active_diff:
                        st.markdown("---")
                        delta = active_diff.get("score_delta", 0.0)
                        d_col1, d_col2, d_col3, d_col4, d_col5 = st.columns(5)
                        d_col1.metric("Baseline Score (Scan A)", f"{active_diff.get('base_score', 0.0):.1f}")
                        d_col2.metric("New Score (Scan B)", f"{active_diff.get('target_score', 0.0):.1f}")
                        d_col3.metric("Score Delta", f"{delta:+.1f}", delta_color="normal" if delta >= 0 else "inverse")
                        d_col4.metric("Fixed Risks", active_diff.get("total_fixed", 0))
                        d_col5.metric("New Risks", active_diff.get("total_new", 0))

                        st.markdown("---")
                        diff_tabs = st.tabs([
                            f"✅ Resolved Vulnerabilities ({active_diff.get('total_fixed', 0)})",
                            f"⚠️ Newly Introduced Risks ({active_diff.get('total_new', 0)})",
                            f"🔄 Persistent Risks ({active_diff.get('total_persistent', 0)})"
                        ])

                        with diff_tabs[0]:
                            fixed_list = active_diff.get("fixed_findings", [])
                            if not fixed_list:
                                st.success("No vulnerabilities were resolved between these two scans.")
                            else:
                                for f in fixed_list:
                                    st.success(f"**[{f['severity']}]** {f['title']}\n\n*URL:* `{f['url']}`\n\n*Category:* {f.get('category', 'N/A')}")

                        with diff_tabs[1]:
                            new_list = active_diff.get("new_findings", [])
                            if not new_list:
                                st.info("No new vulnerabilities introduced.")
                            else:
                                for f in new_list:
                                    st.error(f"**[{f['severity']}]** {f['title']}\n\n*URL:* `{f['url']}`\n\n*Remediation:* {f.get('remediation', 'N/A')}")

                        with diff_tabs[2]:
                            persistent_list = active_diff.get("persistent_findings", [])
                            if not persistent_list:
                                st.info("No persistent vulnerabilities found.")
                            else:
                                for f in persistent_list:
                                    st.warning(f"**[{f['severity']}]** {f['title']}\n\n*URL:* `{f['url']}`\n\n*Remediation:* {f.get('remediation', 'N/A')}")

            else:
                st.error(f"Failed to retrieve scans history from API (HTTP {scans_res.status_code})")

        except Exception as e:
            st.error(f"Error executing scan diff: {e}")
