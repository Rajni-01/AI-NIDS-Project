import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone
import html
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import streamlit as st

from src.nids_backend import (
    load_model_and_encoder,
    load_prediction_csv,
    predict_from_flow_dataframe,
    generate_multi_attack_dataset,
    predictions_to_incidents,
    compute_metrics_and_datasets,
    CLASS_SEVERITY,
    SAMPLE_PRED_PATH,
)

st.set_page_config(
    page_title="Sentinel Network — Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom CSS (Sentinel Dark Theme) ---
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

    :root {
        --bg: #080d1c;
        --surface: #101a2d;
        --line: #26344e;
        --text: #edf4ff;
        --muted: #8e9eb8;
        --cyan: #55d9ed;
        --violet: #9a88ff;
        --red: #ff667f;
        --amber: #ffbd6e;
        --green: #55d7ad;
    }

    html, body, [class*="css"] {
        font-family: "DM Sans", sans-serif;
        color: var(--text);
    }

    .stApp {
        background:
            radial-gradient(circle at 74% -18%, #26345d 0, transparent 38%),
            linear-gradient(145deg, #0b1428 0%, #080d1c 60%, #10122b 100%);
    }

    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, rgba(17,29,51,0.98), rgba(10,16,33,0.98));
        border-right: 1px solid #26334a;
    }

    .eyebrow {
        color: var(--cyan);
        text-transform: uppercase;
        letter-spacing: 2.2px;
        font-size: 11px;
        font-weight: 700;
        margin-bottom: 4px;
    }

    .page-title {
        font-family: "Space Grotesk", sans-serif;
        font-size: 32px;
        font-weight: 700;
        letter-spacing: -1px;
        margin: 0;
        color: #edf4ff;
    }

    .subtitle {
        color: var(--muted);
        font-size: 13px;
        margin-top: 4px;
        margin-bottom: 20px;
    }

    .kpi-card {
        background: linear-gradient(145deg, rgba(24,37,61,0.94), rgba(15,25,43,0.96));
        border: 1px solid #2a3953;
        border-top: 2px solid var(--accent, #55d9ed);
        border-radius: 13px;
        padding: 18px 20px;
        box-shadow: 0 12px 30px rgba(4,9,23,0.25);
    }

    .kpi-label {
        color: #9cacc5;
        font-size: 12px;
        font-weight: 700;
    }

    .kpi-value {
        font-family: "Space Grotesk", sans-serif;
        font-size: 29px;
        font-weight: 700;
        margin: 10px 0 4px;
        color: #edf4ff;
    }

    .kpi-note {
        font-size: 11px;
        color: var(--muted);
    }

    .panel-box {
        background: linear-gradient(145deg, rgba(24,37,61,0.94), rgba(15,25,43,0.96));
        border: 1px solid #2a3953;
        border-radius: 13px;
        padding: 20px;
        margin-bottom: 16px;
    }

    .panel-title {
        font-family: "Space Grotesk", sans-serif;
        font-size: 16px;
        font-weight: 700;
        margin: 0 0 4px 0;
    }

    .panel-kicker {
        font-size: 12px;
        color: var(--muted);
        margin: 0 0 16px 0;
    }

    .tag {
        display: inline-block;
        border-radius: 5px;
        padding: 3px 8px;
        font-size: 11px;
        font-weight: 700;
    }
    .tag-critical { color: #ff8a9b; background: rgba(255,102,127,0.14); }
    .tag-high { color: #ffc580; background: rgba(255,189,110,0.14); }
    .tag-medium { color: #c1b5ff; background: rgba(154,136,255,0.16); }
    .tag-low { color: #68dfbc; background: rgba(85,215,173,0.14); }

    .sev-row {
        display: flex;
        justify-content: space-between;
        font-size: 12px;
        margin: 12px 0 6px;
        color: #acbbd1;
    }

    .bar-bg {
        height: 7px;
        background: #293852;
        border-radius: 10px;
        overflow: hidden;
    }

    .bar-fill {
        height: 100%;
        border-radius: 10px;
        transition: width 0.3s ease;
    }

    .fact-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        border: 1px solid #30415b;
        border-radius: 9px;
        overflow: hidden;
        margin: 18px 0;
    }

    .fact-cell {
        background: #15243a;
        padding: 12px 14px;
        border-right: 1px solid #30415b;
    }
    .fact-cell:last-child { border-right: none; }
    .fact-cell small { display: block; color: #8599b6; font-size: 11px; margin-bottom: 4px; }
    .fact-cell strong { font-size: 12px; color: #edf4ff; }

    .evidence-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
        margin-top: 10px;
    }

    .evidence-card {
        background: #101e33;
        border: 1px solid #2c3c56;
        border-radius: 8px;
        padding: 12px;
    }
    .evidence-card small { display: block; color: #8499b6; font-size: 11px; margin-bottom: 4px; }
    .evidence-card strong { font-size: 12px; color: #edf4ff; word-break: break-all; }

    .timeline-item {
        border-left: 2px solid #3b5570;
        padding: 0 0 16px 16px;
        margin-left: 6px;
    }
    .timeline-item:last-child { border-left-color: transparent; padding-bottom: 0; }
    .timeline-time { color: var(--cyan); font-size: 11px; font-weight: 700; }
    .timeline-title { font-size: 13px; font-weight: 700; margin: 3px 0; }
    .timeline-body { font-size: 12px; color: var(--muted); margin: 0; }
    </style>
    """,
    unsafe_allow_html=True,
)

ZONES = ["Perimeter", "Identity", "Application", "Corporate"]
ZONE_COLORS = ["#55d9ed", "#9a88ff", "#ff667f", "#55d7ad"]

# --- Helper Functions ---
def sev_badge(sev: str) -> str:
    return f'<span class="tag tag-{sev.lower()}">{html.escape(sev)}</span>'

def build_traffic_chart(data: dict) -> go.Figure:
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=data["labels"],
            y=data["traffic"],
            name="Traffic Flows",
            mode="lines",
            line=dict(color="#55d9ed", width=2.5, shape="spline", smoothing=1.0),
            fill="tozeroy",
            fillcolor="rgba(85, 217, 237, 0.08)",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=data["labels"],
            y=data["threats"],
            name="Threat Signals",
            mode="lines",
            line=dict(color="#ff667f", width=2.5, shape="spline", smoothing=1.0),
        )
    )
    fig.update_layout(
        height=250,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        hovermode="x unified",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(color="#aebdd0", size=11)),
        xaxis=dict(showgrid=False, tickfont=dict(color="#8192ad", size=11), zeroline=False),
        yaxis=dict(
            gridcolor="#29374e",
            tickfont=dict(color="#8192ad", size=11),
            zeroline=False,
        ),
    )
    return fig


# --- Sidebar Navigation & Data Controls ---
with st.sidebar:
    st.markdown(
        """
        <div style="margin-bottom: 24px;">
            <div style="font-family:'Space Grotesk',sans-serif; font-size:22px; font-weight:700;">
                🛡️ sentinel<span style="color:#66d8ed;">.</span>
            </div>
            <div style="font-size:10px; letter-spacing:2px; color:#8e9eb8; font-weight:700;">
                AI-NIDS OPERATIONS
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption("WORKSPACE")
    nav_options = ["Overview", "Investigation", "Live Detection", "Flow Analyzer"]
    if "view" not in st.session_state:
        st.session_state.view = "Overview"

    for label in nav_options:
        if st.button(
            label,
            key=f"nav_{label}",
            use_container_width=True,
            type="primary" if st.session_state.view == label else "secondary",
        ):
            st.session_state.view = label
            st.rerun()

    st.markdown("---")
    st.caption("TELEMETRY & INFERENCE DATA")

    data_source = st.selectbox(
        "Data Source",
        [
            "🧪 Multi-Attack Suite (Evaluation)",
            "📁 Sample PCAP Detections (Week 10)",
            "📤 Upload Flow CSV",
        ],
        index=0,
        label_visibility="collapsed",
    )

    active_df = None
    upload_msg = ""

    if data_source == "🧪 Multi-Attack Suite (Evaluation)":
        active_df = generate_multi_attack_dataset()
    elif data_source == "📁 Sample PCAP Detections (Week 10)":
        if SAMPLE_PRED_PATH.exists():
            active_df = load_prediction_csv(SAMPLE_PRED_PATH)
        else:
            st.warning("Week 10 predictions file not found.")
            active_df = generate_multi_attack_dataset()
    elif data_source == "📤 Upload Flow CSV":
        uploaded = st.file_uploader("Upload CSV (Predictions or Flows)", type=["csv"], key="uploaded_flow_file")
        if uploaded is not None:
            try:
                raw_df = pd.read_csv(uploaded)
                if "Predicted_Label" in raw_df.columns:
                    active_df = load_prediction_csv(uploaded)
                    upload_msg = f"Loaded {len(active_df)} pre-computed flow predictions."
                else:
                    with st.spinner("Executing XGBoost model inference..."):
                        active_df = predict_from_flow_dataframe(raw_df)
                        upload_msg = f"Inference complete: {len(active_df)} flows classified!"
            except Exception as e:
                st.error(f"Error reading file: {e}")
                active_df = generate_multi_attack_dataset()
        else:
            st.info("Awaiting file upload... using multi-attack fallback.")
            active_df = generate_multi_attack_dataset()

    if upload_msg:
        st.success(upload_msg)

    st.markdown("---")
    st.markdown(
        """
        <div class="panel-box" style="padding:14px;">
            <div style="font-size:12px; font-weight:700; color:#55d7ad;">● ML Inference Engine Online</div>
            <div style="font-size:11px; color:#8e9eb8; margin-top:6px;">
                Model: <b>XGBoost Multi-Class</b><br>
                Features: <b>78 Statistical Features</b><br>
                Classes: <b>15 Detection Classes</b>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# --- Process Active Data ---
if active_df is None or len(active_df) == 0:
    active_df = generate_multi_attack_dataset()

DATASETS, SEV_COUNTS = compute_metrics_and_datasets(active_df)
INCIDENTS = predictions_to_incidents(active_df)

if "selected_id" not in st.session_state or not any(i["id"] == st.session_state.selected_id for i in INCIDENTS):
    st.session_state.selected_id = INCIDENTS[0]["id"] if INCIDENTS else "INC-2048"

if "live_events" not in st.session_state:
    st.session_state.live_events = []
if "live_ticks" not in st.session_state:
    st.session_state.live_ticks = 0
if "live_paused" not in st.session_state:
    st.session_state.live_paused = False


def open_incident(inc_id: str):
    st.session_state.selected_id = inc_id
    st.session_state.view = "Investigation"


# =========================================================================
# View 1: Security Overview
# =========================================================================
if st.session_state.view == "Overview":
    col_head, col_range = st.columns([3, 1])
    with col_head:
        st.markdown('<p class="eyebrow">Threat intelligence / dashboard</p>', unsafe_allow_html=True)
        st.markdown('<h1 class="page-title">Security Overview</h1>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">Real-time network traffic analysis powered by AI intrusion detection.</p>', unsafe_allow_html=True)
    with col_range:
        selected_range = st.selectbox("Time range", list(DATASETS.keys()), label_visibility="collapsed")

    data = DATASETS[selected_range]
    k1, k2, k3, k4 = st.columns(4)
    kpi_specs = [
        (k1, "Network events", data["metrics"][0], f'<span style="color:#55d7ad;">Active flows</span> analyzed', "#55d9ed"),
        (k2, "Threats detected", data["metrics"][1], f'<span style="color:#ff667f;">Non-benign signatures</span>', "#ff667f"),
        (k3, "High-Risk threats", data["metrics"][2], f'<span style="color:#ffbd6e;">Critical & High alerts</span>', "#ffbd6e"),
        (k4, "Monitored assets", data["metrics"][3], f'Across <span style="color:#55d7ad;">4 network zones</span>', "#9a88ff"),
    ]
    for col, label, val, note, accent in kpi_specs:
        with col:
            st.markdown(
                f"""
                <div class="kpi-card" style="--accent:{accent};">
                    <div class="kpi-label">{label}</div>
                    <div class="kpi-value">{val}</div>
                    <div class="kpi-note">{note}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.write("")
    main_left, main_right = st.columns([1.75, 1])
    with main_left:
        st.markdown(
            '<div class="panel-box"><p class="panel-title">Network traffic & threats</p>'
            '<p class="panel-kicker">Flow activity & identified attack signatures over time</p>',
            unsafe_allow_html=True,
        )
        st.plotly_chart(build_traffic_chart(data), use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    with main_right:
        tot = max(sum(SEV_COUNTS.values()), 1)
        crit_w = max(4, int(SEV_COUNTS["Critical"] / tot * 100)) if SEV_COUNTS["Critical"] > 0 else 0
        high_w = max(4, int(SEV_COUNTS["High"] / tot * 100)) if SEV_COUNTS["High"] > 0 else 0
        med_w = max(4, int(SEV_COUNTS["Medium"] / tot * 100)) if SEV_COUNTS["Medium"] > 0 else 0
        low_w = max(4, int(SEV_COUNTS["Low"] / tot * 100)) if SEV_COUNTS["Low"] > 0 else 0

        st.markdown(
            f"""
            <div class="panel-box">
                <p class="panel-title">Alert severity breakdown</p>
                <p class="panel-kicker">Distribution of ML model classifications</p>
                <div class="sev-row"><span>Critical</span><strong>{SEV_COUNTS['Critical']}</strong></div>
                <div class="bar-bg"><div class="bar-fill" style="width:{crit_w}%;background:#ff667f;"></div></div>
                <div class="sev-row"><span>High</span><strong>{SEV_COUNTS['High']}</strong></div>
                <div class="bar-bg"><div class="bar-fill" style="width:{high_w}%;background:#ffbd6e;"></div></div>
                <div class="sev-row"><span>Medium</span><strong>{SEV_COUNTS['Medium']}</strong></div>
                <div class="bar-bg"><div class="bar-fill" style="width:{med_w}%;background:#9a88ff;"></div></div>
                <div class="sev-row"><span>Low (Benign)</span><strong>{SEV_COUNTS['Low']}</strong></div>
                <div class="bar-bg"><div class="bar-fill" style="width:{low_w}%;background:#55d7ad;"></div></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    bot_left, bot_right = st.columns([1.75, 1])
    with bot_left:
        st.markdown('<p class="panel-title">Recent detected incidents</p><p class="panel-kicker">Select an incident to investigate flow evidence</p>', unsafe_allow_html=True)
        display_incidents = INCIDENTS[:5]
        for inc in display_incidents:
            c1, c2, c3, c4 = st.columns([2.2, 1, 1.4, 0.9])
            c1.markdown(f"**{inc['title']}**  \n`{inc['id']}` · {inc['source']}")
            c2.markdown(sev_badge(inc["severity"]), unsafe_allow_html=True)
            c3.caption(f"{inc['zone']} zone\nConf: {inc['confidence']}%")
            if c4.button("Inspect", key=f"recent_{inc['id']}", use_container_width=True):
                open_incident(inc["id"])
                st.rerun()

    with bot_right:
        top_threats = [i for i in INCIDENTS if i["label"] != "BENIGN"][:3]
        if not top_threats:
            top_threats = INCIDENTS[:3]

        signals_html = ""
        for t in top_threats:
            signals_html += (
                f"<p><strong>{html.escape(t['title'])}</strong><br>"
                f"<span style='color:#8e9eb8;font-size:12px;'>Targeting {t['destination']} · {t['zone']} zone ({t['confidence']}%)</span></p>"
            )

        st.markdown(
            f"""
            <div class="panel-box">
                <p class="panel-title">Live detection activity</p>
                <p class="panel-kicker">Signals evaluated by XGBoost model</p>
                {signals_html}
            </div>
            """,
            unsafe_allow_html=True,
        )


# =========================================================================
# View 2: Incident Investigation
# =========================================================================
elif st.session_state.view == "Investigation":
    st.markdown('<p class="eyebrow">Threat intelligence / analysis</p>', unsafe_allow_html=True)
    st.markdown('<h1 class="page-title">Incident Investigation</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Inspect extracted flow features and machine learning confidence.</p>', unsafe_allow_html=True)

    list_col, detail_col = st.columns([1, 2])
    with list_col:
        query = st.text_input("Search incidents, attacks or IPs", placeholder="e.g., DDoS, 192.168.10.14").strip().lower()
        sev_filter = st.selectbox("Filter by severity", ["All severities", "Critical", "High", "Medium", "Low"])

        matches = [
            i for i in INCIDENTS
            if (sev_filter == "All severities" or i["severity"] == sev_filter)
            and any(query in str(i[k]).lower() for k in ("id", "title", "source", "destination", "asset", "label"))
        ]

        if not matches:
            st.info("No incidents match these filters.")
        else:
            for inc in matches[:25]:
                is_selected = inc["id"] == st.session_state.selected_id
                label = f"{inc['id']} · {inc['label']} ({inc['severity']})"
                if st.button(label, key=f"inv_{inc['id']}", use_container_width=True, type="primary" if is_selected else "secondary"):
                    st.session_state.selected_id = inc["id"]
                    st.rerun()

    with detail_col:
        inc = next((i for i in INCIDENTS if i["id"] == st.session_state.selected_id), INCIDENTS[0] if INCIDENTS else None)
        if inc:
            evidence_html = "".join(
                f'<div class="evidence-card"><small>{html.escape(k)}</small><strong>{html.escape(str(v))}</strong></div>'
                for k, v in inc["evidence"]
            )
            evidence_html += f'<div class="evidence-card"><small>Source IP</small><strong>{inc["source"]}</strong></div>'
            evidence_html += f'<div class="evidence-card"><small>Destination IP</small><strong>{inc["destination"]}</strong></div>'

            timeline_html = "".join(
                f'<div class="timeline-item"><div class="timeline-time">{t}</div>'
                f'<div class="timeline-title">{html.escape(title)}</div>'
                f'<p class="timeline-body">{html.escape(body)}</p></div>'
                for t, title, body in inc["timeline"]
            )

            st.markdown(
                f"""
                <div class="panel-box">
                    {sev_badge(inc["severity"])}
                    <h2 style="font-family:'Space Grotesk',sans-serif; margin:10px 0 8px;">{html.escape(inc["title"])}</h2>
                    <p style="color:#9eafc9; font-size:13px; line-height:1.6;">{html.escape(inc["description"])}</p>
                    <div class="fact-grid">
                        <div class="fact-cell"><small>Incident ID</small><strong>{inc["id"]}</strong></div>
                        <div class="fact-cell"><small>Model Label</small><strong>{inc["label"]}</strong></div>
                        <div class="fact-cell"><small>Affected Asset</small><strong>{inc["asset"]}</strong></div>
                        <div class="fact-cell"><small>Network Zone</small><strong>{inc["zone"]}</strong></div>
                    </div>
                    <p class="panel-title">Model Evidence & Flow Features</p>
                    <div class="evidence-grid">{evidence_html}</div>
                    <p class="panel-title" style="margin-top:22px;">Inference Timeline</p>
                    {timeline_html}
                </div>
                """,
                unsafe_allow_html=True,
            )


# =========================================================================
# View 3: Live Detection
# =========================================================================
elif st.session_state.view == "Live Detection":
    head_l, head_r = st.columns([3, 1])
    with head_l:
        st.markdown('<p class="eyebrow">Threat intelligence / live signals</p>', unsafe_allow_html=True)
        st.markdown('<h1 class="page-title">Live Threat Detection</h1>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">Continuously updating stream of network flows evaluated by the inference engine.</p>', unsafe_allow_html=True)
    with head_r:
        if st.button("Resume feed" if st.session_state.live_paused else "Pause feed", use_container_width=True):
            st.session_state.live_paused = not st.session_state.live_paused
            st.rerun()

    @st.fragment(run_every="4s")
    def live_feed_fragment():
        if not st.session_state.live_paused and len(INCIDENTS) > 0:
            st.session_state.live_ticks += 1
            for ev in st.session_state.live_events:
                ev["age"] += 4

            # Pick next incident from active dataset
            sample_inc = INCIDENTS[(st.session_state.live_ticks * 3 + 1) % len(INCIDENTS)]
            now_utc = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            new_event = {
                "id": sample_inc["id"],
                "title": sample_inc["title"],
                "severity": sample_inc["severity"],
                "zone": sample_inc["zone"],
                "source": sample_inc["source"],
                "destination": sample_inc["destination"],
                "confidence": sample_inc["confidence"],
                "time": now_utc,
                "age": 0,
            }
            st.session_state.live_events.insert(0, new_event)
            st.session_state.live_events = st.session_state.live_events[:30]

        events = st.session_state.live_events
        highest = next((s for s in ["Critical", "High", "Medium", "Low"] if any(e["severity"] == s for e in events)), "—")
        threat_events_count = sum(1 for e in events if e["severity"] != "Low")

        s1, s2, s3 = st.columns(3)
        s1.markdown(f'<div class="kpi-card"><div class="kpi-label">Flows evaluated</div><div class="kpi-value">{st.session_state.live_ticks}</div><div class="kpi-note">Real-time model inferences</div></div>', unsafe_allow_html=True)
        s2.markdown(f'<div class="kpi-card" style="--accent:#ff667f;"><div class="kpi-label">Threats captured</div><div class="kpi-value">{threat_events_count}</div><div class="kpi-note">Non-benign signatures</div></div>', unsafe_allow_html=True)
        s3.markdown(f'<div class="kpi-card" style="--accent:#ffbd6e;"><div class="kpi-label">Highest severity</div><div class="kpi-value">{highest}</div><div class="kpi-note">Current stream window</div></div>', unsafe_allow_html=True)

        st.write("")
        live_l, live_r = st.columns([1.65, 1])
        with live_l:
            live_sev = st.selectbox("Filter live alerts", ["All severities", "Critical", "High", "Medium", "Low"], key="live_sev_filter")
            visible = [e for e in events if live_sev == "All severities" or e["severity"] == live_sev]
            if not visible:
                st.info("Awaiting telemetry matching filter...")
            else:
                for idx, e in enumerate(visible[:10]):
                    fc1, fc2 = st.columns([4, 1])
                    fc1.markdown(
                        f"{sev_badge(e['severity'])} **{e['title']}**  \n"
                        f"<span style='color:#8e9eb8;font-size:12px;'>{e['zone']} zone · {e['source']} → {e['destination']} · {e['time']} ({e['age']}s ago) · Conf: {e['confidence']}%</span>",
                        unsafe_allow_html=True,
                    )
                    if fc2.button(f"Inspect {e['id']}", key=f"live_btn_{idx}_{e['time']}", use_container_width=True):
                        open_incident(e["id"])
                        st.rerun()

        with live_r:
            last_time = events[0]["time"] if events else "Waiting for signals…"
            bars_html = ""
            for idx, z in enumerate(ZONES):
                cnt = sum(1 for e in events if e["zone"] == z)
                width = max(5, min(100, cnt * 15))
                bars_html += (
                    f'<div class="sev-row"><span>{z}</span><strong style="color:#55d9ed;">{cnt} signals</strong></div>'
                    f'<div class="bar-bg"><div class="bar-fill" style="width:{width}%;background:{ZONE_COLORS[idx]};"></div></div>'
                )
            st.markdown(
                f"""
                <div class="panel-box">
                    <p class="panel-title">Monitored Zone Activity</p>
                    <p class="panel-kicker">Last evaluated flow: {last_time}</p>
                    {bars_html}
                    <p style="font-size:11px; color:#8e9eb8; margin-top:16px;">
                        Connected to XGBoost inference engine.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    live_feed_fragment()


# =========================================================================
# View 4: Interactive Flow Analyzer (Direct ML Prediction)
# =========================================================================
elif st.session_state.view == "Flow Analyzer":
    st.markdown('<p class="eyebrow">Machine Learning / Interactive Inference</p>', unsafe_allow_html=True)
    st.markdown('<h1 class="page-title">Interactive Flow Analyzer</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Test arbitrary network flow parameters directly against the trained XGBoost model.</p>', unsafe_allow_html=True)

    # Load model and features
    model, encoder, training_features, _ = load_model_and_encoder()

    st.markdown("### 1. Select a Pre-configured Traffic Scenario")
    scenario_col1, scenario_col2, scenario_col3, scenario_col4 = st.columns(4)

    preset = None
    if scenario_col1.button("🌐 Benign HTTPS Browsing", use_container_width=True):
        preset = {"port": 443, "duration": 1250000, "fwd_pkts": 12, "bwd_pkts": 15, "bytes_sec": 45000.0, "pkt_len_mean": 420.0}
    if scenario_col2.button("🔍 Port Scan Sweep", use_container_width=True):
        preset = {"port": 80, "duration": 45, "fwd_pkts": 1, "bwd_pkts": 0, "bytes_sec": 1200.0, "pkt_len_mean": 0.0}
    if scenario_col3.button("💥 DoS / DDoS Flood", use_container_width=True):
        preset = {"port": 80, "duration": 98000000, "fwd_pkts": 450, "bwd_pkts": 2, "bytes_sec": 890000.0, "pkt_len_mean": 850.0}
    if scenario_col4.button("🔑 SSH Brute Force", use_container_width=True):
        preset = {"port": 22, "duration": 250000, "fwd_pkts": 24, "bwd_pkts": 22, "bytes_sec": 12500.0, "pkt_len_mean": 95.0}

    st.write("")
    st.markdown("### 2. Configure Key Statistical Flow Features")

    fcol1, fcol2, fcol3 = st.columns(3)
    with fcol1:
        dst_port = st.number_input("Destination Port", min_value=0, max_value=65535, value=preset["port"] if preset else 443)
        flow_duration = st.number_input("Flow Duration (µs)", min_value=0, value=preset["duration"] if preset else 500000)
    with fcol2:
        fwd_pkts = st.number_input("Total Forward Packets", min_value=0, value=preset["fwd_pkts"] if preset else 10)
        bwd_pkts = st.number_input("Total Backward Packets", min_value=0, value=preset["bwd_pkts"] if preset else 8)
    with fcol3:
        bytes_sec = st.number_input("Flow Bytes/s", min_value=0.0, value=preset["bytes_sec"] if preset else 15000.0)
        pkt_mean = st.number_input("Packet Length Mean", min_value=0.0, value=preset["pkt_len_mean"] if preset else 250.0)

    if st.button("🚀 Classify Flow with XGBoost", type="primary", use_container_width=True):
        # Construct feature vector with defaults for all 78 features
        feature_dict = {f: 0.0 for f in training_features}
        feature_dict["Destination Port"] = float(dst_port)
        feature_dict["Flow Duration"] = float(flow_duration)
        feature_dict["Total Fwd Packets"] = float(fwd_pkts)
        feature_dict["Total Backward Packets"] = float(bwd_pkts)
        feature_dict["Flow Bytes/s"] = float(bytes_sec)
        feature_dict["Packet Length Mean"] = float(pkt_mean)

        input_df = pd.DataFrame([feature_dict])[training_features]
        encoded_pred = model.predict(input_df)[0]
        predicted_class = encoder.inverse_transform([encoded_pred])[0]
        probs = model.predict_proba(input_df)[0]
        conf = probs[encoded_pred] * 100.0
        severity = CLASS_SEVERITY.get(predicted_class, "Low" if predicted_class == "BENIGN" else "Medium")

        st.markdown("---")
        res_col1, res_col2 = st.columns([1, 1.5])
        with res_col1:
            st.markdown(
                f"""
                <div class="panel-box">
                    <p class="panel-title">Classification Result</p>
                    <div style="font-size:26px; font-weight:700; color:#55d9ed; margin:12px 0;">
                        {predicted_class}
                    </div>
                    <div>{sev_badge(severity)}</div>
                    <p style="margin-top:14px; font-size:13px; color:#8e9eb8;">
                        Confidence Score: <strong style="color:#edf4ff;">{conf:.2f}%</strong><br>
                        Severity Level: <strong style="color:#edf4ff;">{severity}</strong><br>
                        Destination Port: <strong style="color:#edf4ff;">{dst_port}</strong>
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with res_col2:
            # Show top class probabilities
            prob_df = pd.DataFrame({
                "Attack Class": encoder.classes_,
                "Probability": (probs * 100).round(2)
            }).sort_values("Probability", ascending=False).head(6)

            fig_probs = go.Figure(go.Bar(
                x=prob_df["Probability"],
                y=prob_df["Attack Class"],
                orientation="h",
                marker=dict(color="#55d9ed"),
            ))
            fig_probs.update_layout(
                title="Top Class Probabilities (%)",
                height=220,
                margin=dict(l=10, r=10, t=30, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(range=[0, 100], gridcolor="#29374e", tickfont=dict(color="#8192ad", size=10)),
                yaxis=dict(tickfont=dict(color="#8192ad", size=10), autorange="reversed"),
            )
            st.plotly_chart(fig_probs, use_container_width=True)