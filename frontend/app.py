from datetime import datetime, timezone
import html
import plotly.graph_objects as go
import streamlit as st

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
    .evidence-card strong { font-size: 12px; color: #edf4ff; }

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

# --- Mock Data ---
INCIDENTS = [
    {
        "id": "INC-2048",
        "title": "Possible data exfiltration",
        "severity": "Critical",
        "source": "10.42.18.94",
        "destination": "198.51.100.24",
        "asset": "APP-SRV-04",
        "zone": "Application",
        "time": "10:42 UTC",
        "description": "An application server initiated an unusual volume of outbound traffic to an external address. The pattern deviates from its normal baseline and warrants validation.",
        "evidence": [
            ("Detection rule", "Anomalous outbound transfer"),
            ("Protocol / port", "HTTPS / 443"),
            ("Observed volume", "2.8 GB in 17 minutes"),
            ("Confidence", "High · 92%"),
        ],
        "timeline": [
            ("10:42 UTC", "Alert generated", "Outbound transfer exceeded the learned traffic baseline."),
            ("10:31 UTC", "Sustained connection", "A persistent connection to the external destination began."),
            ("10:25 UTC", "First observed activity", "Initial outbound request from APP-SRV-04 was recorded."),
        ],
    },
    {
        "id": "INC-2047",
        "title": "Brute-force login attempt",
        "severity": "High",
        "source": "203.0.113.58",
        "destination": "10.42.3.12",
        "asset": "AUTH-GW-01",
        "zone": "Identity",
        "time": "10:26 UTC",
        "description": "A high rate of failed authentication attempts from one external source targeted the identity gateway within a short interval.",
        "evidence": [
            ("Detection rule", "Authentication failure burst"),
            ("Protocol / port", "HTTPS / 443"),
            ("Failed attempts", "186 in 6 minutes"),
            ("Confidence", "High · 88%"),
        ],
        "timeline": [
            ("10:26 UTC", "Alert generated", "Failed authentication threshold was crossed."),
            ("10:23 UTC", "Attempt rate increased", "Multiple account names were attempted from one address."),
            ("10:20 UTC", "First failed login", "Initial rejected authentication request was recorded."),
        ],
    },
    {
        "id": "INC-2046",
        "title": "Network port sweep",
        "severity": "Medium",
        "source": "192.0.2.147",
        "destination": "10.42.0.0/24",
        "asset": "EDGE-FW-02",
        "zone": "Perimeter",
        "time": "09:58 UTC",
        "description": "A remote host probed multiple service ports across the perimeter segment, consistent with reconnaissance activity.",
        "evidence": [
            ("Detection rule", "Horizontal port scan"),
            ("Protocol / port", "TCP / multiple"),
            ("Ports probed", "43 distinct ports"),
            ("Confidence", "Medium · 79%"),
        ],
        "timeline": [
            ("09:58 UTC", "Alert generated", "Scan threshold reached across monitored hosts."),
            ("09:52 UTC", "Probe expanded", "Requests spread to additional destination hosts."),
            ("09:49 UTC", "First probe", "Initial connection attempt was observed."),
        ],
    },
    {
        "id": "INC-2045",
        "title": "Suspicious DNS queries",
        "severity": "Medium",
        "source": "10.42.22.16",
        "destination": "192.0.2.53",
        "asset": "USER-WS-16",
        "zone": "Corporate",
        "time": "09:17 UTC",
        "description": "A workstation made repeated DNS requests with unusually long subdomains. The pattern may indicate tunneling or automated beaconing.",
        "evidence": [
            ("Detection rule", "DNS query anomaly"),
            ("Protocol / port", "DNS / 53"),
            ("Query count", "312 in 20 minutes"),
            ("Confidence", "Medium · 74%"),
        ],
        "timeline": [
            ("09:17 UTC", "Alert generated", "Query pattern matched anomaly rules."),
            ("09:09 UTC", "Repetition detected", "Long encoded-looking subdomains recurred."),
            ("08:57 UTC", "First unusual query", "Initial query was recorded."),
        ],
    },
    {
        "id": "INC-2044",
        "title": "Policy-blocked connection",
        "severity": "Low",
        "source": "10.42.7.21",
        "destination": "203.0.113.91",
        "asset": "USER-WS-21",
        "zone": "Corporate",
        "time": "08:43 UTC",
        "description": "A workstation attempted to connect to a destination disallowed by the perimeter policy. The connection was blocked.",
        "evidence": [
            ("Detection rule", "Outbound policy violation"),
            ("Protocol / port", "TCP / 8080"),
            ("Connection attempts", "4 blocked"),
            ("Confidence", "High · 95%"),
        ],
        "timeline": [
            ("08:43 UTC", "Alert generated", "Repeated blocked attempts triggered an alert."),
            ("08:41 UTC", "Connection blocked", "Perimeter policy denied the outbound request."),
            ("08:40 UTC", "First attempt", "Initial connection request was observed."),
        ],
    },
]

DATASETS = {
    "24 hours": {
        "labels": ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "23:59"],
        "traffic": [35, 29, 45, 52, 47, 69, 61],
        "threats": [12, 18, 14, 33, 22, 48, 30],
        "metrics": ["2.48M", "128", "1,842", "342"],
    },
    "7 days": {
        "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "traffic": [39, 49, 42, 65, 57, 74, 62],
        "threats": [15, 21, 31, 22, 46, 35, 29],
        "metrics": ["16.9M", "864", "12,406", "342"],
    },
    "30 days": {
        "labels": ["Week 1", "Week 2", "Week 3", "Week 4"],
        "traffic": [42, 54, 66, 61],
        "threats": [19, 33, 26, 43],
        "metrics": ["71.2M", "3,421", "48,690", "342"],
    },
}

ZONES = ["Perimeter", "Identity", "Application", "Corporate"]
ZONE_COLORS = ["#55d9ed", "#9a88ff", "#ff667f", "#55d7ad"]
LIVE_TEMPLATES = [
    {"title": "Outbound transfer anomaly", "severity": "Critical", "zone": "Application", "id": "INC-2048"},
    {"title": "Authentication failure burst", "severity": "High", "zone": "Identity", "id": "INC-2047"},
    {"title": "Port sweep signature", "severity": "Medium", "zone": "Perimeter", "id": "INC-2046"},
    {"title": "Unusual DNS query pattern", "severity": "Medium", "zone": "Corporate", "id": "INC-2045"},
    {"title": "Policy-blocked connection", "severity": "Low", "zone": "Corporate", "id": "INC-2044"},
]

# --- Session State ---
if "view" not in st.session_state:
    st.session_state.view = "Overview"
if "selected_id" not in st.session_state:
    st.session_state.selected_id = INCIDENTS[0]["id"]
if "live_events" not in st.session_state:
    st.session_state.live_events = []
if "live_ticks" not in st.session_state:
    st.session_state.live_ticks = 0
if "live_paused" not in st.session_state:
    st.session_state.live_paused = False


def open_incident(inc_id: str):
    st.session_state.selected_id = inc_id
    st.session_state.view = "Investigation"


def sev_badge(sev: str) -> str:
    return f'<span class="tag tag-{sev.lower()}">{html.escape(sev)}</span>'


def build_traffic_chart(data: dict) -> go.Figure:
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=data["labels"],
            y=data["traffic"],
            name="Traffic",
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
            name="Threats",
            mode="lines",
            line=dict(color="#9a88ff", width=2.5, shape="spline", smoothing=1.0),
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
            range=[0, 100],
            dtick=25,
            ticksuffix="%",
            gridcolor="#29374e",
            tickfont=dict(color="#8192ad", size=11),
            zeroline=False,
        ),
    )
    return fig


# --- Sidebar Navigation ---
with st.sidebar:
    st.markdown(
        """
        <div style="margin-bottom: 24px;">
            <div style="font-family:'Space Grotesk',sans-serif; font-size:22px; font-weight:700;">
                🛡️ sentinel<span style="color:#66d8ed;">.</span>
            </div>
            <div style="font-size:10px; letter-spacing:2px; color:#8e9eb8; font-weight:700;">
                NETWORK DEFENSE
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption("WORKSPACE")
    for label in ["Overview", "Investigation", "Live Detection"]:
        if st.button(
            label,
            key=f"nav_{label}",
            use_container_width=True,
            type="primary" if st.session_state.view == label else "secondary",
        ):
            st.session_state.view = label
            st.rerun()

    st.markdown("---")
    st.markdown(
        """
        <div class="panel-box" style="padding:14px;">
            <div style="font-size:12px; font-weight:700; color:#55d7ad;">● Sensor network online</div>
            <div style="font-size:11px; color:#8e9eb8; margin-top:6px;">
                Illustrative monitoring workspace<br>4 monitored network zones
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# --- View 1: Security Overview ---
if st.session_state.view == "Overview":
    col_head, col_range = st.columns([3, 1])
    with col_head:
        st.markdown('<p class="eyebrow">Threat intelligence / dashboard</p>', unsafe_allow_html=True)
        st.markdown('<h1 class="page-title">Security Overview</h1>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">A clear view of network activity and emerging threats.</p>', unsafe_allow_html=True)
    with col_range:
        selected_range = st.selectbox("Time range", list(DATASETS.keys()), label_visibility="collapsed")

    data = DATASETS[selected_range]
    k1, k2, k3, k4 = st.columns(4)
    kpi_specs = [
        (k1, "Network events", data["metrics"][0], '<span style="color:#55d7ad;">↑ 12.4%</span> vs previous period', "#55d9ed"),
        (k2, "Threats detected", data["metrics"][1], '<span style="color:#ff667f;">↑ 8.2%</span> vs previous period', "#ff667f"),
        (k3, "Blocked attempts", data["metrics"][2], '<span style="color:#55d7ad;">↑ 18.6%</span> prevented at perimeter', "#ffbd6e"),
        (k4, "Assets monitored", data["metrics"][3], 'Across <span style="color:#55d7ad;">4 network zones</span>', "#9a88ff"),
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
            '<p class="panel-kicker">Normalized activity across the selected period</p>',
            unsafe_allow_html=True,
        )
        st.plotly_chart(build_traffic_chart(data), use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    with main_right:
        st.markdown(
            """
            <div class="panel-box">
                <p class="panel-title">Alert severity</p>
                <p class="panel-kicker">Distribution of detected incidents</p>
                <div class="sev-row"><span>Critical</span><strong>12</strong></div>
                <div class="bar-bg"><div class="bar-fill" style="width:26%;background:#ff667f;"></div></div>
                <div class="sev-row"><span>High</span><strong>28</strong></div>
                <div class="bar-bg"><div class="bar-fill" style="width:60%;background:#ffbd6e;"></div></div>
                <div class="sev-row"><span>Medium</span><strong>47</strong></div>
                <div class="bar-bg"><div class="bar-fill" style="width:100%;background:#9a88ff;"></div></div>
                <div class="sev-row"><span>Low</span><strong>41</strong></div>
                <div class="bar-bg"><div class="bar-fill" style="width:87%;background:#55d7ad;"></div></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    bot_left, bot_right = st.columns([1.75, 1])
    with bot_left:
        st.markdown('<p class="panel-title">Recent incidents</p><p class="panel-kicker">Select an incident to investigate</p>', unsafe_allow_html=True)
        for inc in INCIDENTS[:4]:
            c1, c2, c3, c4 = st.columns([2.2, 1, 1.3, 1])
            c1.markdown(f"**{inc['title']}**  \n`{inc['id']}`")
            c2.markdown(sev_badge(inc["severity"]), unsafe_allow_html=True)
            c3.caption(f"{inc['source']} · {inc['time']}")
            if c4.button("Inspect", key=f"recent_{inc['id']}", use_container_width=True):
                open_incident(inc["id"])
                st.rerun()

    with bot_right:
        st.markdown(
            """
            <div class="panel-box">
                <p class="panel-title">Detection activity</p>
                <p class="panel-kicker">Signals from monitored zones</p>
                <p><strong>Perimeter scan identified</strong><br><span style="color:#8e9eb8;font-size:12px;">Elevated port scanning across the edge zone · 8 min ago</span></p>
                <p><strong>Suspicious sign-in pattern</strong><br><span style="color:#8e9eb8;font-size:12px;">Repeated authentication failures on an internal host · 24 min ago</span></p>
                <p><strong>Unusual outbound traffic</strong><br><span style="color:#8e9eb8;font-size:12px;">Unexpected data transfer from the application zone · 41 min ago</span></p>
            </div>
            """,
            unsafe_allow_html=True,
        )


# --- View 2: Incident Investigation ---
elif st.session_state.view == "Investigation":
    st.markdown('<p class="eyebrow">Threat intelligence / analysis</p>', unsafe_allow_html=True)
    st.markdown('<h1 class="page-title">Incident Investigation</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Explore the evidence behind each detection.</p>', unsafe_allow_html=True)

    list_col, detail_col = st.columns([1, 2])
    with list_col:
        query = st.text_input("Search incidents or IPs", placeholder="e.g., INC-2048 or 10.42.18.94").strip().lower()
        sev_filter = st.selectbox("Filter by severity", ["All severities", "Critical", "High", "Medium", "Low"])

        matches = [
            i for i in INCIDENTS
            if (sev_filter == "All severities" or i["severity"] == sev_filter)
            and any(query in str(i[k]).lower() for k in ("id", "title", "source", "destination", "asset"))
        ]

        if not matches:
            st.info("No incidents match these filters.")
        else:
            for inc in matches:
                is_selected = inc["id"] == st.session_state.selected_id
                label = f"{inc['id']} · {inc['severity']} — {inc['title']}"
                if st.button(label, key=f"inv_{inc['id']}", use_container_width=True, type="primary" if is_selected else "secondary"):
                    st.session_state.selected_id = inc["id"]
                    st.rerun()

    with detail_col:
        inc = next((i for i in INCIDENTS if i["id"] == st.session_state.selected_id), INCIDENTS[0])
        evidence_html = "".join(
            f'<div class="evidence-card"><small>{html.escape(k)}</small><strong>{html.escape(v)}</strong></div>'
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
                    <div class="fact-cell"><small>Detected</small><strong>{inc["time"]}</strong></div>
                    <div class="fact-cell"><small>Affected asset</small><strong>{inc["asset"]}</strong></div>
                    <div class="fact-cell"><small>Network zone</small><strong>{inc["zone"]}</strong></div>
                </div>
                <p class="panel-title">Network evidence</p>
                <div class="evidence-grid">{evidence_html}</div>
                <p class="panel-title" style="margin-top:22px;">Event timeline</p>
                {timeline_html}
            </div>
            """,
            unsafe_allow_html=True,
        )


# --- View 3: Live Detection ---
elif st.session_state.view == "Live Detection":
    head_l, head_r = st.columns([3, 1])
    with head_l:
        st.markdown('<p class="eyebrow">Threat intelligence / live signals</p>', unsafe_allow_html=True)
        st.markdown('<h1 class="page-title">Live Threat Detection</h1>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">A continuously updating simulation of monitored network signals.</p>', unsafe_allow_html=True)
    with head_r:
        if st.button("Resume feed" if st.session_state.live_paused else "Pause feed", use_container_width=True):
            st.session_state.live_paused = not st.session_state.live_paused
            st.rerun()

    @st.fragment(run_every="5s")
    def live_feed_fragment():
        if not st.session_state.live_paused:
            st.session_state.live_ticks += 1
            for ev in st.session_state.live_events:
                ev["age"] += 5
            tpl = LIVE_TEMPLATES[(st.session_state.live_ticks * 3 + 1) % len(LIVE_TEMPLATES)]
            inc = next(i for i in INCIDENTS if i["id"] == tpl["id"])
            now_utc = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            st.session_state.live_events.insert(
                0,
                {**tpl, "source": inc["source"], "destination": inc["destination"], "time": now_utc, "age": 0},
            )
            st.session_state.live_events = st.session_state.live_events[:30]

        events = st.session_state.live_events
        highest = next((s for s in ["Critical", "High", "Medium", "Low"] if any(e["severity"] == s for e in events)), "—")

        s1, s2, s3 = st.columns(3)
        s1.markdown(f'<div class="kpi-card"><div class="kpi-label">Signals observed</div><div class="kpi-value">{st.session_state.live_ticks}</div><div class="kpi-note">Since session started</div></div>', unsafe_allow_html=True)
        s2.markdown(f'<div class="kpi-card" style="--accent:#ff667f;"><div class="kpi-label">Threat alerts</div><div class="kpi-value">{st.session_state.live_ticks}</div><div class="kpi-note">New simulated detections</div></div>', unsafe_allow_html=True)
        s3.markdown(f'<div class="kpi-card" style="--accent:#ffbd6e;"><div class="kpi-label">Highest severity</div><div class="kpi-value">{highest}</div><div class="kpi-note">Current session</div></div>', unsafe_allow_html=True)

        st.write("")
        live_l, live_r = st.columns([1.65, 1])
        with live_l:
            live_sev = st.selectbox("Filter live alerts", ["All severities", "Critical", "High", "Medium", "Low"], key="live_sev_filter")
            visible = [e for e in events if live_sev == "All severities" or e["severity"] == live_sev]
            if not visible:
                st.info("No alerts for this severity yet.")
            else:
                for idx, e in enumerate(visible[:12]):
                    fc1, fc2 = st.columns([4, 1])
                    fc1.markdown(
                        f"{sev_badge(e['severity'])} **{e['title']}**  \n"
                        f"<span style='color:#8e9eb8;font-size:12px;'>{e['zone']} zone · {e['source']} → {e['destination']} · {e['time']} ({e['age']}s ago)</span>",
                        unsafe_allow_html=True,
                    )
                    if fc2.button(f"Inspect {e['id']}", key=f"live_btn_{idx}_{e['time']}", use_container_width=True):
                        open_incident(e["id"])
                        st.rerun()

        with live_r:
            last_time = events[0]["time"] if events else "Waiting for first signal…"
            bars_html = ""
            for idx, z in enumerate(ZONES):
                cnt = sum(1 for e in events if e["zone"] == z)
                width = max(5, min(100, cnt * 18))
                bars_html += (
                    f'<div class="sev-row"><span>{z}</span><strong style="color:#55d9ed;">{cnt} signals</strong></div>'
                    f'<div class="bar-bg"><div class="bar-fill" style="width:{width}%;background:{ZONE_COLORS[idx]};"></div></div>'
                )
            st.markdown(
                f"""
                <div class="panel-box">
                    <p class="panel-title">Active network activity</p>
                    <p class="panel-kicker">Last signal: {last_time}</p>
                    {bars_html}
                    <p style="font-size:11px; color:#8e9eb8; margin-top:16px;">
                        Illustrative telemetry only. Ready to connect to live packet capture or ML inference.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    live_feed_fragment()