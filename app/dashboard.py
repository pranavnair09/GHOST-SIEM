import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from app.database import init_db, fetch_events, fetch_stats, fetch_timeline

st.set_page_config(page_title="GHOST-SIEM", page_icon="👻", layout="wide",
                   initial_sidebar_state="expanded")
init_db()

BG = "#242629"
PANEL = "#303236"
RED = "#F04452"
ORANGE = "#F15A24"
PEACH = "#F49A7B"
MUTED = "#AEB2B8"
TEXT = "#F4F4F4"

st.markdown(f"""
<style>
.stApp {{ background: {BG}; color: {TEXT}; }}
[data-testid="stHeader"] {{ background: rgba(0,0,0,0); }}
.block-container {{ padding-top: 1.25rem; padding-bottom: 2rem; max-width: 1600px; }}
h1,h2,h3,p,label,span {{ color: {TEXT}; }}
.ghost-sub {{ color: #C6C8CB; font-size: .88rem; margin-top: -12px; }}
.panel {{ background: {PANEL}; border: 1px solid #55585D; border-radius: 4px;
          padding: 15px 17px; min-height: 112px; }}
.metric-label {{ color: #C4C6C9; font-size: .82rem; }}
.metric-value {{ color: white; font-size: 2rem; font-weight: 700; line-height: 1.25; }}
.metric-foot {{ color: #AEB2B8; font-size: .75rem; }}
.section-title {{ background: #55585D; border-left: 5px solid {RED}; padding: 8px 12px;
                  font-weight: 700; margin: 8px 0 12px 0; }}
div[data-testid="stDataFrame"] {{ border: 1px solid #55585D; }}
.stButton button {{ background: {RED}; color: white; border: 0; }}
.stButton button:hover {{ background: {ORANGE}; color: white; }}
</style>
""", unsafe_allow_html=True)

def panel_metric(label, value, foot=""):
    st.markdown(f"""<div class="panel">
      <div class="metric-label">{label}</div>
      <div class="metric-value">{value}</div>
      <div class="metric-foot">{foot}</div></div>""", unsafe_allow_html=True)

def plot_layout(fig, height=260):
    fig.update_layout(
        height=height, paper_bgcolor=PANEL, plot_bgcolor=PANEL,
        font_color=TEXT, margin=dict(l=12, r=12, t=28, b=12),
        legend=dict(orientation="h", y=-0.25),
        xaxis=dict(gridcolor="#4A4D51", zerolinecolor="#4A4D51"),
        yaxis=dict(gridcolor="#4A4D51", zerolinecolor="#4A4D51")
    )
    return fig

st.markdown("# 👻 GHOST-SIEM")
st.markdown('<div class="ghost-sub">SECURITY INFORMATION & EVENT MANAGEMENT | LOCAL ENDPOINT MONITORING</div>',
            unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## GHOST CONTROL")
    auto = st.toggle("Live refresh", value=True)
    refresh_rate = st.selectbox("Refresh interval", [3, 5, 10, 30], index=1)
    limit = st.slider("Events to display", 50, 1000, 250, 50)
    st.markdown("---")
    st.caption("LOCAL SERVICES")
    try:
        health = requests.get("http://127.0.0.1:8765/health", timeout=1.5).json()
        st.success(f"API: {health.get('status', 'unknown').upper()}")
        st.caption(f"Stored events: {health.get('stored_events', 0):,}")
    except requests.RequestException:
        st.error("API: OFFLINE")
        st.caption("Start the FastAPI ingestion service.")
    st.markdown("---")
    st.caption("LISTENING ADDRESSES")
    st.code("API       127.0.0.1:8765\nDashboard 127.0.0.1:8501")
    st.caption("GHOST-SIEM is an educational local SIEM.")

stats = fetch_stats()
events = fetch_events(limit)
df = pd.DataFrame(events)

st.markdown('<div class="section-title">SYSTEM OVERVIEW</div>', unsafe_allow_html=True)
c1, c2, c3, c4, c5 = st.columns(5)
with c1: panel_metric("TOTAL EVENTS", f"{stats['total']:,}", "All indexed events")
with c2: panel_metric("ERROR / CRITICAL", f"{stats['critical_error']:,}", "Priority events")
with c3: panel_metric("WARNINGS", f"{stats['warnings']:,}", "Warning-level events")
with c4: panel_metric("LOG SOURCES", f"{len(stats['channels'])}", "Distinct channels")
with c5: panel_metric("LATEST EVENT", (stats["latest"] or "N/A")[:16].replace("T"," "), "Stored timestamp")

st.markdown('<div class="section-title">EVENT TELEMETRY</div>', unsafe_allow_html=True)
left, right = st.columns([1.65, 1])
with left:
    timeline = pd.DataFrame(fetch_timeline())
    if not timeline.empty:
        fig = px.area(timeline, x="minute", y="count", title="Event ingestion timeline (last 24 hours)")
        fig.update_traces(line_color=ORANGE, fillcolor="rgba(240,68,82,0.28)")
    else:
        fig = go.Figure()
        fig.add_annotation(text="Waiting for event telemetry", x=.5, y=.5, showarrow=False)
        fig.update_layout(title="Event ingestion timeline (last 24 hours)")
    st.plotly_chart(plot_layout(fig, 300), use_container_width=True)
with right:
    levels = pd.DataFrame(stats["levels"])
    if not levels.empty:
        fig = px.pie(levels, names="level", values="count", hole=.62,
                     title="Event severity distribution",
                     color_discrete_sequence=[RED, ORANGE, PEACH, "#888B91", "#C9C9C9"])
        fig.update_traces(textposition="inside", textinfo="percent+label")
    else:
        fig = go.Figure()
        fig.add_annotation(text="No events indexed", x=.5, y=.5, showarrow=False)
        fig.update_layout(title="Event severity distribution")
    st.plotly_chart(plot_layout(fig, 300), use_container_width=True)

st.markdown('<div class="section-title">LOG SOURCES & COLLECTORS</div>', unsafe_allow_html=True)
a, b = st.columns(2)
with a:
    channels = pd.DataFrame(stats["channels"])
    if not channels.empty:
        fig = px.bar(channels, x="channel", y="count", title="Events by Windows channel",
                     color="channel", color_discrete_sequence=[ORANGE, RED, PEACH])
        fig.update_layout(showlegend=False)
    else:
        fig = go.Figure()
        fig.add_annotation(text="No log sources detected", x=.5, y=.5, showarrow=False)
        fig.update_layout(title="Events by Windows channel")
    st.plotly_chart(plot_layout(fig, 280), use_container_width=True)
with b:
    sources = pd.DataFrame(stats["sources"])
    if not sources.empty:
        fig = px.bar(sources, x="source", y="count", title="Events by collector",
                     color="source", color_discrete_sequence=[RED, ORANGE])
        fig.update_layout(showlegend=False)
    else:
        fig = go.Figure()
        fig.add_annotation(text="No collectors detected", x=.5, y=.5, showarrow=False)
        fig.update_layout(title="Events by collector")
    st.plotly_chart(plot_layout(fig, 280), use_container_width=True)

st.markdown('<div class="section-title">LIVE EVENT STREAM</div>', unsafe_allow_html=True)
if not df.empty:
    search = st.text_input("Search events", placeholder="Search message, provider, event ID, computer...")
    channel_options = ["All"] + sorted([str(x) for x in df["channel"].dropna().unique()])
    selected_channel = st.selectbox("Filter channel", channel_options, horizontal=True)
    view = df.copy()
    if selected_channel != "All":
        view = view[view["channel"] == selected_channel]
    if search:
        mask = view.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False)).any(axis=1)
        view = view[mask]
    display_cols = ["timestamp", "computer", "channel", "provider", "event_id", "level", "message", "source"]
    display_cols = [x for x in display_cols if x in view.columns]
    st.dataframe(view[display_cols], use_container_width=True, hide_index=True, height=380)
    csv = view[display_cols].to_csv(index=False).encode("utf-8")
    st.download_button("Export filtered events (CSV)", csv, "ghost_siem_events.csv", "text/csv")
else:
    st.info("No events yet. Start the PowerShell forwarder or run the demo event generator.")

st.markdown("---")
st.caption("GHOST-SIEM v1.0 | Local educational monitoring | Data stored in data/ghost_siem.db")

if auto:
    time.sleep(refresh_rate)
    st.rerun()
