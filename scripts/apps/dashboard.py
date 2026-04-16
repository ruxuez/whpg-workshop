"""
K-Means Cluster Dashboard — WarehousePG / Greenplum
====================================================
Requirements:
    pip install psycopg2-binary pandas plotly dash dash-bootstrap-components

Run:
    python kmeans_dashboard.py

Then open http://127.0.0.1:5003 in your browser.
"""

import os
import textwrap
import pandas as pd
import psycopg2
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import dash
from dash import dcc, html, Input, Output, State, dash_table, callback_context
import dash_bootstrap_components as dbc

# ─────────────────────────────────────────────
# CONNECTION CONFIG  (edit or use env vars)
# ─────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("WPGHOST",   "localhost"),
    "port":     int(os.getenv("WPGPORT",   "5432")),
    "dbname":   os.getenv("WPGDB",     "demo"),
    "user":     os.getenv("WPGUSER",   "gpadmin"),
    "password": os.getenv("WPGPASS",   ""),
}

CLUSTER_LABELS = {
    0: "Normal traffic",
    1: "Port scan / recon",
    2: "Data exfil candidate",
    3: "C2 beaconing",
    4: "DDoS amplifier",
}

COLORS = ["#378ADD", "#1D9E75", "#D85A30", "#BA7517", "#993356"]

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────

def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def load_cluster_points() -> pd.DataFrame:
    """Join kmeans_assignments with netflow_features for per-IP data."""
    sql = textwrap.dedent("""
        SELECT
            a.src_ip,
            a.cluster_id,
            f.flow_count,
            f.unique_dsts,
            f.unique_ports,
            ROUND((f.total_bytes / 1e6)::numeric, 2)   AS bytes_mb,
            ROUND(f.avg_bytes::numeric, 1)              AS avg_bytes,
            ROUND(f.dst_entropy::numeric, 4)            AS dst_entropy,
            ROUND(f.port_spread::numeric, 4)            AS port_spread,
            f.hour
        FROM netvista_demo.kmeans_assignments  a
        JOIN netvista_demo.netflow_features    f USING (src_ip)
        ORDER BY a.cluster_id, f.flow_count DESC
        LIMIT 20000
    """)
    with get_connection() as conn:
        return pd.read_sql(sql, conn)


def load_cluster_summary() -> pd.DataFrame:
    """Centroid-level aggregates per cluster."""
    sql = textwrap.dedent("""
        SELECT
            a.cluster_id,
            COUNT(*)                                          AS ip_count,
            ROUND(AVG(f.flow_count)::numeric, 1)             AS avg_flows,
            ROUND(AVG(f.unique_dsts)::numeric, 1)            AS avg_dsts,
            ROUND(AVG(f.unique_ports)::numeric, 1)           AS avg_ports,
            ROUND((AVG(f.total_bytes)/1e6)::numeric, 2)      AS avg_bytes_mb,
            ROUND(AVG(f.dst_entropy)::numeric, 4)            AS avg_entropy,
            ROUND(AVG(f.port_spread)::numeric, 4)            AS avg_port_spread,
            ROUND(STDDEV(f.flow_count)::numeric, 1)          AS sd_flows,
            ROUND(STDDEV(f.unique_dsts)::numeric, 1)         AS sd_dsts,
            ROUND(STDDEV(f.unique_ports)::numeric, 1)        AS sd_ports
        FROM netvista_demo.kmeans_assignments a
        JOIN netvista_demo.netflow_features   f USING (src_ip)
        GROUP BY a.cluster_id
        ORDER BY a.cluster_id
    """)
    with get_connection() as conn:
        return pd.read_sql(sql, conn)


def load_top_ips(cluster_id: int, n: int = 20) -> pd.DataFrame:
    sql = textwrap.dedent(f"""
        SELECT
            a.src_ip,
            f.flow_count,
            f.unique_dsts,
            f.unique_ports,
            ROUND((f.total_bytes/1e6)::numeric, 2) AS bytes_mb,
            ROUND(f.dst_entropy::numeric, 4)        AS dst_entropy,
            ROUND(f.port_spread::numeric, 4)        AS port_spread
        FROM netvista_demo.kmeans_assignments a
        JOIN netvista_demo.netflow_features   f USING (src_ip)
        WHERE a.cluster_id = {cluster_id}
        ORDER BY f.flow_count DESC
        LIMIT {n}
    """)
    with get_connection() as conn:
        return pd.read_sql(sql, conn)


def load_syslog_sample(cluster_id: int, n: int = 50) -> pd.DataFrame:
    """Syslogs from IPs in the given cluster."""
    sql = textwrap.dedent(f"""
        SELECT
            e.ts,
            e.hostname,
            e.program,
            LEFT(e.message, 120) AS message,
            e.severity
        FROM netvista_demo.syslog_events e
        WHERE e.hostname IN (
            SELECT src_ip
            FROM netvista_demo.kmeans_assignments
            WHERE cluster_id = {cluster_id}
            LIMIT 200
        )
        ORDER BY e.ts DESC
        LIMIT {n}
    """)
    with get_connection() as conn:
        return pd.read_sql(sql, conn)


# ─────────────────────────────────────────────
# CHART BUILDERS
# ─────────────────────────────────────────────

def fig_scatter(df: pd.DataFrame, x_col: str, y_col: str, highlight: int | None):
    df = df.copy()
    df["label"] = df["cluster_id"].map(CLUSTER_LABELS).fillna("Unknown")
    df["opacity"] = df["cluster_id"].apply(
        lambda c: 1.0 if highlight is None or c == highlight else 0.15
    )
    df["size"] = df["cluster_id"].apply(
        lambda c: 8 if highlight is None or c == highlight else 4
    )
    fig = px.scatter(
        df, x=x_col, y=y_col,
        color="label",
        color_discrete_sequence=COLORS,
        hover_data=["src_ip", "flow_count", "unique_dsts", "unique_ports", "bytes_mb"],
        opacity=0.75,
        labels={x_col: x_col.replace("_", " "), y_col: y_col.replace("_", " ")},
    )
    fig.update_traces(marker=dict(size=6))
    if highlight is not None:
        for trace in fig.data:
            name = trace.name
            is_hl = any(CLUSTER_LABELS.get(c) == name for c in [highlight])
            trace.marker.opacity = 0.85 if is_hl else 0.1
            trace.marker.size = 8 if is_hl else 4
    fig.update_layout(**_layout())
    return fig


def fig_centroid_radar(summary: pd.DataFrame):
    dims = ["avg_flows", "avg_dsts", "avg_ports", "avg_bytes_mb", "avg_entropy", "avg_port_spread"]
    dim_labels = ["Flows", "Unique dsts", "Unique ports", "Bytes (MB)", "Dst entropy", "Port spread"]
    # normalise each dim 0-1
    norm = summary[dims].copy()
    for c in dims:
        mx = norm[c].max()
        norm[c] = norm[c] / mx if mx > 0 else 0

    fig = go.Figure()
    for _, row in summary.iterrows():
        ci = int(row["cluster_id"])
        vals = norm.loc[row.name, dims].tolist()
        vals += [vals[0]]
        fig.add_trace(go.Scatterpolar(
            r=vals,
            theta=dim_labels + [dim_labels[0]],
            fill="toself",
            name=CLUSTER_LABELS.get(ci, f"C{ci}"),
            line_color=COLORS[ci % len(COLORS)],
            opacity=0.65,
        ))
    fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 1], showticklabels=False)),
        showlegend=True,
        **_layout(height=380),
    )
    return fig


def fig_distribution(summary: pd.DataFrame):
    df = summary.copy()
    df["label"] = df["cluster_id"].map(CLUSTER_LABELS)
    fig = px.bar(
        df, x="ip_count", y="label", orientation="h",
        color="label", color_discrete_sequence=COLORS,
        text="ip_count",
        labels={"ip_count": "IP count", "label": ""},
    )
    fig.update_traces(textposition="outside")
    fig.update_layout(showlegend=False, **_layout(height=300))
    return fig


def fig_time_series(df: pd.DataFrame, highlight: int | None):
    df = df.copy()
    df["label"] = df["cluster_id"].map(CLUSTER_LABELS)
    if "hour" in df.columns and df["hour"].notna().any():
        agg = df.groupby(["hour", "cluster_id", "label"])["flow_count"].sum().reset_index()
        fig = px.line(
            agg, x="hour", y="flow_count", color="label",
            color_discrete_sequence=COLORS,
            labels={"flow_count": "Total flows", "hour": "Hour"},
        )
    else:
        # fallback: bar of avg flows
        agg = df.groupby(["cluster_id", "label"])["flow_count"].mean().reset_index()
        fig = px.bar(agg, x="label", y="flow_count", color="label",
                     color_discrete_sequence=COLORS,
                     labels={"flow_count": "Avg flow count"})
    fig.update_layout(showlegend=True, **_layout(height=280))
    return fig


def fig_centroid_heatmap(summary: pd.DataFrame):
    dims = ["avg_flows", "avg_dsts", "avg_ports", "avg_bytes_mb", "avg_entropy", "avg_port_spread"]
    dim_labels = ["Flows", "Unique dsts", "Ports", "Bytes MB", "Entropy", "Port spread"]
    z = summary[dims].values.astype(float)
    # z-score per column for display
    for j in range(z.shape[1]):
        col = z[:, j]
        mu, sd = col.mean(), col.std()
        z[:, j] = (col - mu) / sd if sd > 0 else col - mu
    yl = [CLUSTER_LABELS.get(int(r), f"C{int(r)}") for r in summary["cluster_id"]]
    fig = go.Figure(go.Heatmap(
        z=z, x=dim_labels, y=yl,
        colorscale="RdBu", zmid=0,
        text=summary[dims].round(2).values,
        texttemplate="%{text}",
        hovertemplate="%{y} — %{x}: %{text}<extra></extra>",
    ))
    fig.update_layout(**_layout(height=280))
    return fig


def _layout(height=360):
    return dict(
        height=height,
        margin=dict(l=40, r=20, t=20, b=40),
        plot_bgcolor="#0d1117",
        paper_bgcolor="#0d1117",
        font=dict(family="'JetBrains Mono', monospace", color="#c9d1d9", size=11),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=10)),
        xaxis=dict(gridcolor="#21262d", zerolinecolor="#21262d"),
        yaxis=dict(gridcolor="#21262d", zerolinecolor="#21262d"),
    )


# ─────────────────────────────────────────────
# DASH APP
# ─────────────────────────────────────────────

app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.CYBORG],
    title="NetVista — Cluster Explorer",
)

AXIS_OPTIONS = [
    {"label": "Flow count",    "value": "flow_count"},
    {"label": "Unique dsts",   "value": "unique_dsts"},
    {"label": "Unique ports",  "value": "unique_ports"},
    {"label": "Bytes (MB)",    "value": "bytes_mb"},
    {"label": "Dst entropy",   "value": "dst_entropy"},
    {"label": "Port spread",   "value": "port_spread"},
]

cluster_options = [{"label": f"All clusters", "value": -1}] + [
    {"label": f"C{i} — {CLUSTER_LABELS[i]}", "value": i} for i in range(5)
]

app.layout = dbc.Container(fluid=True, style={"background": "#0d1117", "minHeight": "100vh", "paddingBottom": "40px"}, children=[
    # header
    dbc.Row(dbc.Col(html.Div([
        html.Span("◈ ", style={"color": "#378ADD", "fontSize": "22px"}),
        html.Span("NetVista", style={"fontFamily": "'JetBrains Mono', monospace", "fontSize": "22px",
                                      "fontWeight": "700", "color": "#e6edf3", "letterSpacing": "0.05em"}),
        html.Span("  /  K-Means Cluster Explorer", style={"fontFamily": "'JetBrains Mono', monospace",
                                                            "fontSize": "13px", "color": "#8b949e"}),
    ], style={"padding": "18px 0 12px"}), width=12)),

    # connection status + reload
    dbc.Row([
        dbc.Col(html.Div(id="conn-status", style={"fontSize": "12px", "fontFamily": "monospace"}), width=8),
        dbc.Col(dbc.Button("⟳  Reload data", id="btn-reload", color="secondary", size="sm",
                           style={"float": "right", "fontFamily": "monospace", "fontSize": "12px"}), width=4),
    ], style={"marginBottom": "16px"}),

    # metric cards
    dbc.Row(id="metric-cards", style={"marginBottom": "20px"}),

    # main charts row
    dbc.Row([
        dbc.Col([
            html.Div([
                html.Span("Scatter", style={"fontSize": "12px", "color": "#8b949e", "fontFamily": "monospace",
                                            "marginRight": "16px", "textTransform": "uppercase", "letterSpacing": ".06em"}),
                dcc.Dropdown(id="x-axis", options=AXIS_OPTIONS, value="flow_count",
                             clearable=False, style={"width": "150px", "display": "inline-block",
                                                      "fontSize": "12px", "marginRight": "8px"}),
                html.Span("vs", style={"color": "#8b949e", "fontSize": "12px", "marginRight": "8px"}),
                dcc.Dropdown(id="y-axis", options=AXIS_OPTIONS, value="unique_ports",
                             clearable=False, style={"width": "150px", "display": "inline-block", "fontSize": "12px"}),
            ], style={"marginBottom": "8px", "display": "flex", "alignItems": "center", "gap": "6px"}),
            dcc.Graph(id="scatter-plot", config={"displayModeBar": False}),
        ], md=8),
        dbc.Col([
            html.Div("Cluster sizes", style={"fontSize": "12px", "color": "#8b949e", "fontFamily": "monospace",
                                              "textTransform": "uppercase", "letterSpacing": ".06em", "marginBottom": "8px"}),
            dcc.Graph(id="dist-plot", config={"displayModeBar": False}),
            html.Div("Radar — normalised centroids",
                     style={"fontSize": "12px", "color": "#8b949e", "fontFamily": "monospace",
                            "textTransform": "uppercase", "letterSpacing": ".06em", "marginTop": "14px", "marginBottom": "8px"}),
            dcc.Graph(id="radar-plot", config={"displayModeBar": False}),
        ], md=4),
    ], style={"marginBottom": "20px"}),

    # heatmap + time series
    dbc.Row([
        dbc.Col([
            html.Div("Centroid heatmap (z-scored)", style={"fontSize": "12px", "color": "#8b949e", "fontFamily": "monospace",
                                                            "textTransform": "uppercase", "letterSpacing": ".06em", "marginBottom": "8px"}),
            dcc.Graph(id="heatmap-plot", config={"displayModeBar": False}),
        ], md=6),
        dbc.Col([
            html.Div("Flow volume over time", style={"fontSize": "12px", "color": "#8b949e", "fontFamily": "monospace",
                                                      "textTransform": "uppercase", "letterSpacing": ".06em", "marginBottom": "8px"}),
            dcc.Graph(id="time-plot", config={"displayModeBar": False}),
        ], md=6),
    ], style={"marginBottom": "20px"}),

    # drilldown section
    dbc.Row([
        dbc.Col([
            html.Div([
                html.Span("Cluster drilldown", style={"fontSize": "12px", "color": "#8b949e", "fontFamily": "monospace",
                                                       "textTransform": "uppercase", "letterSpacing": ".06em", "marginRight": "16px"}),
                dcc.Dropdown(id="drilldown-cluster", options=cluster_options, value=0, clearable=False,
                             style={"width": "260px", "display": "inline-block", "fontSize": "12px"}),
            ], style={"marginBottom": "10px", "display": "flex", "alignItems": "center"}),

            dbc.Tabs([
                dbc.Tab(label="Top IPs", tab_id="tab-ips"),
                dbc.Tab(label="Syslog events", tab_id="tab-syslogs"),
            ], id="drilldown-tabs", active_tab="tab-ips", style={"fontSize": "12px"}),

            html.Div(id="drilldown-content", style={"marginTop": "12px"}),
        ], width=12),
    ]),

    # hidden stores
    dcc.Store(id="store-points"),
    dcc.Store(id="store-summary"),
    dcc.Store(id="store-highlight", data=None),
])


# ─────────────────────────────────────────────
# CALLBACKS
# ─────────────────────────────────────────────

@app.callback(
    Output("store-points",  "data"),
    Output("store-summary", "data"),
    Output("conn-status",   "children"),
    Input("btn-reload", "n_clicks"),
    prevent_initial_call=False,
)
def load_data(_):
    try:
        pts  = load_cluster_points()
        summ = load_cluster_summary()
        pts["cluster_id"]  = pts["cluster_id"].astype(int)
        summ["cluster_id"] = summ["cluster_id"].astype(int)
        msg = html.Span([
            html.Span("● ", style={"color": "#3fb950"}),
            html.Span(f"Connected to {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}  ·  "
                      f"{len(pts):,} IPs loaded", style={"color": "#8b949e"}),
        ])
        return pts.to_json(date_format="iso", orient="split"), summ.to_json(date_format="iso", orient="split"), msg
    except Exception as exc:
        msg = html.Span([
            html.Span("● ", style={"color": "#f85149"}),
            html.Span(f"Connection failed: {exc}", style={"color": "#f85149"}),
        ])
        return None, None, msg


@app.callback(
    Output("metric-cards", "children"),
    Input("store-summary", "data"),
    Input("store-points",  "data"),
)
def update_metrics(summ_json, pts_json):
    if not summ_json:
        return []
    summ = pd.read_json(summ_json, orient="split")
    pts  = pd.read_json(pts_json,  orient="split") if pts_json else pd.DataFrame()
    total_ips   = summ["ip_count"].sum()
    largest     = summ.loc[summ["ip_count"].idxmax()]
    anomaly_cls = summ.nlargest(2, "avg_flows").iloc[-1]["cluster_id"]
    anomaly_n   = int(summ.loc[summ["cluster_id"] == anomaly_cls, "ip_count"].values[0])

    def card(label, value, color="#c9d1d9"):
        return dbc.Col(dbc.Card(dbc.CardBody([
            html.P(label, style={"fontSize": "11px", "color": "#8b949e", "fontFamily": "monospace",
                                  "textTransform": "uppercase", "letterSpacing": ".06em", "margin": "0 0 4px"}),
            html.P(value, style={"fontSize": "22px", "fontWeight": "700", "color": color,
                                  "fontFamily": "'JetBrains Mono', monospace", "margin": "0"}),
        ]), style={"background": "#161b22", "border": "0.5px solid #21262d", "borderRadius": "8px"}))

    return [
        card("Total IPs",      f"{int(total_ips):,}"),
        card("Clusters (k)",   "5"),
        card("Largest cluster", f"C{int(largest['cluster_id'])} · {int(largest['ip_count']):,}"),
        card("Anomaly IPs",    f"{anomaly_n:,}", color="#f85149"),
        card("Avg flow count", f"{summ['avg_flows'].mean():.0f}"),
        card("Max entropy",    f"{summ['avg_entropy'].max():.3f}"),
    ]


@app.callback(
    Output("scatter-plot", "figure"),
    Output("dist-plot",    "figure"),
    Output("radar-plot",   "figure"),
    Output("heatmap-plot", "figure"),
    Output("time-plot",    "figure"),
    Input("store-points",  "data"),
    Input("store-summary", "data"),
    Input("x-axis", "value"),
    Input("y-axis", "value"),
    Input("store-highlight", "data"),
)
def update_charts(pts_json, summ_json, x_col, y_col, highlight):
    empty = go.Figure()
    empty.update_layout(**_layout())
    if not pts_json or not summ_json:
        return empty, empty, empty, empty, empty
    pts  = pd.read_json(pts_json,  orient="split")
    summ = pd.read_json(summ_json, orient="split")
    pts["cluster_id"]  = pts["cluster_id"].astype(int)
    summ["cluster_id"] = summ["cluster_id"].astype(int)
    return (
        fig_scatter(pts,  x_col, y_col, highlight),
        fig_distribution(summ),
        fig_centroid_radar(summ),
        fig_centroid_heatmap(summ),
        fig_time_series(pts, highlight),
    )


@app.callback(
    Output("store-highlight", "data"),
    Input("scatter-plot", "clickData"),
    Input("dist-plot",    "clickData"),
)
def update_highlight(scatter_click, dist_click):
    ctx = callback_context
    if not ctx.triggered:
        return None
    # not wiring highlight back for now — placeholder for future
    return None


@app.callback(
    Output("drilldown-content", "children"),
    Input("drilldown-cluster", "value"),
    Input("drilldown-tabs",    "active_tab"),
    Input("store-points",      "data"),
)
def update_drilldown(cluster_id, active_tab, pts_json):
    if pts_json is None:
        return html.P("No data loaded.", style={"color": "#8b949e", "fontFamily": "monospace", "fontSize": "13px"})

    if active_tab == "tab-ips":
        try:
            df = load_top_ips(cluster_id, n=25)
        except Exception as exc:
            # fallback: filter from store
            pts = pd.read_json(pts_json, orient="split")
            pts["cluster_id"] = pts["cluster_id"].astype(int)
            df = pts[pts["cluster_id"] == cluster_id].head(25)
        cols = [{"name": c, "id": c} for c in df.columns]
        return dash_table.DataTable(
            data=df.to_dict("records"),
            columns=cols,
            page_size=20,
            style_table={"overflowX": "auto"},
            style_cell={"background": "#161b22", "color": "#c9d1d9",
                        "fontFamily": "monospace", "fontSize": "12px",
                        "border": "0.5px solid #21262d", "padding": "6px 10px"},
            style_header={"background": "#0d1117", "color": "#8b949e",
                          "fontWeight": "500", "border": "0.5px solid #21262d"},
            style_data_conditional=[{"if": {"row_index": "odd"}, "background": "#0d1117"}],
        )

    elif active_tab == "tab-syslogs":
        try:
            df = load_syslog_sample(cluster_id, n=40)
        except Exception as exc:
            return html.P(f"Could not load syslogs: {exc}",
                          style={"color": "#f85149", "fontFamily": "monospace", "fontSize": "12px"})
        if df.empty:
            return html.P("No syslog events found for this cluster.",
                          style={"color": "#8b949e", "fontFamily": "monospace", "fontSize": "13px"})
        cols = [{"name": c, "id": c} for c in df.columns]
        return dash_table.DataTable(
            data=df.to_dict("records"),
            columns=cols,
            page_size=20,
            style_table={"overflowX": "auto"},
            style_cell={"background": "#161b22", "color": "#c9d1d9",
                        "fontFamily": "monospace", "fontSize": "12px",
                        "border": "0.5px solid #21262d", "padding": "6px 10px",
                        "maxWidth": "340px", "overflow": "hidden", "textOverflow": "ellipsis"},
            style_header={"background": "#0d1117", "color": "#8b949e",
                          "fontWeight": "500", "border": "0.5px solid #21262d"},
            style_data_conditional=[{"if": {"row_index": "odd"}, "background": "#0d1117"}],
        )

    return html.Div()


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  ◈  NetVista K-Means Cluster Explorer")
    print(f"     DB: {DB_CONFIG['user']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}")
    print("     Open http://127.0.0.1:5003\n")
    app.run(debug=True, host="127.0.0.1", port=5003)