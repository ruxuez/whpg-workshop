#!/usr/bin/env python3
"""
NetVista K-Means Cluster Explorer — EDB Postgres AI Branded
Single-file Dash App with WHPG Backend.
Run: python3 dashboard.py
Access: http://localhost:5003
"""
import os
import textwrap
import pandas as pd
import psycopg2
import plotly.express as px
import plotly.graph_objects as go
import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, Input, Output, dash_table, State
from typing import Optional

# ─────────────────────────────────────────────
# CONNECTION CONFIG
# ─────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("WPGHOST",   "localhost"),
    "port":     int(os.getenv("WPGPORT",   "5432")),
    "dbname":   os.getenv("WPGDB",     "demo"),
    "user":     os.getenv("WPGUSER",   "gpadmin"),
    "password": os.getenv("WPGPASS",   ""),
}

# ADAPTED: Specific cluster labels from Lab 3
CLUSTER_LABELS = {
    0: "Normal traffic",
    1: "Port scan / recon",
    2: "Data exfil candidate",
    3: "C2 beaconing",
    4: "DDoS amplifier",
}

# EDB Teal & Corporate Palette
COLORS = ["#3DBFBF", "#1D9E75", "#D85A30", "#E8972A", "#D94040"]

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def load_cluster_points() -> pd.DataFrame:
    # ADAPTED: Joined to kmeans_out (MADlib) and expanded feature columns
    sql = textwrap.dedent("""
        SELECT 
            a.pid::text AS src_ip, 
            a.cluster_id, 
            f.flow_count, 
            f.unique_dsts, 
            f.unique_ports,
            ROUND((f.total_bytes / 1e6)::numeric, 2) AS bytes_mb,
            f.max_bytes,
            f.total_packets,
            f.dst_entropy,
            f.port_spread,
            f.hour
        FROM netvista_demo.kmeans_out a
        JOIN netvista_demo.netflow_features f ON (a.pid::text = f.src_ip::text)
        LIMIT 20000
    """)
    with get_connection() as conn:
        return pd.read_sql(sql, conn)

def load_cluster_summary() -> pd.DataFrame:
    # ADAPTED: Centroid logic updated to your features
    sql = textwrap.dedent("""
        SELECT 
            a.cluster_id, 
            COUNT(*) AS ip_count,
            ROUND(AVG(f.flow_count)::numeric, 1) AS avg_flows,
            ROUND(AVG(f.unique_dsts)::numeric, 1) AS avg_dsts,
            ROUND(AVG(f.unique_ports)::numeric, 1) AS avg_ports,
            ROUND((AVG(f.total_bytes)/1e6)::numeric, 2) AS avg_bytes_mb,
            ROUND(AVG(f.dst_entropy)::numeric, 4) AS avg_entropy,
            ROUND(AVG(f.port_spread)::numeric, 4) AS avg_port_spread
        FROM netvista_demo.kmeans_out a
        JOIN netvista_demo.netflow_features f ON (a.pid::text = f.src_ip::text)
        GROUP BY a.cluster_id 
        ORDER BY a.cluster_id
    """)
    with get_connection() as conn:
        return pd.read_sql(sql, conn)

# ─────────────────────────────────────────────
# STYLE & LAYOUT
# ─────────────────────────────────────────────

def _chart_layout(height=350):
    return dict(
        height=height,
        margin=dict(l=40, r=20, t=20, b=40),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="'IBM Plex Sans', sans-serif", color="#3D3D3D", size=11),
        xaxis=dict(gridcolor="#EEEEEE", zerolinecolor="#E5E5E5"),
        yaxis=dict(gridcolor="#EEEEEE", zerolinecolor="#E5E5E5"),
    )

# ─────────────────────────────────────────────
# DASH APP SETUP
# ─────────────────────────────────────────────

app = dash.Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.BOOTSTRAP,
        "https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;600&family=IBM+Plex+Mono&display=swap"
    ],
    title="NetVista — EDB Postgres AI",
)

# ADAPTED UI Dropdown Options for your specific columns
AXIS_OPTIONS = [
    {"label": "Flows", "value": "flow_count"},
    {"label": "Dsts", "value": "unique_dsts"},
    {"label": "Ports", "value": "unique_ports"},
    {"label": "Bytes (MB)", "value": "bytes_mb"},
    {"label": "Max Bytes", "value": "max_bytes"},
    {"label": "Packets", "value": "total_packets"},
    {"label": "Entropy", "value": "dst_entropy"},
    {"label": "Port Spread", "value": "port_spread"}
]

header = html.Nav(className="nav", style={
    "background": "#fff", "borderBottom": "1px solid #E2E2E2",
    "borderTop": "3px solid #3DBFBF", "height": "58px",
    "display": "flex", "alignItems": "center", "padding": "0 28px",
    "position": "sticky", "top": "0", "zIndex": "100", "boxShadow": "0 1px 3px rgba(0,0,0,.06)"
}, children=[
    html.A(style={"textDecoration": "none", "marginRight": "18px", "display": "flex", "alignItems": "baseline", "gap": "4px"}, children=[
        html.Span("EDB", style={"fontSize": "17px", "fontWeight": "800", "letterSpacing": "1px", "color": "#27A67A"}),
        html.Span("WHPG", style={"fontSize": "17px", "fontWeight": "700", "letterSpacing": ".5px", "color": "#27A67A"}),
    ]),
    html.Div(style={"width": "1px", "height": "24px", "background": "#E2E2E2", "margin": "0 16px"}),
    html.Span("K-Means Cluster Explorer", style={"fontSize": "13px", "fontWeight": "500", "color": "#555555"}),
    html.Div(style={"flex": "1"}),
    html.Div(id="conn-status", className="nav-pill", style={
        "display": "flex", "alignItems": "center", "gap": "7px", "fontSize": "12px", 
        "background": "#F5F5F5", "border": "1px solid #E2E2E2", "padding": "5px 13px", "borderRadius": "20px"
    })
])

app.layout = html.Div(style={"background": "#F5F5F5", "minHeight": "100vh"}, children=[
    header,
    dbc.Container(className="page", style={"maxWidth": "1340px", "margin": "0 auto", "padding": "28px"}, children=[
        
        # Title & Description
        html.Div(className="ph", style={"marginBottom": "26px"}, children=[
            html.H1("AI Factory: Behavior Clustering", style={"fontSize": "21px", "fontWeight": "600"}),
            html.P("Unsupervised anomaly detection using MADlib K-Means on NetFlow feature vectors.", 
                   style={"fontSize": "13.5px", "color": "#555555"}),
        ]),

        # Stats Row
        dbc.Row(id="metric-cards", style={"marginBottom": "26px"}),

        # Control Bar
        html.Div(className="abar", style={"display": "flex", "gap": "10px", "marginBottom": "24px"}, children=[
            dbc.Button("⟳  Refresh Data", id="btn-reload", className="btn bs", 
                       style={"background": "#fff", "color": "#1D8080", "borderColor": "#3DBFBF"}),
            dcc.Dropdown(id="x-axis", options=AXIS_OPTIONS, value="flow_count", clearable=False, style={"width": "180px"}),
            dcc.Dropdown(id="y-axis", options=AXIS_OPTIONS, value="unique_ports", clearable=False, style={"width": "180px"}),
        ]),

        # Charts
        dbc.Row([
            dbc.Col(dbc.Card(className="bcard", children=[
                dbc.CardHeader("Cluster Distribution (Scatter)", style={"fontSize": "12px", "fontWeight": "600"}),
                dbc.CardBody(dcc.Graph(id="scatter-plot", config={"displayModeBar": False}))
            ]), md=8),
            dbc.Col(dbc.Card(className="bcard", children=[
                dbc.CardHeader("Cluster Sizes", style={"fontSize": "12px", "fontWeight": "600"}),
                dbc.CardBody(dcc.Graph(id="dist-plot", config={"displayModeBar": False}))
            ]), md=4),
        ]),

        html.Br(),

        # Heatmap & Radar
        dbc.Row([
            dbc.Col(dbc.Card(className="bcard", children=[
                dbc.CardHeader("Normalised Centroid Profiles", style={"fontSize": "12px", "fontWeight": "600"}),
                dbc.CardBody(dcc.Graph(id="radar-plot", config={"displayModeBar": False}))
            ]), md=6),
            dbc.Col(dbc.Card(className="bcard", children=[
                dbc.CardHeader("Centroid Heatmap (Z-Score)", style={"fontSize": "12px", "fontWeight": "600"}),
                dbc.CardBody(dcc.Graph(id="heatmap-plot", config={"displayModeBar": False}))
            ]), md=6),
        ]),

        html.Br(),

        # Drilldown Table
        dbc.Card(className="bcard", children=[
            dbc.CardHeader(style={"display": "flex", "justifyContent": "space-between", "alignItems": "center"}, children=[
                html.Span("Cluster Forensic Drilldown", style={"fontSize": "12px", "fontWeight": "600"}),
                dcc.Dropdown(id="drilldown-cluster", 
                             options=[{"label": f"C{i}: {CLUSTER_LABELS[i]}", "value": i} for i in range(5)], 
                             value=1, clearable=False, style={"width": "250px", "color": "#333"})
            ]),
            dbc.CardBody(html.Div(id="drilldown-content"))
        ])
    ]),
    
    # Stores
    dcc.Store(id="store-points"),
    dcc.Store(id="store-summary"),
])

# ─────────────────────────────────────────────
# CALLBACKS
# ─────────────────────────────────────────────

@app.callback(
    Output("store-points", "data"),
    Output("store-summary", "data"),
    Output("conn-status", "children"),
    Input("btn-reload", "n_clicks"),
)
def update_data(_):
    try:
        pts = load_cluster_points()
        summ = load_cluster_summary()
        status = [html.Div(className="sdot on"), html.Span(f"Connected: {len(pts):,} IPs")]
        return pts.to_json(orient="split"), summ.to_json(orient="split"), status
    except Exception as e:
        print(f"ERROR: {e}")
        return None, None, [html.Div(className="sdot err"), html.Span("Disconnected")]

@app.callback(
    Output("metric-cards", "children"),
    Input("store-summary", "data")
)
def render_metrics(summ_json):
    if not summ_json: return []
    df = pd.read_json(summ_json, orient="split")
    
    def make_card(lbl, val, sub):
        return dbc.Col(html.Div(className="sc", style={
            "background": "#fff", "border": "1px solid #E2E2E2", "borderTop": "3px solid #3DBFBF",
            "borderRadius": "12px", "padding": "15px 17px", "boxShadow": "0 1px 3px rgba(0,0,0,.06)"
        }, children=[
            html.Div(lbl, style={"fontSize": "10.5px", "fontWeight": "600", "textTransform": "uppercase", "color": "#999"}),
            html.Div(val, style={"fontSize": "21px", "fontWeight": "700", "fontFamily": "IBM Plex Mono"}),
            html.Div(sub, style={"fontSize": "11px", "color": "#999"})
        ]))

    return [
        make_card("Total IPs", f"{df['ip_count'].sum():,}", "Analyzed"),
        make_card("Top Cluster", f"C{df.loc[df['ip_count'].idxmax(), 'cluster_id']}", "Majority"),
        make_card("Avg Flows", f"{df['avg_flows'].mean():.1f}", "Global Mean"),
        make_card("Threat Cluster", "C1", "Reconnaissance")
    ]

@app.callback(
    Output("scatter-plot", "figure"),
    Output("dist-plot", "figure"),
    Output("radar-plot", "figure"),
    Output("heatmap-plot", "figure"),
    Input("store-points", "data"),
    Input("store-summary", "data"),
    Input("x-axis", "value"),
    Input("y-axis", "value"),
)
def update_charts(pts_json, summ_json, x, y):
    if not pts_json: return [go.Figure().update_layout(**_chart_layout())]*4
    pts = pd.read_json(pts_json, orient="split")
    summ = pd.read_json(summ_json, orient="split")
    
    # Scatter
    pts["label"] = pts["cluster_id"].map(CLUSTER_LABELS)
    fig_s = px.scatter(pts, x=x, y=y, color="label", color_discrete_sequence=COLORS, opacity=0.6)
    fig_s.update_layout(**_chart_layout())

    # Dist
    fig_d = px.bar(summ, x="ip_count", y="cluster_id", orientation='h', color_discrete_sequence=[COLORS[0]])
    fig_d.update_layout(**_chart_layout())

    # Radar (Normalised across features)
    fig_r = go.Figure()
    # ADAPTED: Expanded dimensions for radar
    dims = ["avg_flows", "avg_dsts", "avg_ports", "avg_bytes_mb", "avg_entropy", "avg_port_spread"]
    for i, row in summ.iterrows():
        # Simple max-norm for visualization
        r_vals = row[dims].values.astype(float)
        # Normalize each dimension by the global max of that dimension in the summary
        norm_vals = []
        for d in dims:
            max_val = summ[d].max()
            norm_vals.append(row[d] / max_val if max_val > 0 else 0)
            
        fig_r.add_trace(go.Scatterpolar(
            r=norm_vals, 
            theta=["Flows", "Dsts", "Ports", "Bytes", "Entropy", "Spread"], 
            fill='toself', 
            name=f"C{int(row['cluster_id'])}", 
            line_color=COLORS[i%5]
        ))
    fig_r.update_layout(**_chart_layout())

    # Heatmap
    heatmap_dims = ["avg_flows", "avg_dsts", "avg_ports", "avg_bytes_mb", "avg_entropy", "avg_port_spread"]
    fig_h = px.imshow(summ[heatmap_dims].values, labels=dict(x="Feature", y="Cluster"), x=heatmap_dims, color_continuous_scale="RdBu_r")
    fig_h.update_layout(**_chart_layout())

    return fig_s, fig_d, fig_r, fig_h

@app.callback(
    Output("drilldown-content", "children"),
    Input("drilldown-cluster", "value"),
    Input("store-points", "data")
)
def render_table(cid, pts_json):
    if not pts_json: return "No data"
    df = pd.read_json(pts_json, orient="split")
    filtered = df[df["cluster_id"] == cid].head(20)
    return dash_table.DataTable(
        data=filtered.to_dict('records'),
        columns=[{"name": i, "id": i} for i in filtered.columns],
        style_header={'backgroundColor': '#FAFAFA', 'fontWeight': 'bold', 'fontSize': '11px', 'textTransform': 'uppercase'},
        style_cell={'fontSize': '12px', 'fontFamily': 'IBM Plex Mono', 'padding': '8px'},
        style_table={'overflowX': 'auto'}
    )

if __name__ == '__main__':
    print('\n  EDB MADlib Kmeans Dashboard: http://localhost:5003\n')
    app.run(host='0.0.0.0', port=5003, debug=True, threaded=True)