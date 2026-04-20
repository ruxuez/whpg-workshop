"""
NetVista: AI Factory - K-Means Cluster Explorer
===============================================
Requirements:
    pip install psycopg2-binary pandas plotly dash dash-bootstrap-components

Usage:
    python3.9 dashboard.py
"""

import os
import textwrap
import pandas as pd
import psycopg2
import plotly.express as px
import plotly.graph_objects as go
from typing import Optional  # Required for Python 3.9 compatibility
import dash
from dash import dcc, html, Input, Output, dash_table
import dash_bootstrap_components as dbc

# ─────────────────────────────────────────────
# 1. CONNECTION CONFIG
# ─────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("WPGHOST",   "localhost"),
    "port":     int(os.getenv("WPGPORT",   "5432")),
    "dbname":   os.getenv("WPGDB",     "netvista_demo"),
    "user":     os.getenv("WPGUSER",   "gpadmin"),
    "password": os.getenv("WPGPASS",   ""),
}

# Labels based on typical security behavioral clusters
CLUSTER_LABELS = {
    0: "Standard Traffic",
    1: "Recon / Port Scanning",
    2: "Data Exfiltration",
    3: "C2 / Beaconing",
    4: "DDoS / High Volume",
}

COLORS = ["#378ADD", "#1D9E75", "#D85A30", "#BA7517", "#993356"]

# ─────────────────────────────────────────────
# 2. DATABASE HELPERS
# ─────────────────────────────────────────────

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def load_cluster_points() -> pd.DataFrame:
    """Joins MADlib kmeans results with your custom netflow_features table."""
    sql = textwrap.dedent("""
        SELECT
            a.pid::text as src_ip,
            a.cluster_id,
            f.flow_count,
            f.unique_dsts,
            f.unique_ports,
            ROUND((f.total_bytes / 1e6)::numeric, 2)   AS bytes_mb,
            f.max_bytes,
            f.total_packets,
            f.dst_entropy,
            f.port_spread,
            f.hour
        FROM netvista_demo.kmeans_out  a
        JOIN netvista_demo.netflow_features f ON (a.pid::text = f.src_ip::text)
        ORDER BY a.cluster_id, f.flow_count DESC
        LIMIT 15000
    """)
    with get_connection() as conn:
        return pd.read_sql(sql, conn)

def load_cluster_summary() -> pd.DataFrame:
    """Calculates cluster centroids based on your specific features."""
    sql = textwrap.dedent("""
        SELECT
            a.cluster_id,
            COUNT(*)                                          AS ip_count,
            ROUND(AVG(f.flow_count)::numeric, 1)             AS avg_flows,
            ROUND(AVG(f.unique_dsts)::numeric, 1)            AS avg_dsts,
            ROUND(AVG(f.unique_ports)::numeric, 1)           AS avg_ports,
            ROUND((AVG(f.total_bytes)/1e6)::numeric, 2)      AS avg_bytes_mb,
            ROUND(AVG(f.dst_entropy)::numeric, 4)            AS avg_entropy,
            ROUND(AVG(f.port_spread)::numeric, 4)            AS avg_port_spread
        FROM netvista_demo.kmeans_out a
        JOIN netvista_demo.netflow_features f ON (a.pid::text = f.src_ip::text)
        GROUP BY a.cluster_id
        ORDER BY a.cluster_id
    """)
    with get_connection() as conn:
        return pd.read_sql(sql, conn)

def load_top_ips(cluster_id: int, n: int = 20) -> pd.DataFrame:
    sql = textwrap.dedent(f"""
        SELECT
            f.src_ip,
            f.flow_count,
            f.unique_dsts,
            f.unique_ports,
            ROUND((f.total_bytes/1e6)::numeric, 2) AS bytes_mb,
            f.dst_entropy,
            f.port_spread
        FROM netvista_demo.kmeans_out a
        JOIN netvista_demo.netflow_features f ON (a.pid::text = f.src_ip::text)
        WHERE a.cluster_id = {cluster_id}
        ORDER BY f.flow_count DESC
        LIMIT {n}
    """)
    with get_connection() as conn:
        return pd.read_sql(sql, conn)

# ─────────────────────────────────────────────
# 3. CHART BUILDERS
# ─────────────────────────────────────────────

def fig_scatter(df: pd.DataFrame, x_col: str, y_col: str, highlight: Optional[int]):
    df = df.copy()
    df["label"] = df["cluster_id"].map(CLUSTER_LABELS).fillna("Unknown")
    
    fig = px.scatter(
        df, x=x_col, y=y_col,
        color="label",
        color_discrete_sequence=COLORS,
        hover_data=["src_ip", "flow_count", "unique_dsts", "bytes_mb"],
        opacity=0.7,
        labels={x_col: x_col.replace("_", " "), y_col: y_col.replace("_", " ")},
    )
    fig.update_traces(marker=dict(size=7))
    fig.update_layout(**_layout())
    return fig

def fig_centroid_radar(summary: pd.DataFrame):
    dims = ["avg_flows", "avg_dsts", "avg_ports", "avg_bytes_mb", "avg_entropy", "avg_port_spread"]
    dim_labels = ["Flows", "Dsts", "Ports", "Bytes(MB)", "Entropy", "Spread"]
    
    # Normalize 0-1 for radar chart clarity
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
            r=vals, theta=dim_labels + [dim_labels[0]],
            fill="toself",
            name=CLUSTER_LABELS.get(ci, f"C{ci}"),
            line_color=COLORS[ci % len(COLORS)]
        ))
    fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 1], showticklabels=False)),
        **_layout(height=400)
    )
    return fig

def fig_distribution(summary: pd.DataFrame):
    df = summary.copy()
    df["label"] = df["cluster_id"].map(CLUSTER_LABELS)
    fig = px.bar(
        df, x="ip_count", y="label", orientation="h",
        color="label", color_discrete_sequence=COLORS,
        text="ip_count"
    )
    fig.update_layout(showlegend=False, **_layout(height=300))
    return fig

def _layout(height=360):
    return dict(
        height=height,
        margin=dict(l=40, r=20, t=20, b=40),
        plot_bgcolor="#0d1117",
        paper_bgcolor="#0d1117",
        font=dict(family="'JetBrains Mono', monospace", color="#c9d1d9", size=11),
        xaxis=dict(gridcolor="#21262d"),
        yaxis=dict(gridcolor="#21262d"),
    )

# ─────────────────────────────────────────────
# 4. DASH APP
# ─────────────────────────────────────────────

app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG])

AXIS_OPTIONS = [
    {"label": "Flow count",      "value": "flow_count"},
    {"label": "Unique dsts",     "value": "unique_dsts"},
    {"label": "Unique ports",    "value": "unique_ports"},
    {"label": "Bytes (MB)",      "value": "bytes_mb"},
    {"label": "Max Bytes",       "value": "max_bytes"},
    {"label": "Total Packets",   "value": "total_packets"},
    {"label": "Dst entropy",     "value": "dst_entropy"},
    {"label": "Port spread",     "value": "port_spread"},
]

app.layout = dbc.Container(fluid=True, children=[
    dbc.Row(dbc.Col(html.H3("NetVista Cluster Explorer", className="py-3 text-info"))),
    
    dbc.Row([
        dbc.Col([
            html.Label("X-Axis"),
            dcc.Dropdown(id="x-axis", options=AXIS_OPTIONS, value="flow_count", clearable=False),
            html.Label("Y-Axis", className="mt-2"),
            dcc.Dropdown(id="y-axis", options=AXIS_OPTIONS, value="bytes_mb", clearable=False),
            dcc.Graph(id="scatter-plot"),
        ], md=8),
        dbc.Col([
            html.Label("Cluster Distribution"),
            dcc.Graph(id="dist-plot"),
            html.Label("Behavioral Radar"),
            dcc.Graph(id="radar-plot"),
        ], md=4),
    ]),
    
    dbc.Row(dbc.Col([
        html.Hr(),
        html.Label("IP Drilldown"),
        dcc.Dropdown(id="drill-cluster", 
                     options=[{"label": f"{v}", "value": k} for k,v in CLUSTER_LABELS.items()], 
                     value=0),
        html.Div(id="table-container", className="mt-3")
    ])),
    
    dcc.Store(id="data-store")
])

# ─────────────────────────────────────────────
# 5. CALLBACKS
# ─────────────────────────────────────────────

@app.callback(
    Output("data-store", "data"),
    Input("x-axis", "value") # Trigger on load
)
def update_store(_):
    pts = load_cluster_points()
    summ = load_cluster_summary()
    return {"pts": pts.to_json(orient="split"), "summ": summ.to_json(orient="split")}

@app.callback(
    Output("scatter-plot", "figure"),
    Output("dist-plot", "figure"),
    Output("radar-plot", "figure"),
    Input("data-store", "data"),
    Input("x-axis", "value"),
    Input("y-axis", "value")
)
def update_charts(data, x, y):
    if not data: return go.Figure(), go.Figure(), go.Figure()
    pts = pd.read_json(data["pts"], orient="split")
    summ = pd.read_json(data["summ"], orient="split")
    return fig_scatter(pts, x, y, None), fig_distribution(summ), fig_centroid_radar(summ)

@app.callback(
    Output("table-container", "children"),
    Input("drill-cluster", "value")
)
def update_table(cluster_id):
    df = load_top_ips(cluster_id)
    return dash_table.DataTable(
        data=df.to_dict("records"),
        columns=[{"name": i, "id": i} for i in df.columns],
        style_header={'backgroundColor': '#161b22', 'color': 'white'},
        style_cell={'backgroundColor': '#0d1117', 'color': '#c9d1d9'}
    )

if __name__ == '__main__':
    print('\n  EDB MADlib Kmeans Dashboard: http://localhost:5003\n')
    app.run(host='0.0.0.0', port=5003, debug=True, threaded=True)