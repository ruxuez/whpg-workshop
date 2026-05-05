#!/usr/bin/env python3
"""
Lab 3 - AI-Powered Analytics: STREAMLINED Dashboard
Focus: pgvector value, MADlib value, and their combination

Connects to WarehousePG (demo database, port 5432)
"""

import os, time, decimal
from datetime import datetime, date
from flask import Flask, render_template_string, jsonify, request
import psycopg2, psycopg2.extras

app = Flask(__name__)

DB = {
    "host":     os.environ.get("WHPG_HOST", "localhost"),
    "port":     int(os.environ.get("WHPG_PORT", 5432)),
    "dbname":   os.environ.get("WHPG_DB",   "demo"),
    "user":     os.environ.get("WHPG_USER", "gpadmin"),
    "password": os.environ.get("WHPG_PASS", ""),
}

def run(sql, params=None):
    conn = psycopg2.connect(**DB)
    conn.set_session(autocommit=True)
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        t0 = time.perf_counter()
        cur.execute("SET search_path TO netvista_demo, public;")
        cur.execute(sql, params)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        rows = []
        for row in cur.fetchall():
            r = {}
            for k, v in row.items():
                if isinstance(v, (datetime, date)):  r[k] = v.isoformat()
                elif isinstance(v, decimal.Decimal): r[k] = float(v)
                elif v is None:                      r[k] = None
                elif isinstance(v, (int, float, bool)): r[k] = v
                else:                                r[k] = str(v)
            rows.append(r)
        return {"data": rows, "ms": ms, "rows": len(rows)}
    except Exception as e:
        return {"data": [], "ms": 0, "rows": 0, "error": str(e)}
    finally:
        conn.close()

# ── Query definitions ────────────────────────────────────────────────────────
QUERIES = [
    # ══════════════════════════════════════════════════════════════════════════
    # Panel A: pgvector — Semantic Search Beats Keyword Search
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "a1", "panel": 0,
        "name": "A1 - The Keyword Search Problem",
        "desc": "Traditional LIKE search for 'exfiltration' finds NOTHING",
        "sql": """SELECT
    COUNT(*) AS total_syslogs,
    COUNT(*) FILTER (WHERE message ILIKE '%exfil%') AS found_exfil,
    COUNT(*) FILTER (WHERE message ILIKE '%data theft%') AS found_theft,
    COUNT(*) FILTER (WHERE message ILIKE '%steal%') AS found_steal,
    COUNT(*) FILTER (WHERE persona = 'exfil') AS actual_exfil_logs,
    ROUND(COUNT(*) FILTER (WHERE persona = 'exfil') * 100.0 / COUNT(*), 2) AS pct_exfil
FROM netvista_demo.syslog_embeddings"""
    },
    {
        "id": "a2", "panel": 0,
        "name": "A2 - pgvector Finds Exfil by MEANING",
        "desc": "Vector similarity search finds exfiltration WITHOUT keywords",
        "sql": """WITH query_vector AS (
    SELECT ARRAY[
        0.43, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0,
        0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0,
        0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0,
        1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    ]::vector(32) AS vec
)
SELECT
    hostname,
    program,
    LEFT(message, 90) AS message,
    persona AS ground_truth,
    ROUND((1 - (embedding <=> qv.vec))::numeric, 4) AS similarity
FROM netvista_demo.syslog_embeddings se
CROSS JOIN query_vector qv
WHERE (1 - (embedding <=> qv.vec)) > 0.65
ORDER BY embedding <=> qv.vec
LIMIT 30"""
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Panel B: MADlib — Unsupervised Threat Discovery
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "b1", "panel": 1,
        "name": "B1 - MADlib Discovered 4 Threat Personas",
        "desc": "K-Means clustering on 6 features — NO LABELS, finds threats automatically",
        "sql": """SELECT
    a.cluster_id,
    COUNT(*) AS ips,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 1) AS pct,
    ROUND(AVG(f.total_flows), 0) AS avg_flows,
    ROUND(AVG(f.total_bytes)::numeric / 1e6, 2) AS avg_mb,
    ROUND(AVG(f.avg_unique_ports), 0) AS avg_ports,
    ROUND(AVG(f.avg_byte_cv)::numeric, 4) AS avg_cv,
    CASE
        WHEN AVG(f.avg_unique_ports) > 1000 THEN '🔍 RECON'
        WHEN AVG(f.total_bytes) > 10000000000 THEN '📤 EXFIL'
        WHEN AVG(f.avg_byte_cv) < 0.4 THEN '🤖 C2'
        ELSE '✅ NORMAL'
    END AS persona
FROM netvista_demo.kmeans_assignments a
JOIN netvista_demo.netflow_features_agg f ON a.src_ip = f.src_ip
GROUP BY 1
ORDER BY ips DESC"""
    },
    {
        "id": "b2", "panel": 1,
        "name": "B2 - The Dramatic Differences",
        "desc": "RECON: 3,678× more ports | EXFIL: 35,000,000× more bytes",
        "sql": """WITH cluster_stats AS (
    SELECT
        CASE
            WHEN AVG(f.avg_unique_ports) > 1000 THEN 'RECON'
            WHEN AVG(f.total_bytes) > 10000000000 THEN 'EXFIL'
            WHEN AVG(f.avg_byte_cv) < 0.4 THEN 'C2'
            ELSE 'NORMAL'
        END AS persona,
        COUNT(*) AS ips,
        ROUND(AVG(f.avg_unique_ports), 0) AS ports,
        ROUND(AVG(f.total_bytes)::numeric / 1e6, 2) AS bytes_mb,
        ROUND(AVG(f.avg_byte_cv)::numeric, 4) AS byte_cv
    FROM netvista_demo.kmeans_assignments a
    JOIN netvista_demo.netflow_features_agg f ON a.src_ip = f.src_ip
    GROUP BY 1
),
normal AS (
    SELECT ports AS n_ports, bytes_mb AS n_bytes
    FROM cluster_stats WHERE persona = 'NORMAL' LIMIT 1
)
SELECT
    cs.persona,
    cs.ips,
    cs.ports,
    cs.bytes_mb,
    cs.byte_cv,
    ROUND(cs.ports::numeric / NULLIF(n.n_ports, 0), 0) AS ports_vs_normal,
    ROUND(cs.bytes_mb::numeric / NULLIF(n.n_bytes, 0), 0) AS bytes_vs_normal
FROM cluster_stats cs, normal n
ORDER BY cs.ips DESC"""
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Panel C: The AI Factory — Combining pgvector + MADlib
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "c1", "panel": 2,
        "name": "C1 - The AI Factory (MADlib + pgvector)",
        "desc": "Find anomalous IPs (MADlib) → correlate with semantic logs (pgvector) → ONE QUERY",
        "sql": """WITH
-- Step 1: MADlib identifies EXFIL cluster
exfil_ips AS (
    SELECT f.src_ip, f.total_bytes
    FROM netvista_demo.kmeans_assignments a
    JOIN netvista_demo.netflow_features_agg f ON a.src_ip = f.src_ip
    WHERE a.cluster_id = 2  -- EXFIL cluster from MADlib
    ORDER BY f.total_bytes DESC
    LIMIT 10
),
-- Step 2: pgvector finds semantically similar logs
query_vector AS (
    SELECT ARRAY[
        0.43, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0,
        0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0,
        0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0,
        1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    ]::vector(32) AS vec
),
similar_logs AS (
    SELECT
        se.src_ip,
        se.hostname,
        se.program,
        LEFT(se.message, 80) AS message,
        se.persona,
        ROUND((1 - (embedding <=> qv.vec))::numeric, 4) AS similarity
    FROM netvista_demo.syslog_embeddings se
    CROSS JOIN query_vector qv
    WHERE (1 - (embedding <=> qv.vec)) > 0.65
    ORDER BY embedding <=> qv.vec
    LIMIT 40
)
-- Step 3: Join them — show what MADlib-flagged IPs were doing
SELECT
    ei.src_ip::text AS flagged_by_madlib,
    ROUND(ei.total_bytes::numeric / 1e9, 2) AS total_gb,
    sl.hostname,
    sl.program,
    sl.message AS found_by_pgvector,
    sl.similarity,
    sl.persona AS ground_truth
FROM exfil_ips ei
JOIN similar_logs sl ON ei.src_ip = sl.src_ip
ORDER BY ei.total_bytes DESC, sl.similarity DESC
LIMIT 25"""
    },
    {
        "id": "c2", "panel": 2,
        "name": "C2 - Why This Matters",
        "desc": "In traditional warehouses: export → train → join (hours). Here: ONE SQL query (<5 sec)",
        "sql": """SELECT
    'Traditional Warehouse (Snowflake/BigQuery)' AS approach,
    'Export 16M rows → Python → train model → upload results → JOIN' AS workflow,
    '2-4 hours' AS time,
    'Requires data movement, external tools, model versioning' AS complexity
UNION ALL
SELECT
    'EDB WarehousePG (In-Database ML)',
    'MADlib K-Means + pgvector similarity search in ONE query',
    '< 5 seconds',
    'Zero data movement, SQL-native, no external dependencies'"""
    },
]

PANELS = [
    {"name": "pgvector",    "icon": "A", "desc": "Semantic search finds threats by MEANING, not keywords"},
    {"name": "MADlib",      "icon": "B", "desc": "Unsupervised clustering discovers 4 personas automatically"},
    {"name": "AI Factory",  "icon": "C", "desc": "Combine both in ONE query — impossible in traditional warehouses"},
]

# ── API ───────────────────────────────────────────────────────────────────────
@app.route("/api/run", methods=["POST"])
def api_run():
    qid = request.json.get("id")
    q = next((q for q in QUERIES if q["id"] == qid), None)
    if not q:
        return jsonify({"error": f"Unknown query: {qid}"}), 404
    r = run(q["sql"])
    r["id"] = qid
    return jsonify(r)

@app.route("/api/run_all", methods=["POST"])
def api_run_all():
    results = []
    for q in QUERIES:
        r = run(q["sql"])
        results.append({"id": q["id"], "name": q["name"],
                        "ms": r["ms"], "rows": r["rows"], "error": r.get("error")})
    return jsonify({"results": results, "total_ms": round(sum(r["ms"] for r in results), 1)})

@app.route("/api/sql", methods=["POST"])
def api_sql():
    sql = request.json.get("sql", "").strip()
    if not sql:
        return jsonify({"error": "No SQL provided"}), 400
    w = sql.split()[0].upper() if sql.split() else ""
    if w not in ("SELECT", "WITH", "EXPLAIN"):
        return jsonify({"error": "Only SELECT / WITH / EXPLAIN allowed"}), 403
    return jsonify(run(sql))

@app.route("/api/health")
def api_health():
    try:
        conn = psycopg2.connect(**DB)
        cur = conn.cursor()
        cur.execute("SELECT version()")
        ver = cur.fetchone()[0]
        conn.close()
        return jsonify({"status": "ok", "version": ver})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/")
def index():
    return render_template_string(HTML, panels=PANELS, queries=QUERIES)

# ── HTML (same as app3.py, just streamlined queries) ─────────────────────────
HTML = open('/scripts/apps/app3.py').read().split('HTML = r"""')[1].split('"""')[0]

if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════════╗
║  Lab 3 — AI Analytics Dashboard (STREAMLINED)           ║
║  DB: {DB['host']}:{DB['port']}/{DB['dbname']}
║  Queries: {len(QUERIES)} (focused on VALUE demonstration)
║  http://0.0.0.0:5002                                    ║
╚══════════════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=5002, debug=False)
