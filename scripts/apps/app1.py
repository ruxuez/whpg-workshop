#!/usr/bin/env python3
"""
NetVista × EDB WarehousePG — Network Analytics Demo
with Data Reload support (runs the 4 SQL scripts in sequence).

SETUP:
    pip3 install flask psycopg2-binary
    export WHPG_HOST=localhost WHPG_PORT=5432 WHPG_DB=gpadmin WHPG_USER=gpadmin
    python3 app.py

Then:  ssh -L 5001:localhost:5001 ec2-user@<ec2-ip>  →  http://localhost:5001
"""

import os, time, decimal, json, subprocess, threading
from datetime import datetime, date
from flask import Flask, render_template_string, jsonify, request, Response, stream_with_context
import psycopg2, psycopg2.extras

app = Flask(__name__)

DB = {
    "host":     os.environ.get("WHPG_HOST", "localhost"),
    "port":     int(os.environ.get("WHPG_PORT", 5432)),
    "dbname":   os.environ.get("WHPG_DB",   "demo"),
    "user":     os.environ.get("WHPG_USER", "gpadmin"),
    "password": os.environ.get("WHPG_PASS", ""),
}

# ── Reload scripts (in order) ───────────────────────────────────────────────
WORKSHOP_DIR = os.environ.get("WORKSHOP_DIR", "/home/gpadmin/workshop")
RELOAD_SCRIPTS = [
    ("01_schema.sql",            "Drop & recreate schema"),
    ("02_seed_reference.sql",    "Seed reference tables"),
    ("03_seed_traffic.sql",      "Seed traffic data (~50M rows, Jan-Apr 2026)"),
    ("06_ai_analytics.sql",      "Build AI / pgvector analytics"),
    ("07_kmeans_fallback.sql",   "K-Means assignments (MADlib or SQL fallback)"),
]

# Global reload state so the SSE stream can follow it
_reload_lock   = threading.Lock()
_reload_running = False
_reload_log    = []   # list of (ts, level, msg)

def _append_log(level, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    _reload_log.append((ts, level, msg))

# ── DB helper ───────────────────────────────────────────────────────────────
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
                if isinstance(v, (datetime, date)): r[k] = v.isoformat()
                elif isinstance(v, decimal.Decimal): r[k] = float(v)
                elif v is None: r[k] = None
                elif isinstance(v, (int, float, bool)): r[k] = v
                else: r[k] = str(v)
            rows.append(r)
        return {"data": rows, "ms": ms, "rows": len(rows)}
    except Exception as e:
        return {"data": [], "ms": 0, "rows": 0, "error": str(e)}
    finally:
        conn.close()


# ── 12 curated queries ───────────────────────────────────────────────────────
QUERIES = [
    # ── Panel 1: Network Traffic ─────────────────────────────────────────────
    {
        "id": "1a", "panel": 0,
        "name": "1A · Threat Intel Match",
        "desc": "Native inet <<= join — 6 LOC vs 52 on Snowflake",
        "sql": """SELECT n.src_ip::text, t.feed_name, t.category, t.confidence,
    COUNT(*) AS hit_count, SUM(n.bytes) AS total_bytes,
    MIN(n.ts) AS first_seen, MAX(n.ts) AS last_seen
FROM netflow_logs n
JOIN threat_intel_feeds t ON n.src_ip <<= t.ip_range
WHERE n.ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
  AND t.active = TRUE AND t.confidence >= 80
GROUP BY 1, 2, 3, 4
ORDER BY hit_count DESC LIMIT 20"""
    },
    {
        "id": "1b", "panel": 0,
        "name": "1B · Anomaly Detection (z-score)",
        "desc": "Traffic spikes > 3σ in the last 24h",
        "sql": """WITH hourly AS (
    SELECT date_trunc('hour', ts) AS hour, src_ip,
        SUM(bytes) AS total_bytes, COUNT(*) AS flow_count
    FROM netflow_logs WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
    GROUP BY 1, 2
), stats AS (
    SELECT src_ip, AVG(total_bytes) AS avg_b, STDDEV(total_bytes) AS std_b
    FROM hourly GROUP BY 1 HAVING STDDEV(total_bytes) > 0
)
SELECT h.hour, h.src_ip::text, h.total_bytes, h.flow_count,
    ROUND(s.avg_b::numeric, 0) AS avg_bytes,
    ROUND(((h.total_bytes - s.avg_b) / s.std_b)::numeric, 2) AS z_score
FROM hourly h JOIN stats s ON h.src_ip = s.src_ip
WHERE (h.total_bytes - s.avg_b) / s.std_b > 3
ORDER BY z_score DESC LIMIT 20"""
    },
    {
        "id": "1c", "panel": 0,
        "name": "1C · Top Talkers by Subnet",
        "desc": "Dynamic /24 grouping with set_masklen() — impossible on Snowflake",
        "sql": """SELECT network(set_masklen(src_ip, 24)) AS src_subnet,
    COUNT(*) AS flows, SUM(bytes) AS total_bytes,
    COUNT(DISTINCT dst_ip) AS unique_destinations
FROM netflow_logs WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
GROUP BY 1 ORDER BY total_bytes DESC LIMIT 15"""
    },

    # ── Panel 2: Log Analytics ────────────────────────────────────────────────
    {
        "id": "2a", "panel": 1,
        "name": "2A · Cross-Source Correlation",
        "desc": "syslog + firewall + DNS in one query — replaces Splunk",
        "sql": """SELECT s.ts AS event_time, s.src_ip::text, s.hostname, s.program,
    LEFT(s.message, 80) AS syslog_msg,
    f.action AS fw_action, f.dst_port AS fw_port,
    d.query_name AS dns_query, d.response_code AS dns_rcode
FROM syslog_events s
JOIN firewall_logs f ON s.src_ip = f.src_ip
    AND f.ts BETWEEN s.ts - interval '5 seconds' AND s.ts + interval '5 seconds'
LEFT JOIN dns_logs d ON s.src_ip = d.client_ip
    AND d.ts BETWEEN s.ts - interval '10 seconds' AND s.ts + interval '10 seconds'
WHERE s.severity <= 2 AND s.ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
ORDER BY s.ts DESC LIMIT 30"""
    },
    {
        "id": "2b", "panel": 1,
        "name": "2B · Suspicious DNS + FW Deny",
        "desc": "Hosts querying bad domains AND being blocked",
        "sql": """SELECT d.client_ip::text, d.query_name,
    COUNT(DISTINCT d.dns_id) AS dns_queries,
    COUNT(DISTINCT f.fw_id) AS fw_denies,
    MAX(d.ts) AS last_dns_query, MAX(f.ts) AS last_fw_deny
FROM dns_logs d
JOIN firewall_logs f ON d.client_ip = f.src_ip
    AND f.action IN ('DENY', 'DROP')
    AND f.ts BETWEEN d.ts - interval '1 hour' AND d.ts + interval '1 hour'
WHERE (d.query_name LIKE '%.evil.%' OR d.query_name LIKE '%.xyz'
   OR d.query_name LIKE '%exfil%' OR d.query_name LIKE '%malware%'
   OR d.query_name LIKE '%c2-%' OR d.query_name LIKE '%darknet%')
  AND d.ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
GROUP BY 1, 2 ORDER BY dns_queries DESC LIMIT 20"""
    },
    {
        "id": "2c", "panel": 1,
        "name": "2C · Log Volume Dashboard",
        "desc": "All 5 sources — $2M+ Splunk savings",
        "sql": """SELECT 'netflow' AS source, COUNT(*) AS events, pg_size_pretty(pg_total_relation_size('netflow_logs')) AS storage
    FROM netflow_logs WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
UNION ALL SELECT 'dns', COUNT(*), pg_size_pretty(pg_total_relation_size('dns_logs'))
    FROM dns_logs WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
UNION ALL SELECT 'firewall', COUNT(*), pg_size_pretty(pg_total_relation_size('firewall_logs'))
    FROM firewall_logs WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
UNION ALL SELECT 'syslog', COUNT(*), pg_size_pretty(pg_total_relation_size('syslog_events'))
    FROM syslog_events WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
UNION ALL SELECT 'bgp', COUNT(*), pg_size_pretty(pg_total_relation_size('bgp_events'))
    FROM bgp_events WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
ORDER BY events DESC"""
    },

    # ── Panel 3: IPAM & SLA ───────────────────────────────────────────────────
    {
        "id": "3a", "panel": 2,
        "name": "3A · Subnet Utilization",
        "desc": "Native CIDR containment — <<= operator on /8 block",
        "sql": """SELECT subnet::text, masklen(subnet) AS prefix_len, region_code,
    description, allocated_ips, total_ips, utilization_pct, health_status
FROM v_ipam_utilization
WHERE subnet <<= '10.0.0.0/8'::cidr
ORDER BY utilization_pct DESC"""
    },
    {
        "id": "3b", "panel": 2,
        "name": "3B · SLA Breach Timeline",
        "desc": "Hourly breach/warning per customer — last 6 hours",
        "sql": """SELECT date_trunc('hour', m.ts) AS hour,
    c.customer_name, c.tier,
    ROUND(AVG(m.latency_ms), 1) AS avg_latency,
    sc.latency_sla_ms,
    CASE WHEN AVG(m.latency_ms) > sc.latency_sla_ms THEN 'BREACH'
         WHEN AVG(m.latency_ms) > sc.latency_sla_ms * 0.8 THEN 'WARNING'
         ELSE 'OK' END AS status
FROM network_metrics m
JOIN customers c ON m.customer_id = c.customer_id
JOIN sla_contracts sc ON c.customer_id = sc.customer_id AND sc.effective_to IS NULL
WHERE m.ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
GROUP BY 1, 2, 3, 5
HAVING AVG(m.latency_ms) > sc.latency_sla_ms * 0.8
ORDER BY 1 DESC, avg_latency DESC"""
    },
    {
        "id": "3c", "panel": 2,
        "name": "3C · QoE Scorecard",
        "desc": "Per-customer quality scoring — worst-first for churn prevention",
        "sql": """SELECT c.customer_name, c.tier, r.region_code,
    ROUND(AVG(m.latency_ms), 1) AS avg_latency,
    ROUND(AVG(m.jitter_ms), 1) AS avg_jitter,
    ROUND(AVG(m.packet_loss_pct), 2) AS avg_loss,
    ROUND(AVG(m.mos_score), 1) AS avg_mos,
    netvista_demo.calc_qoe_score(AVG(m.latency_ms), AVG(m.jitter_ms), AVG(m.packet_loss_pct)) AS qoe_score,
    sc.latency_sla_ms
FROM customers c
JOIN sla_contracts sc ON c.customer_id = sc.customer_id AND sc.effective_to IS NULL
JOIN regions r ON c.region_id = r.region_id
JOIN network_metrics m ON c.customer_id = m.customer_id AND m.ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
GROUP BY 1, 2, 3, 9
ORDER BY qoe_score ASC"""
    },

    # ── Panel 4: Security ─────────────────────────────────────────────────────
    {
        "id": "4a", "panel": 3,
        "name": "4A · Live Threats + Geo",
        "desc": "Aggregated threat matches with country enrichment",
        "sql": """SELECT n.src_ip::text, t.feed_name, t.category AS threat,
    t.confidence, g.country_name AS src_country,
    COUNT(*) AS flow_count,
    pg_size_pretty(SUM(n.bytes)) AS total_bytes,
    COUNT(DISTINCT n.dst_ip) AS unique_targets
FROM netflow_logs n
JOIN threat_intel_feeds t ON n.src_ip <<= t.ip_range AND t.active AND t.confidence >= 80
LEFT JOIN geo_ip g ON n.src_ip <<= g.network
WHERE n.ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
GROUP BY 1, 2, 3, 4, 5
ORDER BY flow_count DESC LIMIT 20"""
    },
    {
        "id": "4b", "panel": 3,
        "name": "4B · Forensic IP Trace",
        "desc": "Trace 185.220.101.34 across ALL log sources",
        "sql": """SELECT * FROM (
    (SELECT 'netflow' AS source, ts, 'src→' || host(dst_ip) || ':' || dst_port AS detail, bytes::text AS extra
        FROM netflow_logs WHERE src_ip = '185.220.101.34'::inet AND ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
        ORDER BY ts DESC LIMIT 15)
    UNION ALL
    (SELECT 'firewall', ts, action || ' ' || host(dst_ip) || ':' || dst_port, zone_src || '→' || zone_dst
        FROM firewall_logs WHERE src_ip = '185.220.101.34'::inet AND ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
        ORDER BY ts DESC LIMIT 15)
    UNION ALL
    (SELECT 'dns', ts, query_name || ' (' || query_type || ')', response_code
        FROM dns_logs WHERE client_ip = '185.220.101.34'::inet AND ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
        ORDER BY ts DESC LIMIT 15)
    UNION ALL
    (SELECT 'syslog', ts, LEFT(message, 80), hostname
        FROM syslog_events WHERE src_ip = '185.220.101.34'::inet AND ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
        ORDER BY ts DESC LIMIT 15)
) forensic ORDER BY ts DESC LIMIT 40"""
    },
    {
        "id": "4c", "panel": 3,
        "name": "4C · Regional Threat Summary",
        "desc": "The 'wow' query — top threat + riskiest customer + hottest subnet per region",
        "sql": """WITH threat_ips AS (
    SELECT ip_range, category FROM threat_intel_feeds WHERE active AND confidence >= 70
), ts AS (
    SELECT r.region_code, t.category, COUNT(*) AS hits,
        ROW_NUMBER() OVER (PARTITION BY r.region_code ORDER BY COUNT(*) DESC) AS rn
    FROM netflow_logs n JOIN threat_ips t ON n.src_ip <<= t.ip_range
    JOIN regions r ON n.region_id = r.region_id
    WHERE n.ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59' GROUP BY 1, 2
), rc AS (
    SELECT r.region_code, c.customer_name, AVG(m.latency_ms) AS avg_lat,
        ROW_NUMBER() OVER (PARTITION BY r.region_code ORDER BY AVG(m.latency_ms) DESC) AS rn
    FROM network_metrics m JOIN customers c ON m.customer_id = c.customer_id
    JOIN regions r ON c.region_id = r.region_id
    WHERE m.ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59' GROUP BY 1, 2
), hs AS (
    SELECT r.region_code, network(set_masklen(n.src_ip, 24)) AS subnet,
        COUNT(*) FILTER (WHERE n.src_ip <<= ANY(SELECT ip_range FROM threat_ips)) AS tflows,
        ROW_NUMBER() OVER (PARTITION BY r.region_code ORDER BY
            COUNT(*) FILTER (WHERE n.src_ip <<= ANY(SELECT ip_range FROM threat_ips)) DESC) AS rn
    FROM netflow_logs n JOIN regions r ON n.region_id = r.region_id
    WHERE n.ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59' GROUP BY 1, 2
)
SELECT ts.region_code, ts.category AS top_threat, ts.hits AS threat_hits,
    rc.customer_name AS highest_risk_customer, ROUND(rc.avg_lat, 1) AS their_latency_ms,
    hs.subnet::text AS hottest_subnet, hs.tflows AS threat_flows
FROM ts JOIN rc ON ts.region_code = rc.region_code AND rc.rn = 1
JOIN hs ON ts.region_code = hs.region_code AND hs.rn = 1
WHERE ts.rn = 1 ORDER BY ts.hits DESC"""
    },
]

PANELS = [
    {"name": "Network Traffic", "icon": "1", "desc": "Native inet operators on 31M+ netflow rows"},
    {"name": "Log Analytics",   "icon": "2", "desc": "Cross-source correlation — replace Splunk"},
    {"name": "IPAM & SLA",      "icon": "3", "desc": "CIDR math + real-time customer SLA monitoring"},
    {"name": "Security",        "icon": "4", "desc": "Threat intel + geo enrichment + forensics"},
]


# ── API routes ───────────────────────────────────────────────────────────────

@app.route("/api/queries")
def api_queries():
    return jsonify({"panels": PANELS, "queries": QUERIES})


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
        results.append({"id": q["id"], "name": q["name"], "ms": r["ms"],
                        "rows": r["rows"], "error": r.get("error")})
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


# ── Data Reload ──────────────────────────────────────────────────────────────

@app.route("/api/reload/start", methods=["POST"])
def api_reload_start():
    global _reload_running, _reload_log
    with _reload_lock:
        if _reload_running:
            return jsonify({"ok": False, "msg": "Reload already in progress"}), 409
        _reload_running = True
        _reload_log = []

    def _run():
        global _reload_running
        try:
            _append_log("info", f"Starting full data reload in {WORKSHOP_DIR}")
            _append_log("info", f"Running {len(RELOAD_SCRIPTS)} scripts sequentially")
            t_total = time.time()

            for fname, label in RELOAD_SCRIPTS:
                fpath = os.path.join(WORKSHOP_DIR, fname)
                if not os.path.exists(fpath):
                    _append_log("error", f"✗ Script not found: {fpath}")
                    continue

                _append_log("step", f"▶ [{label}]  psql -d gpadmin -f {fname}")
                t0 = time.time()
                try:
                    proc = subprocess.Popen(
                        ["psql", "-d", DB["dbname"], "-U", DB["user"], "-f", fpath,
                         "-v", "ON_ERROR_STOP=0"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        cwd=WORKSHOP_DIR,
                    )
                    for line in proc.stdout:
                        line = line.rstrip()
                        if line:
                            # classify line
                            lvl = "log"
                            if "ERROR" in line or "FATAL" in line:
                                lvl = "error"
                            elif "NOTICE" in line or "WARNING" in line:
                                lvl = "notice"
                            elif line.startswith("INSERT") or line.startswith("CREATE") \
                                    or line.startswith("DROP") or line.startswith("ANALYZE") \
                                    or line.startswith("TRUNCATE"):
                                lvl = "ok"
                            _append_log(lvl, line)
                    proc.wait()
                    elapsed = round(time.time() - t0, 1)
                    if proc.returncode == 0:
                        _append_log("ok", f"✓ {fname} completed in {elapsed}s")
                    else:
                        _append_log("error", f"✗ {fname} exited with code {proc.returncode} ({elapsed}s)")
                except Exception as e:
                    _append_log("error", f"✗ Failed to run {fname}: {e}")

            total_elapsed = round(time.time() - t_total, 1)
            _append_log("done", f"🎉 Full reload complete in {total_elapsed}s — ~50M rows loaded (Jan–Apr 2026)")
        finally:
            _reload_running = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"ok": True, "msg": "Reload started"})


@app.route("/api/reload/status")
def api_reload_status():
    """Returns current log + running flag — polled by the UI every 1s."""
    return jsonify({
        "running": _reload_running,
        "log": _reload_log,   # list of [ts, level, msg]
    })


@app.route("/api/reload/abort", methods=["POST"])
def api_reload_abort():
    # We can't kill a running psql cleanly, but we can flip the flag
    global _reload_running
    _reload_running = False
    _append_log("error", "⚠ Reload aborted by user — current script may still be running")
    return jsonify({"ok": True})


@app.route("/")
def index():
    return render_template_string(HTML, panels=PANELS, queries=QUERIES,
                                  reload_scripts=RELOAD_SCRIPTS,
                                  workshop_dir=WORKSHOP_DIR)


# ── HTML template ────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetVista × WarehousePG</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256'%3E%3Cg transform='translate(-862,18)'%3E%3Cpath fill='%232a9993' d='M1060.7,2.12c-30.98,2.37-56.03,27.09-58.74,58.06-2.88,33.35,19.98,61.96,50.96,68.22v61.62c0,2.54-2.03,4.4-4.4,4.4h-16.76c-2.54,0-4.4-2.03-4.4-4.4v-44.35c0-7.28-5.92-13.37-13.37-13.37h-49.94c-7.28,0-13.37,5.92-13.37,13.37v44.35c0,2.54-2.03,4.4-4.4,4.4h-16.76c-2.37,0-4.4-2.03-4.4-4.4v-97.17l73.47-73.47c1.69-1.69,1.69-4.57,0-6.26l-11.85-11.85c-1.69-1.69-4.57-1.69-6.26,0l-125.27,125.27c-1.69,1.69-1.69,4.57,0,6.26l11.85,11.85c1.69,1.69,4.57,1.69,6.26,0l26.07-26.24v88.37c0,7.28,5.92,13.37,13.37,13.37h50.11c7.28,0,13.37-5.92,13.37-13.37v-44.35c0-2.54,2.03-4.4,4.4-4.4h16.76c2.37,0,4.4,2.03,4.4,4.4v44.35c0,7.28,5.92,13.37,13.37,13.37h50.11c7.28,0,13.37-5.92,13.37-13.37v-98.19c0-2.54-2.03-4.4-4.4-4.4h-7.45c-20.99,0-38.77-16.59-39.27-37.58-.51-21.67,17.44-39.61,39.11-39.1,20.99.34,37.58,18.28,37.58,39.27v123.41c0,2.54,2.03,4.4,4.4,4.4h16.76c2.54,0,4.4-2.03,4.4-4.4v-124.26c-.17-36.9-31.49-66.53-69.07-63.82Z'/%3E%3Ccircle fill='%232a9993' cx='1065.61' cy='65.94' r='12.7'/%3E%3C/g%3E%3C/svg%3E">
<style>
:root{
  --bg:#f0f2f5;--card:#ffffff;--border:#d1d5db;--text:#1e293b;--dim:#6b7280;
  --muted:#4b5563;--accent:#059669;--adim:rgba(6,214,160,.12);
  --warn:#d97706;--wdim:rgba(251,191,36,.1);--danger:#ef4444;--ddim:rgba(239,68,68,.1);
  --blue:#2563eb;--bdim:rgba(59,130,246,.1);--purple:#7c3aed;--cyan:#0891b2;
  --reload:#0f172a;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Outfit',system-ui,sans-serif}

/* ── header ── */
.hdr{background:linear-gradient(135deg,#1e293b,#0f172a);border-bottom:1px solid #334155;
     padding:0 28px;height:54px;display:flex;align-items:center;justify-content:space-between;
     position:sticky;top:0;z-index:300}
.hdr-left{display:flex;align-items:center;gap:12px}
.logo-svg{width:36px;height:36px;flex-shrink:0}
.hdr h1{font-size:18px;font-weight:700;letter-spacing:-.4px;color:#e2e8f0}
.hdr h1 span{color:#34d399}
.hdr-sub{color:#94a3b8;font-size:11px}
.hdr-right{display:flex;align-items:center;gap:12px}
.live-badge{background:rgba(52,211,153,.18);color:#34d399;padding:3px 10px;border-radius:5px;
            font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace;
            animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.55}}
.dot-live{width:8px;height:8px;border-radius:50%;background:#34d399;
          box-shadow:0 0 6px #059669;display:inline-block}
#ttl{color:#e2e8f0;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600}

/* ── tabs ── */
.tabs{background:#f8fafc;border-bottom:1px solid var(--border);
      padding:8px 28px;display:flex;gap:4px;overflow-x:auto;position:sticky;top:54px;z-index:200}
.tab{background:0;border:1px solid transparent;color:var(--muted);padding:8px 16px;
     border-radius:7px;cursor:pointer;font-size:13px;font-family:inherit;
     transition:.18s;white-space:nowrap;font-weight:500}
.tab:hover{color:var(--text);background:rgba(0,0,0,.04)}
.tab.on{background:var(--adim);border-color:rgba(6,214,160,.3);color:var(--accent);font-weight:600}
.tab.reload-tab{border-color:rgba(251,191,36,.3);color:var(--warn)}
.tab.reload-tab.on{background:var(--wdim);border-color:rgba(251,191,36,.5);color:var(--warn)}

/* ── layout ── */
.main{padding:24px 28px;max-width:1440px;margin:0 auto}
.pnl{display:none}.pnl.on{display:block;animation:fi .25s ease}
@keyframes fi{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}

/* ── section header ── */
.sec-hdr{margin-bottom:20px}
.sec-hdr .n{background:linear-gradient(135deg,var(--accent),var(--cyan));color:#fff;
            width:30px;height:30px;border-radius:7px;display:inline-flex;align-items:center;
            justify-content:center;font-size:13px;font-weight:800;
            font-family:'JetBrains Mono',monospace;margin-right:10px;vertical-align:middle}
.sec-hdr h2{display:inline;font-size:20px;font-weight:700;vertical-align:middle}
.sec-hdr .d{color:var(--dim);font-size:13px;margin-top:4px;margin-left:40px}

/* ── summary bar ── */
.sbar{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px;padding:14px 18px;
      background:var(--card);border:1px solid var(--border);border-radius:11px;align-items:center}
.sstat{text-align:center;min-width:80px}
.sstat .l{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.5px}
.sstat .v{font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace}
.rabtn{background:linear-gradient(135deg,var(--purple),var(--blue));color:#fff;border:0;
       padding:10px 22px;border-radius:7px;font-size:13px;font-weight:700;
       cursor:pointer;font-family:inherit;margin-left:auto;transition:.15s}
.rabtn:hover{opacity:.85}.rabtn:disabled{opacity:.4;cursor:wait}

/* ── query grid ── */
.qgrid{display:grid;grid-template-columns:1fr;gap:12px;margin-bottom:24px}
.qcard{background:var(--card);border:1px solid var(--border);border-radius:11px;
       box-shadow:0 1px 3px rgba(0,0,0,.07);overflow:hidden;transition:.18s}
.qcard:hover{border-color:rgba(6,214,160,.3)}
.qbar{display:flex;align-items:center;gap:10px;padding:13px 16px;cursor:pointer}
.qid{min-width:32px;height:24px;border-radius:5px;display:flex;align-items:center;
     justify-content:center;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700}
.p0 .qid{background:var(--adim);color:var(--accent)}
.p1 .qid{background:var(--bdim);color:var(--blue)}
.p2 .qid{background:rgba(167,139,250,.15);color:var(--purple)}
.p3 .qid{background:var(--ddim);color:var(--danger)}
.qname{flex:1;font-size:14px;font-weight:500}
.qdesc{color:var(--dim);font-size:11px}
.qtm .t{background:var(--adim);color:var(--accent);padding:2px 8px;border-radius:4px;
        font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace}
.qtm .t.slow{background:var(--wdim);color:var(--warn)}
.qtm .r{color:var(--dim);margin-left:6px;font-size:11px;font-family:'JetBrains Mono',monospace}
.rbtn{background:var(--adim);color:var(--accent);border:1px solid rgba(6,214,160,.3);
      padding:5px 12px;border-radius:5px;cursor:pointer;font-family:'JetBrains Mono',monospace;
      font-size:11px;font-weight:600;transition:.15s}
.rbtn:hover{background:rgba(6,214,160,.22)}.rbtn:disabled{opacity:.4;cursor:wait}
.qbody{display:none;padding:0 16px 16px}.qcard.open .qbody{display:block}
.qsql{background:#f8fafc;border-radius:6px;padding:10px 12px;
      font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);
      line-height:1.55;max-height:180px;overflow:auto;margin-bottom:10px;
      white-space:pre-wrap;word-break:break-all}
.qactions{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}
.qres{overflow-x:auto;max-height:380px;overflow-y:auto;border-radius:6px}

/* ── table ── */
table{width:100%;border-collapse:collapse;font-size:12px;font-family:'JetBrains Mono',monospace}
th{text-align:left;padding:7px 10px;color:var(--dim);font-size:10px;text-transform:uppercase;
   letter-spacing:.5px;border-bottom:1px solid var(--border);font-weight:500;
   position:sticky;top:0;background:var(--card);z-index:1}
td{padding:7px 10px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
.empty{color:var(--dim);padding:20px;text-align:center;font-size:13px}
.spinner{width:26px;height:26px;border:3px solid var(--border);border-top-color:var(--accent);
         border-radius:50%;animation:sp .75s linear infinite;margin:0 auto}
@keyframes sp{to{transform:rotate(360deg)}}

/* ── SQL editor ── */
.sqled{width:100%;min-height:140px;background:#f8fafc;border:1px solid var(--border);
       border-radius:8px;color:var(--text);font-family:'JetBrains Mono',monospace;
       font-size:13px;padding:14px;resize:vertical;line-height:1.6}
.sqled:focus{outline:0;border-color:var(--accent)}
.runbtn{background:linear-gradient(135deg,var(--accent),var(--cyan));color:#fff;border:0;
        padding:10px 22px;border-radius:7px;font-size:13px;font-weight:700;
        cursor:pointer;font-family:inherit;margin-top:10px;transition:.15s}
.runbtn:hover{opacity:.85}

/* ── RELOAD PANEL ── */
.reload-card{background:var(--card);border:1px solid var(--border);border-radius:12px;
             overflow:hidden;margin-bottom:14px}
.reload-hdr{background:#0f172a;padding:18px 22px;display:flex;align-items:center;
            justify-content:space-between;gap:14px;flex-wrap:wrap}
.reload-title{color:#e2e8f0;font-size:16px;font-weight:700}
.reload-sub{color:#94a3b8;font-size:12px;margin-top:2px}
.reload-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.btn-reload{background:linear-gradient(135deg,#d97706,#b45309);color:#fff;border:0;
            padding:10px 24px;border-radius:8px;font-size:13px;font-weight:700;
            cursor:pointer;font-family:inherit;transition:.15s;white-space:nowrap}
.btn-reload:hover{opacity:.88}.btn-reload:disabled{opacity:.4;cursor:not-allowed}
.btn-abort{background:var(--ddim);color:var(--danger);border:1px solid rgba(239,68,68,.3);
           padding:8px 16px;border-radius:8px;font-size:12px;font-weight:600;
           cursor:pointer;font-family:inherit;transition:.15s}
.btn-abort:hover{background:rgba(239,68,68,.2)}.btn-abort:disabled{opacity:.4;cursor:not-allowed}

.reload-body{padding:20px 22px}
.reload-steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:18px}
.step-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;
           padding:12px 14px;transition:.2s}
.step-card.active{border-color:var(--warn);background:var(--wdim)}
.step-card.done{border-color:var(--accent);background:var(--adim)}
.step-card.error{border-color:var(--danger);background:var(--ddim)}
.step-num{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;
          color:var(--dim);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em}
.step-name{font-size:12px;font-weight:600;color:var(--text)}
.step-file{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);margin-top:2px}
.step-status{font-size:10px;font-weight:600;margin-top:5px}
.step-status.idle{color:var(--dim)}.step-status.running{color:var(--warn)}
.step-status.done{color:var(--accent)}.step-status.error{color:var(--danger)}

/* log box */
.logbox{background:#0d1117;border:1px solid #30363d;border-radius:8px;
        height:360px;overflow-y:auto;padding:12px 14px;
        font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.7}
.log-line{display:flex;gap:10px;padding:1px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.log-ts{color:#484f58;min-width:60px;flex-shrink:0}
.log-msg{flex:1;word-break:break-all}
.log-info   .log-msg{color:#8b949e}
.log-step   .log-msg{color:#79c0ff;font-weight:600}
.log-ok     .log-msg{color:#3fb950}
.log-notice .log-msg{color:#d29922}
.log-error  .log-msg{color:#f85149}
.log-done   .log-msg{color:#58a6ff;font-weight:700;font-size:12px}
.log-log    .log-msg{color:#8b949e}

.reload-status-bar{display:flex;align-items:center;gap:12px;
                   background:var(--bg);border:1px solid var(--border);
                   border-radius:8px;padding:10px 14px;margin-bottom:12px;flex-wrap:wrap}
.rstat{font-size:12px;color:var(--dim)}
.rstat strong{color:var(--text);font-family:'JetBrains Mono',monospace}
.progress-ring{width:14px;height:14px;border:2px solid var(--border);
               border-top-color:var(--warn);border-radius:50%;
               animation:sp .7s linear infinite;display:none}
.progress-ring.active{display:inline-block}

/* ── footer ── */
.ft{margin-top:32px;padding:14px 0;border-top:1px solid var(--border);
    display:flex;justify-content:space-between;color:var(--dim);font-size:11px}
</style>
</head>
<body>

<!-- HEADER -->
<div class="hdr">
  <div class="hdr-left">
    <svg class="logo-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
      <g transform="translate(-862,18)">
        <path fill="#2a9993" d="M1060.7,2.12c-30.98,2.37-56.03,27.09-58.74,58.06-2.88,33.35,19.98,61.96,50.96,68.22v61.62c0,2.54-2.03,4.4-4.4,4.4h-16.76c-2.54,0-4.4-2.03-4.4-4.4v-44.35c0-7.28-5.92-13.37-13.37-13.37h-49.94c-7.28,0-13.37,5.92-13.37,13.37v44.35c0,2.54-2.03,4.4-4.4,4.4h-16.76c-2.37,0-4.4-2.03-4.4-4.4v-97.17l73.47-73.47c1.69-1.69,1.69-4.57,0-6.26l-11.85-11.85c-1.69-1.69-4.57-1.69-6.26,0l-125.27,125.27c-1.69,1.69-1.69,4.57,0,6.26l11.85,11.85c1.69,1.69,4.57,1.69,6.26,0l26.07-26.24v88.37c0,7.28,5.92,13.37,13.37,13.37h50.11c7.28,0,13.37-5.92,13.37-13.37v-44.35c0-2.54,2.03-4.4,4.4-4.4h16.76c2.37,0,4.4,2.03,4.4,4.4v44.35c0,7.28,5.92,13.37,13.37,13.37h50.11c7.28,0,13.37-5.92,13.37-13.37v-98.19c0-2.54-2.03-4.4-4.4-4.4h-7.45c-20.99,0-38.77-16.59-39.27-37.58-.51-21.67,17.44-39.61,39.11-39.1,20.99.34,37.58,18.28,37.58,39.27v123.41c0,2.54,2.03,4.4,4.4,4.4h16.76c2.54,0,4.4-2.03,4.4-4.4v-124.26c-.17-36.9-31.49-66.53-69.07-63.82Z"/>
        <circle fill="#2a9993" cx="1065.61" cy="65.94" r="12.7"/>
      </g>
    </svg>
    <div>
      <h1>WarehousePG <span>Network Analytics</span></h1>
      <div class="hdr-sub">NetVista × EDB — Live on WHPG · ~50M rows · Jan–Apr 2026</div>
    </div>
  </div>
  <div class="hdr-right">
    <span class="dot-live"></span>
    <div class="live-badge">LIVE</div>
    <div id="ttl"></div>
  </div>
</div>

<!-- TABS -->
<div class="tabs" id="tabs">
  <button class="tab on" onclick="switchTab(0)">Network Traffic</button>
  <button class="tab"    onclick="switchTab(1)">Log Analytics</button>
  <button class="tab"    onclick="switchTab(2)">IPAM &amp; SLA</button>
  <button class="tab"    onclick="switchTab(3)">Security</button>
  <button class="tab"    onclick="switchTab(4)" style="margin-left:4px;border-color:rgba(167,139,250,.3);color:var(--purple)">SQL Editor</button>
  <button class="tab reload-tab" onclick="switchTab(5)" id="tab-reload">⟳ Data Reload</button>
</div>

<div class="main" id="main">

  <!-- Query panels 0-3 injected by JS -->

  <!-- SQL EDITOR panel -->
  <div class="pnl" id="pnl-4">
    <div class="sec-hdr">
      <span class="n">Q</span><h2>SQL Editor</h2>
      <div class="d">Run any SELECT against the live 95.8M row dataset</div>
    </div>
    <textarea class="sqled" id="sqlin" spellcheck="false">SELECT src_ip::text, dst_ip::text, dst_port,
    SUM(bytes) AS total_bytes, COUNT(*) AS flow_count
FROM netflow_logs
WHERE src_ip <<= '10.128.0.0/16'::cidr
  AND ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59'
GROUP BY 1, 2, 3 ORDER BY total_bytes DESC LIMIT 20;</textarea>
    <button class="runbtn" onclick="runSQL()">▶ Run Query</button>
    <span id="sqlt" style="margin-left:12px"></span>
    <div style="margin-top:14px;overflow-x:auto;max-height:500px;overflow-y:auto;border-radius:8px" id="sqlr"></div>
  </div>

  <!-- DATA RELOAD panel -->
  <div class="pnl" id="pnl-5">
    <div class="sec-hdr">
      <span class="n" style="background:linear-gradient(135deg,var(--warn),#b45309)">↺</span>
      <h2>Data Reload</h2>
      <div class="d">Re-runs all 4 SQL scripts to refresh timestamps to <em>now()</em> — fixes "last 6 hours" filter</div>
    </div>

    <!-- Main reload card -->
    <div class="reload-card">
      <div class="reload-hdr">
        <div>
          <div class="reload-title">Full Dataset Reload</div>
          <div class="reload-sub">{{ workshop_dir }} — drops schema, reseeds, loads ~50M rows (Jan–Apr 2026), rebuilds AI analytics</div>
        </div>
        <div class="reload-actions">
          <div class="progress-ring" id="reload-spinner"></div>
          <button class="btn-reload" id="btn-reload" onclick="startReload()">⟳ Start Reload</button>
          <button class="btn-abort"  id="btn-abort"  onclick="abortReload()" disabled>✕ Abort</button>
        </div>
      </div>

      <div class="reload-body">
        <!-- Status bar -->
        <div class="reload-status-bar">
          <div class="rstat">Status: <strong id="rstat-txt">Idle</strong></div>
          <div class="rstat">Steps: <strong id="rstat-step">—</strong></div>
          <div class="rstat">Elapsed: <strong id="rstat-elapsed">—</strong></div>
        </div>

        <!-- Step cards -->
        <div class="reload-steps" id="reload-steps">
          {% for fname, label in reload_scripts %}
          <div class="step-card" id="step-{{ loop.index0 }}">
            <div class="step-num">Step {{ loop.index }}</div>
            <div class="step-name">{{ label }}</div>
            <div class="step-file">{{ fname }}</div>
            <div class="step-status idle" id="step-st-{{ loop.index0 }}">Waiting</div>
          </div>
          {% endfor %}
        </div>

        <!-- Log box -->
        <div style="font-size:11px;color:var(--dim);margin-bottom:6px;
                    display:flex;justify-content:space-between;align-items:center">
          <span>Live output</span>
          <button onclick="clearLog()" style="background:0;border:0;color:var(--dim);
                  cursor:pointer;font-size:11px;font-family:inherit">Clear</button>
        </div>
        <div class="logbox" id="reload-log">
          <div class="log-line log-info">
            <span class="log-ts">--:--:--</span>
            <span class="log-msg">Ready — click "Start Reload" to refresh all data to current timestamps.</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Info card -->
    <div style="background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px 22px">
      <div style="font-weight:600;margin-bottom:10px;font-size:14px">What this does</div>
      <div style="font-size:13px;color:var(--muted);line-height:1.8">
        All queries filter for <code style="background:var(--bg);padding:1px 5px;border-radius:3px;font-family:'JetBrains Mono',monospace">ts &gt; now() - interval '6 hours'</code> (or 24h).
        Data spans <strong>Jan 1 – Apr 23 2026</strong> across 113 daily partitions. Queries use fixed date range filters so results are always available.<br><br>
        This reload drops and recreates the schema, reseeds reference tables, inserts ~50M rows
        across the full Jan–Apr 2026 window, and rebuilds the pgvector embeddings table.
        It takes approximately <strong>3–5 minutes</strong>.
      </div>
      <div style="margin-top:14px;display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px">
        {% for fname, label in reload_scripts %}
        <div style="background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:10px 12px">
          <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--accent);margin-bottom:3px">{{ fname }}</div>
          <div style="font-size:12px;font-weight:500">{{ label }}</div>
        </div>
        {% endfor %}
      </div>
    </div>
  </div>

  <div class="ft">
    <div>EDB WarehousePG — Native network types + MPP parallel engine</div>
    <div style="font-family:'JetBrains Mono',monospace" id="ftr">95.8M rows | 7 regions</div>
  </div>
</div><!-- /main -->

<script>
const PANELS = {{ panels|tojson }};
const QUERIES = {{ queries|tojson }};
const results = {};
let activeTab = 0;

// ── Clock ──────────────────────────────────────────────────────────────────
function tickClock(){
  const t = new Date().toLocaleTimeString('en-GB',{hour12:false});
  document.getElementById('ttl').textContent = t;
}
tickClock(); setInterval(tickClock, 1000);

// ── Helpers ────────────────────────────────────────────────────────────────
function esc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function fmt(n){
  if(n==null) return '—';
  n = Number(n);
  if(n>=1e9) return (n/1e9).toFixed(1)+'B';
  if(n>=1e6) return (n/1e6).toFixed(1)+'M';
  if(n>=1e3) return (n/1e3).toFixed(1)+'K';
  return n.toLocaleString();
}
function fmtMs(ms){ return ms < 1000 ? ms+'ms' : (ms/1000).toFixed(1)+'s'; }

function tbl(rows){
  if(!rows || !rows.length) return '<div class="empty">No results — data may need a reload (timestamps expired)</div>';
  const ks = Object.keys(rows[0]);
  let h = '<table><thead><tr>'+ks.map(k=>'<th>'+esc(k)+'</th>').join('')+'</tr></thead><tbody>';
  rows.forEach(r=>{ h += '<tr>'+ks.map(k=>'<td>'+(r[k]!=null?esc(String(r[k])):'—')+'</td>').join('')+'</tr>'; });
  return h+'</tbody></table>';
}

// ── Build query panels (0–3) ───────────────────────────────────────────────
function buildPanels(){
  const main = document.getElementById('main');
  // Insert before the SQL editor panel (pnl-4)
  const anchor = document.getElementById('pnl-4');

  PANELS.forEach((p, pi)=>{
    const qs = QUERIES.filter(q=>q.panel===pi);
    let h = `<div class="pnl${pi===0?' on':''}" id="pnl-${pi}">`;
    h += `<div class="sec-hdr"><span class="n">${p.icon}</span><h2>${p.name}</h2><div class="d">${p.desc}</div></div>`;
    h += `<div class="sbar">
      <div class="sstat"><div class="l">Queries</div><div class="v" style="color:var(--accent)">${qs.length}</div></div>
      <div class="sstat"><div class="l">Completed</div><div class="v" style="color:var(--blue)" id="done-${pi}">0</div></div>
      <div class="sstat"><div class="l">Total Time</div><div class="v" style="color:var(--warn)" id="tms-${pi}">—</div></div>
      <button class="rabtn" id="rabtn-${pi}" onclick="runPanel(${pi})">▶ Run All 3</button>
    </div>`;
    h += `<div class="qgrid">`;
    qs.forEach(q=>{
      h += `<div class="qcard p${pi}" id="qc-${q.id}">
        <div class="qbar" onclick="toggle('${q.id}')">
          <span class="qid">${q.id.toUpperCase()}</span>
          <div style="flex:1"><div class="qname">${esc(q.name)}</div><div class="qdesc">${esc(q.desc)}</div></div>
          <span class="qtm" id="qt-${q.id}"></span>
          <button class="rbtn" id="rb-${q.id}" onclick="event.stopPropagation();runQ('${q.id}')">Run</button>
        </div>
        <div class="qbody">
          <div class="qsql">${esc(q.sql)}</div>
          <div class="qactions">
            <button class="rbtn" onclick="runQ('${q.id}')">▶ Run</button>
            <button class="rbtn" onclick="copyQ('${q.id}')" style="background:var(--bdim);color:var(--blue);border-color:rgba(59,130,246,.3)">Copy SQL</button>
            <button class="rbtn" onclick="toEditor('${q.id}')" style="background:rgba(167,139,250,.1);color:var(--purple);border-color:rgba(167,139,250,.3)">Edit in SQL</button>
          </div>
          <div class="qres" id="qr-${q.id}"></div>
        </div>
      </div>`;
    });
    h += `</div></div>`;

    const div = document.createElement('div');
    div.innerHTML = h;
    main.insertBefore(div.firstChild, anchor);
  });
}

function switchTab(i){
  document.querySelectorAll('.tab').forEach((t,j)=>t.classList.toggle('on', j===i));
  document.querySelectorAll('.pnl').forEach((p,j)=>p.classList.toggle('on', j===i));
  activeTab = i;
}

function toggle(id){ document.getElementById('qc-'+id)?.classList.toggle('open'); }

// ── Run query ──────────────────────────────────────────────────────────────
async function runQ(id){
  const btn = document.getElementById('rb-'+id);
  btn.disabled=true; btn.textContent='…';
  document.getElementById('qr-'+id).innerHTML = '<div style="padding:20px;text-align:center"><div class="spinner"></div></div>';
  document.getElementById('qc-'+id).classList.add('open');
  try{
    const r = await(await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})})).json();
    results[id] = r;
    const slow = r.ms > 5000;
    document.getElementById('qt-'+id).innerHTML =
      `<span class="t${slow?' slow':''}">${fmtMs(r.ms)}</span><span class="r">${r.rows} rows</span>`;
    document.getElementById('qr-'+id).innerHTML = r.error
      ? `<div style="color:var(--danger);padding:12px;font-family:'JetBrains Mono',monospace;font-size:12px">ERROR: ${esc(r.error)}</div>`
      : tbl(r.data);
  } catch(e){
    document.getElementById('qr-'+id).innerHTML = `<div style="color:var(--danger);padding:12px">${e.message}</div>`;
  }
  btn.disabled=false; btn.textContent='Run';
  updatePanel(QUERIES.find(q=>q.id===id).panel);
}

async function runPanel(pi){
  const btn = document.getElementById('rabtn-'+pi);
  btn.disabled=true; btn.textContent='Running…';
  for(const q of QUERIES.filter(q=>q.panel===pi)) await runQ(q.id);
  btn.disabled=false; btn.textContent='▶ Run All 3';
}

function updatePanel(pi){
  const qs = QUERIES.filter(q=>q.panel===pi);
  const done = qs.filter(q=>results[q.id]);
  const ms = done.reduce((s,q)=>s+(results[q.id]?.ms||0),0);
  document.getElementById('done-'+pi).textContent = done.length;
  document.getElementById('tms-'+pi).textContent = done.length ? fmtMs(Math.round(ms)) : '—';
}

function copyQ(id){ navigator.clipboard.writeText(QUERIES.find(q=>q.id===id).sql+';'); }
function toEditor(id){
  document.getElementById('sqlin').value = QUERIES.find(q=>q.id===id).sql+';';
  switchTab(4);
}

// ── SQL editor ─────────────────────────────────────────────────────────────
async function runSQL(){
  const sql = document.getElementById('sqlin').value;
  document.getElementById('sqlr').innerHTML = '<div style="padding:20px;text-align:center"><div class="spinner"></div></div>';
  document.getElementById('sqlt').innerHTML = '';
  try{
    const r = await(await fetch('/api/sql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sql})})).json();
    if(r.error){
      document.getElementById('sqlr').innerHTML = `<div style="color:var(--danger);padding:16px;font-family:'JetBrains Mono',monospace;font-size:12px">ERROR: ${esc(r.error)}</div>`;
      return;
    }
    const slow = r.ms > 5000;
    document.getElementById('sqlt').innerHTML =
      `<span style="background:var(--adim);color:var(--accent);padding:3px 10px;border-radius:4px;font-size:11px;font-family:'JetBrains Mono',monospace;font-weight:600" class="${slow?'slow':''}">${fmtMs(r.ms)}</span>
       <span style="color:var(--dim);font-size:12px;margin-left:6px">${r.rows} rows</span>`;
    document.getElementById('sqlr').innerHTML = tbl(r.data);
  } catch(e){ document.getElementById('sqlr').innerHTML = `<div style="color:var(--danger);padding:16px">${e.message}</div>`; }
}

// ── DATA RELOAD ────────────────────────────────────────────────────────────
let reloadPollTimer = null;
let reloadStartTs   = null;
let lastLogLen      = 0;

const STEP_KEYWORDS = [
  '01_schema',
  '02_seed_reference',
  '03_load_external',
  '06_ai_analytics',
  '07_kmeans_fallback',
];

function setStepState(idx, state){
  const card = document.getElementById('step-'+idx);
  const st   = document.getElementById('step-st-'+idx);
  if(!card) return;
  card.className = 'step-card' + (state!=='idle' ? ' '+state : '');
  st.className   = 'step-status '+state;
  const labels = {idle:'Waiting', active:'Running…', done:'✓ Done', error:'✗ Error'};
  st.textContent = labels[state] || state;
}

function guessActiveStep(logLines){
  // Walk backwards to find the last "step" entry and map to STEP_KEYWORDS index
  for(let i = logLines.length-1; i >= 0; i--){
    const [,, msg] = logLines[i];
    for(let s=0; s<STEP_KEYWORDS.length; s++){
      if(msg && msg.includes(STEP_KEYWORDS[s])) return s;
    }
  }
  return -1;
}

function renderLog(logLines, append=false){
  const box = document.getElementById('reload-log');
  if(!append){ box.innerHTML = ''; lastLogLen = 0; }
  const newLines = logLines.slice(lastLogLen);
  newLines.forEach(([ts, lvl, msg])=>{
    const div = document.createElement('div');
    div.className = 'log-line log-'+lvl;
    div.innerHTML = `<span class="log-ts">${esc(ts)}</span><span class="log-msg">${esc(msg)}</span>`;
    box.appendChild(div);
  });
  if(newLines.length){ box.scrollTop = box.scrollHeight; }
  lastLogLen = logLines.length;
}

async function pollReload(){
  try{
    const r = await(await fetch('/api/reload/status')).json();
    renderLog(r.log, true);

    // Update elapsed
    if(reloadStartTs){
      const sec = Math.round((Date.now()-reloadStartTs)/1000);
      document.getElementById('rstat-elapsed').textContent = sec+'s';
    }

    // Determine active step from log content
    const activeStep = guessActiveStep(r.log);
    for(let i=0; i<STEP_KEYWORDS.length; i++){
      // Mark done if a later step has started, or if done log line seen
      const isDone = activeStep > i || (!r.running && r.log.some(([,,m])=>m && m.includes('✓') && m.includes(STEP_KEYWORDS[i])));
      const isErr  = r.log.some(([,l,])=>l==='error') && activeStep===i && !isDone;
      const isActive = r.running && activeStep===i;
      if(isDone)       setStepState(i, 'done');
      else if(isErr)   setStepState(i, 'error');
      else if(isActive)setStepState(i, 'active');
      else             setStepState(i, 'idle');
    }

    // Update step counter
    const stepsDone = STEP_KEYWORDS.filter((_,i)=>
      r.log.some(([,,m])=>m && m.includes('✓') && m.includes(STEP_KEYWORDS[i]))
    ).length;
    document.getElementById('rstat-step').textContent = stepsDone+' / '+STEP_KEYWORDS.length;

    if(r.running){
      document.getElementById('rstat-txt').textContent = 'Running';
      document.getElementById('reload-spinner').classList.add('active');
    } else {
      document.getElementById('reload-spinner').classList.remove('active');
      clearInterval(reloadPollTimer);
      reloadPollTimer = null;
      document.getElementById('btn-reload').disabled = false;
      document.getElementById('btn-abort').disabled  = true;
      document.getElementById('rstat-txt').textContent =
        r.log.some(([,l])=>l==='done') ? '✓ Complete' : 'Idle';
      document.getElementById('tab-reload').textContent = '✓ Reload Done';
      setTimeout(()=>{ document.getElementById('tab-reload').textContent = '⟳ Data Reload'; }, 5000);
    }
  } catch(e){ console.error('poll error', e); }
}

async function startReload(){
  if(!confirm('This will drop and recreate the entire schema (~5–8 min). Proceed?')) return;

  lastLogLen = 0;
  document.getElementById('reload-log').innerHTML = '';
  for(let i=0; i<STEP_KEYWORDS.length; i++) setStepState(i,'idle');

  const r = await(await fetch('/api/reload/start',{method:'POST'})).json();
  if(!r.ok){ alert('Error: '+r.msg); return; }

  reloadStartTs = Date.now();
  document.getElementById('btn-reload').disabled = true;
  document.getElementById('btn-abort').disabled  = false;
  document.getElementById('rstat-txt').textContent = 'Running';
  document.getElementById('rstat-elapsed').textContent = '0s';
  document.getElementById('reload-spinner').classList.add('active');
  document.getElementById('tab-reload').textContent = '↻ Reloading…';

  reloadPollTimer = setInterval(pollReload, 1000);
}

async function abortReload(){
  if(!confirm('Abort the reload? The current script may continue running.')) return;
  await fetch('/api/reload/abort',{method:'POST'});
  clearInterval(reloadPollTimer);
  document.getElementById('btn-reload').disabled = false;
  document.getElementById('btn-abort').disabled  = true;
  document.getElementById('rstat-txt').textContent = 'Aborted';
  document.getElementById('reload-spinner').classList.remove('active');
}

function clearLog(){
  document.getElementById('reload-log').innerHTML='';
  lastLogLen = 0;
}

// ── Row count ──────────────────────────────────────────────────────────────
fetch('/api/sql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sql:
  "SELECT SUM(c)::bigint AS total FROM (SELECT COUNT(*) AS c FROM netflow_logs WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59' UNION ALL SELECT COUNT(*) FROM dns_logs WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59' UNION ALL SELECT COUNT(*) FROM firewall_logs WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59' UNION ALL SELECT COUNT(*) FROM syslog_events WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59' UNION ALL SELECT COUNT(*) FROM bgp_events WHERE ts BETWEEN '2026-01-01' AND '2026-04-23 23:59:59' UNION ALL SELECT COUNT(*) FROM network_metrics) x"
})}).then(r=>r.json()).then(d=>{
  const t = d.data?.[0]?.total;
  if(t){ document.getElementById('ttl').textContent = fmt(t)+' rows'; document.getElementById('ftr').textContent = fmt(t)+' rows | 7 regions'; }
}).catch(()=>{});

// ── Init ───────────────────────────────────────────────────────────────────
buildPanels();
// Check if a reload is already running (e.g. page refresh mid-reload)
fetch('/api/reload/status').then(r=>r.json()).then(d=>{
  if(d.running){
    reloadStartTs = Date.now();
    document.getElementById('btn-reload').disabled = true;
    document.getElementById('btn-abort').disabled  = false;
    document.getElementById('reload-spinner').classList.add('active');
    reloadPollTimer = setInterval(pollReload, 1000);
  } else if(d.log && d.log.length){
    renderLog(d.log, false);
  }
});
</script>
</body></html>"""


if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════╗
║  NetVista × WarehousePG — Network Analytics Demo    ║
║  DB: {DB['host']}:{DB['port']}/{DB['dbname']}
║  Queries: {len(QUERIES)} across {len(PANELS)} panels
║  Workshop: {WORKSHOP_DIR}
║  Data: Jan 1 – Apr 23 2026  (~50M rows)             ║
║  Data: Jan 1 – Apr 23 2026  (~50M rows)             ║
║  http://0.0.0.0:5001                                ║
╚══════════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=5001, debug=False)

