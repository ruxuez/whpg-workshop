-- ============================================================================
-- NetVista × EDB WarehousePG — Demo Queries (All 5 Use Cases)
-- ============================================================================
-- Optimized for single-node demo (~96M rows, 7 days of data).
-- Each query targets < 5s execution time.
--
-- Legend:
--   ⚡ = Native network type operator (the competitive differentiator)
--   🔗 = Cross-source correlation (Splunk replacement value)
--   💰 = Direct cost savings vs current stack
-- ============================================================================
SET search_path TO netvista_demo, public;
\timing on


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ UC1: NETWORK TRAFFIC ANALYTICS & ANOMALY DETECTION                      ║
-- ╚════════════════════════════════════════════════════════════════════════════╝

-- ─── 1A: Subnet-level traffic aggregation ───────────────────────────────────
-- ⚡ Uses <<= (contained within) operator — ONE line vs 50+ LOC on competitors
-- "Show me all traffic FROM our US-West infrastructure TO any threat intel IP"
SELECT
    src_ip,
    dst_ip,
    dst_port,
    SUM(bytes)        AS total_bytes,
    SUM(packets)      AS total_packets,
    COUNT(*)          AS flow_count
FROM netflow_logs
WHERE src_ip <<= '10.128.0.0/16'::cidr     -- ⚡ native subnet containment
  AND ts > now() - interval '6 hours'
GROUP BY 1, 2, 3
ORDER BY total_bytes DESC
LIMIT 20;


-- ─── 1B: Threat intel matching with native IP join ──────────────────────────
-- ⚡ Native <<= join — on Databricks this requires ip_to_int() + range scan
-- "Match ALL flows against our threat feeds in one query"
SELECT
    n.src_ip,
    t.feed_name,
    t.category,
    t.confidence,
    COUNT(*)          AS hit_count,
    SUM(n.bytes)      AS total_bytes,
    MIN(n.ts)         AS first_seen,
    MAX(n.ts)         AS last_seen
FROM netflow_logs n
JOIN threat_intel_feeds t
    ON n.src_ip <<= t.ip_range            -- ⚡ THE killer feature
WHERE n.ts > now() - interval '6 hours'
  AND t.active = TRUE
  AND t.confidence >= 80
GROUP BY 1, 2, 3, 4
ORDER BY hit_count DESC;


-- ─── 1C: Anomaly detection — traffic spike z-scores ────────────────────────
-- Optimized: compute directly instead of scanning full view over 7 days.
-- "Detect traffic volumes exceeding 3 standard deviations in the last 24h"
WITH hourly AS (
    SELECT
        date_trunc('hour', ts)   AS hour,
        src_ip,
        SUM(bytes)               AS total_bytes,
        COUNT(*)                 AS flow_count
    FROM netflow_logs
    WHERE ts > now() - interval '24 hours'
    GROUP BY 1, 2
),
stats AS (
    SELECT
        src_ip,
        AVG(total_bytes)    AS avg_bytes,
        STDDEV(total_bytes) AS stddev_bytes
    FROM hourly
    GROUP BY 1
    HAVING STDDEV(total_bytes) > 0
)
SELECT
    h.hour,
    h.src_ip,
    h.total_bytes,
    h.flow_count,
    ROUND(s.avg_bytes::numeric, 0)                                          AS avg_bytes,
    ROUND(((h.total_bytes - s.avg_bytes) / s.stddev_bytes)::numeric, 2)     AS z_score
FROM hourly h
JOIN stats s ON h.src_ip = s.src_ip
WHERE (h.total_bytes - s.avg_bytes) / s.stddev_bytes > 3
ORDER BY z_score DESC
LIMIT 20;


-- ─── 1D: Top talkers by subnet (impossible on Snowflake) ───────────────────
-- ⚡ Groups by CIDR block dynamically
SELECT
    network(set_masklen(src_ip, 24)) AS src_subnet,   -- ⚡ dynamic subnet grouping
    COUNT(*)                         AS flows,
    SUM(bytes)                       AS total_bytes,
    COUNT(DISTINCT dst_ip)           AS unique_destinations
FROM netflow_logs
WHERE ts > now() - interval '1 hour'
GROUP BY 1
ORDER BY total_bytes DESC
LIMIT 15;


-- ─── 1E: Port scanning detection ───────────────────────────────────────────
-- "Find IPs scanning >50 distinct ports" — uses 24h window to catch synthetic scans
SELECT
    src_ip,
    COUNT(DISTINCT dst_port) AS ports_scanned,
    COUNT(DISTINCT dst_ip)   AS targets,
    COUNT(*)                 AS total_flows,
    MIN(ts)                  AS scan_start,
    MAX(ts)                  AS scan_end
FROM netflow_logs
WHERE ts > now() - interval '24 hours'
  AND protocol = 6  -- TCP
  AND packets <= 3  -- scan signature: low packet count
GROUP BY src_ip
HAVING COUNT(DISTINCT dst_port) > 50
ORDER BY ports_scanned DESC
LIMIT 20;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ UC2: CENTRALIZED LOG ANALYTICS                                          ║
-- ╚════════════════════════════════════════════════════════════════════════════╝

-- ─── 2A: Cross-source correlation — syslog + firewall + DNS ─────────────────
-- 🔗 Single SQL query correlates 3 sources — replaces Splunk correlation rules
-- "For every critical syslog event, find matching firewall + DNS activity"
SELECT
    s.ts              AS event_time,
    s.src_ip,
    s.hostname,
    s.program,
    LEFT(s.message, 80) AS syslog_msg,
    f.action          AS fw_action,
    f.dst_port        AS fw_port,
    d.query_name      AS dns_query,
    d.response_code   AS dns_rcode
FROM syslog_events s
JOIN firewall_logs f
    ON s.src_ip = f.src_ip                              -- ⚡ native inet join
    AND f.ts BETWEEN s.ts - interval '5 seconds'
                 AND s.ts + interval '5 seconds'
LEFT JOIN dns_logs d
    ON s.src_ip = d.client_ip                           -- ⚡ native inet join
    AND d.ts BETWEEN s.ts - interval '10 seconds'
                  AND s.ts + interval '10 seconds'
WHERE s.severity <= 2                                    -- critical + alert
  AND s.ts > now() - interval '6 hours'
ORDER BY s.ts DESC
LIMIT 30;


-- ─── 2B: Log volume dashboard — all sources ────────────────────────────────
-- 💰 Replaces Splunk license for historical analytics ($2M+ savings)
SELECT
    'netflow'  AS source, COUNT(*) AS events, pg_size_pretty(pg_total_relation_size('netflow_logs')) AS storage
    FROM netflow_logs WHERE ts > now() - interval '24 hours'
UNION ALL
SELECT
    'syslog',  COUNT(*), pg_size_pretty(pg_total_relation_size('syslog_events'))
    FROM syslog_events WHERE ts > now() - interval '24 hours'
UNION ALL
SELECT
    'firewall', COUNT(*), pg_size_pretty(pg_total_relation_size('firewall_logs'))
    FROM firewall_logs WHERE ts > now() - interval '24 hours'
UNION ALL
SELECT
    'dns',      COUNT(*), pg_size_pretty(pg_total_relation_size('dns_logs'))
    FROM dns_logs WHERE ts > now() - interval '24 hours'
UNION ALL
SELECT
    'bgp',      COUNT(*), pg_size_pretty(pg_total_relation_size('bgp_events'))
    FROM bgp_events WHERE ts > now() - interval '24 hours'
ORDER BY events DESC;


-- ─── 2C: Suspicious DNS + firewall correlation ─────────────────────────────
-- "Find internal hosts querying known-bad domains AND being denied by firewall"
SELECT
    d.client_ip,
    d.query_name,
    COUNT(DISTINCT d.dns_id) AS dns_queries,
    COUNT(DISTINCT f.fw_id)  AS fw_denies,
    MAX(d.ts)                AS last_dns_query,
    MAX(f.ts)                AS last_fw_deny
FROM dns_logs d
JOIN firewall_logs f
    ON d.client_ip = f.src_ip
    AND f.action IN ('DENY', 'DROP')
    AND f.ts BETWEEN d.ts - interval '30 seconds'
                 AND d.ts + interval '30 seconds'
WHERE (d.query_name LIKE '%.evil.%'
    OR d.query_name LIKE '%.xyz'
    OR d.query_name LIKE '%exfil%'
    OR d.query_name LIKE '%malware%')
  AND d.ts > now() - interval '24 hours'
GROUP BY 1, 2
ORDER BY dns_queries DESC
LIMIT 20;


-- ─── 2D: BGP route instability — recent withdrawals ────────────────────────
-- Shows withdrawal bursts that indicate routing instability
SELECT
    b.ts,
    b.peer_ip,
    b.prefix,
    b.event_type,
    b.as_path,
    r.region_code
FROM bgp_events b
JOIN regions r ON b.region_id = r.region_id
WHERE b.event_type = 'WITHDRAW'
  AND b.ts > now() - interval '6 hours'
ORDER BY b.ts DESC
LIMIT 20;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ UC3: IPAM ANALYTICS                                                     ║
-- ╚════════════════════════════════════════════════════════════════════════════╝

-- ─── 3A: Subnet utilization with native CIDR ────────────────────────────────
-- ⚡ masklen(), host(), set_masklen() — all native, zero UDFs
SELECT
    subnet,
    masklen(subnet)         AS prefix_len,
    region_code,
    description,
    allocated_ips,
    total_ips,
    utilization_pct,
    health_status
FROM v_ipam_utilization
WHERE subnet <<= '10.0.0.0/8'::cidr          -- ⚡ native containment
ORDER BY utilization_pct DESC;


-- ─── 3B: Underutilized subnets (reclamation candidates) ────────────────────
SELECT
    subnet,
    region_code,
    description,
    total_ips,
    allocated_ips,
    utilization_pct,
    total_ips - allocated_ips AS reclaimable_ips
FROM v_ipam_utilization
WHERE utilization_pct < 30
  AND total_ips >= 100                         -- only meaningful blocks
ORDER BY reclaimable_ips DESC;


-- ─── 3C: Subnet overlap detection ──────────────────────────────────────────
-- ⚡ Uses native && (overlap) operator — try doing this on Snowflake!
SELECT * FROM v_subnet_overlaps;


-- ─── 3D: IPAM + live traffic correlation ────────────────────────────────────
-- "Which allocated IPs haven't generated any traffic in 24 hours?"
-- Optimized: 24h window instead of 7d avoids full netflow scan.
WITH active_ips AS (
    SELECT DISTINCT src_ip AS ip FROM netflow_logs WHERE ts > now() - interval '24 hours'
    UNION
    SELECT DISTINCT dst_ip FROM netflow_logs WHERE ts > now() - interval '24 hours'
)
SELECT
    a.ip_address,
    a.hostname,
    a.device_type,
    a.status,
    a.last_seen,
    s.subnet,
    r.region_code
FROM ipam_allocations a
JOIN subnets s ON a.subnet_id = s.subnet_id
JOIN regions r ON a.region_id = r.region_id
LEFT JOIN active_ips ai ON ai.ip = a.ip_address
WHERE a.status = 'active'
  AND ai.ip IS NULL
ORDER BY a.last_seen NULLS FIRST
LIMIT 20;


-- ─── 3E: IPv4 capacity planning ────────────────────────────────────────────
SELECT
    r.region_code,
    COUNT(*)                              AS subnet_count,
    SUM(i.total_ips)                      AS total_capacity,
    SUM(i.allocated_ips)                  AS total_allocated,
    ROUND(SUM(i.allocated_ips)::numeric
        / NULLIF(SUM(i.total_ips), 0) * 100, 1) AS overall_util_pct,
    SUM(i.total_ips - i.allocated_ips)    AS available_ips
FROM ipam_summary i
JOIN subnets s ON i.subnet_id = s.subnet_id
JOIN regions r ON s.region_id = r.region_id
GROUP BY r.region_code
ORDER BY overall_util_pct DESC;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ UC4: CUSTOMER SLA & QoE ANALYTICS                                       ║
-- ╚════════════════════════════════════════════════════════════════════════════╝

-- ─── 4A: Real-time SLA status dashboard ─────────────────────────────────────
SELECT * FROM v_sla_status
ORDER BY
    CASE sla_status
        WHEN 'BREACH'  THEN 1
        WHEN 'AT RISK' THEN 2
        ELSE 3
    END,
    avg_latency DESC;


-- ─── 4B: Per-customer QoE scoring ──────────────────────────────────────────
SELECT
    c.customer_name,
    c.tier,
    r.region_code,
    ROUND(AVG(m.latency_ms), 1)         AS avg_latency,
    ROUND(AVG(m.jitter_ms), 1)          AS avg_jitter,
    ROUND(AVG(m.packet_loss_pct), 2)    AS avg_loss,
    ROUND(AVG(m.mos_score), 1)          AS avg_mos,
    netvista_demo.calc_qoe_score(
        AVG(m.latency_ms),
        AVG(m.jitter_ms),
        AVG(m.packet_loss_pct)
    )                                    AS qoe_score,
    sc.target_availability,
    sc.latency_sla_ms
FROM customers c
JOIN sla_contracts sc ON c.customer_id = sc.customer_id
    AND sc.effective_to IS NULL
JOIN regions r ON c.region_id = r.region_id
JOIN network_metrics m ON c.customer_id = m.customer_id
    AND m.ts > now() - interval '1 hour'
GROUP BY 1, 2, 3, 9, 10
ORDER BY qoe_score ASC;


-- ─── 4C: SLA breach timeline (last 6 hours) ────────────────────────────────
-- Narrowed from 24h — cleaner output, shows the recent trend
SELECT
    date_trunc('hour', m.ts)             AS hour,
    c.customer_name,
    c.tier,
    ROUND(AVG(m.latency_ms), 1)         AS avg_latency,
    sc.latency_sla_ms,
    CASE WHEN AVG(m.latency_ms) > sc.latency_sla_ms
         THEN 'BREACH'
         WHEN AVG(m.latency_ms) > sc.latency_sla_ms * 0.8
         THEN 'WARNING'
         ELSE 'OK'
    END                                  AS status
FROM network_metrics m
JOIN customers c ON m.customer_id = c.customer_id
JOIN sla_contracts sc ON c.customer_id = sc.customer_id
    AND sc.effective_to IS NULL
WHERE m.ts > now() - interval '6 hours'
GROUP BY 1, 2, 3, 5
HAVING AVG(m.latency_ms) > sc.latency_sla_ms * 0.8
ORDER BY 1 DESC, avg_latency DESC;


-- ─── 4D: Network path quality by subnet ────────────────────────────────────
SELECT
    network(set_masklen(m.probe_ip, 24)) AS probe_subnet,
    r.region_code,
    COUNT(DISTINCT m.customer_id)        AS customers_affected,
    ROUND(AVG(m.latency_ms), 1)         AS avg_latency,
    ROUND(MAX(m.latency_ms), 1)         AS max_latency,
    ROUND(AVG(m.packet_loss_pct), 2)    AS avg_loss,
    COUNT(*) FILTER (WHERE m.latency_ms > 100) AS spike_count
FROM network_metrics m
JOIN regions r ON m.region_id = r.region_id
WHERE m.ts > now() - interval '1 hour'
GROUP BY 1, 2
HAVING AVG(m.latency_ms) > 30
ORDER BY avg_latency DESC
LIMIT 20;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ UC5: SECURITY & COMPLIANCE                                              ║
-- ╚════════════════════════════════════════════════════════════════════════════╝

-- ─── 5A: Live threat matches (aggregated per source IP) ─────────────────────
-- ⚡ Native <<= join + geo enrichment in one pass.
-- Aggregated to show one row per src_ip (not 50 rows of same IP).
SELECT
    n.src_ip,
    t.feed_name,
    t.category                            AS threat_category,
    t.confidence,
    g.country_name                        AS src_country,
    g.city                                AS src_city,
    COUNT(*)                              AS flow_count,
    pg_size_pretty(SUM(n.bytes))          AS total_bytes,
    COUNT(DISTINCT n.dst_ip)              AS unique_targets,
    MIN(n.ts)                             AS first_seen,
    MAX(n.ts)                             AS last_seen
FROM netflow_logs n
JOIN threat_intel_feeds t
    ON n.src_ip <<= t.ip_range
    AND t.active AND t.confidence >= 80
LEFT JOIN geo_ip g ON n.src_ip <<= g.network
WHERE n.ts > now() - interval '6 hours'
GROUP BY 1, 2, 3, 4, 5, 6
ORDER BY flow_count DESC
LIMIT 20;


-- ─── 5B: Geo-IP enrichment for compliance ──────────────────────────────────
-- ⚡ Native <<= join to geo_ip — data residency compliance
-- Narrowed to 6h to keep under 5s on single node
SELECT
    g.country_code,
    g.country_name,
    COUNT(DISTINCT n.src_ip)   AS unique_sources,
    COUNT(*)                   AS total_flows,
    pg_size_pretty(SUM(n.bytes)) AS total_bytes,
    COUNT(*) FILTER (
        WHERE n.src_ip <<= ANY(
            SELECT ip_range FROM threat_intel_feeds
            WHERE active AND confidence >= 70
        )
    )                          AS threat_matched_flows
FROM netflow_logs n
JOIN geo_ip g ON n.src_ip <<= g.network
WHERE n.ts > now() - interval '6 hours'
GROUP BY 1, 2
ORDER BY threat_matched_flows DESC, total_flows DESC;


-- ─── 5C: Security incident summary ─────────────────────────────────────────
SELECT
    threat_category,
    severity,
    status,
    COUNT(*)                   AS incident_count,
    COUNT(DISTINCT src_ip)     AS unique_sources,
    MIN(ts)                    AS earliest,
    MAX(ts)                    AS latest
FROM security_incidents
WHERE ts > now() - interval '30 days'
GROUP BY 1, 2, 3
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        ELSE 4
    END,
    incident_count DESC;


-- ─── 5D: Forensic investigation — trace an IP across all sources ────────────
-- 🔗 "Give me EVERYTHING about this suspicious IP across ALL log sources"
SELECT * FROM (
    (SELECT 'netflow' AS source, ts, 'src→' || host(dst_ip) || ':' || dst_port AS detail, bytes::text AS extra
        FROM netflow_logs WHERE src_ip = '185.220.101.34'::inet AND ts > now() - interval '24 hours'
        ORDER BY ts DESC LIMIT 20)
    UNION ALL
    (SELECT 'firewall', ts, action || ' ' || host(dst_ip) || ':' || dst_port, zone_src || '→' || zone_dst
        FROM firewall_logs WHERE src_ip = '185.220.101.34'::inet AND ts > now() - interval '24 hours'
        ORDER BY ts DESC LIMIT 20)
    UNION ALL
    (SELECT 'dns', ts, query_name || ' (' || query_type || ')', response_code
        FROM dns_logs WHERE client_ip = '185.220.101.34'::inet AND ts > now() - interval '24 hours'
        ORDER BY ts DESC LIMIT 20)
    UNION ALL
    (SELECT 'syslog', ts, LEFT(message, 80), hostname
        FROM syslog_events WHERE src_ip = '185.220.101.34'::inet AND ts > now() - interval '24 hours'
        ORDER BY ts DESC LIMIT 20)
) forensic
ORDER BY ts DESC
LIMIT 50;


-- ─── 5E: Compliance — data residency check ─────────────────────────────────
-- "Are any customer flows crossing data residency boundaries?"
-- Optimized: 6h window instead of 24h (was 35s, now ~5s)
SELECT
    c.customer_name,
    c.tier,
    r_cust.region_code    AS customer_region,
    g.country_code        AS traffic_dest_country,
    g.country_name,
    COUNT(*)              AS flow_count,
    pg_size_pretty(SUM(n.bytes)) AS bytes_transferred
FROM netflow_logs n
JOIN customers c ON n.src_ip <<= c.assigned_subnet       -- ⚡ customer identification
JOIN regions r_cust ON c.region_id = r_cust.region_id
JOIN geo_ip g ON n.dst_ip <<= g.network                   -- ⚡ geo enrichment
WHERE n.ts > now() - interval '6 hours'
  AND g.country_code != (
        CASE r_cust.region_code
            WHEN 'US-EAST' THEN 'US'
            WHEN 'US-WEST' THEN 'US'
            WHEN 'EU-WEST' THEN 'DE'
            WHEN 'EU-EAST' THEN 'PL'
            WHEN 'APAC-JP' THEN 'JP'
            WHEN 'APAC-SG' THEN 'SG'
            WHEN 'LATAM'   THEN 'BR'
        END
    )
GROUP BY 1, 2, 3, 4, 5
ORDER BY flow_count DESC
LIMIT 30;


-- ============================================================================
-- ⭐ BONUS: The "wow" query — everything native, one statement
-- ============================================================================
-- "For each region: top threat, highest-risk customer, hottest subnet"
-- Optimized: pre-materialize threat IPs, 6h window on netflow CTEs
WITH threat_ips AS (
    SELECT ip_range, category
    FROM threat_intel_feeds
    WHERE active AND confidence >= 70
),
threat_summary AS (
    SELECT
        r.region_code,
        t.category,
        COUNT(*)           AS hits,
        ROW_NUMBER() OVER (PARTITION BY r.region_code ORDER BY COUNT(*) DESC) AS rn
    FROM netflow_logs n
    JOIN threat_ips t ON n.src_ip <<= t.ip_range
    JOIN regions r ON n.region_id = r.region_id
    WHERE n.ts > now() - interval '6 hours'
    GROUP BY 1, 2
),
risk_customers AS (
    SELECT
        r.region_code,
        c.customer_name,
        AVG(m.latency_ms) AS avg_lat,
        ROW_NUMBER() OVER (PARTITION BY r.region_code ORDER BY AVG(m.latency_ms) DESC) AS rn
    FROM network_metrics m
    JOIN customers c ON m.customer_id = c.customer_id
    JOIN regions r ON c.region_id = r.region_id
    WHERE m.ts > now() - interval '1 hour'
    GROUP BY 1, 2
),
hot_subnets AS (
    SELECT
        r.region_code,
        network(set_masklen(n.src_ip, 24)) AS subnet,
        COUNT(*) FILTER (WHERE n.src_ip <<= ANY(SELECT ip_range FROM threat_ips)) AS threat_flows,
        ROW_NUMBER() OVER (PARTITION BY r.region_code ORDER BY
            COUNT(*) FILTER (WHERE n.src_ip <<= ANY(SELECT ip_range FROM threat_ips)) DESC) AS rn
    FROM netflow_logs n
    JOIN regions r ON n.region_id = r.region_id
    WHERE n.ts > now() - interval '6 hours'
    GROUP BY 1, 2
)
SELECT
    ts.region_code,
    ts.category            AS top_threat,
    ts.hits                AS threat_hits,
    rc.customer_name       AS highest_risk_customer,
    ROUND(rc.avg_lat, 1)   AS their_latency_ms,
    hs.subnet::text        AS hottest_subnet,
    hs.threat_flows
FROM threat_summary ts
JOIN risk_customers rc ON ts.region_code = rc.region_code AND rc.rn = 1
JOIN hot_subnets hs ON ts.region_code = hs.region_code AND hs.rn = 1
WHERE ts.rn = 1
ORDER BY ts.hits DESC;

\timing off
