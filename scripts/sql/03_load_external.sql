-- ============================================================================
-- NetVista × EDB WarehousePG — Load Data via External Tables (gpfdist)
-- ============================================================================
-- Run AFTER:
--   1. 01_schema.sql + 02_seed_reference.sql are loaded
--   2. python3 data_generator.py has created CSV files
--   3. gpfdist is running:  gpfdist -d ./csv_data -p 8081 &
--
-- Adjust GPFDIST_HOST if gpfdist runs on a different machine.
-- ============================================================================
SET search_path TO netvista_demo, public;
SET statement_mem = '512MB';

-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  Configuration — change GPFDIST_HOST if needed                             ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝
-- Default: gpfdist running locally on port 8081
-- If remote:  gpfdist://10.0.0.5:8081/netflow_logs.csv

\set GPFDIST_HOST 'localhost'
\set GPFDIST_PORT '8081'


-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 1: Create External Tables                                            ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

DO $$ BEGIN RAISE NOTICE '[%] Creating external tables...', clock_timestamp(); END $$;

-- ── Netflow Logs ────────────────────────────────────────────────────────────
DROP EXTERNAL TABLE IF EXISTS ext_netflow_logs;
CREATE READABLE EXTERNAL TABLE ext_netflow_logs (
    ts              TIMESTAMP,
    src_ip          TEXT,          -- loaded as text, cast to inet on INSERT
    dst_ip          TEXT,
    src_port        INT,
    dst_port        INT,
    protocol        SMALLINT,
    bytes           BIGINT,
    packets         BIGINT,
    tcp_flags       TEXT,
    flow_duration   TEXT,
    src_as          TEXT,
    dst_as          TEXT,
    input_if        TEXT,
    output_if       TEXT,
    sampler_id      TEXT,
    region_id       INT
) LOCATION ('gpfdist://localhost:8081/netflow_logs.csv')
FORMAT 'CSV'
LOG ERRORS SEGMENT REJECT LIMIT 1000;

-- ── DNS Logs ────────────────────────────────────────────────────────────────
DROP EXTERNAL TABLE IF EXISTS ext_dns_logs;
CREATE READABLE EXTERNAL TABLE ext_dns_logs (
    ts              TIMESTAMP,
    client_ip       TEXT,
    query_name      VARCHAR(256),
    query_type      VARCHAR(10),
    response_code   VARCHAR(16),
    response_ip     TEXT,
    response_time   INT,
    is_recursive    TEXT,
    region_id       INT
) LOCATION ('gpfdist://localhost:8081/dns_logs.csv')
FORMAT 'CSV'
LOG ERRORS SEGMENT REJECT LIMIT 1000;

-- ── Firewall Logs ───────────────────────────────────────────────────────────
DROP EXTERNAL TABLE IF EXISTS ext_firewall_logs;
CREATE READABLE EXTERNAL TABLE ext_firewall_logs (
    ts              TIMESTAMP,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INT,
    dst_port        INT,
    protocol        SMALLINT,
    action          VARCHAR(10),
    rule_id         INT,
    bytes           BIGINT,
    zone_src        VARCHAR(32),
    zone_dst        VARCHAR(32),
    region_id       INT
) LOCATION ('gpfdist://localhost:8081/firewall_logs.csv')
FORMAT 'CSV'
LOG ERRORS SEGMENT REJECT LIMIT 1000;

-- ── Syslog Events ───────────────────────────────────────────────────────────
DROP EXTERNAL TABLE IF EXISTS ext_syslog_events;
CREATE READABLE EXTERNAL TABLE ext_syslog_events (
    ts              TIMESTAMP,
    src_ip          TEXT,
    hostname        VARCHAR(128),
    facility        SMALLINT,
    severity        SMALLINT,
    program         VARCHAR(64),
    message         TEXT,
    region_id       INT
) LOCATION ('gpfdist://localhost:8081/syslog_events.csv')
FORMAT 'CSV'
LOG ERRORS SEGMENT REJECT LIMIT 1000;

-- ── BGP Events ──────────────────────────────────────────────────────────────
DROP EXTERNAL TABLE IF EXISTS ext_bgp_events;
CREATE READABLE EXTERNAL TABLE ext_bgp_events (
    ts              TIMESTAMP,
    peer_ip         TEXT,
    prefix          TEXT,
    event_type      VARCHAR(16),
    as_path         TEXT,
    next_hop        TEXT,
    origin          VARCHAR(10),
    local_pref      INT,
    med             INT,
    community       TEXT,
    region_id       INT
) LOCATION ('gpfdist://localhost:8081/bgp_events.csv')
FORMAT 'CSV'
LOG ERRORS SEGMENT REJECT LIMIT 1000;

-- ── Network Metrics ─────────────────────────────────────────────────────────
DROP EXTERNAL TABLE IF EXISTS ext_network_metrics;
CREATE READABLE EXTERNAL TABLE ext_network_metrics (
    ts              TIMESTAMP,
    customer_id     INT,
    region_id       INT,
    probe_ip        TEXT,
    latency_ms      NUMERIC(8,2),
    jitter_ms       NUMERIC(8,2),
    packet_loss_pct NUMERIC(5,2),
    throughput_mbps NUMERIC(10,2),
    mos_score       NUMERIC(3,1)
) LOCATION ('gpfdist://localhost:8081/network_metrics.csv')
FORMAT 'CSV'
LOG ERRORS SEGMENT REJECT LIMIT 1000;


-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 2: Truncate Target Tables                                            ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

DO $$ BEGIN RAISE NOTICE '[%] Truncating fact tables...', clock_timestamp(); END $$;

TRUNCATE netflow_logs;
TRUNCATE dns_logs;
TRUNCATE firewall_logs;
TRUNCATE syslog_events;
TRUNCATE bgp_events;
TRUNCATE network_metrics;


-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 3: Load from External Tables → Native Tables                        ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

-- ── Netflow ─────────────────────────────────────────────────────────────────
DO $$ BEGIN RAISE NOTICE '[%] Loading netflow_logs (~33M rows)...', clock_timestamp(); END $$;

INSERT INTO netflow_logs (ts, src_ip, dst_ip, src_port, dst_port, protocol,
                          bytes, packets, tcp_flags, flow_duration,
                          src_as, dst_as, input_if, output_if, sampler_id, region_id)
SELECT
    ts,
    src_ip::inet,
    dst_ip::inet,
    src_port,
    dst_port,
    protocol,
    bytes,
    packets,
    NULLIF(tcp_flags, '')::smallint,
    NULLIF(flow_duration, '')::int,
    NULLIF(src_as, '')::int,
    NULLIF(dst_as, '')::int,
    NULLIF(input_if, '')::int,
    NULLIF(output_if, '')::int,
    NULLIF(sampler_id, '')::smallint,
    region_id
FROM ext_netflow_logs;

DO $$ BEGIN RAISE NOTICE '[%] netflow_logs loaded.', clock_timestamp(); END $$;

-- ── DNS ─────────────────────────────────────────────────────────────────────
DO $$ BEGIN RAISE NOTICE '[%] Loading dns_logs (~25M rows)...', clock_timestamp(); END $$;

INSERT INTO dns_logs (ts, client_ip, query_name, query_type, response_code,
                      response_ip, response_time, is_recursive, region_id)
SELECT
    ts,
    client_ip::inet,
    query_name,
    query_type,
    response_code,
    NULLIF(response_ip, '')::inet,
    response_time,
    CASE WHEN is_recursive = 't' THEN TRUE ELSE FALSE END,
    region_id
FROM ext_dns_logs;

DO $$ BEGIN RAISE NOTICE '[%] dns_logs loaded.', clock_timestamp(); END $$;

-- ── Firewall ────────────────────────────────────────────────────────────────
DO $$ BEGIN RAISE NOTICE '[%] Loading firewall_logs (~22.5M rows)...', clock_timestamp(); END $$;

INSERT INTO firewall_logs (ts, src_ip, dst_ip, src_port, dst_port, protocol,
                           action, rule_id, bytes, zone_src, zone_dst, region_id)
SELECT
    ts,
    src_ip::inet,
    dst_ip::inet,
    src_port,
    dst_port,
    protocol,
    action,
    rule_id,
    bytes,
    zone_src,
    zone_dst,
    region_id
FROM ext_firewall_logs;

DO $$ BEGIN RAISE NOTICE '[%] firewall_logs loaded.', clock_timestamp(); END $$;

-- ── Syslog ──────────────────────────────────────────────────────────────────
DO $$ BEGIN RAISE NOTICE '[%] Loading syslog_events (~15M rows)...', clock_timestamp(); END $$;

INSERT INTO syslog_events (ts, src_ip, hostname, facility, severity,
                           program, message, region_id)
SELECT
    ts,
    src_ip::inet,
    hostname,
    facility,
    severity,
    program,
    message,
    region_id
FROM ext_syslog_events;

DO $$ BEGIN RAISE NOTICE '[%] syslog_events loaded.', clock_timestamp(); END $$;

-- ── BGP ─────────────────────────────────────────────────────────────────────
DO $$ BEGIN RAISE NOTICE '[%] Loading bgp_events (~1.5M rows)...', clock_timestamp(); END $$;

INSERT INTO bgp_events (ts, peer_ip, prefix, event_type, as_path,
                        next_hop, origin, local_pref, med, community, region_id)
SELECT
    ts,
    peer_ip::inet,
    prefix::cidr,
    event_type,
    as_path,
    NULLIF(next_hop, '')::inet,
    origin,
    local_pref,
    med,
    NULLIF(community, ''),
    region_id
FROM ext_bgp_events;

DO $$ BEGIN RAISE NOTICE '[%] bgp_events loaded.', clock_timestamp(); END $$;

-- ── Network Metrics ─────────────────────────────────────────────────────────
DO $$ BEGIN RAISE NOTICE '[%] Loading network_metrics (~150K rows)...', clock_timestamp(); END $$;

INSERT INTO network_metrics (ts, customer_id, region_id, probe_ip,
                             latency_ms, jitter_ms, packet_loss_pct,
                             throughput_mbps, mos_score)
SELECT
    ts,
    customer_id,
    region_id,
    probe_ip::inet,
    latency_ms,
    jitter_ms,
    packet_loss_pct,
    throughput_mbps,
    mos_score
FROM ext_network_metrics;

DO $$ BEGIN RAISE NOTICE '[%] network_metrics loaded.', clock_timestamp(); END $$;


-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 4: Generate IPAM + Security (small tables — keep inline)             ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

DO $$ BEGIN RAISE NOTICE '[%] Generating IPAM allocations...', clock_timestamp(); END $$;

TRUNCATE ipam_allocations;
TRUNCATE ipam_summary;
TRUNCATE security_incidents;

INSERT INTO ipam_allocations (ip_address, subnet_id, mac_address, hostname, device_type, status, allocated_at, last_seen, region_id)
SELECT
    (
        split_part(host(s.subnet), '.', 1) || '.' ||
        split_part(host(s.subnet), '.', 2) || '.' ||
        split_part(host(s.subnet), '.', 3) || '.' ||
        (2 + g)::text
    )::inet,
    s.subnet_id,
    (
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0')
    )::macaddr,
    (ARRAY['srv','rtr','sw','fw','lb','ap','cam','phone','vm','container'])[1+(random()*9)::int]
        || '-' || (ARRAY['prod','stg','dev','mgmt','mon'])[1+(random()*4)::int]
        || '-' || LPAD(g::text, 4, '0'),
    (ARRAY['server','router','switch','firewall','load-balancer','access-point','ip-phone','virtual-machine','container','iot-sensor'])[1+(random()*9)::int],
    CASE
        WHEN random() < 0.78 THEN 'active'
        WHEN random() < 0.88 THEN 'reserved'
        WHEN random() < 0.95 THEN 'deprecated'
        ELSE 'available'
    END,
    now() - (random() * interval '730 days'),
    CASE WHEN random() < 0.85
        THEN now() - (random() * interval '1 day')
        ELSE now() - (random() * interval '90 days')
    END,
    s.region_id
FROM subnets s
CROSS JOIN generate_series(1, 200) g
WHERE masklen(s.subnet) >= 24
  AND g <= LEAST(253, (power(2, (32 - masklen(s.subnet))))::int - 3)
  AND random() < 0.75;

INSERT INTO ipam_summary (subnet_id, subnet, region_id, total_ips, allocated_ips, reserved_ips, utilization_pct)
SELECT
    s.subnet_id, s.subnet, s.region_id,
    netvista_demo.cidr_host_count(s.subnet)::int,
    COUNT(a.alloc_id) FILTER (WHERE a.status = 'active'),
    COUNT(a.alloc_id) FILTER (WHERE a.status = 'reserved'),
    ROUND(
        COUNT(a.alloc_id) FILTER (WHERE a.status IN ('active','reserved'))::numeric
        / NULLIF(netvista_demo.cidr_host_count(s.subnet), 0) * 100, 1
    )
FROM subnets s
LEFT JOIN ipam_allocations a ON a.subnet_id = s.subnet_id
WHERE masklen(s.subnet) >= 24
GROUP BY s.subnet_id, s.subnet, s.region_id;

-- Security incidents
INSERT INTO security_incidents (ts, src_ip, dst_ip, threat_category, severity, feed_id, matched_rule, description, status, region_id)
SELECT
    now() - (random() * interval '30 days'),
    t.ip_single,
    (
        (ARRAY['10.10','10.20','10.128','172.16','192.168','10.200'])[1 + (random()*5)::int]
        || '.' || (random()*254+1)::int || '.' || (random()*254+1)::int
    )::inet,
    t.category,
    (ARRAY['critical','high','medium','low'])[
        CASE WHEN t.confidence >= 90 THEN 1 + (random()*1)::int
             WHEN t.confidence >= 80 THEN 2 + (random()*1)::int
             ELSE 3 + (random()*1)::int END
    ],
    t.feed_id,
    'RULE-' || LPAD((random()*9999+1)::int::text, 4, '0'),
    'Threat detected: ' || t.category || ' from ' || host(t.ip_single),
    (ARRAY['open','open','investigating','investigating','mitigated','closed'])[1+(random()*5)::int],
    (1 + (random()*6)::int)
FROM threat_intel_feeds t
CROSS JOIN generate_series(1, 250) g
WHERE t.active = TRUE;


-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 5: ANALYZE + Final Report                                            ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

DO $$ BEGIN RAISE NOTICE '[%] Running ANALYZE...', clock_timestamp(); END $$;

ANALYZE netvista_demo.netflow_logs;
ANALYZE netvista_demo.dns_logs;
ANALYZE netvista_demo.firewall_logs;
ANALYZE netvista_demo.syslog_events;
ANALYZE netvista_demo.bgp_events;
ANALYZE netvista_demo.network_metrics;
ANALYZE netvista_demo.ipam_allocations;
ANALYZE netvista_demo.ipam_summary;
ANALYZE netvista_demo.security_incidents;

DO $$
DECLARE
    r RECORD;
    total BIGINT := 0;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '╔══════════════════════════════════════════════════════════════╗';
    RAISE NOTICE '║  EXTERNAL TABLE LOAD COMPLETE                              ║';
    RAISE NOTICE '╠══════════════════════════════════════════════════════════════╣';
    FOR r IN
        SELECT 'netflow_logs'        AS tbl, COUNT(*) AS cnt FROM netvista_demo.netflow_logs
        UNION ALL SELECT 'dns_logs',          COUNT(*) FROM netvista_demo.dns_logs
        UNION ALL SELECT 'firewall_logs',     COUNT(*) FROM netvista_demo.firewall_logs
        UNION ALL SELECT 'syslog_events',     COUNT(*) FROM netvista_demo.syslog_events
        UNION ALL SELECT 'bgp_events',        COUNT(*) FROM netvista_demo.bgp_events
        UNION ALL SELECT 'network_metrics',   COUNT(*) FROM netvista_demo.network_metrics
        UNION ALL SELECT 'ipam_allocations',  COUNT(*) FROM netvista_demo.ipam_allocations
        UNION ALL SELECT 'ipam_summary',      COUNT(*) FROM netvista_demo.ipam_summary
        UNION ALL SELECT 'security_incidents',COUNT(*) FROM netvista_demo.security_incidents
        ORDER BY 2 DESC
    LOOP
        total := total + r.cnt;
        RAISE NOTICE '║  % : % rows  ║', RPAD(r.tbl, 22), LPAD(TO_CHAR(r.cnt, '99,999,999'), 12);
    END LOOP;
    RAISE NOTICE '╠══════════════════════════════════════════════════════════════╣';
    RAISE NOTICE '║  TOTAL                         : % rows  ║', LPAD(TO_CHAR(total, '99,999,999'), 12);
    RAISE NOTICE '╚══════════════════════════════════════════════════════════════╝';
END $$;

-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 6: Cleanup (optional — drop external tables after load)              ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝
-- Uncomment to remove external table definitions after successful load:
-- DROP EXTERNAL TABLE IF EXISTS ext_netflow_logs;
-- DROP EXTERNAL TABLE IF EXISTS ext_dns_logs;
-- DROP EXTERNAL TABLE IF EXISTS ext_firewall_logs;
-- DROP EXTERNAL TABLE IF EXISTS ext_syslog_events;
-- DROP EXTERNAL TABLE IF EXISTS ext_bgp_events;
-- DROP EXTERNAL TABLE IF EXISTS ext_network_metrics;
