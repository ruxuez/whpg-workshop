-- ============================================================================
-- NetVista × EDB WarehousePG — Network Analytics Data Model
-- ============================================================================
-- All 5 Use Cases | Native inet/cidr/macaddr types | WHPG MPP Optimized
-- Deploy on WarehousePG 7+
--
-- Run order:
--   01_schema.sql        → Tables, types, indexes
--   02_seed_reference.sql → Reference/lookup data
--   03_seed_traffic.sql   → Synthetic operational data (configurable scale)
--   04_demo_queries.sql   → All 5 UC demo queries
-- ============================================================================

-- ─── Cleanup (idempotent) ───────────────────────────────────────────────────
DROP SCHEMA IF EXISTS netvista_demo CASCADE;
CREATE SCHEMA netvista_demo;
SET search_path TO netvista_demo, public;

-- ============================================================================
-- REFERENCE / DIMENSION TABLES
-- ============================================================================

-- ─── Regions ────────────────────────────────────────────────────────────────
CREATE TABLE regions (
    region_id       SERIAL,
    region_code     VARCHAR(16)  NOT NULL,
    region_name     VARCHAR(64)  NOT NULL,
    timezone        VARCHAR(40)  NOT NULL
) DISTRIBUTED BY (region_id);

-- ─── Subnets (IPAM master) ─────────────────────────────────────────────────
-- KEY: Uses native cidr type — no string parsing, no UDFs
CREATE TABLE subnets (
    subnet_id       SERIAL,
    subnet          cidr          NOT NULL,
    region_id       INT           NOT NULL,
    vlan_id         INT,
    description     VARCHAR(128),
    subnet_type     VARCHAR(20)   NOT NULL DEFAULT 'infrastructure',
                    -- infrastructure | customer | management | dmz | transit
    parent_subnet   cidr,
    created_at      TIMESTAMP     NOT NULL DEFAULT now()
) DISTRIBUTED BY (subnet_id);

CREATE INDEX idx_subnets_cidr ON subnets USING gist (subnet inet_ops);

-- ─── Customers ──────────────────────────────────────────────────────────────
CREATE TABLE customers (
    customer_id     SERIAL,
    customer_name   VARCHAR(128)  NOT NULL,
    region_id       INT           NOT NULL,
    tier            VARCHAR(16)   NOT NULL DEFAULT 'standard',
                    -- enterprise | premium | standard
    assigned_subnet cidr,
    onboarded_at    DATE          NOT NULL DEFAULT CURRENT_DATE
) DISTRIBUTED BY (customer_id);

-- ─── SLA Contracts ──────────────────────────────────────────────────────────
CREATE TABLE sla_contracts (
    sla_id              SERIAL,
    customer_id         INT           NOT NULL,
    target_availability NUMERIC(6,3)  NOT NULL DEFAULT 99.950,  -- %
    latency_sla_ms      INT           NOT NULL DEFAULT 50,
    jitter_sla_ms       NUMERIC(5,1)  NOT NULL DEFAULT 10.0,
    packet_loss_sla_pct NUMERIC(4,2)  NOT NULL DEFAULT 0.50,
    effective_from      DATE          NOT NULL DEFAULT CURRENT_DATE,
    effective_to        DATE
) DISTRIBUTED BY (customer_id);

-- ─── Threat Intel Feeds ─────────────────────────────────────────────────────
-- KEY: ip_range is cidr — enables native <<= containment joins
CREATE TABLE threat_intel_feeds (
    feed_id         SERIAL,
    feed_name       VARCHAR(64)   NOT NULL,
    ip_range        cidr          NOT NULL,
    ip_single       inet,
    category        VARCHAR(32)   NOT NULL,
                    -- c2 | scanner | botnet | ddos | exfil | bruteforce | tor_exit
    confidence      INT           NOT NULL,
    country_code    CHAR(2),
    first_seen      TIMESTAMP     NOT NULL DEFAULT now(),
    last_seen       TIMESTAMP     NOT NULL DEFAULT now(),
    active          BOOLEAN       NOT NULL DEFAULT TRUE
) DISTRIBUTED BY (feed_id);

CREATE INDEX idx_threat_cidr ON threat_intel_feeds USING gist (ip_range inet_ops);

-- ─── Geo-IP Mapping ─────────────────────────────────────────────────────────
CREATE TABLE geo_ip (
    geo_id          SERIAL,
    network         cidr          NOT NULL,
    country_code    CHAR(2)       NOT NULL,
    country_name    VARCHAR(64)   NOT NULL,
    city            VARCHAR(64),
    latitude        NUMERIC(8,5),
    longitude       NUMERIC(8,5),
    asn             INT,
    as_org          VARCHAR(128)
) DISTRIBUTED BY (geo_id);

CREATE INDEX idx_geoip_cidr ON geo_ip USING gist (network inet_ops);


-- ============================================================================
-- FACT / EVENT TABLES  (Append-optimized, partitioned by time)
-- ============================================================================

-- ─── UC1: NetFlow / sFlow / IPFIX Logs ──────────────────────────────────────
-- KEY: src_ip and dst_ip are inet — enables native subnet containment
CREATE TABLE netflow_logs (
    flow_id         BIGSERIAL,
    ts              TIMESTAMP     NOT NULL,
    src_ip          inet          NOT NULL,
    dst_ip          inet          NOT NULL,
    src_port        INT,
    dst_port        INT,
    protocol        SMALLINT      NOT NULL,   -- 6=TCP, 17=UDP, 1=ICMP
    bytes           BIGINT        NOT NULL,
    packets         BIGINT        NOT NULL,
    tcp_flags       SMALLINT,
    flow_duration   INT,                       -- milliseconds
    src_as          INT,
    dst_as          INT,
    input_if        INT,
    output_if       INT,
    sampler_id      SMALLINT,
    region_id       INT
) WITH (appendoptimized=true, orientation=column,compresstype=zstd, compresslevel=3)
DISTRIBUTED BY (flow_id)
PARTITION BY RANGE (ts) (
    START ('2026-01-01'::timestamp) INCLUSIVE
    END   ('2026-05-01'::timestamp) EXCLUSIVE
    EVERY (INTERVAL '1 day')
);

-- ─── UC2: Syslog Events ────────────────────────────────────────────────────
CREATE TABLE syslog_events (
    event_id        BIGSERIAL,
    ts              TIMESTAMP     NOT NULL,
    src_ip          inet          NOT NULL,
    hostname        VARCHAR(128),
    facility        SMALLINT,
    severity        SMALLINT      NOT NULL,   -- 0=emerg ... 7=debug
    program         VARCHAR(64),
    message         TEXT,
    region_id       INT
) WITH (appendoptimized=true, orientation=column,compresstype=zstd, compresslevel=3)
DISTRIBUTED BY (event_id)
PARTITION BY RANGE (ts) (
    START ('2026-01-01'::timestamp) INCLUSIVE
    END   ('2026-05-01'::timestamp) EXCLUSIVE
    EVERY (INTERVAL '1 day')
);

-- ─── UC2: Firewall Logs ────────────────────────────────────────────────────
CREATE TABLE firewall_logs (
    fw_id           BIGSERIAL,
    ts              TIMESTAMP     NOT NULL,
    src_ip          inet          NOT NULL,
    dst_ip          inet          NOT NULL,
    src_port        INT,
    dst_port        INT,
    protocol        SMALLINT,
    action          VARCHAR(10)   NOT NULL,   -- ALLOW | DENY | DROP | REJECT
    rule_id         INT,
    bytes           BIGINT,
    zone_src        VARCHAR(32),
    zone_dst        VARCHAR(32),
    region_id       INT
) WITH (appendoptimized=true, orientation=column,compresstype=zstd, compresslevel=3)
DISTRIBUTED BY (fw_id)
PARTITION BY RANGE (ts) (
    START ('2026-01-01'::timestamp) INCLUSIVE
    END   ('2026-05-01'::timestamp) EXCLUSIVE
    EVERY (INTERVAL '1 day')
);

-- ─── UC2: DNS Query Logs ───────────────────────────────────────────────────
CREATE TABLE dns_logs (
    dns_id          BIGSERIAL,
    ts              TIMESTAMP     NOT NULL,
    client_ip       inet          NOT NULL,
    query_name      VARCHAR(256)  NOT NULL,
    query_type      VARCHAR(10)   NOT NULL,   -- A | AAAA | MX | CNAME | TXT | PTR
    response_code   VARCHAR(16)   NOT NULL,   -- NOERROR | NXDOMAIN | SERVFAIL
    response_ip     inet,
    response_time   INT,                       -- microseconds
    is_recursive    BOOLEAN       DEFAULT TRUE,
    region_id       INT
) WITH (appendoptimized=true, orientation=column,compresstype=zstd, compresslevel=3)
DISTRIBUTED BY (dns_id)
PARTITION BY RANGE (ts) (
    START ('2026-01-01'::timestamp) INCLUSIVE
    END   ('2026-05-01'::timestamp) EXCLUSIVE
    EVERY (INTERVAL '1 day')
);

-- ─── UC2: BGP Route Changes ────────────────────────────────────────────────
CREATE TABLE bgp_events (
    bgp_id          BIGSERIAL,
    ts              TIMESTAMP     NOT NULL,
    peer_ip         inet          NOT NULL,
    prefix          cidr          NOT NULL,
    event_type      VARCHAR(16)   NOT NULL,   -- ANNOUNCE | WITHDRAW | UPDATE
    as_path         TEXT,
    next_hop        inet,
    origin          VARCHAR(10),               -- IGP | EGP | INCOMPLETE
    local_pref      INT,
    med             INT,
    community       TEXT,
    region_id       INT
) WITH (appendoptimized=true, orientation=column,compresstype=zstd, compresslevel=3)
DISTRIBUTED BY (bgp_id)
PARTITION BY RANGE (ts) (
    START ('2026-01-01'::timestamp) INCLUSIVE
    END   ('2026-05-01'::timestamp) EXCLUSIVE
    EVERY (INTERVAL '1 day')
);

-- ─── UC3: IPAM Allocations (current state + history) ───────────────────────
CREATE TABLE ipam_allocations (
    alloc_id        SERIAL,
    ip_address      inet          NOT NULL,
    subnet_id       INT           NOT NULL,
    mac_address     macaddr,
    hostname        VARCHAR(128),
    device_type     VARCHAR(32),
    status          VARCHAR(16)   NOT NULL DEFAULT 'active',
                    -- active | reserved | deprecated | available
    allocated_at    TIMESTAMP     NOT NULL DEFAULT now(),
    released_at     TIMESTAMP,
    last_seen       TIMESTAMP,
    region_id       INT
) DISTRIBUTED BY (alloc_id);

CREATE INDEX idx_ipam_ip ON ipam_allocations USING gist (ip_address inet_ops);

-- ─── UC3: IPAM Summary (materialized / refreshed) ──────────────────────────
CREATE TABLE ipam_summary (
    subnet_id       INT,
    subnet          cidr          NOT NULL,
    region_id       INT,
    total_ips       INT           NOT NULL,
    allocated_ips   INT           NOT NULL,
    reserved_ips    INT           NOT NULL DEFAULT 0,
    utilization_pct NUMERIC(5,1)  NOT NULL,
    last_refreshed  TIMESTAMP     NOT NULL DEFAULT now()
) DISTRIBUTED BY (subnet_id);

-- ─── UC4: Network Metrics (per customer, time-series) ──────────────────────
CREATE TABLE network_metrics (
    metric_id       BIGSERIAL,
    ts              TIMESTAMP     NOT NULL,
    customer_id     INT           NOT NULL,
    region_id       INT,
    probe_ip        inet,
    latency_ms      NUMERIC(8,2)  NOT NULL,
    jitter_ms       NUMERIC(8,2)  NOT NULL,
    packet_loss_pct NUMERIC(5,2)  NOT NULL,
    throughput_mbps NUMERIC(10,2),
    mos_score       NUMERIC(3,1)           -- Mean Opinion Score (1.0 - 5.0)
) WITH (appendoptimized=true, orientation=column,compresstype=zstd, compresslevel=3)
DISTRIBUTED BY (metric_id)
PARTITION BY RANGE (ts) (
    START ('2026-01-01'::timestamp) INCLUSIVE
    END   ('2026-05-01'::timestamp) EXCLUSIVE
    EVERY (INTERVAL '1 day')
);

-- ─── UC5: Security Incidents ────────────────────────────────────────────────
CREATE TABLE security_incidents (
    incident_id     SERIAL,
    ts              TIMESTAMP     NOT NULL DEFAULT now(),
    src_ip          inet          NOT NULL,
    dst_ip          inet,
    threat_category VARCHAR(32)   NOT NULL,
    severity        VARCHAR(10)   NOT NULL,   -- critical | high | medium | low
    feed_id         INT,
    matched_rule    VARCHAR(64),
    description     TEXT,
    status          VARCHAR(16)   NOT NULL DEFAULT 'open',
                    -- open | investigating | mitigated | closed
    region_id       INT
) DISTRIBUTED BY (incident_id);


-- ============================================================================
-- VIEWS  (Ready-to-use analytics layers)
-- ============================================================================

-- ─── UC1: Traffic Summary (hourly) ──────────────────────────────────────────
CREATE VIEW v_traffic_hourly AS
SELECT
    date_trunc('hour', ts)                  AS hour,
    r.region_code,
    COUNT(*)                                AS flow_count,
    SUM(bytes)                              AS total_bytes,
    SUM(packets)                            AS total_packets,
    COUNT(DISTINCT src_ip)                  AS unique_src,
    COUNT(DISTINCT dst_ip)                  AS unique_dst
FROM netflow_logs n
LEFT JOIN regions r ON n.region_id = r.region_id
GROUP BY 1, 2;

-- ─── UC1: Anomaly Detection (flows exceeding 3σ) ───────────────────────────
CREATE VIEW v_traffic_anomalies AS
WITH hourly AS (
    SELECT
        date_trunc('hour', ts)  AS hour,
        src_ip,
        SUM(bytes)              AS total_bytes,
        COUNT(*)                AS flow_count
    FROM netflow_logs
    WHERE ts > now() - interval '7 days'
    GROUP BY 1, 2
),
stats AS (
    SELECT
        src_ip,
        AVG(total_bytes)                           AS avg_bytes,
        STDDEV_POP(total_bytes)                    AS std_bytes
    FROM hourly
    GROUP BY src_ip
)
SELECT
    h.hour,
    h.src_ip,
    h.total_bytes,
    h.flow_count,
    s.avg_bytes,
    ROUND((h.total_bytes - s.avg_bytes) / NULLIF(s.std_bytes, 0), 2) AS z_score
FROM hourly h
JOIN stats s USING (src_ip)
WHERE (h.total_bytes - s.avg_bytes) / NULLIF(s.std_bytes, 0) > 3
ORDER BY z_score DESC;

-- ─── UC2: Cross-source Event Correlation ────────────────────────────────────
CREATE VIEW v_correlated_events AS
SELECT
    s.ts                       AS syslog_ts,
    s.src_ip,
    s.severity                 AS syslog_severity,
    s.message                  AS syslog_msg,
    f.action                   AS fw_action,
    f.dst_ip                   AS fw_dst,
    f.dst_port                 AS fw_port,
    d.query_name               AS dns_query,
    d.response_code            AS dns_rcode
FROM syslog_events s
JOIN firewall_logs f
    ON s.src_ip = f.src_ip
    AND f.ts BETWEEN s.ts - interval '5 seconds'
                 AND s.ts + interval '5 seconds'
LEFT JOIN dns_logs d
    ON s.src_ip = d.client_ip
    AND d.ts BETWEEN s.ts - interval '10 seconds'
                  AND s.ts + interval '10 seconds'
WHERE s.severity <= 3;  -- critical, alert, error, warning

-- ─── UC3: IPAM Utilization Dashboard ────────────────────────────────────────
CREATE VIEW v_ipam_utilization AS
SELECT
    s.subnet,
    masklen(s.subnet)                  AS prefix_len,
    s.description,
    r.region_code,
    i.total_ips,
    i.allocated_ips,
    i.reserved_ips,
    i.utilization_pct,
    CASE
        WHEN i.utilization_pct >= 90 THEN 'critical'
        WHEN i.utilization_pct >= 70 THEN 'warning'
        ELSE 'healthy'
    END                                AS health_status,
    i.last_refreshed
FROM ipam_summary i
JOIN subnets s ON i.subnet_id = s.subnet_id
JOIN regions r ON s.region_id = r.region_id;

-- ─── UC3: Subnet Overlap Detection ─────────────────────────────────────────
CREATE VIEW v_subnet_overlaps AS
SELECT
    a.subnet_id  AS subnet_a_id,
    a.subnet     AS subnet_a,
    b.subnet_id  AS subnet_b_id,
    b.subnet     AS subnet_b,
    ra.region_code AS region_a,
    rb.region_code AS region_b
FROM subnets a
JOIN subnets b ON a.subnet_id < b.subnet_id
JOIN regions ra ON a.region_id = ra.region_id
JOIN regions rb ON b.region_id = rb.region_id
WHERE a.subnet && b.subnet               -- native overlap operator!
  AND NOT (a.subnet >>= b.subnet)         -- exclude parent-child
  AND NOT (b.subnet >>= a.subnet);

-- ─── UC4: SLA Status (real-time) ───────────────────────────────────────────
CREATE VIEW v_sla_status AS
SELECT
    c.customer_id,
    c.customer_name,
    c.tier,
    r.region_code,
    sc.target_availability,
    sc.latency_sla_ms,
    sc.packet_loss_sla_pct,
    AVG(m.latency_ms)                     AS avg_latency,
    AVG(m.jitter_ms)                      AS avg_jitter,
    AVG(m.packet_loss_pct)                AS avg_loss,
    AVG(m.mos_score)                      AS avg_mos,
    CASE
        WHEN AVG(m.latency_ms) > sc.latency_sla_ms
          OR AVG(m.packet_loss_pct) > sc.packet_loss_sla_pct
        THEN 'BREACH'
        WHEN AVG(m.latency_ms) > sc.latency_sla_ms * 0.8
          OR AVG(m.packet_loss_pct) > sc.packet_loss_sla_pct * 0.8
        THEN 'AT RISK'
        ELSE 'HEALTHY'
    END                                   AS sla_status
FROM customers c
JOIN sla_contracts sc ON c.customer_id = sc.customer_id
    AND sc.effective_to IS NULL
JOIN regions r ON c.region_id = r.region_id
JOIN network_metrics m ON c.customer_id = m.customer_id
    AND m.ts > now() - interval '24 hours'
GROUP BY 1, 2, 3, 4, 5, 6, 7;

-- ─── UC5: Threat Matches (live) ────────────────────────────────────────────
CREATE VIEW v_threat_matches AS
SELECT
    n.ts,
    n.src_ip,
    n.dst_ip,
    n.dst_port,
    n.bytes,
    t.feed_name,
    t.category          AS threat_category,
    t.confidence,
    t.country_code      AS threat_origin,
    g.country_name      AS src_geo_country,
    g.city              AS src_geo_city
FROM netflow_logs n
JOIN threat_intel_feeds t
    ON n.src_ip <<= t.ip_range       -- ⚡ NATIVE containment — the killer feature
    AND t.active = TRUE
LEFT JOIN geo_ip g
    ON n.src_ip <<= g.network
WHERE n.ts > now() - interval '24 hours'
  AND t.confidence >= 70;


-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Calculate available IPs in a CIDR block
CREATE OR REPLACE FUNCTION cidr_host_count(net cidr) RETURNS BIGINT AS $$
    SELECT (power(2, (CASE
        WHEN family(net) = 4 THEN 32
        ELSE 128
    END - masklen(net))))::bigint - 2;  -- subtract network + broadcast
$$ LANGUAGE SQL IMMUTABLE STRICT;

-- QoE score from network metrics (simplified ITU-T E-model)
CREATE OR REPLACE FUNCTION calc_qoe_score(
    latency_ms NUMERIC,
    jitter_ms NUMERIC,
    loss_pct NUMERIC
) RETURNS INT AS $$
    SELECT GREATEST(0, LEAST(100,
        ROUND(100
            - (latency_ms * 0.4)
            - (jitter_ms * 1.5)
            - (loss_pct * 25)
        )::INT
    ));
$$ LANGUAGE SQL IMMUTABLE STRICT;


-- ============================================================================
-- DONE — Schema ready
-- ============================================================================
-- Next: Run 02_seed_reference.sql to populate reference data
-- ============================================================================

