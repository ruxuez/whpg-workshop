-- ═══════════════════════════════════════════════════════════════════════════════
-- Lab 3: AI-Powered Analytics — pgvector + MADlib on Network Data
-- ═══════════════════════════════════════════════════════════════════════════════
-- This lab demonstrates AI/ML capabilities directly inside WarehousePG,
-- eliminating the need to export data to external ML platforms.
--
-- Part A: pgvector — Semantic search on network events
-- Part B: MADlib  — Anomaly detection model on netflow data
-- Part C: PG Airman preview — natural language to SQL
-- ═══════════════════════════════════════════════════════════════════════════════

SET search_path TO netvista_demo, public;

-- ═══════════════════════════════════════════════════════════════════════════════
-- CLEANUP — drop previous lab artifacts if they exist (safe to re-run)
-- ═══════════════════════════════════════════════════════════════════════════════
DROP TABLE IF EXISTS netvista_demo.kmeans_assignments;
DROP TABLE IF EXISTS netvista_demo.netflow_features_norm;
DROP TABLE IF EXISTS netvista_demo.netflow_features;
DROP TABLE IF EXISTS netvista_demo.syslog_embeddings;
DROP INDEX IF EXISTS netvista_demo.idx_syslog_embedding_hnsw;

-- ═══════════════════════════════════════════════════════════════════════════════
-- PART A: pgvector — Similarity Search on Network Events
-- ═══════════════════════════════════════════════════════════════════════════════
-- Use case: An analyst wants to find events SIMILAR to a known incident,
-- not just exact matches. "Show me syslog messages that look like this attack."

-- Step 1: Enable pgvector
CREATE EXTENSION IF NOT EXISTS vector;

-- Step 2: Create a table to store syslog message embeddings
-- In production, embeddings come from an ML model (e.g., sentence-transformers).
-- For the workshop, we generate synthetic embeddings from message features.
CREATE TABLE netvista_demo.syslog_embeddings (
    event_id     BIGINT,
    hostname     TEXT,
    program      TEXT,
    message TEXT,
    severity     INT,
    embedding    vector(16)       -- 16-dimensional feature vector
) DISTRIBUTED BY (event_id);

-- Step 3: Generate feature-based embeddings from syslog messages
-- Each dimension captures a signal: severity, program type, message patterns, etc.
INSERT INTO netvista_demo.syslog_embeddings (event_id, hostname, program, message, severity, embedding)
SELECT
    event_id,
    hostname,
    program,
    LEFT(message, 200),
    severity,
    -- Build a 16-dim feature vector from message characteristics
    ARRAY[
        severity::float / 7.0,                                           -- normalized severity
        CASE WHEN program = 'sshd' THEN 1.0 ELSE 0.0 END,              -- SSH activity
        CASE WHEN program = 'firewalld' THEN 1.0 ELSE 0.0 END,         -- firewall activity
        CASE WHEN program = 'kernel' THEN 1.0 ELSE 0.0 END,            -- kernel messages
        CASE WHEN program = 'haproxy' THEN 1.0 ELSE 0.0 END,           -- load balancer
        CASE WHEN program = 'kubelet' THEN 1.0 ELSE 0.0 END,           -- k8s activity
        CASE WHEN program = 'bgpd' THEN 1.0 ELSE 0.0 END,             -- routing
        CASE WHEN message LIKE '%SYN flood%' THEN 1.0 ELSE 0.0 END,   -- DDoS indicator
        CASE WHEN message LIKE '%password%' THEN 1.0 ELSE 0.0 END,    -- auth failure
        CASE WHEN message LIKE '%DOWN%' THEN 1.0 ELSE 0.0 END,        -- service down
        CASE WHEN message LIKE '%OUT OF MEMORY%' THEN 1.0 ELSE 0.0 END, -- OOM
        CASE WHEN message LIKE '%Link down%' THEN 1.0 ELSE 0.0 END,   -- network failure
        CASE WHEN message LIKE '%container%' THEN 1.0 ELSE 0.0 END,   -- container event
        CASE WHEN message LIKE '%DNS%' THEN 1.0 ELSE 0.0 END,         -- DNS related
        CASE WHEN hostname LIKE 'ids-%' THEN 1.0 ELSE 0.0 END,        -- IDS host
        CASE WHEN hostname LIKE 'waf-%' THEN 1.0 ELSE 0.0 END         -- WAF host
    ]::vector(16)
FROM netvista_demo.syslog_events
WHERE ts > now() - interval '24 hours'
LIMIT 100000;   -- 100K events for the workshop

-- Step 4: Create HNSW index for fast approximate nearest-neighbor search
-- CREATE INDEX idx_syslog_embedding_hnsw
-- ON netvista_demo.syslog_embeddings
-- USING hnsw (embedding vector_cosine_ops)
-- WITH (m = 16, ef_construction = 64);

ANALYZE netvista_demo.syslog_embeddings;

-- ─── pgvector Demo Queries ──────────────────────────────────────────────────

-- Query A1: "Find events similar to this SYN flood attack"
-- The analyst provides a known-bad event signature as a vector
-- \timing on

-- SELECT
--     event_id,
--     hostname,
--     program,
--     LEFT(message, 80) AS message,
--     severity,
--     1 - (embedding <=> (
--         SELECT embedding FROM netvista_demo.syslog_embeddings
--         WHERE message LIKE '%SYN flood%'
--         LIMIT 1
--     )) AS similarity_score
-- FROM netvista_demo.syslog_embeddings
-- ORDER BY embedding <=> (
--     SELECT embedding FROM netvista_demo.syslog_embeddings
--     WHERE message LIKE '%SYN flood%'
--     LIMIT 1
-- )
-- LIMIT 20;

-- -- Query A2: "Find events similar to authentication failures"
-- SELECT
--     event_id,
--     hostname,
--     program,
--     LEFT(message, 80) AS message,
--     severity,
--     1 - (embedding <=> (
--         SELECT embedding FROM netvista_demo.syslog_embeddings
--         WHERE message LIKE '%password%'
--         LIMIT 1
--     )) AS similarity_score
-- FROM netvista_demo.syslog_embeddings
-- ORDER BY embedding <=> (
--     SELECT embedding FROM netvista_demo.syslog_embeddings
--     WHERE message LIKE '%password%'
--     LIMIT 1
-- )
-- LIMIT 20;

-- -- Query A3: "Cluster similar events — how many distinct attack patterns?"
-- -- Group events by nearest centroid (using K-means via vector distance)
-- WITH attack_patterns AS (
--     SELECT
--         event_id,
--         hostname,
--         program,
--         LEFT(message, 60) AS msg,
--         severity,
--         CASE
--             WHEN message LIKE '%SYN flood%' OR message LIKE '%flooding%' THEN 'DDoS'
--             WHEN message LIKE '%password%' OR message LIKE '%authenticating%' THEN 'Auth Failure'
--             WHEN message LIKE '%DOWN%' OR message LIKE '%Link down%' THEN 'Infra Down'
--             WHEN message LIKE '%OUT OF MEMORY%' OR message LIKE '%OOM%' THEN 'Resource Exhaustion'
--             WHEN message LIKE '%container%' OR message LIKE '%kubelet%' THEN 'Container Event'
--             WHEN message LIKE '%DNS%' OR message LIKE '%query rate%' THEN 'DNS Anomaly'
--             ELSE 'Other'
--         END AS pattern_category
--     FROM netvista_demo.syslog_embeddings
-- )
-- SELECT
--     pattern_category,
--     COUNT(*) AS event_count,
--     COUNT(DISTINCT hostname) AS affected_hosts,
--     ROUND(AVG(severity), 1) AS avg_severity
-- FROM attack_patterns
-- GROUP BY 1
-- ORDER BY event_count DESC;

-- \timing off


-- ═══════════════════════════════════════════════════════════════════════════════
-- PART B: MADlib — Anomaly Detection on Netflow Data
-- ═══════════════════════════════════════════════════════════════════════════════
-- Use case: Build a statistical model to detect abnormal traffic patterns
-- without exporting data to Python/Spark.

-- Step 1: Create a feature table for ML training
-- Each row = one source IP's hourly behavior profile
CREATE TABLE netvista_demo.netflow_features AS
SELECT
    date_trunc('hour', ts) AS hour,
    src_ip,
    COUNT(*)                          AS flow_count,
    COUNT(DISTINCT dst_ip)            AS unique_dsts,
    COUNT(DISTINCT dst_port)          AS unique_ports,
    SUM(bytes)                        AS total_bytes,
    AVG(bytes)                        AS avg_bytes,
    STDDEV_SAMP(bytes)                AS stddev_bytes,
    MAX(bytes)                        AS max_bytes,
    SUM(packets)                      AS total_packets,
    -- Entropy proxy: ratio of unique destinations to total flows
    ROUND(COUNT(DISTINCT dst_ip)::numeric / NULLIF(COUNT(*), 0), 4) AS dst_entropy,
    -- Port spread: ratio of unique ports to total flows
    ROUND(COUNT(DISTINCT dst_port)::numeric / NULLIF(COUNT(*), 0), 4) AS port_spread
FROM netvista_demo.netflow_logs
WHERE ts > now() - interval '24 hours'
GROUP BY 1, 2
HAVING COUNT(*) >= 5  -- minimum activity threshold
DISTRIBUTED BY (src_ip);

ANALYZE netvista_demo.netflow_features;

-- Step 2: Summary statistics for each feature
-- This gives the analyst a baseline for "normal" behavior
-- SELECT
--     COUNT(*) AS total_profiles,
--     ROUND(AVG(flow_count), 1) AS avg_flows,
--     ROUND(AVG(unique_dsts), 1) AS avg_destinations,
--     ROUND(AVG(unique_ports), 1) AS avg_ports,
--     ROUND(AVG(total_bytes)::numeric, 0) AS avg_bytes,
--     ROUND(AVG(dst_entropy)::numeric, 4) AS avg_dst_entropy,
--     ROUND(AVG(port_spread)::numeric, 4) AS avg_port_spread
-- FROM netvista_demo.netflow_features;

-- Step 3: Z-Score anomaly detection (pure SQL, no MADlib needed)
-- Flag any hourly profile where 2+ features exceed 3 standard deviations
-- WITH stats AS (
--     SELECT
--         AVG(flow_count) AS mu_flows, STDDEV_SAMP(flow_count) AS sd_flows,
--         AVG(unique_dsts) AS mu_dsts, STDDEV_SAMP(unique_dsts) AS sd_dsts,
--         AVG(unique_ports) AS mu_ports, STDDEV_SAMP(unique_ports) AS sd_ports,
--         AVG(total_bytes) AS mu_bytes, STDDEV_SAMP(total_bytes) AS sd_bytes
--     FROM netvista_demo.netflow_features
-- ),
-- scored AS (
--     SELECT
--         f.hour, f.src_ip::text,
--         f.flow_count, f.unique_dsts, f.unique_ports, f.total_bytes,
--         ROUND(ABS(f.flow_count - s.mu_flows) / NULLIF(s.sd_flows, 0), 2) AS z_flows,
--         ROUND(ABS(f.unique_dsts - s.mu_dsts) / NULLIF(s.sd_dsts, 0), 2) AS z_dsts,
--         ROUND(ABS(f.unique_ports - s.mu_ports) / NULLIF(s.sd_ports, 0), 2) AS z_ports,
--         ROUND(ABS(f.total_bytes - s.mu_bytes) / NULLIF(s.sd_bytes, 0), 2) AS z_bytes
--     FROM netvista_demo.netflow_features f, stats s
-- )
-- SELECT
--     hour, src_ip,
--     flow_count, unique_dsts, unique_ports, total_bytes,
--     z_flows, z_dsts, z_ports, z_bytes,
--     (CASE WHEN z_flows > 3 THEN 1 ELSE 0 END +
--      CASE WHEN z_dsts > 3 THEN 1 ELSE 0 END +
--      CASE WHEN z_ports > 3 THEN 1 ELSE 0 END +
--      CASE WHEN z_bytes > 3 THEN 1 ELSE 0 END) AS anomaly_dimensions
-- FROM scored
-- WHERE (CASE WHEN z_flows > 3 THEN 1 ELSE 0 END +
--        CASE WHEN z_dsts > 3 THEN 1 ELSE 0 END +
--        CASE WHEN z_ports > 3 THEN 1 ELSE 0 END +
--        CASE WHEN z_bytes > 3 THEN 1 ELSE 0 END) >= 2
-- ORDER BY anomaly_dimensions DESC, z_bytes DESC
-- LIMIT 30;

-- Step 4: MADlib K-Means clustering (if MADlib is installed)
-- Groups all hourly IP profiles into behavioral clusters
-- Anomalous IPs will end up in small/outlier clusters

-- Uncomment if MADlib is available:
/*
-- Normalize features for clustering
CREATE TABLE netvista_demo.netflow_features_norm AS
SELECT
    src_ip,
    ARRAY[
        (flow_count - (SELECT AVG(flow_count) FROM netvista_demo.netflow_features)) /
            NULLIF((SELECT STDDEV(flow_count) FROM netvista_demo.netflow_features), 0),
        (unique_dsts - (SELECT AVG(unique_dsts) FROM netvista_demo.netflow_features)) /
            NULLIF((SELECT STDDEV(unique_dsts) FROM netvista_demo.netflow_features), 0),
        (unique_ports - (SELECT AVG(unique_ports) FROM netvista_demo.netflow_features)) /
            NULLIF((SELECT STDDEV(unique_ports) FROM netvista_demo.netflow_features), 0),
        (total_bytes - (SELECT AVG(total_bytes) FROM netvista_demo.netflow_features)) /
            NULLIF((SELECT STDDEV(total_bytes) FROM netvista_demo.netflow_features), 0)
    ]::double precision[] AS features
FROM netvista_demo.netflow_features
DISTRIBUTED BY (src_ip);

-- Run K-Means++ (5 clusters) — returns centroids inline
SELECT * FROM madlib.kmeanspp(
    'netvista_demo.netflow_features_norm',   -- source table
    'features',                              -- feature column
    5,                                       -- k clusters
    'madlib.dist_norm2',                     -- distance function
    'madlib.avg',                            -- aggregate function
    100,                                     -- max iterations
    0.001::double precision                  -- convergence threshold
);

-- Build cluster assignments manually
-- kmeanspp doesn't create a table — we assign each point to its nearest centroid
CREATE TABLE netvista_demo.kmeans_assignments AS
WITH model AS (
    SELECT centroids
    FROM madlib.kmeanspp(
        'netvista_demo.netflow_features_norm',
        'features', 5, 'madlib.dist_norm2', 'madlib.avg',
        100, 0.001::double precision
    )
),
centroids AS (
    SELECT
        i - 1 AS cluster_id,
        ARRAY[m.centroids[i][1], m.centroids[i][2], m.centroids[i][3], m.centroids[i][4]]::double precision[] AS centroid
    FROM model m, generate_series(1, 5) AS i
),
ranked AS (
    SELECT
        n.src_ip,
        c.cluster_id,
        ROW_NUMBER() OVER (
            PARTITION BY n.src_ip
            ORDER BY madlib.dist_norm2(n.features, c.centroid)
        ) AS rn
    FROM netvista_demo.netflow_features_norm n, centroids c
)
SELECT src_ip, cluster_id
FROM ranked WHERE rn = 1
DISTRIBUTED BY (src_ip);

-- See cluster assignments with profile stats
SELECT
    a.cluster_id,
    COUNT(*) AS member_count,
    ROUND(AVG(f.flow_count), 1) AS avg_flows,
    ROUND(AVG(f.total_bytes)::numeric, 0) AS avg_bytes,
    ROUND(AVG(f.unique_dsts), 1) AS avg_destinations,
    ROUND(AVG(f.unique_ports), 1) AS avg_ports
FROM netvista_demo.kmeans_assignments a
JOIN netvista_demo.netflow_features f ON a.src_ip = f.src_ip
GROUP BY 1 ORDER BY 2 DESC;
*/


-- ═══════════════════════════════════════════════════════════════════════════════
-- PART C: AI Factory — Combining Vector Search + Anomaly Detection
-- ═══════════════════════════════════════════════════════════════════════════════
-- The "money query": Find anomalous traffic AND similar historical incidents
-- in a single query — impossible on Snowflake/Databricks without exporting data.

-- Find anomalous IPs (from Part B), then for each one find the most similar
-- historical syslog events (from Part A) — all inside the database.

WITH anomalous_ips AS (
    -- Step 1: Find statistically anomalous sources
    SELECT src_ip, SUM(total_bytes) AS bytes, SUM(flow_count) AS flows
    FROM netvista_demo.netflow_features
    GROUP BY src_ip
    HAVING SUM(total_bytes) > (
        SELECT AVG(total_bytes) + 3 * STDDEV_SAMP(total_bytes)
        FROM netvista_demo.netflow_features
    )
    LIMIT 10
),
matching_syslog AS (
    -- Step 2: For each anomalous IP, find related syslog events
    SELECT
        a.src_ip::text AS anomalous_ip,
        a.bytes,
        a.flows,
        se.hostname,
        se.program,
        LEFT(se.message, 80) AS related_event,
        se.severity
    FROM anomalous_ips a
    JOIN netvista_demo.syslog_embeddings se ON se.hostname LIKE '%' ||
        CASE
            WHEN a.src_ip <<= '10.128.0.0/16'::cidr THEN 'us-w'
            WHEN a.src_ip <<= '10.10.0.0/16'::cidr THEN 'us-e'
            WHEN a.src_ip <<= '172.16.0.0/12'::cidr THEN 'eu'
            WHEN a.src_ip <<= '192.168.0.0/16'::cidr THEN 'jp'
            WHEN a.src_ip <<= '10.200.0.0/16'::cidr THEN 'sg'
            ELSE 'br'
        END || '%'
    WHERE se.severity <= 3
)
SELECT * FROM matching_syslog
ORDER BY severity, bytes DESC
LIMIT 30;

-- ═══════════════════════════════════════════════════════════════════════════════
-- CLEANUP (optional — remove lab artifacts)
-- ═══════════════════════════════════════════════════════════════════════════════
-- DROP TABLE IF EXISTS netvista_demo.syslog_embeddings;
-- DROP TABLE IF EXISTS netvista_demo.netflow_features;
-- DROP TABLE IF EXISTS netvista_demo.netflow_features_norm;
-- DROP TABLE IF EXISTS netvista_demo.kmeans_assignments;
-- DROP INDEX IF EXISTS idx_syslog_embedding_hnsw;
