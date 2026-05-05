-- =============================================================================
-- 07_kmeans_fallback.sql
-- Creates netvista_demo.kmeans_assignments used by query B3.
--
-- Strategy:
--   1. If MADlib's kmeanspp function is present  → run real K-Means clustering
--   2. Otherwise                                 → pure-SQL z-score percentile
--                                                  bucketing (5 pseudo-clusters)
--
-- Both paths produce identical schema:
--   kmeans_assignments(src_ip inet, cluster_id int)
--
-- Run after 06_ai_analytics.sql (netflow_features must already exist).
-- =============================================================================

SET search_path TO netvista_demo, public;

-- Drop existing tables so we always get a clean rebuild
DROP TABLE IF EXISTS netvista_demo.kmeans_assignments;
DROP TABLE IF EXISTS netvista_demo.netflow_features_norm;

DO $$
BEGIN

  -- ══════════════════════════════════════════════════════════════════════════
  -- PATH A: MADlib available → real kmeanspp
  -- ══════════════════════════════════════════════════════════════════════════
  IF EXISTS (
      SELECT 1
      FROM   pg_proc     p
      JOIN   pg_namespace n ON n.oid = p.pronamespace
      WHERE  n.nspname = 'madlib'
      AND    p.proname = 'kmeanspp'
  ) THEN

    RAISE NOTICE 'MADlib detected — building normalised feature table';

    -- Normalise the four behavioural features (z-score)
    -- CREATE TABLE netvista_demo.netflow_features_norm AS
    -- SELECT
    --     src_ip,
    --     ARRAY[
    --         (flow_count   - (SELECT AVG(flow_count)   FROM netvista_demo.netflow_features)) /
    --             NULLIF((SELECT STDDEV(flow_count)   FROM netvista_demo.netflow_features), 0),
    --         (unique_dsts  - (SELECT AVG(unique_dsts)  FROM netvista_demo.netflow_features)) /
    --             NULLIF((SELECT STDDEV(unique_dsts)  FROM netvista_demo.netflow_features), 0),
    --         (unique_ports - (SELECT AVG(unique_ports) FROM netvista_demo.netflow_features)) /
    --             NULLIF((SELECT STDDEV(unique_ports) FROM netvista_demo.netflow_features), 0),
    --         (total_bytes  - (SELECT AVG(total_bytes)  FROM netvista_demo.netflow_features)) /
    --             NULLIF((SELECT STDDEV(total_bytes)  FROM netvista_demo.netflow_features), 0)
    --     ]::double precision[] AS features
    -- FROM netvista_demo.netflow_features
    -- DISTRIBUTED BY (src_ip);
    -- Normalise the SIX behavioural features for better persona separation
    CREATE TABLE netvista_demo.netflow_features_norm AS
    SELECT
        src_ip,
        ARRAY[
            (flow_count   - (SELECT AVG(flow_count)   FROM netvista_demo.netflow_features)) /
                NULLIF((SELECT STDDEV(flow_count)   FROM netvista_demo.netflow_features), 0),
            (unique_dsts  - (SELECT AVG(unique_dsts)  FROM netvista_demo.netflow_features)) /
                NULLIF((SELECT STDDEV(unique_dsts)  FROM netvista_demo.netflow_features), 0),
            (unique_ports - (SELECT AVG(unique_ports) FROM netvista_demo.netflow_features)) /
                NULLIF((SELECT STDDEV(unique_ports) FROM netvista_demo.netflow_features), 0),
            (total_bytes  - (SELECT AVG(total_bytes)  FROM netvista_demo.netflow_features)) /
                NULLIF((SELECT STDDEV(total_bytes)  FROM netvista_demo.netflow_features), 0),
            -- Added for Personas
            (dst_entropy  - (SELECT AVG(dst_entropy)  FROM netvista_demo.netflow_features)) /
                NULLIF((SELECT STDDEV(dst_entropy)  FROM netvista_demo.netflow_features), 0),
            (port_spread  - (SELECT AVG(port_spread)  FROM netvista_demo.netflow_features)) /
                NULLIF((SELECT STDDEV(port_spread)  FROM netvista_demo.netflow_features), 0)
        ]::double precision[] AS features
    FROM netvista_demo.netflow_features
    DISTRIBUTED BY (src_ip);

    RAISE NOTICE 'Running madlib.kmeanspp (k=5, max_iter=100) …';

    -- Assign each src_ip to the nearest centroid produced by kmeanspp.
    -- kmeanspp returns centroids only; we compute assignments with a
    -- cross-join + ROW_NUMBER window function.
    CREATE TABLE netvista_demo.kmeans_assignments AS
    WITH model AS (
        SELECT centroids
        FROM madlib.kmeanspp(
            'netvista_demo.netflow_features_norm',  -- source table
            'features',                             -- feature column
            5,                                      -- k clusters
            'madlib.dist_norm2',                    -- distance metric
            'madlib.avg',                           -- centroid aggregate
            100,                                    -- max iterations
            0.001::double precision                 -- convergence threshold
        )
    ),
    -- Unpack the 2-D centroid array into one row per cluster
    centroids AS (
        SELECT
            i - 1 AS cluster_id,
            ARRAY[
                m.centroids[i][1],
                m.centroids[i][2],
                m.centroids[i][3],
                m.centroids[i][4],
                m.centroids[i][5], m.centroids[i][6] -- UNPACK ALL 6
            ]::double precision[] AS centroid
        FROM model m, generate_series(1, 5) AS i
    ),
    -- For every (IP, centroid) pair compute distance; keep closest
    ranked AS (
        SELECT
            n.src_ip,
            c.cluster_id,
            ROW_NUMBER() OVER (
                PARTITION BY n.src_ip
                ORDER BY madlib.dist_norm2(n.features, c.centroid)
            ) AS rn
        FROM netvista_demo.netflow_features_norm n
        CROSS JOIN centroids c
    )
    SELECT src_ip, cluster_id
    FROM   ranked
    WHERE  rn = 1
    DISTRIBUTED BY (src_ip);

    RAISE NOTICE 'MADlib kmeanspp complete — kmeans_assignments populated';

  -- ══════════════════════════════════════════════════════════════════════════
  -- PATH B: MADlib absent → pure-SQL z-score percentile bucketing
  -- Produces 5 pseudo-clusters (0 = normal … 4 = extreme outlier) that the
  -- B3 query consumes in exactly the same way as real K-Means output.
  -- ══════════════════════════════════════════════════════════════════════════
  ELSE

    RAISE NOTICE 'MADlib not found — using SQL z-score fallback for kmeans_assignments';

    CREATE TABLE netvista_demo.kmeans_assignments AS
    WITH stats AS (
        -- Global mean / stddev for each behavioural feature
        SELECT
            AVG(flow_count)   AS mu_f,  STDDEV_SAMP(flow_count)   AS sd_f,
            AVG(total_bytes)  AS mu_b,  STDDEV_SAMP(total_bytes)  AS sd_b,
            AVG(unique_dsts)  AS mu_d,  STDDEV_SAMP(unique_dsts)  AS sd_d,
            AVG(unique_ports) AS mu_p,  STDDEV_SAMP(unique_ports) AS sd_p,
            AVG(dst_entropy)  AS mu_e,  STDDEV_SAMP(dst_entropy)  AS sd_e,
            AVG(port_spread)  AS mu_s,  STDDEV_SAMP(port_spread)  AS sd_s,
            AVG(byte_cv)      AS mu_cv, STDDEV_SAMP(byte_cv)      AS sd_cv
        FROM netvista_demo.netflow_features
    ),
    scored AS (
        -- Persona-aware scoring: weight the features that distinguish personas
        SELECT
            f.src_ip,
            -- Z-scores for each feature
            ABS(f.flow_count   - s.mu_f)  / NULLIF(s.sd_f, 0)  AS z_flow,
            ABS(f.total_bytes  - s.mu_b)  / NULLIF(s.sd_b, 0)  AS z_bytes,
            ABS(f.unique_ports - s.mu_p)  / NULLIF(s.sd_p, 0)  AS z_ports,
            ABS(f.dst_entropy  - s.mu_e)  / NULLIF(s.sd_e, 0)  AS z_entropy,
            ABS(f.port_spread  - s.mu_s)  / NULLIF(s.sd_s, 0)  AS z_spread,
            ABS(f.byte_cv      - s.mu_cv) / NULLIF(s.sd_cv, 0) AS z_cv,
            -- Composite anomaly score
            (   ABS(f.flow_count   - s.mu_f)  / NULLIF(s.sd_f, 0)
            + ABS(f.total_bytes  - s.mu_b)  / NULLIF(s.sd_b, 0) * 2.0  -- weight bytes higher
            + ABS(f.unique_ports - s.mu_p)  / NULLIF(s.sd_p, 0) * 2.0  -- weight ports higher
            + ABS(f.dst_entropy  - s.mu_e)  / NULLIF(s.sd_e, 0)
            + ABS(f.port_spread  - s.mu_s)  / NULLIF(s.sd_s, 0)
            + ABS(f.byte_cv      - s.mu_cv) / NULLIF(s.sd_cv, 0)
            ) AS anomaly_score,
            -- Raw features for persona detection
            f.unique_ports, f.total_bytes, f.dst_entropy, f.byte_cv
        FROM netvista_demo.netflow_features f, stats s
    ),
    -- Persona-based clustering (rule-based for SQL fallback)
    -- This mirrors the expected K-Means output with clear persona boundaries
    SELECT
        src_ip,
        CASE
            -- RECON: high ports (z > 4) + low bytes
            WHEN z_ports > 4 AND z_bytes < 2 AND unique_ports > 50 THEN 1
            -- EXFIL: extreme bytes (z > 5) + low entropy
            WHEN z_bytes > 5 AND dst_entropy < 0.2 AND total_bytes > 50000000 THEN 2
            -- C2: low byte_cv (constant payload) + moderate flow + low entropy
            WHEN byte_cv < 0.4 AND dst_entropy < 0.3 AND z_flow BETWEEN 0.5 AND 3 THEN 3
            -- High anomaly but doesn't fit clear patterns
            WHEN anomaly_score > 8 THEN 4
            -- NORMAL: everything else
            ELSE 0
        END AS cluster_id
    FROM scored
    DISTRIBUTED BY (src_ip);

    RAISE NOTICE 'SQL fallback clustering complete — kmeans_assignments populated';

  END IF;

END$$;

-- Refresh planner stats so the JOIN in B3 gets good estimates
ANALYZE netvista_demo.kmeans_assignments;

-- Quick sanity check — printed to psql output / reload log
SELECT
    cluster_id,
    COUNT(*)                          AS member_count,
    ROUND(COUNT(*) * 100.0
          / SUM(COUNT(*)) OVER (), 1) AS pct_of_total
FROM netvista_demo.kmeans_assignments
GROUP BY 1
ORDER BY 1;


