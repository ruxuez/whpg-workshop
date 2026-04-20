# Lab 3: AI Analytics & The AI Factory

## Overview
In this lab, you will elevate your WarehousePG skills from standard SQL and vectorized Lakehouse queries to **In-Database Machine Learning**. You will leverage **pgvector** for high-dimensional semantic search and **Apache MADlib** for statistical modeling and clustering. The final goal is to build a unified **AI Factory** query that correlates raw log embeddings with network traffic anomalies in a single execution pass.

---

###  Part A: Semantic Analysis with `pgvector`
Traditional log analysis relies on rigid `LIKE` or `REGEX` matches. Part A demonstrates how to find security events based on **meaning**, not just keywords.

| ID | Query | Demonstration |
| :--- | :--- | :--- |
| **A1** | **Similar to SYN Flood** | Uses `pgvector` cosine similarity (`<=>`) to find syslogs semantically similar to a known DDoS attack vector. |
| **A2** | **Similar to Auth Failures** | Identifies brute-force patterns by clustering password and authentication event embeddings. |
| **A3** | **Attack Pattern Clusters** | Labels semantic groups using `CASE` statements and aggregates them to visualize attack trends. |

---

### Part B: Statistical Modeling with Apache MADlib
Part B focuses on **behavioral baselining**. Instead of looking at what logs *say*, we look at what IPs *do*.

| ID | Query | Demonstration |
| :--- | :--- | :--- |
| **B1** | **Netflow Baseline Stats** | Calculates summary statistics (mean/stddev) for hourly IP behavior to establish "normal" traffic profiles. |
| **B2** | **Z-Score Anomaly Detection** | Flags malicious IPs where two or more traffic features (e.g., `bytes_out`, `duration`) exceed **3σ** (three standard deviations). |
| **B3** | **MADlib K-Means Profiles** | Groups IPs into behavioral clusters; IPs landing in small, isolated clusters are identified as outliers. |



---

### Part C: The AI Factory (Integrated Intelligence)
The "AI Factory" is the peak of the lab. It combines the semantic intelligence of Part A with the statistical rigor of Part B to provide a 360-degree view of security threats.

| ID | Query | Demonstration |
| :--- | :--- | :--- |
| **C1** | **Anomaly + Syslog Correlation** | The "One Pass" query: It joins the statistical anomalies from MADlib with semantic syslog matches from `pgvector` to find IPs that are both acting weird and talking like attackers. |
| **C2** | **Embedding Coverage** | A data readiness check to ensure every host and program in the warehouse has sufficient embedding coverage for the AI models. |
| **C3** | **Anomalous IP Profiles** | A ranked list of investigation candidates based on combined anomaly scores and total data exfiltration (bytes). |

### Tabs preparation

Prepare 1 Shell Tab:
- Connection to `cdw` envionment shell (WarehousePG Tab):
```bash
docker exec -u gpadmin -w /home/gpadmin -it cdw /bin/bash
```
---

## Lab Assignment Instructions

### Lab Data Initialization  (**⚠️WarehousePG Tab**)
You will now create the schema and seed the database with network telemetry data.

Execute these from the **⚠️WarehousePG Tab**.

```bash
psql demo
```

Clean database:
```sql
SET search_path TO netvista_demo, public;

DROP TABLE IF EXISTS netvista_demo.kmeans_assignments;
DROP TABLE IF EXISTS netvista_demo.netflow_features_norm;
DROP TABLE IF EXISTS netvista_demo.netflow_features;
DROP TABLE IF EXISTS netvista_demo.syslog_embeddings;
DROP INDEX IF EXISTS netvista_demo.idx_syslog_embedding_hnsw;
````

#### PART A: pgvector — Similarity Search on Network Events

* **Use case:**

An analyst wants to find events SIMILAR to a known incident, not just exact matches.
*Example: "Show me syslog messages that look like this attack."*

* **Step 1: Enable pgvector**
```sql
CREATE EXTENSION IF NOT EXISTS vector;
````

* **Step 2: Create a table to store syslog message embeddings**

In production, embeddings come from an ML model (e.g., sentence-transformers).
For the workshop, we generate synthetic embeddings from message features.
```sql
CREATE TABLE netvista_demo.syslog_embeddings (
    event_id     BIGINT,
    hostname     TEXT,
    program      TEXT,
    message TEXT,
    severity     INT,
    embedding    vector(16)       -- 16-dimensional feature vector
) DISTRIBUTED BY (event_id);
````

* **Step 3: Generate feature-based embeddings from syslog messages**

Each dimension captures a signal: severity, program type, message patterns, etc.

```sql
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

ANALYZE netvista_demo.syslog_embeddings;
```

#### PART B: MADlib — Anomaly Detection on Netflow Data

**Use case:** Build a statistical model to detect abnormal traffic patterns without exporting data to Python/Spark.

* **Step 1: Create a feature table for ML training**

Each row = one source IP's hourly behavior profile
```sql
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
```

* **Step 2: MADlib K-Means clustering**

Groups all hourly IP profiles into behavioral clusters.

Anomalous IPs will end up in small/outlier clusters.
```sql
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
                NULLIF((SELECT STDDEV(total_bytes)  FROM netvista_demo.netflow_features), 0)
        ]::double precision[] AS features
    FROM netvista_demo.netflow_features
    DISTRIBUTED BY (src_ip);
```

Assign each src_ip to the nearest centroid produced by `kmeanspp`.

`kmeanspp` returns centroids only; we compute assignments with a `cross-join` + `ROW_NUMBER` window function.
```sql
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
                m.centroids[i][4]
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

ANALYZE netvista_demo.kmeans_assignments;
```
Quit WarehousePG:
```sql
\quit
```
### Visualize K-Means Clusters with the MADlib Dashboard

Launch the application by running the following command in the terminal:

```shell
python3.9 /scripts/apps/dashboard.py
```
Access the UI: Open application from your browser:
`http://localhost:5003`

Explore the Data: Use the dropdown menus to change the scatter plot axes.

This allows you to visualize how different dimensions (like flow_count vs. bytes_mb) impact the formation of the 5 behavioral clusters.

Once finished, you can go back to **⚠️WarehousePG Tab** and Press `CTRL+C` to quit application:

---

### Lab App Dashboard

1.  **Launch the AI Dashboard: ⚠️WarehousePG Tab**
    ```shell
    python3.9 /scripts/apps/app3.py
    ```


2.  Access the UI: Open application from your browser:
`http://localhost:5003`
3.  Execute different queries

*	Notice how the WarehousePG coordinator handles the **Vector Scan** alongside the **MADlib** UDFs.
* Observe how In-Database ML avoids the "Data Movement" tax by keeping the model near the 5 million rows of data.

---

### Deliverables
* **Vector Search Result:** A screenshot showing syslogs that were semantically similar to a "SYN Flood" but did *not* contain the word "Flood."
* **Anomaly Report:** The list of top 5 IPs flagged by the Part C AI Factory query.
* **Technical Reflection:** Explain why joining vector embeddings with network statistics is more effective for threat hunting than using either method alone.