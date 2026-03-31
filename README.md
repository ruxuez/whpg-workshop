# Analytics Database (WarehousePG + PGAA)

Multi-node WarehousePG cluster with PGAA extension for querying Iceberg tables and Delta/Parquet files.

## Architecture

This setup creates a distributed WarehousePG cluster with:

- **Coordinator** (`cdw`): Master node managing query planning and coordination
- **Segment 1** (`sdw1`): Data processing node with 2 primary + 2 mirror segments
- **Segment 2** (`sdw2`): Data processing node with 2 primary + 2 mirror segments

Total: 4 primary segments and 4 mirror segments for high availability.

## Prerequisites

- EDB Subscription Token (set as environment variable)
- Catalog component must be running (Lakekeeper + MinIO)
- Network: `converged-analytics-network` (created by catalog stack)

## Quick Start

### 1. Build and Start Cluster

```bash
cd analytics-db
docker-compose build
docker-compose up -d
```

### 2. Monitor Startup

Watch the coordinator logs (~5-10 minutes for first-time init):

```bash
docker logs -f cdw
```

Wait for the "DEPLOYMENT SUCCESSFUL" banner.

### 3. Verify Cluster

```bash
# Check all containers are running
docker ps | grep -E "cdw|sdw"

# Check cluster status
docker exec cdw bash -ic "source /usr/local/greenplum-db/greenplum_path.sh && gpstate"
```

### 4. Setup PGAA

Setup with local Lakekeeper catalog:

```bash
cd ..
python3 scripts/setup_whpg.py --local-catalog
```

Optionally, setup Delta tables from public S3:

```bash
python3 scripts/setup_whpg.py --delta-tables
```

## Configuration Files

- **docker-compose.yml**: Multi-container setup (coordinator + 2 segments)
- **Dockerfile**: Rocky Linux 8 based image with WarehousePG 7, PGAA, PGFS
- **gpinitsystem_config**: Cluster initialization settings
- **hostfile_gpinitsystem**: List of segment hosts (sdw1, sdw2)
- **init_system.sh**: Container startup script that:
  - Starts SSH daemon for inter-container communication
  - Sets up SSH keys for passwordless access
  - Runs `gpinitsystem` to create the distributed cluster
  - Configures pg_hba.conf for external access

## Credentials

- **User**: `gpadmin`
- **Password**: `changeme@123`
- **Database**: `demo` (created during initialization)

## Connecting

From host machine:

```bash
PGPASSWORD=changeme@123 psql -h localhost -p 5432 -U gpadmin -d demo
```

## Schemas and Tables

After running setup scripts:

### demo schema (local Iceberg catalog)

Managed by Lakekeeper catalog, tables replicated from PGD:

- `demo.countries`
- `demo.products`
- `demo.customers`
- `demo.sales`

### sample_delta_tpch_sf_1 schema (public S3 Delta tables)

Read-only Delta/Parquet tables from EDB public bucket:

- `sample_delta_tpch_sf_1.customer`
- `sample_delta_tpch_sf_1.lineitem`
- `sample_delta_tpch_sf_1.nation`
- `sample_delta_tpch_sf_1.orders`
- `sample_delta_tpch_sf_1.part`
- `sample_delta_tpch_sf_1.partsupp`
- `sample_delta_tpch_sf_1.region`
- `sample_delta_tpch_sf_1.supplier`

## Querying with Different Engines

PGAA supports multiple execution engines:

### Datafusion (default - embedded)

```sql
-- No configuration needed, automatically used by default
SELECT COUNT(*) FROM sample_delta_tpch_sf_1.customer;
```

### Spark Connect (requires Spark cluster)

```sql
-- Point to Spark Connect endpoint
SET pgaa.executor_engine = 'spark_connect';
SET pgaa.spark_connect_url = 'sc://spark-connect-host:15002';

SELECT COUNT(*) FROM sample_delta_tpch_sf_1.customer;
```

## WarehousePG Specifics

### Distributed Tables

WarehousePG supports distributed tables for parallel query execution:

```sql
-- Replicated (small dimension tables)
CREATE TABLE demo.countries () USING PGAA WITH (...)
DISTRIBUTED REPLICATED;

-- Distributed by hash (large fact tables)
CREATE TABLE demo.sales () USING PGAA WITH (...)
DISTRIBUTED BY (id);

-- Randomly distributed
CREATE TABLE demo.products () USING PGAA WITH (...)
DISTRIBUTED RANDOMLY;
```

### Cluster Information

```sql
-- View segment configuration
SELECT * FROM gp_segment_configuration ORDER BY dbid;

-- View cluster state
\! source /usr/local/greenplum-db/greenplum_path.sh && gpstate
```

## Volumes

- **master**: Coordinator node data directory
- **sdw1_primary1, sdw1_primary2**: Segment 1 primary data directories
- **sdw1_mirror1, sdw1_mirror2**: Segment 1 mirror data directories
- **sdw2_primary1, sdw2_primary2**: Segment 2 primary data directories
- **sdw2_mirror1, sdw2_mirror2**: Segment 2 mirror data directories

## Troubleshooting

### Check container logs

```bash
# Coordinator
docker logs cdw

# Segments
docker logs sdw1
docker logs sdw2
```

### Restart cluster

```bash
# From inside coordinator container
docker exec cdw bash -ic "source /usr/local/greenplum-db/greenplum_path.sh && gpstop -a -M fast && gpstart -a"
```

### Access coordinator shell

```bash
docker exec -it cdw bash -ic bash
```

### Cluster won't initialize

- Check that all three containers are running
- Verify SSH connectivity between containers:
  ```bash
  docker exec cdw ssh sdw1 hostname
  docker exec cdw ssh sdw2 hostname
  ```
- Check segment host ownership of data directories:
  ```bash
  docker exec sdw1 ls -la /data1 /data2
  ```

### Check PGAA configuration

```bash
PGPASSWORD=changeme@123 psql -h localhost -p 5432 -U gpadmin -d demo -c "SELECT * FROM pgaa.list_catalogs();"
PGPASSWORD=changeme@123 psql -h localhost -p 5432 -U gpadmin -d demo -c '\dx'
```

### Performance Tuning

```sql
-- Disable pushdown for debugging
SET pgaa.enable_groupby_pushdown = off;
SET pgaa.enable_join_pushdown = off;

-- Re-enable
SET pgaa.enable_groupby_pushdown = on;
SET pgaa.enable_join_pushdown = on;
```

## Stopping

```bash
docker-compose down
```

To remove volumes (destroys all data):

```bash
docker-compose down -v
```

## Rebuilding

If you need to completely rebuild the cluster:

```bash
# Stop and remove everything
docker-compose down -v

# Remove images
docker rmi whpg_cdw

# Rebuild and start
docker-compose build
docker-compose up -d
```
