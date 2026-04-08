-- ═══════════════════════════════════════════════════════════════════════════════
-- Lab 2: PGAA Iceberg Tables on MinIO + Native WHPG Comparison Tables
-- ═══════════════════════════════════════════════════════════════════════════════
--
-- Run AFTER iceberg_data_generator.py has populated MinIO.
--
-- Adjust the S3 URL, endpoint, and credentials below to match your environment.
-- ═══════════════════════════════════════════════════════════════════════════════

-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 1: PGFS Storage Location                                             ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

SELECT pgfs.delete_storage_location('minio_iceberg');

SELECT pgfs.create_storage_location(
    name        => 'minio_iceberg',
    url         => 's3://warehouse/iceberg',
    options     => '{"endpoint": "http://minio:9000", "allow_http": "true"}',
    credentials => '{"access_key_id": "minioadmin", "secret_access_key": "minioadmin"}'
);

SELECT * FROM pgfs.list_storage_locations();


-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 2: PGAA Iceberg Tables                                               ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

DROP TABLE IF EXISTS customers_iceberg;
CREATE TABLE customers_iceberg ()
USING PGAA WITH (
    pgaa.storage_location = 'minio_iceberg',
    pgaa.path             = 'analytics/customers',
    pgaa.format           = 'iceberg'
);

DROP TABLE IF EXISTS products_iceberg;
CREATE TABLE products_iceberg ()
USING PGAA WITH (
    pgaa.storage_location = 'minio_iceberg',
    pgaa.path             = 'analytics/products',
    pgaa.format           = 'iceberg'
);

DROP TABLE IF EXISTS orders_iceberg;
CREATE TABLE orders_iceberg ()
USING PGAA WITH (
    pgaa.storage_location = 'minio_iceberg',
    pgaa.path             = 'analytics/orders',
    pgaa.format           = 'iceberg'
);

DROP TABLE IF EXISTS order_items_iceberg;
CREATE TABLE order_items_iceberg ()
USING PGAA WITH (
    pgaa.storage_location = 'minio_iceberg',
    pgaa.path             = 'analytics/order_items',
    pgaa.format           = 'iceberg'
);

DROP TABLE IF EXISTS events_iceberg;
CREATE TABLE events_iceberg ()
USING PGAA WITH (
    pgaa.storage_location = 'minio_iceberg',
    pgaa.path             = 'analytics/events',
    pgaa.format           = 'iceberg'
);

-- Quick check
SELECT 'customers_iceberg' AS tbl, COUNT(*) FROM customers_iceberg
UNION ALL SELECT 'products_iceberg',    COUNT(*) FROM products_iceberg
UNION ALL SELECT 'orders_iceberg',      COUNT(*) FROM orders_iceberg
UNION ALL SELECT 'order_items_iceberg', COUNT(*) FROM order_items_iceberg
UNION ALL SELECT 'events_iceberg',      COUNT(*) FROM events_iceberg
ORDER BY 2 DESC;


-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 3: Native WHPG Tables (AO Columnar + ZSTD)                          ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

CREATE SCHEMA IF NOT EXISTS demo;

-- Customers
DROP TABLE IF EXISTS demo.customers CASCADE;
CREATE TABLE demo.customers (
    customer_id     BIGINT,
    email           TEXT,
    first_name      TEXT,
    last_name       TEXT,
    country         TEXT,
    city            TEXT,
    signup_date     DATE,
    is_active       BOOLEAN,
    lifetime_value  NUMERIC(38,2)
) WITH (appendonly=true, orientation=column, compresstype=zstd)
DISTRIBUTED BY (customer_id);
INSERT INTO demo.customers SELECT * FROM customers_iceberg;
ANALYZE demo.customers;

-- Products
DROP TABLE IF EXISTS demo.products CASCADE;
CREATE TABLE demo.products (
    product_id      BIGINT,
    sku             TEXT,
    name            TEXT,
    category        TEXT,
    subcategory     TEXT,
    price           NUMERIC(38,2),
    cost            NUMERIC(38,2),
    stock_quantity  BIGINT,
    is_available    BOOLEAN
) WITH (appendonly=true, orientation=column, compresstype=zstd)
DISTRIBUTED BY (product_id);
INSERT INTO demo.products SELECT * FROM products_iceberg;
ANALYZE demo.products;

-- Orders
DROP TABLE IF EXISTS demo.orders CASCADE;
CREATE TABLE demo.orders (
    order_id        BIGINT,
    customer_id     BIGINT,
    order_date      DATE,
    order_timestamp TIMESTAMP,
    status          TEXT,
    shipping_country TEXT,
    shipping_city   TEXT,
    total_amount    NUMERIC(38,2),
    discount_amount NUMERIC(38,2)
) WITH (appendonly=true, orientation=column, compresstype=zstd)
DISTRIBUTED BY (order_id);
INSERT INTO demo.orders SELECT * FROM orders_iceberg;
ANALYZE demo.orders;

-- Order Items
DROP TABLE IF EXISTS demo.order_items CASCADE;
CREATE TABLE demo.order_items (
    item_id         BIGINT,
    order_id        BIGINT,
    product_id      BIGINT,
    quantity        BIGINT,
    unit_price      NUMERIC(38,2),
    line_total      NUMERIC(38,2)
) WITH (appendonly=true, orientation=column, compresstype=zstd)
DISTRIBUTED BY (item_id);
INSERT INTO demo.order_items SELECT * FROM order_items_iceberg;
ANALYZE demo.order_items;

-- Events
DROP TABLE IF EXISTS demo.events CASCADE;
CREATE TABLE demo.events (
    event_id        BIGINT,
    event_timestamp TIMESTAMP,
    event_date      DATE,
    customer_id     BIGINT,
    event_type      TEXT,
    page_url        TEXT,
    product_id      BIGINT,
    session_id      TEXT,
    device_type     TEXT,
    country         TEXT
) WITH (appendonly=true, orientation=column, compresstype=zstd)
DISTRIBUTED BY (event_id);
INSERT INTO demo.events SELECT * FROM events_iceberg;
ANALYZE demo.events;


-- ╔══════════════════════════════════════════════════════════════════════════════╗
-- ║  STEP 4: Verify Row Counts                                                 ║
-- ╚══════════════════════════════════════════════════════════════════════════════╝

DO $$
DECLARE r RECORD;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '╔══════════════════════════════════════════════════════════════╗';
    RAISE NOTICE '║  PGAA Lab 2 — Setup Complete                               ║';
    RAISE NOTICE '╠══════════════════════════════════════════════════════════════╣';
    FOR r IN
        SELECT 'customers'   AS tbl,
               (SELECT COUNT(*) FROM customers_iceberg)  AS ice,
               (SELECT COUNT(*) FROM demo.customers)     AS nat
        UNION ALL SELECT 'products',
               (SELECT COUNT(*) FROM products_iceberg),
               (SELECT COUNT(*) FROM demo.products)
        UNION ALL SELECT 'orders',
               (SELECT COUNT(*) FROM orders_iceberg),
               (SELECT COUNT(*) FROM demo.orders)
        UNION ALL SELECT 'order_items',
               (SELECT COUNT(*) FROM order_items_iceberg),
               (SELECT COUNT(*) FROM demo.order_items)
        UNION ALL SELECT 'events',
               (SELECT COUNT(*) FROM events_iceberg),
               (SELECT COUNT(*) FROM demo.events)
        ORDER BY 2 DESC
    LOOP
        RAISE NOTICE '║  %  iceberg=% native=% %',
            RPAD(r.tbl, 14),
            LPAD(r.ice::text, 7),
            LPAD(r.nat::text, 7),
            CASE WHEN r.ice = r.nat THEN '✓' ELSE '✗' END;
    END LOOP;
    RAISE NOTICE '╚══════════════════════════════════════════════════════════════╝';
    RAISE NOTICE '';
    RAISE NOTICE 'Next: python3 pgaa_dashboard_app.py  →  http://localhost:5000';
END $$;
