#!/usr/bin/env python3
"""
Setup WarehousePG with PGAA - Configure catalogs and create tables.

This script configures WarehousePG to use PGAA for analytics workloads.
It supports two modes:

1. Local catalog mode (--local-catalog):
   - Adds Lakekeeper Iceberg REST catalog
   - Creates 'demo' schema with Iceberg tables managed by catalog
   - Tables: countries, products, customers, sales

2. Delta tables mode (--delta-tables):
   - Creates storage location for public S3 bucket
   - Creates 'sample_delta_tpch_sf_1' schema with Delta/Parquet tables
   - Tables: customer, lineitem, nation, orders, part, partsupp, region, supplier

Usage:
    python3 setup_whpg.py --local-catalog
    python3 setup_whpg.py --delta-tables
    python3 setup_whpg.py --local-catalog --delta-tables
"""

import argparse
import json
import sys
from pathlib import Path

import psycopg2
import psycopg2.extras
import requests
import tomli
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


def load_config():
    """Load configuration from demo-config.toml."""
    config_path = Path(__file__).parent.parent / "demo-config.toml"
    if not config_path.exists():
        console.print(f"[red]Error: Configuration file not found: {config_path}[/red]")
        sys.exit(1)

    with open(config_path, "rb") as f:
        return tomli.load(f)


def connect_whpg(config):
    """Connect to WarehousePG."""
    whpg_config = config.get("warehousepg", {})
    return psycopg2.connect(
        host=whpg_config.get("host", "localhost"),
        port=whpg_config.get("port", 5432),
        database=whpg_config.get("database", "demo"),
        user=whpg_config.get("user", "gpadmin"),
        password=whpg_config.get("password", "changeme@123"),
    )


def setup_pgaa_extension(conn):
    """Ensure PGAA extension is loaded and configured."""
    with conn.cursor() as cur:
        console.print("[cyan]Setting up PGAA extension...[/cyan]")

        # Load PGAA and PGFS extensions
        cur.execute("CREATE EXTENSION IF NOT EXISTS pgaa CASCADE")
        cur.execute("CREATE EXTENSION IF NOT EXISTS pgfs CASCADE")

        # Configure PGAA settings
        cur.execute("SELECT name, setting FROM pg_settings WHERE name LIKE 'pgaa.%' ORDER BY name")
        settings = cur.fetchall()

        console.print("[green]PGAA extension loaded. Current settings:[/green]")
        for name, setting in settings:
            console.print(f"  {name} = {setting}")

    conn.commit()


def get_lakekeeper_warehouse(catalog_url, warehouse_name):
    """Fetch the warehouse ID from Lakekeeper API by name."""
    # Extract base URL (remove /catalog suffix if present)
    base_url = catalog_url.replace("/catalog", "").rstrip("/")

    try:
        console.print(f"[cyan]Querying Lakekeeper for warehouse '{warehouse_name}'...[/cyan]")

        # List warehouses from Lakekeeper management API
        response = requests.get(f"{base_url}/management/v1/warehouse", timeout=5)
        response.raise_for_status()

        warehouses = response.json().get("warehouses", [])

        if not warehouses:
            console.print("[red]Error: No warehouses found in Lakekeeper[/red]")
            return None

        # Filter by warehouse name (field is "name" not "warehouse-name")
        matching_warehouses = [w for w in warehouses if w.get("name") == warehouse_name]

        if not matching_warehouses:
            console.print(f"[red]Error: No warehouse found with name '{warehouse_name}'[/red]")
            console.print(
                f"[yellow]Available warehouses: {', '.join([w.get('name', 'unknown') for w in warehouses])}[/yellow]"
            )
            return None

        warehouse = matching_warehouses[0]
        warehouse_id = warehouse.get("id")

        console.print(f"[green]✓ Found warehouse: {warehouse_name} ({warehouse_id})[/green]")
        return warehouse_id

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error querying Lakekeeper: {e}[/red]")
        return None


def add_lakekeeper_catalog(conn, config):
    """Add Lakekeeper Iceberg REST catalog."""
    catalog_config = config.get("catalog", {})
    catalog_name = catalog_config.get("name", "demo_catalog")
    catalog_url = catalog_config.get("url", "http://lakekeeper:8181/catalog")
    warehouse_name = catalog_config.get("warehouse_name", "demo-warehouse")

    # Get warehouse ID dynamically from Lakekeeper
    warehouse_id = get_lakekeeper_warehouse(catalog_url, warehouse_name)

    if not warehouse_id:
        console.print("[red]Error: Could not retrieve warehouse_id from Lakekeeper[/red]")
        return False

    with conn.cursor() as cur:
        console.print(f"[cyan]Adding Lakekeeper catalog '{catalog_name}'...[/cyan]")

        # Check if catalog already exists
        cur.execute("SELECT name FROM pgaa.list_catalogs() WHERE name = %s", (catalog_name,))
        if cur.fetchone():
            console.print(f"[yellow]Catalog '{catalog_name}' already exists, skipping[/yellow]")
            return True

        # Add catalog
        catalog_options = json.dumps(
            {
                "url": catalog_url,
                "warehouse": warehouse_id,
            }
        )

        cur.execute(
            "SELECT pgaa.add_catalog(%s, %s, %s)", (catalog_name, "iceberg-rest", catalog_options)
        )

        console.print(f"[green]✓ Catalog '{catalog_name}' added successfully[/green]")

    conn.commit()
    return True


def setup_local_catalog_tables(conn, config):
    """Create demo schema with Iceberg tables managed by local catalog."""
    catalog_config = config.get("catalog", {})
    catalog_name = catalog_config.get("name", "demo_catalog")

    with conn.cursor() as cur:
        console.print("[cyan]Setting up local catalog tables in 'demo' schema...[/cyan]")

        # Create schema
        cur.execute("CREATE SCHEMA IF NOT EXISTS demo")
        console.print("[green]✓ Schema 'demo' created[/green]")

        # Define tables to create
        tables = [
            "countries",
            "products",
            "customers",
            "sales",
        ]

        for table_name in tables:
            # Check if table exists
            cur.execute(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = 'demo' AND table_name = %s",
                (table_name,),
            )
            if cur.fetchone():
                console.print(
                    f"[yellow]Table 'demo.{table_name}' already exists, skipping[/yellow]"
                )
                continue

            # Create table using PGAA
            create_sql = f"""
                CREATE TABLE demo.{table_name} ()
                USING PGAA
                WITH (
                    pgaa.managed_by = '{catalog_name}',
                    pgaa.catalog_namespace = 'demo',
                    pgaa.catalog_table = '{table_name}',
                    pgaa.format = 'iceberg'
                )
            """
            cur.execute(create_sql)
            console.print(f"[green]✓ Table 'demo.{table_name}' created[/green]")

    conn.commit()
    console.print("[green]✓ Local catalog tables setup complete[/green]")


def setup_delta_tables(conn):
    """Create sample_delta_tpch_sf_1 schema with Delta/Parquet tables from public S3."""
    with conn.cursor() as cur:
        console.print("[cyan]Setting up Delta tables from public S3 bucket...[/cyan]")

        # Create storage location
        storage_name = "biganimal-sample-data"
        storage_url = "s3://beacon-analytics-demo-data-eu-west-1-prod"
        storage_options = json.dumps({"aws_skip_signature": "true"})

        # Check if storage location exists
        cur.execute(
            "SELECT name FROM pgfs.list_storage_locations() WHERE name = %s",
            (storage_name,),
        )
        if not cur.fetchone():
            cur.execute(
                "SELECT pgfs.create_storage_location(%s, %s, %s)",
                (storage_name, storage_url, storage_options),
            )
            console.print(f"[green]✓ Storage location '{storage_name}' created[/green]")
        else:
            console.print(
                f"[yellow]Storage location '{storage_name}' already exists, skipping[/yellow]"
            )

        # Create schema
        cur.execute("CREATE SCHEMA IF NOT EXISTS sample_delta_tpch_sf_1")
        console.print("[green]✓ Schema 'sample_delta_tpch_sf_1' created[/green]")

        # Define tables to create with their paths
        tables = {
            "customer": "tpch_sf_1/customer",
            "lineitem": "tpch_sf_1/lineitem",
            "nation": "tpch_sf_1/nation",
            "orders": "tpch_sf_1/orders",
            "part": "tpch_sf_1/part",
            "partsupp": "tpch_sf_1/partsupp",
            "region": "tpch_sf_1/region",
            "supplier": "tpch_sf_1/supplier",
        }

        for table_name, table_path in tables.items():
            # Check if table exists
            cur.execute(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = 'sample_delta_tpch_sf_1' AND table_name = %s",
                (table_name,),
            )
            if cur.fetchone():
                console.print(
                    f"[yellow]Table 'sample_delta_tpch_sf_1.{table_name}' already exists, skipping[/yellow]"
                )
                continue

            # Create table using PGAA
            create_sql = f"""
                CREATE TABLE sample_delta_tpch_sf_1.{table_name} ()
                USING PGAA
                WITH (
                    pgaa.storage_location = '{storage_name}',
                    pgaa.path = '{table_path}'
                )
            """
            cur.execute(create_sql)
            console.print(f"[green]✓ Table 'sample_delta_tpch_sf_1.{table_name}' created[/green]")

    conn.commit()
    console.print("[green]✓ Delta tables setup complete[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="Setup WarehousePG with PGAA catalogs and tables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--local-catalog",
        action="store_true",
        help="Setup local Lakekeeper catalog with demo schema tables",
    )
    parser.add_argument(
        "--delta-tables",
        action="store_true",
        help="Setup Delta tables from public S3 bucket",
    )

    args = parser.parse_args()

    if not args.local_catalog and not args.delta_tables:
        console.print("[red]Error: Must specify at least one setup mode[/red]")
        parser.print_help()
        sys.exit(1)

    # Load config
    config = load_config()

    # Connect to WarehousePG
    console.print("[cyan]Connecting to WarehousePG...[/cyan]")
    try:
        conn = connect_whpg(config)
        console.print("[green]✓ Connected to WarehousePG[/green]")
    except Exception as e:
        console.print(f"[red]Error connecting to WarehousePG: {e}[/red]")
        sys.exit(1)

    try:
        # Setup PGAA extension
        setup_pgaa_extension(conn)

        # Setup local catalog if requested
        if args.local_catalog:
            if add_lakekeeper_catalog(conn, config):
                setup_local_catalog_tables(conn, config)

        # Setup Delta tables if requested
        if args.delta_tables:
            setup_delta_tables(conn)

        console.print("\n[green bold]✓ WarehousePG setup complete![/green bold]")

    except Exception as e:
        console.print(f"\n[red bold]Error during setup: {e}[/red bold]")
        import traceback

        traceback.print_exc()
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
