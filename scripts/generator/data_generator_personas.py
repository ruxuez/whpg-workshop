#!/usr/bin/env python3
"""
NetVista × EDB WarehousePG — Persona-Based Data Generator
Lab 3: Hybrid Forensic Discovery (MADlib + pgvector)

Generates netflow_logs and syslog_events with THREE distinct behavioral personas
that create clear, discoverable patterns for MADlib K-Means clustering and
pgvector semantic search:

  1. NORMAL        — baseline traffic (bulk of the dataset)
  2. RECON         — port scanning / reconnaissance
  3. EXFILTRATION  — low destination count, massive bytes
  4. C2_BEACONING  — periodic small flows at fixed intervals

Usage:
    pip3 install faker numpy pandas tqdm
    python3 data_generator_personas.py [--scale medium]

Outputs (gzip CSV, ready for gpfdist):
    csv_data/netflow_logs.csv.gz
    csv_data/syslog_events.csv.gz
"""

import argparse
import csv
import gzip
import os
import random
import math
from datetime import datetime, timedelta
from typing import List, Tuple

try:
    import numpy as np
    from faker import Faker
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

# ── Configuration ─────────────────────────────────────────────────────────────

SCALES = {
    "small":  {"netflow": 200_000,   "syslog": 50_000},
    "medium": {"netflow": 2_000_000, "syslog": 400_000},
    "large":  {"netflow": 15_800_000,"syslog": 7_500_000},
}

NOW = datetime(2026, 4, 23, 23, 59, 59)
START = datetime(2026, 4, 1, 0, 0, 0)

# ── IP Pools per Persona ───────────────────────────────────────────────────────

# Normal IPs — drawn from internal subnets (lots of them)
NORMAL_SUBNETS = [
    ("10.20.1.", 1),     # US-EAST Customer Acme        → region 1
    ("10.20.2.", 1),     # US-EAST Customer Globex
    ("10.128.1.", 2),    # US-WEST management            → region 2
    ("172.17.1.", 3),    # EU-WEST Siemens               → region 3
    ("192.168.10.", 5),  # APAC-JP SoftBank              → region 5
    ("10.200.1.", 6),    # APAC-SG                       → region 6
    ("10.50.1.", 7),     # LATAM                         → region 7
]

# Recon IPs — small dedicated pool to make the cluster tight
RECON_IPS = [f"10.10.10.{i}" for i in range(10, 25)]          # US-East DMZ block

# Exfil IPs — very few, always talk to same external destination
EXFIL_IPS = [f"10.20.1.{i}" for i in range(200, 210)]         # Acme subnet
EXFIL_DST = "103.224.82.15"                                    # known-bad CrowdStrike IP

# C2 Beaconing IPs — moderate pool, periodic traffic
C2_IPS = [f"192.168.10.{i}" for i in range(50, 70)]           # APAC-JP SoftBank

# ── Syslog Message Templates per Persona ─────────────────────────────────────

SYSLOG_NORMAL = [
    ("sshd",      2, "Accepted publickey for svcacct from {ip} port {port}"),
    ("sshd",      6, "pam_unix(sshd:session): session opened for user admin"),
    ("kernel",    6, "eth0: renamed from veth{rand}"),
    ("cron",      6, "CRON[{rand}]: (root) CMD (/usr/lib/check_mk_agent/plugins/60/network_stats)"),
    ("kubelet",   7, "Reconciler: start to reconcile pod {rand}"),
    ("haproxy",   6, "Proxy http-in started."),
    ("systemd",   6, "Started Session {rand} of user ubuntu."),
    ("ntpd",      6, "synchronized to 10.0.0.1, stratum 3"),
    ("rsyslogd",  6, "imjournal: journal files changed, reloading"),
    ("bgpd",      5, "BGP: 10.30.0.1 KEEPALIVE rcvd"),
]

SYSLOG_RECON = [
    ("kernel",    1, "nf_conntrack: table full, dropping packet from {ip}"),
    ("firewalld", 2, "REJECT TCP from {ip}:{port} to {dst}:{dport} (Connection refused)"),
    ("sshd",      0, "Connection from {ip} closed [preauth] — ICMP Unreachable"),
    ("firewalld", 3, "Port scan detected: {ip} hit {rand} unique ports in 60s"),
    ("snort",     2, "SCAN SYN FIN detected from {ip} — possible nmap"),
    ("kernel",    1, "TCP: SYN retransmission flood from {ip}"),
    ("sshd",      3, "Invalid user admin from {ip} port {port}"),
    ("iptables",  3, "REJECT IN=eth0 SRC={ip} DST={dst} PROTO=TCP — RST flag"),
    ("firewalld", 2, "Connection reset by peer: {ip} — likely port probe"),
    ("snort",     2, "ICMP Unreachable from {ip}: host unreachable (TTL exceeded)"),
]

SYSLOG_EXFIL = [
    ("rsync",     1, "Large outbound transfer: {ip} → {dst}: {size}MB in {dur}s"),
    ("openvpn",   0, "Encrypted tunnel established: {ip} → {dst}:443 (TLS 1.3)"),
    ("backup-svc",1, "Archive exported: /opt/data/customer_db_full.tar.gz ({size}MB)"),
    ("audit",     0, "SYSCALL execve: process backup-manager spawned by svcacct from {ip}"),
    ("rclone",    3, "Data sync to cloud: {size}GB transferred to remote endpoint {dst}"),
    ("sshd",      3, "SFTP subsystem request: {ip} uploading /tmp/export_{rand}.zip ({size}MB)"),
    ("netfilter", 1, "ALERT: Sustained high-bandwidth flow {ip}→{dst}: {size}MB over 10min"),
    ("audit",     3, "File read: /etc/passwd by svcacct ({ip}) — possible credential harvest"),
    ("curl",      4, "POST https://{dst}/upload?token={rand} — {size}MB payload — 200 OK"),
    ("backup-svc",3, "Backup completed: customer_records_{rand}.tar encrypted and staged"),
]

SYSLOG_C2 = [
    ("cron",      6, "Heartbeat detected: agent check-in from {ip} — seq={rand}"),
    ("curl",      6, "Keep-alive received: {ip} → C2:{port} — next poll in {interval}s"),
    ("svchost",   5, "Polling remote host {dst}:{port} — last seen {rand}s ago"),
    ("beacon",    4, "C2 beacon: {ip} → {dst} jitter={jitter}ms interval={interval}s"),
    ("cron",      5, "Scheduled task: /tmp/.svc_update {rand} — (hidden process)"),
    ("systemd",   5, "Service svc_monitor.service: watchdog keepalive ping"),
    ("sshd",      5, "TCP keep-alive received: {ip}:{port} — idle time {rand}s"),
    ("beacon",    4, "DNS beacon query: {rand}.update.svc.internal — TTL 60s"),
    ("cron",      5, "Heartbeat ping: agent {rand} alive, awaiting instructions"),
    ("svchost",   4, "Polling remote host: GET /ping HTTP/1.1 — 204 No Content"),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def rand_ip(prefix: str) -> str:
    return f"{prefix}{random.randint(2, 254)}"

def rand_port() -> int:
    return random.randint(1024, 65535)

def rand_ts(start: datetime, end: datetime) -> datetime:
    delta = end - start
    return start + timedelta(seconds=random.random() * delta.total_seconds())

def periodic_ts(base: datetime, interval_s: int, jitter_s: int = 2) -> datetime:
    """Returns a timestamp jittered around a periodic beacon interval."""
    return base + timedelta(seconds=random.gauss(0, jitter_s))

def fmt_ts(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")

# ── Netflow Row Builders ───────────────────────────────────────────────────────

_flow_id = 0
def next_id() -> int:
    global _flow_id
    _flow_id += 1
    return _flow_id

def make_normal_flow(ts: datetime) -> dict:
    """Regular business traffic — moderate bytes, limited ports."""
    subnet, region = random.choice(NORMAL_SUBNETS)
    src = rand_ip(subnet)
    dst_prefix, _ = random.choice(NORMAL_SUBNETS)
    dst = rand_ip(dst_prefix)
    proto = random.choice([6, 6, 6, 17])  # mostly TCP
    port = random.choice([80, 443, 8080, 22, 3306, 5432, 6379, 9200])
    byt = int(random.lognormvariate(math.log(50_000), 1.5))
    return {
        "id": next_id(), "ts": fmt_ts(ts), "src_ip": src, "dst_ip": dst,
        "src_port": rand_port(), "dst_port": port, "protocol": proto,
        "bytes": max(64, byt), "packets": max(1, byt // 1400),
        "tcp_flags": 24, "flow_duration": random.randint(100, 30_000),
        "src_as": "", "dst_as": "", "input_if": "", "output_if": "",
        "sampler_id": "", "region_id": region,
    }

def make_recon_flow(ts: datetime) -> dict:
    """Recon/scanner: many unique dst_ports, tiny bytes, rapid flows."""
    src = random.choice(RECON_IPS)
    dst = rand_ip(random.choice(NORMAL_SUBNETS)[0])
    # Spread across ALL port ranges to get high unique_ports
    dst_port = random.randint(1, 65535)
    byt = random.randint(40, 120)  # tiny — just SYN/RST
    return {
        "id": next_id(), "ts": fmt_ts(ts), "src_ip": src, "dst_ip": dst,
        "src_port": rand_port(), "dst_port": dst_port, "protocol": 6,
        "bytes": byt, "packets": 1,
        "tcp_flags": 2,  # SYN only
        "flow_duration": random.randint(1, 50),
        "src_as": "", "dst_as": "", "input_if": "", "output_if": "",
        "sampler_id": "", "region_id": 1,
    }

def make_exfil_flow(ts: datetime) -> dict:
    """Exfiltration: very few unique dsts, MASSIVE bytes per flow."""
    src = random.choice(EXFIL_IPS)
    # Always talking to the same C2/exfil destination (low unique_dsts)
    dst = EXFIL_DST
    # Huge payload: 10MB – 500MB per flow
    byt = random.randint(10_000_000, 500_000_000)
    return {
        "id": next_id(), "ts": fmt_ts(ts), "src_ip": src, "dst_ip": dst,
        "src_port": rand_port(), "dst_port": 443, "protocol": 6,
        "bytes": byt, "packets": byt // 1400,
        "tcp_flags": 24,
        "flow_duration": random.randint(60_000, 600_000),
        "src_as": "", "dst_as": "", "input_if": "", "output_if": "",
        "sampler_id": "", "region_id": 1,
    }

def make_c2_flow(ts: datetime, interval_s: int = 300) -> dict:
    """C2 Beaconing: very regular small flows, almost identical byte counts."""
    src = random.choice(C2_IPS)
    dst = random.choice(["185.220.101.34", "91.219.236.222"])  # known C2 from threat_intel
    # Consistent small payload with very low variance (the "heartbeat")
    byt = int(random.gauss(512, 30))  # ~512 bytes, tight std-dev
    byt = max(256, byt)
    return {
        "id": next_id(), "ts": fmt_ts(ts), "src_ip": src, "dst_ip": dst,
        "src_port": rand_port(), "dst_port": random.choice([80, 443, 8080]),
        "protocol": 6,
        "bytes": byt, "packets": max(1, byt // 512),
        "tcp_flags": 24,
        "flow_duration": random.randint(200, 800),
        "src_as": "", "dst_as": "", "input_if": "", "output_if": "",
        "sampler_id": "", "region_id": 5,
    }

def make_inbound_attack(ts):
    """Simulates a hit from a known-bad Source IP in the threat intel feed."""
    return {
        "id": next_id(), 
        "ts": fmt_ts(ts), 
        "src_ip": "185.220.101.34",  # Match AlienVault OTX in your seed
        "dst_ip": rand_ip("10.20.1."), # Hitting an internal Acme IP
        "src_port": rand_port(), 
        "dst_port": 22, 
        "protocol": 6,
        "bytes": 5000, 
        "packets": 10,
        "tcp_flags": 2, # SYN
        "flow_duration": 100,
        "src_as": "", "dst_as": "", "input_if": "", "output_if": "",
        "sampler_id": "", "region_id": 1
    }

# ── Syslog Row Builders ────────────────────────────────────────────────────────

_evt_id = 0
def next_evt() -> int:
    global _evt_id
    _evt_id += 1
    return _evt_id

def render_msg(template: str, ip: str) -> str:
    return template.format(
        ip=ip,
        dst=EXFIL_DST,
        port=rand_port(),
        dport=random.choice([80, 443, 22, 8080]),
        rand=random.randint(1000, 9999),
        size=random.randint(50, 2048),
        dur=random.randint(5, 300),
        interval=random.choice([30, 60, 120, 300]),
        jitter=random.randint(10, 200),
    )

def hostname_for_ip(ip: str) -> str:
    if ip.startswith("10.10"):   return f"ids-us-e-{random.randint(1,4):02d}"
    if ip.startswith("10.20.1"): return f"srv-acme-{random.randint(1,8):02d}"
    if ip.startswith("10.20.2"): return f"srv-globex-{random.randint(1,8):02d}"
    if ip.startswith("192.168"): return f"host-jp-{random.randint(1,20):02d}"
    if ip.startswith("172.17"):  return f"srv-eu-{random.randint(1,6):02d}"
    return f"host-{ip.replace('.', '-')}"

def make_syslog(ts: datetime, templates: list, ip: str, region: int) -> dict:
    prog, sev, tmpl = random.choice(templates)
    return {
        "id": next_evt(), "ts": fmt_ts(ts),
        "src_ip": ip,
        "hostname": hostname_for_ip(ip),
        "facility": 1,
        "severity": sev,
        "program": prog,
        "message": render_msg(tmpl, ip),
        "region_id": region,
    }

# ── Writers ───────────────────────────────────────────────────────────────────

NETFLOW_COLS = ["id","ts","src_ip","dst_ip","src_port","dst_port","protocol",
                "bytes","packets","tcp_flags","flow_duration","src_as","dst_as",
                "input_if","output_if","sampler_id","region_id"]

SYSLOG_COLS = ["id","ts","src_ip","hostname","facility","severity","program","message","region_id"]

SYSLOG_INBOUND = [
    ("sshd", 3, "Failed password for root from {ip} port {port} ssh2"),
    ("snort", 2, "ET EXPLOIT Possible SSH Brute Force from {ip}"),
]

def write_rows(rows: list, path: str, cols: list):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with gzip.open(path, "wt", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"  ✓ Wrote {len(rows):,} rows → {path}")

# ── Main ───────────────────────────────────────────────────────────────────────

def generate(scale: str = "medium"):
    cfg = SCALES[scale]
    n_net  = cfg["netflow"]
    n_sys  = cfg["syslog"]

    print(f"\n{'='*60}")
    print(f"  NetVista Persona-Based Data Generator")
    print(f"  Scale: {scale}  |  NetFlow: {n_net:,}  |  Syslog: {n_sys:,}")
    print(f"{'='*60}\n")

    # ── Mix ratios ──────────────────────────────────────────────────────────
    # Deliberately imbalanced so MADlib finds a large "normal" cluster
    # and small tight "threat" clusters.
    #
    #  Normal      70%  → cluster 0 (large, baseline)
    #  Recon       12%  → cluster 1 (many ports, tiny bytes)
    #  Exfil        8%  → cluster 2 (few dsts, huge bytes)
    #  C2          10%  → cluster 3 (fixed bytes, periodic)

    n_normal = int(n_net * 0.70)
    n_recon  = int(n_net * 0.12)
    n_exfil  = int(n_net * 0.08)
    n_c2     = n_net - n_normal - n_recon - n_exfil
    n_inbound = int(n_net * 0.02) # Add 2% inbound hits
    n_normal -= n_inbound        # Subtract from normal to keep total stable

    print("Generating NetFlow rows…")
    netflow_rows = []

    # Normal
    print(f"  Normal      : {n_normal:,} rows")
    for _ in range(n_normal):
        ts = rand_ts(START, NOW)
        netflow_rows.append(make_normal_flow(ts))

    # Recon — cluster activity in 4-hour bursts
    print(f"  Recon       : {n_recon:,} rows")
    recon_start = NOW - timedelta(hours=6)
    recon_end   = NOW - timedelta(hours=2)
    for _ in range(n_recon):
        ts = rand_ts(recon_start, recon_end)
        netflow_rows.append(make_recon_flow(ts))

    # Exfil — concentrated in 3-hour window
    print(f"  Exfiltration: {n_exfil:,} rows")
    exfil_start = NOW - timedelta(hours=5)
    exfil_end   = NOW - timedelta(hours=2)
    for _ in range(n_exfil):
        ts = rand_ts(exfil_start, exfil_end)
        netflow_rows.append(make_exfil_flow(ts))

    # C2 Beaconing — every 5 minutes (300s), per-IP, over last 12h
    print(f"  C2 Beaconing: {n_c2:,} rows")
    interval_s = 300
    c2_start = NOW - timedelta(hours=12)
    c2_rows_per_ip = n_c2 // len(C2_IPS)
    for ip in C2_IPS:
        base = c2_start
        for _ in range(c2_rows_per_ip):
            base = base + timedelta(seconds=interval_s + random.gauss(0, 3))
            if base > NOW:
                break
            netflow_rows.append(make_c2_flow(base, interval_s))

    print(f"  Inbound Threats: {n_inbound:,} rows")
    for _ in range(n_inbound):
        ts = rand_ts(START, NOW)
        netflow_rows.append(make_inbound_attack(ts))

    random.shuffle(netflow_rows)

    # ── Syslog ────────────────────────────────────────────────────────────
    s_normal = int(n_sys * 0.60)
    s_recon  = int(n_sys * 0.18)
    s_exfil  = int(n_sys * 0.12)
    s_c2     = n_sys - s_normal - s_recon - s_exfil

    print(f"\nGenerating Syslog rows…")
    syslog_rows = []

    print(f"  Normal      : {s_normal:,} rows")
    for _ in range(s_normal):
        subnet, region = random.choice(NORMAL_SUBNETS)
        ip = rand_ip(subnet)
        ts = rand_ts(START, NOW)
        syslog_rows.append(make_syslog(ts, SYSLOG_NORMAL, ip, region))

    print(f"  Recon       : {s_recon:,} rows")
    for _ in range(s_recon):
        ip = random.choice(RECON_IPS)
        ts = rand_ts(recon_start, recon_end)
        syslog_rows.append(make_syslog(ts, SYSLOG_RECON, ip, 1))

    print(f"  Exfiltration: {s_exfil:,} rows")
    for _ in range(s_exfil):
        ip = random.choice(EXFIL_IPS)
        ts = rand_ts(exfil_start, exfil_end)
        syslog_rows.append(make_syslog(ts, SYSLOG_EXFIL, ip, 1))

    print(f"  C2 Beaconing: {s_c2:,} rows")
    for _ in range(s_c2):
        ip = random.choice(C2_IPS)
        ts = rand_ts(c2_start, NOW)
        syslog_rows.append(make_syslog(ts, SYSLOG_C2, ip, 5))

    for _ in range(int(n_sys * 0.05)):
        ts = rand_ts(START, NOW)
        syslog_rows.append(make_syslog(ts, SYSLOG_INBOUND, "185.220.101.34", 1))

    random.shuffle(syslog_rows)

    # ── Write ──────────────────────────────────────────────────────────────
    print("\nWriting CSV files…")
    os.makedirs("csv_data", exist_ok=True)
    write_rows(netflow_rows, "csv_data/netflow_logs.csv.gz",   NETFLOW_COLS)
    write_rows(syslog_rows,  "csv_data/syslog_events.csv.gz",  SYSLOG_COLS)

    print(f"\n{'='*60}")
    print("  DONE — Persona statistics:")
    print(f"  {'Persona':<18} {'NetFlow':>10}  {'Syslog':>10}")
    print(f"  {'-'*42}")
    print(f"  {'Normal':<18} {n_normal:>10,}  {s_normal:>10,}")
    print(f"  {'Recon (scanner)':<18} {n_recon:>10,}  {s_recon:>10,}")
    print(f"  {'Exfiltration':<18} {n_exfil:>10,}  {s_exfil:>10,}")
    print(f"  {'C2 Beaconing':<18} {n_c2:>10,}  {s_c2:>10,}")
    print(f"  {'-'*42}")
    print(f"  {'TOTAL':<18} {n_net:>10,}  {n_sys:>10,}")
    print(f"{'='*60}\n")
    print("Next step:")
    print("  gpfdist -d ./csv_data -p 8081 &")
    print("  psql -f 01_schema.sql && psql -f 02_seed_reference.sql")
    print("  psql -f 03_load_external.sql && psql -f 06_lab3_ai_analytics.sql")
    print("  psql -f 07_kmeans_fallback.sql")
    print("  python3 app3.py\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetVista persona-based data generator")
    parser.add_argument("--scale", choices=["small", "medium", "large"],
                        default="medium", help="Dataset size (default: medium)")
    args = parser.parse_args()
    generate(args.scale)
