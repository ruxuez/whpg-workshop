#!/usr/bin/env python3
"""
NetVista × WarehousePG — CSV Data Generator for External Table Loading

Generates CSV files for all 6 major fact tables that can be served via gpfdist
and loaded through WHPG READABLE EXTERNAL TABLEs.

Usage:
    python3 data_generator.py [--output-dir /path/to/csv] [--scale 1]

Scale factor:
    1 (default) → ~100M rows  (production demo)
    0.1         → ~10M rows   (quick test)
    0.01        → ~1M rows    (dev / smoke test)

Output:
    <output-dir>/netflow_logs.csv       (~33M rows at scale=1)
    <output-dir>/dns_logs.csv           (~25M rows)
    <output-dir>/firewall_logs.csv      (~22.5M rows)
    <output-dir>/syslog_events.csv      (~15M rows)
    <output-dir>/bgp_events.csv         (~1.5M rows)
    <output-dir>/network_metrics.csv    (~150K rows)

Then:
    gpfdist -d <output-dir> -p 8081 &
    psql -f 03_load_external.sql
"""

import argparse
import csv
import math
import os
import random
import sys
from datetime import datetime, timedelta

# ── Configuration ────────────────────────────────────────────────────────────
INTERNAL_PREFIXES = [
    "10.10", "10.20", "10.21", "10.22", "10.128", "10.129",
    "172.16", "172.17", "172.20", "172.21",
    "192.168", "10.200", "10.201", "10.50", "10.51",
]

DST_PREFIXES = [
    "10.10", "10.20", "10.128", "172.16", "172.17",
    "192.168", "10.200", "10.50", "10.129", "172.20",
]

THREAT_IPS = [
    "185.220.101.34", "91.219.236.222", "45.155.205.99",
    "23.129.64.130", "104.244.76.13", "198.98.56.78",
    "5.188.86.172", "209.141.33.21", "103.224.82.15",
    "58.218.198.100", "222.186.42.7", "218.92.0.31",
]

DST_PORTS = [
    80, 443, 443, 443, 22, 53, 53, 8080, 3306, 5432, 8443, 25, 110,
    143, 993, 389, 636, 3389, 8888, 9200, 9300, 5601, 6379, 27017,
]

DNS_INTERNAL = ["api", "portal", "mail", "vpn", "sso", "cdn", "static", "ws", "auth", "billing"]
DNS_EXTERNAL = ["google.com", "youtube.com", "facebook.com", "microsoft.com", "apple.com",
                "amazon.com", "twitter.com", "linkedin.com", "github.com", "stackoverflow.com"]
DNS_CLOUD = ["s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com",
             "cdn.cloudflare.com", "fastly.net"]
DNS_SAAS = ["zoom.us", "slack.com", "teams.microsoft.com", "webex.com", "office365.com",
            "salesforce.com", "servicenow.com", "jira.atlassian.com"]
DNS_BAD = ["evil.com", "malware.xyz", "exfil-data.evil.cc", "c2-callback.evil.com",
           "drop.evil.net", "beacon.xyz", "payload.evil.org"]
DNS_TYPES = ["A", "A", "A", "A", "AAAA", "AAAA", "MX", "MX", "CNAME", "TXT", "PTR"]
DNS_RCODES = ["NOERROR", "NOERROR", "NOERROR", "NOERROR", "NOERROR",
              "NOERROR", "NOERROR", "NXDOMAIN", "NXDOMAIN", "SERVFAIL"]

FW_ACTIONS = ["ALLOW", "ALLOW", "ALLOW", "ALLOW", "ALLOW", "ALLOW", "DENY", "DENY", "DROP", "REJECT"]
FW_ZONES_SRC = ["external", "internal", "dmz", "mgmt", "transit"]
FW_ZONES_DST = ["internal", "external", "dmz", "mgmt", "transit"]

SYSLOG_HOSTNAMES = [
    "us-east-rtr-01", "us-east-fw-01", "us-east-sw-01", "us-west-rtr-01",
    "us-west-fw-01", "eu-west-rtr-01", "eu-west-fw-01", "eu-east-rtr-01",
    "jp-rtr-01", "jp-fw-01", "sg-rtr-01", "sg-fw-01", "br-rtr-01",
]
SYSLOG_PROGRAMS = [
    "sshd", "pam_unix", "sudo", "kernel", "bgpd", "ospfd", "snmpd",
    "nginx", "haproxy", "docker", "kubelet", "iptables", "postfix",
    "named", "systemd", "conntrackd",
]

BGP_ORIGINS = ["IGP", "IGP", "IGP", "EGP", "INCOMPLETE"]

NOW = datetime.now()


def rand_ip(prefixes):
    p = random.choice(prefixes)
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"


def rand_ext_ip():
    return f"{random.randint(1,222)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def rand_ts(days_back=7):
    return (NOW - timedelta(seconds=random.random() * days_back * 86400)).strftime("%Y-%m-%d %H:%M:%S.%f")[:23]


def progress(label, current, total):
    if current % max(1, total // 20) == 0 or current == total:
        pct = current * 100 // total
        print(f"\r  {label}: {pct:3d}% ({current:,}/{total:,})", end="", flush=True)
    if current == total:
        print()


# ── Generators ───────────────────────────────────────────────────────────────

def gen_netflow(writer, count):
    """Generate netflow_logs rows."""
    # Base traffic
    base = int(count * 0.947)  # ~30M of 31.68M
    ddos = int(count * 0.047)  # ~1.5M
    scan = int(count * 0.005)  # ~150K
    exfil = count - base - ddos - scan  # ~30K

    row_num = 0
    total = count

    # Base
    for i in range(1, base + 1):
        src = random.choice(THREAT_IPS) if random.random() < 0.15 else rand_ip(INTERNAL_PREFIXES)
        dst = rand_ip(DST_PREFIXES) if random.random() < 0.6 else rand_ext_ip()
        proto = 6 if random.random() < 0.70 else (17 if random.random() < 0.83 else 1)
        byt = max(64, int(math.exp(random.random() * 7.5 + 5)))
        pkt = max(1, int(math.exp(random.random() * 4.5 + 1.5)))
        flags = random.choice([2, 2, 18, 16, 16, 16, 17, 24, 24, 25]) if random.random() < 0.7 else ""
        dur = max(1, int(math.exp(random.random() * 6 + 2)))
        writer.writerow([rand_ts(), src, dst, random.randint(1024, 65534), random.choice(DST_PORTS),
                         proto, byt, pkt, flags, dur, "", "", "", "", "", random.randint(1, 7)])
        row_num += 1
        progress("netflow (base)", row_num, total)

    # DDoS
    ddos_start = NOW - timedelta(hours=18)
    for i in range(ddos):
        ts = (ddos_start + timedelta(seconds=random.random() * 7200)).strftime("%Y-%m-%d %H:%M:%S.%f")[:23]
        src = f"{random.choice([31,45,62,77,89,103,118,141,156,178,185,191,203,211,223])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        dst = random.choice(["10.20.1.100", "10.20.1.101", "10.20.1.102"])
        writer.writerow([ts, src, dst, random.randint(1024, 65534), 80, 6,
                         random.randint(40, 120), 1, 2, 0, "", "", "", "", "", 1])
        row_num += 1
        progress("netflow (ddos)", row_num, total)

    # Port scan
    scan_start = NOW - timedelta(hours=6)
    scanners = ["45.155.205.99", "198.98.56.78", "222.186.42.7"]
    for i in range(scan):
        ts = (scan_start + timedelta(milliseconds=i * 15)).strftime("%Y-%m-%d %H:%M:%S.%f")[:23]
        src = scanners[i % 3]
        dst = f"10.10.1.{1 + (i % 254)}"
        writer.writerow([ts, src, dst, random.randint(40000, 65000), 1 + (i % 65535), 6,
                         44, 1, 2, 0, "", "", "", "", "", [3, 1, 2][i % 3]])
        row_num += 1
        progress("netflow (scan)", row_num, total)

    # Exfil
    for i in range(exfil):
        ts = rand_ts(3)
        src = f"10.20.1.{50 + random.randint(0, 10)}"
        dst = random.choice(["103.224.82.15", "58.218.198.100"])
        writer.writerow([ts, src, dst, random.randint(40000, 65000),
                         random.choice([443, 8443, 53, 993]), 6,
                         random.randint(1000000, 51000000), random.randint(1000, 51000),
                         24, random.randint(30000, 330000), "", "", "", "", "", 1])
        row_num += 1
        progress("netflow (exfil)", row_num, total)


def gen_dns(writer, count):
    for i in range(1, count + 1):
        client = rand_ip(DST_PREFIXES)
        r = random.random()
        if r < 0.20:
            qname = f"{random.choice(DNS_INTERNAL)}.netvista.com"
        elif r < 0.40:
            qname = random.choice(DNS_EXTERNAL)
        elif r < 0.55:
            qname = random.choice(DNS_CLOUD)
        elif r < 0.70:
            qname = random.choice(DNS_SAAS)
        elif r < 0.80:
            qname = f"host-{random.randint(1,9999)}.internal.netvista.local"
        elif r < 0.95:
            qname = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(8,20)))}.{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(3,8)))}.com"
        else:
            qname = random.choice(DNS_BAD)
        resp_ip = rand_ext_ip() if random.random() < 0.8 else ""
        writer.writerow([rand_ts(), client, qname, random.choice(DNS_TYPES),
                         random.choice(DNS_RCODES), resp_ip,
                         random.randint(50, 50000), "t" if random.random() < 0.9 else "f",
                         random.randint(1, 7)])
        progress("dns_logs", i, count)


def gen_firewall(writer, count):
    for i in range(1, count + 1):
        src = random.choice(THREAT_IPS) if random.random() < 0.12 else rand_ip(INTERNAL_PREFIXES)
        dst = rand_ip(DST_PREFIXES) if random.random() < 0.5 else rand_ext_ip()
        proto = 6 if random.random() < 0.7 else (17 if random.random() < 0.85 else 1)
        action = random.choice(FW_ACTIONS)
        byt = max(0, int(math.exp(random.random() * 7 + 4))) if action == "ALLOW" else 0
        writer.writerow([rand_ts(), src, dst, random.randint(1024, 65534), random.choice(DST_PORTS),
                         proto, action, random.randint(1, 9999), byt,
                         random.choice(FW_ZONES_SRC), random.choice(FW_ZONES_DST),
                         random.randint(1, 7)])
        progress("firewall_logs", i, count)


def gen_syslog(writer, count):
    for i in range(1, count + 1):
        src = rand_ip(INTERNAL_PREFIXES)
        hostname = random.choice(SYSLOG_HOSTNAMES) + f"-{random.randint(1,50):02d}"
        program = random.choice(SYSLOG_PROGRAMS)
        severity = random.choices([0, 1, 2, 3, 4, 5, 6, 7],
                                  weights=[1, 2, 5, 10, 15, 25, 30, 12])[0]
        # Generate realistic message based on program
        msg = _syslog_message(program, severity)
        writer.writerow([rand_ts(), src, hostname, random.randint(0, 23), severity,
                         program, msg, random.randint(1, 7)])
        progress("syslog_events", i, count)


def _syslog_message(program, severity):
    if program == "sshd":
        return random.choice([
            f"Failed password for root from {rand_ext_ip()} port {random.randint(30000,65000)} ssh2",
            f"Accepted publickey for admin from {rand_ip(INTERNAL_PREFIXES)} port {random.randint(30000,65000)} ssh2",
            f"Connection closed by {rand_ext_ip()} port {random.randint(30000,65000)} [preauth]",
            f"Invalid user {random.choice(['admin','test','oracle','postgres'])} from {rand_ext_ip()} port {random.randint(30000,65000)}",
        ])
    elif program == "kernel":
        return random.choice([
            f"possible SYN flooding on port {random.choice([80,443,8080])}. Sending cookies.",
            f"nf_conntrack: table full, dropping packet.",
            f"TCP: out of memory -- consider tuning tcp_mem",
            f"NMI watchdog: BUG: soft lockup - CPU#{random.randint(0,63)} stuck for {random.randint(22,62)}s!",
            f"OOM killer: Kill process {random.randint(1000,50000)} (java) score {random.randint(500,999)}",
        ])
    elif program == "bgpd":
        return random.choice([
            f"BGP peer {rand_ip(['172.16','172.17','172.20'])} state changed from Established to Idle",
            f"Prefix limit reached for peer {rand_ip(['172.16','172.17'])} (max: 100000)",
            f"Received UPDATE from {rand_ip(['172.16','172.17'])}: WITHDRAW {random.randint(1,222)}.0.0.0/{random.choice([16,20,24])}",
        ])
    elif program == "nginx":
        return random.choice([
            f"502 Bad Gateway upstream={rand_ip(INTERNAL_PREFIXES)}:{random.choice([8080,8443,9090])}",
            f"503 Service Unavailable upstream={rand_ip(INTERNAL_PREFIXES)}:{random.choice([8080,8443])}",
            f"504 Gateway Timeout upstream={rand_ip(INTERNAL_PREFIXES)}:8080",
        ])
    elif program == "docker":
        cid = ''.join(random.choices('0123456789abcdef', k=12))
        return f"container {cid} {random.choice(['started','stopped','killed','OOMKilled','restarting'])} (image: {random.choice(['nginx:latest','redis:7','postgres:16','node:20'])})"
    elif program == "kubelet":
        pod = f"{random.choice(['frontend','backend','worker','scheduler','api-gateway'])}-{''.join(random.choices('0123456789abcdef', k=8))}"
        return f"Pod {pod} {random.choice(['evicted due to memory pressure','failed readiness probe','CrashLoopBackOff','completed successfully'])}"
    else:
        return f"{program}: {random.choice(['connection','event','status','alert','warning'])} from {rand_ip(INTERNAL_PREFIXES)}"


def gen_bgp(writer, count):
    base = count - 2000  # reserve 2000 for flapping
    for i in range(1, base + 1):
        peer = f"172.{random.randint(16,30)}.{random.randint(0,255)}.{random.randint(1,254)}"
        mask = random.choice([16, 16, 20, 20, 22, 24, 24, 24])
        o1 = random.randint(1, 222)
        o2 = random.randint(0, 255)
        o3 = random.randint(0, 255)
        # Zero out host bits to make valid CIDR
        if mask <= 8:
            o2, o3 = 0, 0
        elif mask <= 16:
            o2 = (o2 >> (16 - mask)) << (16 - mask) if mask > 8 else 0
            o3 = 0
        elif mask <= 24:
            o3 = (o3 >> (24 - mask)) << (24 - mask) if mask > 16 else 0
        prefix_ip = f"{o1}.{o2}.{o3}.0"
        event = random.choice(["ANNOUNCE"] * 5 + ["WITHDRAW"] * 2 + ["UPDATE"] * 2)
        as_path = f"2914 {random.randint(1,65534)}"
        if random.random() < 0.6:
            as_path += f" {random.randint(1,65534)}"
        if random.random() < 0.3:
            as_path += f" {random.randint(1,65534)}"
        nh = f"172.{random.randint(16,30)}.{random.randint(0,255)}.{random.randint(1,254)}"
        origin = random.choice(BGP_ORIGINS)
        lp = random.choice([100, 100, 150, 200, 250, 300])
        med = random.randint(0, 1000)
        comm = f"2914:{random.choice([100,200,300,400,500,1000,2000,3000])} 2914:{random.choice([100,200,300,400,500,1000,2000,3000])}" if random.random() < 0.5 else ""
        writer.writerow([rand_ts(), peer, f"{prefix_ip}/{mask}", event, as_path,
                         nh, origin, lp, med, comm, random.randint(1, 7)])
        progress("bgp_events", i, count)

    # Flapping
    flap_start = NOW - timedelta(hours=12)
    for g in range(1, 2001):
        ts = (flap_start + timedelta(seconds=g * 3)).strftime("%Y-%m-%d %H:%M:%S.%f")[:23]
        event = "WITHDRAW" if g % 2 == 0 else "ANNOUNCE"
        writer.writerow([ts, "172.16.0.1", "10.20.0.0/16", event,
                         "2914 65001", "172.16.0.1", "IGP", 100, 0, "", 3])
        progress("bgp_events", base + g, count)


def gen_metrics(writer, num_customers=15, days=7):
    """Generate network_metrics — one row per customer per minute."""
    region_base = {1: 12, 2: 18, 3: 25, 4: 35, 5: 45, 6: 55, 7: 65}
    # customer_id -> (region_id, tier)
    customers = [
        (1, 1, "enterprise"), (2, 1, "enterprise"), (3, 2, "premium"),
        (4, 3, "enterprise"), (5, 4, "standard"), (6, 5, "enterprise"),
        (7, 5, "premium"), (8, 6, "enterprise"), (9, 7, "premium"),
        (10, 5, "enterprise"), (11, 1, "enterprise"), (12, 3, "enterprise"),
        (13, 7, "standard"), (14, 2, "enterprise"), (15, 3, "enterprise"),
    ]
    minutes = days * 24 * 60
    total = len(customers) * minutes
    count = 0
    for cid, rid, tier in customers:
        base_lat = region_base.get(rid, 30)
        tier_adj = -5 if tier == "enterprise" else (-2 if tier == "premium" else 0)
        for m in range(minutes):
            ts = (NOW - timedelta(minutes=minutes - m)).strftime("%Y-%m-%d %H:%M:%S")
            probe = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            lat = round(base_lat + random.random() * 15 + tier_adj +
                        (50 + random.random() * 150 if random.random() < 0.03 else 0), 2)
            jit = round(random.random() * 6 + 0.5 + (random.random() * 25 if random.random() < 0.05 else 0), 2)
            loss = round(random.random() * 0.08 if random.random() < 0.82 else
                         (random.random() * 0.3 if random.random() < 0.55 else
                          (random.random() * 1.5 if random.random() < 0.7 else random.random() * 5.0)), 2)
            tp = round(random.random() * 900 + 100, 2)
            mos = round(max(1.0, min(5.0, 4.5 - lat * 0.02 - jit * 0.04 - loss * 0.5)), 1)
            writer.writerow([ts, cid, rid, probe, lat, jit, loss, tp, mos])
            count += 1
            progress("network_metrics", count, total)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="NetVista CSV Data Generator")
    parser.add_argument("--output-dir", default="./csv_data", help="Output directory for CSV files")
    parser.add_argument("--scale", type=float, default=1.0, help="Scale factor (1.0 = ~100M rows)")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    s = args.scale

    targets = {
        "netflow_logs":    int(31680000 * s),
        "dns_logs":        int(25000000 * s),
        "firewall_logs":   int(22500000 * s),
        "syslog_events":   int(15000000 * s),
        "bgp_events":      int(1502000 * s),
        "network_metrics": 0,  # special: driven by customer count × days
    }

    print(f"╔═══════════════════════════════════════════════════════╗")
    print(f"║  NetVista CSV Data Generator  (scale={s})            ║")
    print(f"║  Output: {args.output_dir:<44s} ║")
    print(f"╠═══════════════════════════════════════════════════════╣")
    for t, c in targets.items():
        if t == "network_metrics":
            c = 15 * 7 * 24 * 60  # 15 customers × 7 days × 1440 min
        print(f"║  {t:<22s} : {c:>12,} rows          ║")
    print(f"╚═══════════════════════════════════════════════════════╝")
    print()

    generators = [
        ("netflow_logs", ["ts", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                          "bytes", "packets", "tcp_flags", "flow_duration",
                          "src_as", "dst_as", "input_if", "output_if", "sampler_id", "region_id"],
         lambda w, n: gen_netflow(w, n), targets["netflow_logs"]),
        ("dns_logs", ["ts", "client_ip", "query_name", "query_type", "response_code",
                      "response_ip", "response_time", "is_recursive", "region_id"],
         lambda w, n: gen_dns(w, n), targets["dns_logs"]),
        ("firewall_logs", ["ts", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                           "action", "rule_id", "bytes", "zone_src", "zone_dst", "region_id"],
         lambda w, n: gen_firewall(w, n), targets["firewall_logs"]),
        ("syslog_events", ["ts", "src_ip", "hostname", "facility", "severity",
                           "program", "message", "region_id"],
         lambda w, n: gen_syslog(w, n), targets["syslog_events"]),
        ("bgp_events", ["ts", "peer_ip", "prefix", "event_type", "as_path",
                        "next_hop", "origin", "local_pref", "med", "community", "region_id"],
         lambda w, n: gen_bgp(w, n), targets["bgp_events"]),
        ("network_metrics", ["ts", "customer_id", "region_id", "probe_ip",
                             "latency_ms", "jitter_ms", "packet_loss_pct",
                             "throughput_mbps", "mos_score"],
         lambda w, n: gen_metrics(w), 0),
    ]

    for name, headers, gen_fn, count in generators:
        path = os.path.join(args.output_dir, f"{name}.csv")
        print(f"\n[*] Generating {name} → {path}")
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            # No header row — gpfdist external tables don't expect headers
            gen_fn(writer, count)
        size_mb = os.path.getsize(path) / (1024 * 1024)
        print(f"    → {size_mb:.1f} MB")

    print(f"\n✓ All CSV files generated in {args.output_dir}/")
    print(f"  Next: gpfdist -d {args.output_dir} -p 8081 &")
    print(f"  Then: psql -f 03_load_external.sql")


if __name__ == "__main__":
    main()
