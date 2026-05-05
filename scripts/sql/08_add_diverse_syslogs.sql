-- ============================================================================
-- Add Diverse Syslog Messages for Demo Quality
-- ============================================================================
SET search_path TO netvista_demo, public;

-- Add diverse RECON messages
INSERT INTO netvista_demo.syslog_embeddings
    (event_id, src_ip, hostname, program, message, severity, persona, embedding)
VALUES
    -- RECON messages with diverse phrasings
    (900001, '10.10.10.15', 'srv-acme-01', 'firewalld', 'Port scan detected: 10.10.10.15 hit 4523 unique ports in 60s', 2, 'recon',
     ARRAY[0.2, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.02, 0.03, 0.01, 0.04, 0.02, 0.01]::vector(32)),

    (900002, '10.10.10.12', 'ids-us-e-02', 'firewalld', 'REJECT TCP from 10.10.10.12:52341 to 10.20.1.50:22 (Connection refused)', 2, 'recon',
     ARRAY[0.2, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.01, 0.02, 0.03, 0.02, 0.01, 0.02]::vector(32)),

    (900003, '10.10.10.18', 'ids-us-e-01', 'snort', 'SCAN SYN FIN detected from 10.10.10.18 — possible nmap', 2, 'recon',
     ARRAY[0.2, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.03, 0.01, 0.02, 0.01, 0.03, 0.02]::vector(32)),

    (900004, '10.10.10.20', 'srv-acme-03', 'kernel', 'TCP: SYN retransmission flood from 10.10.10.20', 1, 'recon',
     ARRAY[0.1, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.02, 0.01, 0.03, 0.02, 0.01, 0.03]::vector(32)),

    (900005, '10.10.10.14', 'srv-acme-02', 'iptables', 'REJECT IN=eth0 SRC=10.10.10.14 DST=10.20.1.100 PROTO=TCP — RST flag', 3, 'recon',
     ARRAY[0.4, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.8, 0.0, 0.0, 0.0, 0.0, 0.5, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.01, 0.02, 0.01, 0.03, 0.02, 0.01]::vector(32)),

    (900006, '10.10.10.22', 'ids-us-e-03', 'firewalld', 'Connection reset by peer: 10.10.10.22 — likely port probe', 2, 'recon',
     ARRAY[0.2, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.5, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.8, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.02, 0.03, 0.02, 0.01, 0.02, 0.03]::vector(32)),

    (900007, '10.10.10.11', 'srv-acme-05', 'sshd', 'Invalid user admin from 10.10.10.11 port 41234', 3, 'recon',
     ARRAY[0.4, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.03, 0.01, 0.02, 0.03, 0.01, 0.02]::vector(32)),

    (900008, '10.10.10.19', 'ids-us-e-02', 'snort', 'ICMP Unreachable from 10.10.10.19: host unreachable (TTL exceeded)', 2, 'recon',
     ARRAY[0.2, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.5, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.01, 0.03, 0.02, 0.01, 0.03, 0.02]::vector(32)),

    -- EXFIL messages with diverse phrasings
    (900010, '10.20.1.205', 'srv-acme-04', 'rsync', 'Large outbound transfer: 10.20.1.205 → 103.224.82.15: 284MB in 145s', 1, 'exfil',
     ARRAY[0.1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.5, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.02, 0.01, 0.03, 0.02, 0.01, 0.02]::vector(32)),

    (900011, '10.20.1.203', 'srv-acme-06', 'backup-svc', 'Archive exported: /opt/data/customer_db_full.tar.gz (250MB)', 1, 'exfil',
     ARRAY[0.1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.8, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.5, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.01, 0.02, 0.01, 0.03, 0.02, 0.01]::vector(32)),

    (900012, '10.20.1.207', 'srv-acme-02', 'rclone', 'Data sync to cloud: 3.2GB transferred to remote endpoint 103.224.82.15', 3, 'exfil',
     ARRAY[0.4, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.8, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.03, 0.01, 0.02, 0.01, 0.03, 0.02]::vector(32)),

    (900013, '10.20.1.201', 'srv-acme-08', 'openvpn', 'Encrypted tunnel established: 10.20.1.201 → 103.224.82.15:443 (TLS 1.3)', 0, 'exfil',
     ARRAY[0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.5, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.02, 0.03, 0.01, 0.02, 0.01, 0.03]::vector(32)),

    (900014, '10.20.1.209', 'srv-acme-03', 'netfilter', 'ALERT: Sustained high-bandwidth flow 10.20.1.209→103.224.82.15: 450MB over 10min', 1, 'exfil',
     ARRAY[0.1, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.5, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.01, 0.02, 0.03, 0.01, 0.02, 0.01]::vector(32)),

    (900015, '10.20.1.202', 'srv-acme-07', 'backup-svc', 'Backup completed: customer_records_8472.tar encrypted and staged', 3, 'exfil',
     ARRAY[0.4, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.5, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.02, 0.01, 0.02, 0.03, 0.01, 0.02]::vector(32)),

    (900016, '10.20.1.208', 'srv-acme-05', 'curl', 'POST https://103.224.82.15/upload?token=7821 — 180MB payload — 200 OK', 4, 'exfil',
     ARRAY[0.5, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.03, 0.02, 0.01, 0.02, 0.03, 0.01]::vector(32)),

    -- C2 messages with diverse phrasings
    (900020, '192.168.10.52', 'host-jp-12', 'beacon', 'C2 beacon: 192.168.10.52 → 91.219.236.222 jitter=45ms interval=300s', 4, 'c2',
     ARRAY[0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.02, 0.01, 0.03, 0.02, 0.01, 0.02]::vector(32)),

    (900021, '192.168.10.55', 'host-jp-15', 'cron', 'Heartbeat detected: agent check-in from 192.168.10.55 — seq=4821', 6, 'c2',
     ARRAY[0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.01, 0.02, 0.01, 0.03, 0.02, 0.01]::vector(32)),

    (900022, '192.168.10.58', 'host-jp-08', 'svchost', 'Polling remote host 91.219.236.222:443 — last seen 287s ago', 5, 'c2',
     ARRAY[0.7, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.03, 0.01, 0.02, 0.01, 0.03, 0.02]::vector(32)),

    (900023, '192.168.10.61', 'host-jp-11', 'curl', 'Keep-alive received: 192.168.10.61 → C2:8080 — next poll in 120s', 6, 'c2',
     ARRAY[0.8, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.02, 0.03, 0.01, 0.02, 0.01, 0.03]::vector(32)),

    (900024, '192.168.10.64', 'host-jp-14', 'beacon', 'DNS beacon query: 8472.update.svc.internal — TTL 60s', 4, 'c2',
     ARRAY[0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.01, 0.02, 0.03, 0.01, 0.02, 0.01]::vector(32)),

    (900025, '192.168.10.67', 'host-jp-17', 'svchost', 'Polling remote host: GET /ping HTTP/1.1 — 204 No Content', 4, 'c2',
     ARRAY[0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.02, 0.01, 0.02, 0.03, 0.01, 0.02]::vector(32));

ANALYZE netvista_demo.syslog_embeddings;

-- Verify diversity
SELECT
    persona,
    COUNT(DISTINCT LEFT(message, 40)) as unique_message_prefixes,
    COUNT(*) as total_logs
FROM netvista_demo.syslog_embeddings
WHERE persona IN ('recon', 'exfil', 'c2')
GROUP BY persona
ORDER BY persona;

-- Show sample diversity
SELECT
    persona,
    program,
    LEFT(message, 70) as sample_message
FROM netvista_demo.syslog_embeddings
WHERE persona IN ('recon', 'exfil', 'c2')
AND event_id >= 900000
ORDER BY persona, event_id;
