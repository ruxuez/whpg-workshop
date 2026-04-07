-- ============================================================================
-- NetVista × EDB WarehousePG — Scale-Up to ~100M Rows
-- ============================================================================
-- Truncates all fact tables and reloads at 3x scale.
-- Run AFTER 01_schema.sql + 02_seed_reference.sql have been loaded.
--
-- TARGET: ~100M total rows
--   netflow_logs     : 33,000,000  (30M base + 1.5M DDoS + 150K scan + 30K exfil)
--   dns_logs         : 25,000,000
--   firewall_logs    : 22,500,000
--   syslog_events    : 15,000,000
--   bgp_events       :  1,500,000
--   network_metrics  :    150,000
--   ipam_allocations :     ~2,500
--   security_incidents:    ~3,000
--   TOTAL            : ~97,300,000
--
-- ESTIMATED LOAD TIME: 5mn on 1 node (16 vcpu)
-- ESTIMATED STORAGE:   ~< 5GB compressed (zstd level 3)
-- ============================================================================
SET search_path TO netvista_demo, public;
SET statement_mem = '512MB';

-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ TRUNCATE ALL FACT TABLES                                                ║
-- ╚════════════════════════════════════════════════════════════════════════════╝
DO $$ BEGIN RAISE NOTICE '[%] Truncating all fact tables...', clock_timestamp(); END $$;

TRUNCATE netflow_logs;
TRUNCATE syslog_events;
TRUNCATE firewall_logs;
TRUNCATE dns_logs;
TRUNCATE bgp_events;
TRUNCATE ipam_allocations;
TRUNCATE ipam_summary;
TRUNCATE network_metrics;
TRUNCATE security_incidents;

DO $$ BEGIN RAISE NOTICE '[%] Truncate complete. Starting 100M generation...', clock_timestamp(); END $$;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ NETFLOW LOGS — 30,000,000 base rows (30 batches of 1M)                 ║
-- ╚════════════════════════════════════════════════════════════════════════════╝
DO $$ BEGIN RAISE NOTICE '[%] Generating netflow_logs — 30M rows (30 batches)...', clock_timestamp(); END $$;

DO $$
DECLARE
    batch INT;
BEGIN
    FOR batch IN 1..30 LOOP
        IF batch % 5 = 0 THEN
            RAISE NOTICE '[%] netflow batch %/30 ...', clock_timestamp(), batch;
        END IF;

        INSERT INTO netflow_logs (
            ts, src_ip, dst_ip, src_port, dst_port,
            protocol, bytes, packets, tcp_flags, flow_duration, region_id
        )
        SELECT
            now() - (random() * interval '7 days') AS ts,
            CASE WHEN random() < 0.15
                THEN (ARRAY[
                    '185.220.101.34', '91.219.236.222', '45.155.205.99',
                    '23.129.64.130',  '104.244.76.13',  '198.98.56.78',
                    '5.188.86.172',   '209.141.33.21',  '103.224.82.15',
                    '58.218.198.100', '222.186.42.7',   '218.92.0.31'
                ])[1 + (random()*11)::int]::inet
                ELSE (
                    (ARRAY[
                        '10.10','10.20','10.21','10.22','10.128','10.129',
                        '172.16','172.17','172.20','172.21',
                        '192.168','10.200','10.201','10.50','10.51'
                    ])[1 + (random()*14)::int]
                    || '.' || (random()*254+1)::int
                    || '.' || (random()*254+1)::int
                )::inet
            END AS src_ip,
            CASE WHEN random() < 0.6
                THEN (
                    (ARRAY[
                        '10.10','10.20','10.128','172.16','172.17',
                        '192.168','10.200','10.50','10.129','172.20'
                    ])[1 + (random()*9)::int]
                    || '.' || (random()*254+1)::int
                    || '.' || (random()*254+1)::int
                )::inet
                ELSE (
                    (1 + (random()*222)::int)
                    || '.' || (random()*255)::int
                    || '.' || (random()*255)::int
                    || '.' || (1 + (random()*254)::int)
                )::inet
            END AS dst_ip,
            (1024 + (random()*64510)::int),
            (ARRAY[
                80, 443, 443, 443, 22, 53, 53,
                8080, 3306, 5432, 8443, 25, 110,
                143, 993, 389, 636, 3389, 8888,
                9200, 9300, 5601, 6379, 27017
            ])[1 + (random()*24)::int],
            CASE
                WHEN random() < 0.70 THEN 6
                WHEN random() < 0.95 THEN 17
                ELSE 1
            END,
            GREATEST(64, (exp(random() * 7.5 + 5))::bigint),
            GREATEST(1, (exp(random() * 4.5 + 1.5))::bigint),
            CASE WHEN random() < 0.70
                THEN (ARRAY[2,2,18,16,16,16,17,24,24,25])[1 + (random()*9)::int]
                ELSE NULL
            END,
            GREATEST(1, (exp(random() * 6 + 2))::int),
            (1 + (random()*6)::int)
        FROM generate_series(1, 1000000);
    END LOOP;
END $$;

DO $$ BEGIN RAISE NOTICE '[%] netflow base 30M complete.', clock_timestamp(); END $$;

-- DDoS — 1.5M flows
DO $$ BEGIN RAISE NOTICE '[%] DDoS simulation — 1.5M flows...', clock_timestamp(); END $$;

INSERT INTO netflow_logs (ts, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, tcp_flags, flow_duration, region_id)
SELECT
    now() - interval '18 hours' + (random() * interval '2 hours'),
    (
        (ARRAY[31,45,62,77,89,103,118,141,156,178,185,191,203,211,223])[1 + (random()*14)::int]
        || '.' || (random()*255)::int
        || '.' || (random()*255)::int
        || '.' || (1 + (random()*254)::int)
    )::inet,
    (ARRAY['10.20.1.100','10.20.1.101','10.20.1.102'])[1 + (random()*2)::int]::inet,
    (1024 + (random()*64510)::int),
    80, 6,
    (40 + (random()*80)::int)::bigint,
    1::bigint, 2, 0, 1
FROM generate_series(1, 1500000);

-- Port scan — 150K flows
DO $$ BEGIN RAISE NOTICE '[%] Port scan simulation — 150K flows...', clock_timestamp(); END $$;

INSERT INTO netflow_logs (ts, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, tcp_flags, flow_duration, region_id)
SELECT
    now() - interval '6 hours' + (g * interval '15 milliseconds'),
    (ARRAY['45.155.205.99','198.98.56.78','222.186.42.7'])[1 + (g % 3)]::inet,
    ('10.10.1.' || (1 + (g % 254)))::inet,
    (40000 + (random()*25000)::int),
    (1 + (g % 65535)), 6,
    44::bigint, 1::bigint, 2, 0,
    CASE g % 3 WHEN 0 THEN 3 WHEN 1 THEN 1 ELSE 2 END
FROM generate_series(1, 150000) g;

-- Exfiltration — 30K flows
DO $$ BEGIN RAISE NOTICE '[%] Exfiltration simulation — 30K flows...', clock_timestamp(); END $$;

INSERT INTO netflow_logs (ts, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, tcp_flags, flow_duration, region_id)
SELECT
    now() - interval '3 days' + (random() * interval '48 hours'),
    ('10.20.1.' || (50 + (random()*10)::int))::inet,
    (ARRAY['103.224.82.15','58.218.198.100'])[1 + (random()*1)::int]::inet,
    (40000 + (random()*25000)::int),
    (ARRAY[443, 8443, 53, 993])[1 + (random()*3)::int], 6,
    (1000000 + (random() * 50000000)::int)::bigint,
    (1000 + (random() * 50000)::int)::bigint,
    24, (30000 + (random() * 300000)::int), 1
FROM generate_series(1, 30000);

DO $$ BEGIN RAISE NOTICE '[%] netflow_logs COMPLETE (~31.68M rows).', clock_timestamp(); END $$;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ DNS LOGS — 25,000,000 rows (25 batches of 1M)                          ║
-- ╚════════════════════════════════════════════════════════════════════════════╝
DO $$ BEGIN RAISE NOTICE '[%] Generating dns_logs — 25M rows (25 batches)...', clock_timestamp(); END $$;

DO $$
DECLARE
    batch INT;
BEGIN
    FOR batch IN 1..25 LOOP
        IF batch % 5 = 0 THEN
            RAISE NOTICE '[%] dns batch %/25 ...', clock_timestamp(), batch;
        END IF;

        INSERT INTO dns_logs (
            ts, client_ip, query_name, query_type,
            response_code, response_ip, response_time, is_recursive, region_id
        )
        SELECT
            now() - (random() * interval '7 days'),
            (
                (ARRAY['10.10','10.20','10.128','172.16','192.168','10.200','10.50','10.129','172.17','172.20'])[1 + (random()*9)::int]
                || '.' || (random()*254+1)::int || '.' || (random()*254+1)::int
            )::inet,
            CASE
                WHEN random() < 0.20 THEN (ARRAY['api','portal','mail','vpn','sso','cdn','static','ws','auth','billing'])[1+(random()*9)::int] || '.netvista.com'
                WHEN random() < 0.40 THEN (ARRAY['google.com','youtube.com','facebook.com','microsoft.com','apple.com','amazon.com','twitter.com','linkedin.com','github.com','stackoverflow.com'])[1+(random()*9)::int]
                WHEN random() < 0.55 THEN (ARRAY['s3.amazonaws.com','blob.core.windows.net','storage.googleapis.com','cdn.cloudflare.com','fastly.net'])[1+(random()*4)::int]
                WHEN random() < 0.70 THEN (ARRAY['zoom.us','slack.com','teams.microsoft.com','webex.com','office365.com','salesforce.com','servicenow.com','jira.atlassian.com'])[1+(random()*7)::int]
                WHEN random() < 0.85 THEN substr(md5(random()::text), 1, 8) || '.' || (ARRAY['com','net','org','io','co','cloud'])[1+(random()*5)::int]
                WHEN random() < 0.92 THEN substr(md5(random()::text), 1, 12) || '.' || (ARRAY['xyz','top','buzz','club','icu','work'])[1+(random()*5)::int]
                WHEN random() < 0.95 THEN (ARRAY['c2-beacon.evil.ru','exfil-data.cn','malware-drop.xyz','phishing-login.com','crypto-mine.io'])[1+(random()*4)::int]
                WHEN random() < 0.98 THEN 'ns' || (random()*99+1)::int || '.' || (ARRAY['darknet.ru','shadow.cn','hidden-service.onion','covert-c2.ir'])[1+(random()*3)::int]
                ELSE substr(md5(random()::text), 1, 32) || '.' || (ARRAY['evil.ru','malware.cn','exfil.xyz'])[1+(random()*2)::int]
            END,
            (ARRAY['A','A','A','A','AAAA','AAAA','MX','CNAME','CNAME','TXT','PTR','SRV'])[1 + (random()*11)::int],
            CASE
                WHEN random() < 0.90 THEN 'NOERROR'
                WHEN random() < 0.97 THEN 'NXDOMAIN'
                WHEN random() < 0.99 THEN 'SERVFAIL'
                ELSE 'REFUSED'
            END,
            CASE WHEN random() < 0.90
                THEN ((random()*222+1)::int || '.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int)::inet
                ELSE NULL
            END,
            CASE WHEN random() < 0.8
                THEN (100 + (random() * 2000)::int)
                ELSE (2000 + (random() * 30000)::int)
            END,
            random() < 0.85,
            (1 + (random()*6)::int)
        FROM generate_series(1, 1000000);
    END LOOP;
END $$;

DO $$ BEGIN RAISE NOTICE '[%] dns_logs COMPLETE.', clock_timestamp(); END $$;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ FIREWALL LOGS — 22,500,000 rows (15 batches of 1.5M)                   ║
-- ╚════════════════════════════════════════════════════════════════════════════╝
DO $$ BEGIN RAISE NOTICE '[%] Generating firewall_logs — 22.5M rows (15 batches)...', clock_timestamp(); END $$;

DO $$
DECLARE
    batch INT;
BEGIN
    FOR batch IN 1..15 LOOP
        IF batch % 5 = 0 THEN
            RAISE NOTICE '[%] firewall batch %/15 ...', clock_timestamp(), batch;
        END IF;

        INSERT INTO firewall_logs (
            ts, src_ip, dst_ip, src_port, dst_port,
            protocol, action, rule_id, bytes, zone_src, zone_dst, region_id
        )
        SELECT
            now() - (random() * interval '7 days'),
            CASE WHEN random() < 0.3
                THEN (
                    (1 + (random()*222)::int) || '.' || (random()*255)::int
                    || '.' || (random()*255)::int || '.' || (1+(random()*254)::int)
                )::inet
                ELSE (
                    (ARRAY[
                        '10.10','10.20','10.128','10.129','172.16','172.17',
                        '172.20','192.168','10.200','10.50'
                    ])[1 + (random()*9)::int]
                    || '.' || (random()*254+1)::int || '.' || (random()*254+1)::int
                )::inet
            END,
            (
                (ARRAY[
                    '10.10','10.20','10.128','172.16','172.17',
                    '192.168','10.200','10.50','10.129','172.20'
                ])[1 + (random()*9)::int]
                || '.' || (random()*254+1)::int || '.' || (random()*254+1)::int
            )::inet,
            (1024 + (random()*64510)::int),
            (ARRAY[
                80,443,443,443,22,53,53,8080,3306,5432,
                25,3389,8443,9200,6379,27017,445,135,139,161
            ])[1 + (random()*19)::int],
            CASE WHEN random() < 0.7 THEN 6 ELSE 17 END,
            CASE
                WHEN random() < 0.72 THEN 'ALLOW'
                WHEN random() < 0.87 THEN 'DENY'
                WHEN random() < 0.97 THEN 'DROP'
                ELSE 'REJECT'
            END,
            (1 + (random()*100)::int),
            GREATEST(0, (exp(random() * 7 + 3))::bigint),
            (ARRAY['external','external','internal','internal','dmz','management','transit','guest','partner'])[1 + (random()*8)::int],
            (ARRAY['internal','internal','internal','dmz','external','management','customer','database','api'])[1 + (random()*8)::int],
            (1 + (random()*6)::int)
        FROM generate_series(1, 1500000);
    END LOOP;
END $$;

DO $$ BEGIN RAISE NOTICE '[%] firewall_logs COMPLETE.', clock_timestamp(); END $$;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ SYSLOG EVENTS — 15,000,000 rows (15 batches of 1M)                     ║
-- ╚════════════════════════════════════════════════════════════════════════════╝
DO $$ BEGIN RAISE NOTICE '[%] Generating syslog_events — 15M rows (15 batches)...', clock_timestamp(); END $$;

DO $$
DECLARE
    batch INT;
BEGIN
    FOR batch IN 1..15 LOOP
        IF batch % 5 = 0 THEN
            RAISE NOTICE '[%] syslog batch %/15 ...', clock_timestamp(), batch;
        END IF;

        INSERT INTO syslog_events (ts, src_ip, hostname, facility, severity, program, message, region_id)
        SELECT
            now() - (random() * interval '7 days'),
            (
                (ARRAY[
                    '10.10','10.20','10.128','10.129','172.16','172.17',
                    '172.20','192.168','10.200','10.50'
                ])[1 + (random()*9)::int]
                || '.' || (random()*254+1)::int
                || '.' || (random()*254+1)::int
            )::inet,
            (ARRAY['fw','rtr','sw','srv','lb','dns','vpn','waf','ids','proxy'])[1 + (random()*9)::int]
                || '-' || (ARRAY['us-e','us-w','eu-w','eu-e','jp','sg','br'])[1 + (random()*6)::int]
                || '-' || LPAD((random()*999+1)::int::text, 3, '0'),
            (random() * 23)::smallint,
            (ARRAY[
                7,7,7,7,7,7,
                6,6,6,6,6,6,6,6,6,6,6,6,
                5,5,5,5,5,
                4,4,4,4,4,4,4,
                3,3,3,3,
                2,2,
                1,
                0
            ])[1 + (random()*37)::int],
            (ARRAY[
                'sshd','sshd','httpd','httpd','httpd',
                'kernel','firewalld','firewalld','named','named',
                'bgpd','snmpd','ntpd','auditd','sudo',
                'docker','kubelet','nginx','haproxy','postfix'
            ])[1 + (random()*19)::int],
            CASE (random()*19)::int
                WHEN 0  THEN 'Failed password for root from ' || ((random()*222+1)::int || '.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int) || ' port ' || (1024+(random()*64510)::int) || ' ssh2'
                WHEN 1  THEN 'Failed password for admin from ' || ((random()*222+1)::int || '.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int) || ' port ' || (1024+(random()*64510)::int) || ' ssh2'
                WHEN 2  THEN 'Accepted publickey for deploy from 10.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int || ' port ' || (1024+(random()*64510)::int)
                WHEN 3  THEN 'Connection closed by authenticating user ' || (ARRAY['admin','root','deploy','operator','noc'])[1+(random()*4)::int] || ' 10.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int
                WHEN 4  THEN 'OUT OF MEMORY: Kill process ' || (random()*65535)::int || ' (' || (ARRAY['java','python3','node','postgres','elasticsearch'])[1+(random()*4)::int] || ') score ' || (800+(random()*200)::int) || ' or sacrifice child'
                WHEN 5  THEN 'Link ' || (ARRAY['up','down'])[1+(random()*1)::int] || ' on interface ' || (ARRAY['eth','bond','ens','eno'])[1+(random()*3)::int] || (random()*8)::int
                WHEN 6  THEN 'BGP neighbor 172.' || (16+(random()*15)::int) || '.' || (random()*255)::int || '.' || (random()*254+1)::int || ' state changed to ' || (ARRAY['Established','Idle','Active','OpenSent','OpenConfirm'])[1+(random()*4)::int]
                WHEN 7  THEN 'DNS query rate limit exceeded from 10.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int || ' (' || (100+(random()*9900)::int) || ' queries/sec)'
                WHEN 8  THEN 'Certificate ' || (ARRAY['expiring in','expired','renewed for'])[1+(random()*2)::int] || ' ' || (random()*90)::int || ' days for ' || (ARRAY['api.netvista.com','portal.netvista.com','vpn.netvista.com','mail.netvista.com','cdn.netvista.com','sso.netvista.com'])[1+(random()*5)::int]
                WHEN 9  THEN 'SNMP trap: ' || (ARRAY['high CPU utilization','high memory usage','disk space low','interface errors','temperature warning'])[1+(random()*4)::int] || ' (' || (80+(random()*20)::int) || '%) on ' || (ARRAY['core-rtr','dist-sw','edge-fw','lb','wan-rtr'])[1+(random()*4)::int] || '-' || (random()*50+1)::int
                WHEN 10 THEN 'Audit: user ' || (ARRAY['admin','operator','noc','deploy','backup','monitor'])[1+(random()*5)::int] || ' executed: ' || (ARRAY['show ip route','show bgp summary','reload','configure terminal','show interfaces','clear counters','write memory'])[1+(random()*6)::int]
                WHEN 11 THEN 'iptables: DROP IN=' || (ARRAY['eth0','eth1','bond0'])[1+(random()*2)::int] || ' SRC=' || ((random()*222+1)::int || '.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int) || ' DST=10.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int || ' PROTO=TCP DPT=' || (ARRAY[22,23,445,3389,4444,5555])[1+(random()*5)::int]
                WHEN 12 THEN 'nginx: ' || (ARRAY['502 Bad Gateway','503 Service Unavailable','504 Gateway Timeout','413 Request Entity Too Large'])[1+(random()*3)::int] || ' upstream=' || ((random()*254+1)::int) || '.' || ((random()*255)::int) || '.' || ((random()*255)::int) || '.' || ((random()*254+1)::int) || ':' || (ARRAY[8080,8443,9090])[1+(random()*2)::int]
                WHEN 13 THEN 'haproxy: Server ' || (ARRAY['backend_web','backend_api','backend_db'])[1+(random()*2)::int] || '/' || (ARRAY['srv','app','node'])[1+(random()*2)::int] || (random()*10+1)::int || ' is ' || (ARRAY['DOWN','UP'])[1+(random()*1)::int] || ', reason: ' || (ARRAY['Layer4 timeout','Layer7 wrong status','Layer4 connection problem'])[1+(random()*2)::int]
                WHEN 14 THEN 'docker: container ' || substr(md5(random()::text), 1, 12) || ' ' || (ARRAY['started','stopped','killed','OOMKilled','restarting'])[1+(random()*4)::int] || ' (image: ' || (ARRAY['nginx:latest','redis:7','postgres:16','node:20','python:3.12'])[1+(random()*4)::int] || ')'
                WHEN 15 THEN 'kubelet: Pod ' || (ARRAY['frontend','backend','worker','scheduler','api-gateway'])[1+(random()*4)::int] || '-' || substr(md5(random()::text), 1, 8) || ' ' || (ARRAY['evicted due to memory pressure','failed readiness probe','CrashLoopBackOff','completed successfully'])[1+(random()*3)::int]
                WHEN 16 THEN 'kernel: possible SYN flooding on port ' || (ARRAY[80,443,8080])[1+(random()*2)::int] || '. Sending cookies. Check SNMP counters.'
                WHEN 17 THEN 'postfix/smtpd: NOQUEUE: reject: RCPT from unknown[' || ((random()*222+1)::int || '.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int) || ']: 554 5.7.1 Service unavailable'
                WHEN 18 THEN 'sudo: ' || (ARRAY['admin','operator','deploy'])[1+(random()*2)::int] || ' : TTY=pts/' || (random()*10)::int || ' ; PWD=/root ; USER=root ; COMMAND=/bin/' || (ARRAY['systemctl restart nginx','journalctl -f','tcpdump -i eth0','iptables -L'])[1+(random()*3)::int]
                ELSE         'kernel: NMI watchdog: BUG: soft lockup - CPU#' || (random()*64)::int || ' stuck for ' || (22+(random()*40)::int) || 's!'
            END,
            (1 + (random()*6)::int)
        FROM generate_series(1, 1000000);
    END LOOP;
END $$;

DO $$ BEGIN RAISE NOTICE '[%] syslog_events COMPLETE.', clock_timestamp(); END $$;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ BGP EVENTS — 1,500,000 rows                                             ║
-- ╚════════════════════════════════════════════════════════════════════════════╝
DO $$ BEGIN RAISE NOTICE '[%] Generating bgp_events — 1.5M rows...', clock_timestamp(); END $$;

DO $$
DECLARE
    batch INT;
BEGIN
    FOR batch IN 1..3 LOOP
        RAISE NOTICE '[%] bgp batch %/3 ...', clock_timestamp(), batch;

        INSERT INTO bgp_events (ts, peer_ip, prefix, event_type, as_path, next_hop, origin, local_pref, med, community, region_id)
        SELECT
            now() - (random() * interval '7 days'),
            ('172.' || (16 + (random()*15)::int) || '.' || (random()*255)::int || '.' || (random()*254+1)::int)::inet,
            network(
                (
                    (1+(random()*222)::int) || '.' || ((random()*255)::int) || '.' || ((random()*255)::int) || '.' || ((random()*255)::int)
                    || '/' || (ARRAY[16,16,20,20,22,24,24,24])[1+(random()*7)::int]
                )::inet
            )::cidr,
            (ARRAY['ANNOUNCE','ANNOUNCE','ANNOUNCE','ANNOUNCE','ANNOUNCE','WITHDRAW','WITHDRAW','UPDATE','UPDATE'])[1 + (random()*8)::int],
            '2914 ' || (1+(random()*65534)::int)
                || CASE WHEN random() < 0.6 THEN ' ' || (1+(random()*65534)::int) ELSE '' END
                || CASE WHEN random() < 0.3 THEN ' ' || (1+(random()*65534)::int) ELSE '' END
                || CASE WHEN random() < 0.1 THEN ' ' || (1+(random()*65534)::int) ELSE '' END,
            ('172.' || (16 + (random()*15)::int) || '.' || (random()*255)::int || '.' || (random()*254+1)::int)::inet,
            (ARRAY['IGP','IGP','IGP','EGP','INCOMPLETE'])[1 + (random()*4)::int],
            (ARRAY[100, 100, 150, 200, 250, 300])[1 + (random()*5)::int],
            (random() * 1000)::int,
            CASE WHEN random() < 0.5
                THEN '2914:' || (ARRAY[100,200,300,400,500,1000,2000,3000])[1+(random()*7)::int]
                     || ' 2914:' || (ARRAY[100,200,300,400,500,1000,2000,3000])[1+(random()*7)::int]
                ELSE NULL
            END,
            (1 + (random()*6)::int)
        FROM generate_series(1, 500000);
    END LOOP;
END $$;

-- BGP flapping
INSERT INTO bgp_events (ts, peer_ip, prefix, event_type, as_path, next_hop, origin, local_pref, med, region_id)
SELECT
    now() - interval '12 hours' + (g * interval '3 seconds'),
    '172.16.0.1'::inet, '10.20.0.0/16'::cidr,
    CASE WHEN g % 2 = 0 THEN 'WITHDRAW' ELSE 'ANNOUNCE' END,
    '2914 65001', '172.16.0.1'::inet, 'IGP', 100, 0, 3
FROM generate_series(1, 2000) g;

DO $$ BEGIN RAISE NOTICE '[%] bgp_events COMPLETE.', clock_timestamp(); END $$;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ IPAM, METRICS, INCIDENTS (same as before — these don't need 3x)         ║
-- ╚════════════════════════════════════════════════════════════════════════════╝
DO $$ BEGIN RAISE NOTICE '[%] Generating IPAM allocations...', clock_timestamp(); END $$;

INSERT INTO ipam_allocations (ip_address, subnet_id, mac_address, hostname, device_type, status, allocated_at, last_seen, region_id)
SELECT
    (
        split_part(host(s.subnet), '.', 1) || '.' ||
        split_part(host(s.subnet), '.', 2) || '.' ||
        split_part(host(s.subnet), '.', 3) || '.' ||
        (2 + g)::text
    )::inet,
    s.subnet_id,
    (
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0') || ':' ||
        LPAD(to_hex((random()*255)::int), 2, '0')
    )::macaddr,
    (ARRAY['srv','rtr','sw','fw','lb','ap','cam','phone','vm','container'])[1+(random()*9)::int]
        || '-' || (ARRAY['prod','stg','dev','mgmt','mon'])[1+(random()*4)::int]
        || '-' || LPAD(g::text, 4, '0'),
    (ARRAY['server','router','switch','firewall','load-balancer','access-point','ip-phone','virtual-machine','container','iot-sensor'])[1+(random()*9)::int],
    CASE
        WHEN random() < 0.78 THEN 'active'
        WHEN random() < 0.88 THEN 'reserved'
        WHEN random() < 0.95 THEN 'deprecated'
        ELSE 'available'
    END,
    now() - (random() * interval '730 days'),
    CASE WHEN random() < 0.85
        THEN now() - (random() * interval '1 day')
        ELSE now() - (random() * interval '90 days')
    END,
    s.region_id
FROM subnets s
CROSS JOIN generate_series(1, 200) g
WHERE masklen(s.subnet) >= 24
  AND g <= LEAST(253, (power(2, (32 - masklen(s.subnet))))::int - 3)
  AND random() < 0.75;

TRUNCATE ipam_summary;
INSERT INTO ipam_summary (subnet_id, subnet, region_id, total_ips, allocated_ips, reserved_ips, utilization_pct)
SELECT
    s.subnet_id, s.subnet, s.region_id,
    netvista_demo.cidr_host_count(s.subnet)::int,
    COUNT(a.alloc_id) FILTER (WHERE a.status = 'active'),
    COUNT(a.alloc_id) FILTER (WHERE a.status = 'reserved'),
    ROUND(
        COUNT(a.alloc_id) FILTER (WHERE a.status IN ('active','reserved'))::numeric
        / NULLIF(netvista_demo.cidr_host_count(s.subnet), 0) * 100, 1
    )
FROM subnets s
LEFT JOIN ipam_allocations a ON a.subnet_id = s.subnet_id
WHERE masklen(s.subnet) >= 24
GROUP BY s.subnet_id, s.subnet, s.region_id;

DO $$ BEGIN RAISE NOTICE '[%] IPAM COMPLETE.', clock_timestamp(); END $$;

-- Network metrics
DO $$ BEGIN RAISE NOTICE '[%] Generating network_metrics...', clock_timestamp(); END $$;

INSERT INTO network_metrics (ts, customer_id, region_id, probe_ip, latency_ms, jitter_ms, packet_loss_pct, throughput_mbps, mos_score)
SELECT
    ts, c.customer_id, c.region_id,
    ('10.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*254+1)::int)::inet,
    ROUND((
        CASE c.region_id
            WHEN 1 THEN 12  WHEN 2 THEN 18  WHEN 3 THEN 25
            WHEN 4 THEN 35  WHEN 5 THEN 45  WHEN 6 THEN 55  WHEN 7 THEN 65
        END
        + (random() * 15)
        + CASE WHEN random() < 0.03 THEN 50 + random() * 150 ELSE 0 END
        - CASE c.tier WHEN 'enterprise' THEN 5 WHEN 'premium' THEN 2 ELSE 0 END
    )::numeric, 2),
    ROUND((random() * 6 + 0.5 + CASE WHEN random() < 0.05 THEN random() * 25 ELSE 0 END)::numeric, 2),
    ROUND((CASE
        WHEN random() < 0.82 THEN random() * 0.08
        WHEN random() < 0.92 THEN random() * 0.3
        WHEN random() < 0.97 THEN random() * 1.5
        ELSE random() * 5.0
    END)::numeric, 2),
    ROUND((random() * 900 + 100)::numeric, 2),
    NULL
FROM customers c
CROSS JOIN generate_series(now() - interval '7 days', now(), interval '1 minute') AS ts;

UPDATE network_metrics
SET mos_score = ROUND(GREATEST(1.0, LEAST(5.0,
    4.5 - (latency_ms * 0.02) - (jitter_ms * 0.04) - (packet_loss_pct * 0.5)
))::numeric, 1);

DO $$ BEGIN RAISE NOTICE '[%] network_metrics COMPLETE.', clock_timestamp(); END $$;

-- Security incidents
DO $$ BEGIN RAISE NOTICE '[%] Generating security_incidents...', clock_timestamp(); END $$;

INSERT INTO security_incidents (ts, src_ip, dst_ip, threat_category, severity, feed_id, matched_rule, description, status, region_id)
SELECT
    now() - (random() * interval '30 days'),
    t.ip_single,
    (
        (ARRAY['10.10','10.20','10.128','172.16','192.168','10.200'])[1 + (random()*5)::int]
        || '.' || (random()*254+1)::int || '.' || (random()*254+1)::int
    )::inet,
    t.category,
    (ARRAY['critical','high','medium','low'])[
        CASE WHEN t.confidence >= 90 THEN 1 + (random()*1)::int
             WHEN t.confidence >= 80 THEN 2 + (random()*1)::int
             ELSE 3 + (random()*1)::int END
    ],
    t.feed_id,
    'RULE-' || LPAD((random()*9999+1)::int::text, 4, '0'),
    CASE t.category
        WHEN 'c2'         THEN 'C2 beacon detected: callback to ' || host(t.ip_single) || ' interval ~' || (60+(random()*300)::int) || 's'
        WHEN 'scanner'    THEN 'Port scan from ' || host(t.ip_single) || ': ' || (50+(random()*65000)::int) || ' ports probed'
        WHEN 'ddos'       THEN 'Volumetric DDoS from ' || host(t.ip_single) || ': ' || (1000+(random()*100000)::int) || ' pps'
        WHEN 'botnet'     THEN 'Botnet C2: ' || host(t.ip_single) || ' encrypted channel port ' || (ARRAY[443,8443,4443])[1+(random()*2)::int]
        WHEN 'exfil'      THEN 'Exfiltration: ' || (10+(random()*2000)::int) || ' MB to ' || host(t.ip_single)
        WHEN 'bruteforce' THEN 'SSH brute-force from ' || host(t.ip_single) || ': ' || (100+(random()*10000)::int) || ' attempts'
        WHEN 'tor_exit'   THEN 'Tor exit node: ' || host(t.ip_single) || ' ' || (random()*1000+1)::int || ' connections'
        ELSE 'Threat match: ' || host(t.ip_single)
    END,
    (ARRAY['open','open','open','open','investigating','investigating','mitigated','mitigated','closed'])[1+(random()*8)::int],
    (1 + (random()*6)::int)
FROM threat_intel_feeds t
CROSS JOIN generate_series(1, 250) g
WHERE t.active = TRUE;

DO $$ BEGIN RAISE NOTICE '[%] security_incidents COMPLETE.', clock_timestamp(); END $$;


-- ╔════════════════════════════════════════════════════════════════════════════╗
-- ║ ANALYZE + FINAL REPORT                                                  ║
-- ╚════════════════════════════════════════════════════════════════════════════╝
DO $$ BEGIN RAISE NOTICE '[%] Running ANALYZE...', clock_timestamp(); END $$;

ANALYZE netvista_demo.netflow_logs;
ANALYZE netvista_demo.syslog_events;
ANALYZE netvista_demo.firewall_logs;
ANALYZE netvista_demo.dns_logs;
ANALYZE netvista_demo.bgp_events;
ANALYZE netvista_demo.ipam_allocations;
ANALYZE netvista_demo.ipam_summary;
ANALYZE netvista_demo.network_metrics;
ANALYZE netvista_demo.security_incidents;

DO $$
DECLARE
    r RECORD;
    total BIGINT := 0;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '╔══════════════════════════════════════════════════════════════╗';
    RAISE NOTICE '║  100M SCALE DATA GENERATION COMPLETE                       ║';
    RAISE NOTICE '╠══════════════════════════════════════════════════════════════╣';
    FOR r IN
        SELECT 'netflow_logs'        AS tbl, COUNT(*) AS cnt FROM netvista_demo.netflow_logs
        UNION ALL SELECT 'dns_logs',          COUNT(*) FROM netvista_demo.dns_logs
        UNION ALL SELECT 'firewall_logs',     COUNT(*) FROM netvista_demo.firewall_logs
        UNION ALL SELECT 'syslog_events',     COUNT(*) FROM netvista_demo.syslog_events
        UNION ALL SELECT 'bgp_events',        COUNT(*) FROM netvista_demo.bgp_events
        UNION ALL SELECT 'network_metrics',   COUNT(*) FROM netvista_demo.network_metrics
        UNION ALL SELECT 'ipam_allocations',  COUNT(*) FROM netvista_demo.ipam_allocations
        UNION ALL SELECT 'ipam_summary',      COUNT(*) FROM netvista_demo.ipam_summary
        UNION ALL SELECT 'security_incidents',COUNT(*) FROM netvista_demo.security_incidents
        ORDER BY 2 DESC
    LOOP
        total := total + r.cnt;
        RAISE NOTICE '║  % : % rows  ║', RPAD(r.tbl, 22), LPAD(TO_CHAR(r.cnt, '99,999,999'), 12);
    END LOOP;
    RAISE NOTICE '╠══════════════════════════════════════════════════════════════╣';
    RAISE NOTICE '║  TOTAL                         : % rows  ║', LPAD(TO_CHAR(total, '99,999,999'), 12);
    RAISE NOTICE '╚══════════════════════════════════════════════════════════════╝';
END $$;
