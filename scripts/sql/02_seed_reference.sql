-- ============================================================================
-- NetVista × EDB WarehousePG — Reference Data Seed
-- ============================================================================
SET search_path TO netvista_demo, public;

-- ─── Regions ────────────────────────────────────────────────────────────────
INSERT INTO regions (region_code, region_name, timezone) VALUES
    ('US-EAST',  'US East (Virginia)',        'America/New_York'),
    ('US-WEST',  'US West (Oregon)',          'America/Los_Angeles'),
    ('EU-WEST',  'EU West (Frankfurt)',       'Europe/Berlin'),
    ('EU-EAST',  'EU East (Warsaw)',          'Europe/Warsaw'),
    ('APAC-JP',  'APAC Japan (Tokyo)',        'Asia/Tokyo'),
    ('APAC-SG',  'APAC Singapore',           'Asia/Singapore'),
    ('LATAM',    'Latin America (São Paulo)', 'America/Sao_Paulo');

-- ─── Subnets (global address space — realistic telco-scale) ──────────────────
INSERT INTO subnets (subnet, region_id, vlan_id, description, subnet_type, parent_subnet) VALUES
    -- US-EAST
    ('10.0.0.0/8',       1, NULL, 'US-East Supernet',              'infrastructure', NULL),
    ('10.10.0.0/16',     1, 100,  'US-East Core Infrastructure',   'infrastructure', '10.0.0.0/8'),
    ('10.10.1.0/24',     1, 101,  'US-East Management VLAN',       'management',     '10.10.0.0/16'),
    ('10.10.10.0/24',    1, 110,  'US-East DMZ',                   'dmz',            '10.10.0.0/16'),
    ('10.20.0.0/16',     1, 200,  'US-East Customer Block A',      'customer',       '10.0.0.0/8'),
    ('10.20.1.0/24',     1, 201,  'NetVista Enterprise Client - Acme',  'customer',       '10.20.0.0/16'),
    ('10.20.2.0/24',     1, 202,  'NetVista Enterprise Client - Globex','customer',       '10.20.0.0/16'),
    ('10.30.0.0/16',     1, 300,  'US-East Transit Peering',       'transit',        '10.0.0.0/8'),
    -- US-WEST
    ('10.128.0.0/16',    2, 500,  'US-West Core Infrastructure',   'infrastructure', NULL),
    ('10.128.1.0/24',    2, 501,  'US-West Management',            'management',     '10.128.0.0/16'),
    ('10.128.10.0/24',   2, 510,  'US-West DMZ',                   'dmz',            '10.128.0.0/16'),
    ('10.129.0.0/16',    2, 600,  'US-West Customer Block',        'customer',       NULL),
    ('10.129.1.0/24',    2, 601,  'NetVista Enterprise - Initech',      'customer',       '10.129.0.0/16'),
    -- EU-WEST
    ('172.16.0.0/12',    3, NULL, 'EU-West Supernet',              'infrastructure', NULL),
    ('172.16.0.0/16',    3, 700,  'EU-West Core',                  'infrastructure', '172.16.0.0/12'),
    ('172.16.1.0/24',    3, 701,  'EU-West Management',            'management',     '172.16.0.0/16'),
    ('172.17.0.0/16',    3, 800,  'EU-West Customer Block',        'customer',       '172.16.0.0/12'),
    ('172.17.1.0/24',    3, 801,  'NetVista EU Client - Siemens',       'customer',       '172.17.0.0/16'),
    -- EU-EAST
    ('172.20.0.0/16',    4, 900,  'EU-East Core',                  'infrastructure', NULL),
    ('172.20.1.0/24',    4, 901,  'EU-East Management',            'management',     '172.20.0.0/16'),
    ('172.21.0.0/16',    4, 1000, 'EU-East Customer Block',        'customer',       NULL),
    -- APAC-JP
    ('192.168.0.0/16',   5, NULL, 'APAC-JP Supernet',              'infrastructure', NULL),
    ('192.168.1.0/24',   5, 1100, 'APAC-JP Core',                  'infrastructure', '192.168.0.0/16'),
    ('192.168.10.0/24',  5, 1110, 'APAC-JP Customer - SoftBank',   'customer',       '192.168.0.0/16'),
    ('192.168.20.0/24',  5, 1120, 'APAC-JP Customer - Rakuten',    'customer',       '192.168.0.0/16'),
    -- APAC-SG
    ('10.200.0.0/16',    6, 1200, 'APAC-SG Core',                  'infrastructure', NULL),
    ('10.200.1.0/24',    6, 1201, 'APAC-SG Management',            'management',     '10.200.0.0/16'),
    ('10.201.0.0/16',    6, 1300, 'APAC-SG Customer Block',        'customer',       NULL),
    -- LATAM
    ('10.50.0.0/16',     7, 1400, 'LATAM Core',                    'infrastructure', NULL),
    ('10.50.1.0/24',     7, 1401, 'LATAM Management',              'management',     '10.50.0.0/16'),
    ('10.51.0.0/16',     7, 1500, 'LATAM Customer Block',          'customer',       NULL);

-- ─── Customers ──────────────────────────────────────────────────────────────
INSERT INTO customers (customer_name, region_id, tier, assigned_subnet) VALUES
    ('Acme Corp',             1, 'enterprise', '10.20.1.0/24'),
    ('Globex International',  1, 'enterprise', '10.20.2.0/24'),
    ('Initech Solutions',     2, 'premium',    '10.129.1.0/24'),
    ('Siemens Digital',       3, 'enterprise', '172.17.1.0/24'),
    ('Warsaw Dynamics',       4, 'standard',   '172.21.0.0/16'),
    ('SoftBank Mobile',       5, 'enterprise', '192.168.10.0/24'),
    ('Rakuten Services',      5, 'premium',    '192.168.20.0/24'),
    ('SingTel Enterprise',    6, 'enterprise', '10.201.0.0/16'),
    ('Telefonica Brasil',     7, 'premium',    '10.51.0.0/16'),
    ('NetVista Internal Ops',      5, 'enterprise', '192.168.1.0/24'),
    ('Verizon Peering',       1, 'enterprise', '10.30.0.0/16'),
    ('Deutsche Telekom',      3, 'enterprise', '172.17.0.0/16'),
    ('Telmex Enterprise',     7, 'standard',   '10.50.0.0/16'),
    ('AWS Transit',           2, 'enterprise', '10.128.0.0/16'),
    ('Azure Connect',         3, 'enterprise', '172.16.0.0/16');

-- ─── SLA Contracts ──────────────────────────────────────────────────────────
INSERT INTO sla_contracts (customer_id, target_availability, latency_sla_ms, jitter_sla_ms, packet_loss_sla_pct, effective_from)
SELECT
    customer_id,
    CASE tier
        WHEN 'enterprise' THEN 99.990
        WHEN 'premium'    THEN 99.950
        ELSE                   99.900
    END,
    CASE tier WHEN 'enterprise' THEN 30 WHEN 'premium' THEN 50 ELSE 80 END,
    CASE tier WHEN 'enterprise' THEN 5.0 WHEN 'premium' THEN 10.0 ELSE 15.0 END,
    CASE tier WHEN 'enterprise' THEN 0.10 WHEN 'premium' THEN 0.50 ELSE 1.00 END,
    onboarded_at
FROM customers;

-- ─── Threat Intel Feeds ─────────────────────────────────────────────────────
INSERT INTO threat_intel_feeds (feed_name, ip_range, ip_single, category, confidence, country_code, first_seen, last_seen) VALUES
    -- Known C2 infrastructure
    ('AlienVault OTX',  '185.220.101.0/24',  '185.220.101.34',   'c2',         95, 'DE', now()-interval '60 days', now()-interval '2 hours'),
    ('AlienVault OTX',  '91.219.236.0/24',   '91.219.236.222',   'c2',         92, 'RU', now()-interval '45 days', now()-interval '5 hours'),
    -- Scanners / reconnaissance
    ('Shodan Honeypot', '45.155.205.0/24',   '45.155.205.99',    'scanner',    88, 'NL', now()-interval '30 days', now()-interval '1 hour'),
    ('GreyNoise',       '198.98.56.0/24',    '198.98.56.78',     'scanner',    85, 'US', now()-interval '90 days', now()-interval '3 hours'),
    -- Tor exit nodes
    ('TOR Exit List',   '23.129.64.0/24',    '23.129.64.130',    'tor_exit',   90, 'US', now()-interval '180 days', now()-interval '30 minutes'),
    ('TOR Exit List',   '104.244.76.0/24',   '104.244.76.13',    'tor_exit',   90, 'LU', now()-interval '120 days', now()-interval '45 minutes'),
    -- DDoS botnets
    ('Spamhaus DROP',   '5.188.86.0/24',     '5.188.86.172',     'ddos',       93, 'RU', now()-interval '15 days', now()-interval '10 minutes'),
    ('Spamhaus DROP',   '209.141.33.0/24',   '209.141.33.21',    'botnet',     87, 'US', now()-interval '20 days', now()-interval '1 hour'),
    -- Exfiltration / APT
    ('CrowdStrike',     '103.224.80.0/22',   '103.224.82.15',    'exfil',      96, 'CN', now()-interval '10 days', now()-interval '4 hours'),
    ('FireEye',         '58.218.198.0/24',   '58.218.198.100',   'exfil',      91, 'CN', now()-interval '25 days', now()-interval '6 hours'),
    -- Brute-force
    ('Fail2Ban Agg',    '222.186.42.0/24',   '222.186.42.7',     'bruteforce', 82, 'CN', now()-interval '7 days',  now()-interval '20 minutes'),
    ('Fail2Ban Agg',    '218.92.0.0/16',     '218.92.0.31',      'bruteforce', 78, 'CN', now()-interval '14 days', now()-interval '2 hours');

-- ─── Geo-IP (sample blocks) ────────────────────────────────────────────────
INSERT INTO geo_ip (network, country_code, country_name, city, latitude, longitude, asn, as_org) VALUES
    ('185.220.100.0/22', 'DE', 'Germany',       'Frankfurt',  50.11550,  8.68420,  205100, 'F3 Netze'),
    ('91.219.236.0/24',  'RU', 'Russia',        'Moscow',     55.75580, 37.61730,  57043,  'Hostkey'),
    ('45.155.205.0/24',  'NL', 'Netherlands',   'Amsterdam',  52.37400,  4.88970,  212238, 'Datacamp'),
    ('198.98.56.0/24',   'US', 'United States', 'New York',   40.71430,-74.00600,  53667,  'FranTech'),
    ('23.129.64.0/24',   'US', 'United States', 'Seattle',    47.60620,-122.33210, 396507, 'Emerald Onion'),
    ('104.244.76.0/24',  'LU', 'Luxembourg',    'Luxembourg', 49.61170,  6.13000,  212906, 'Liteserver'),
    ('5.188.86.0/24',    'RU', 'Russia',        'St Petersburg',59.93430,30.33510,  49505,  'OOO Network'),
    ('209.141.33.0/24',  'US', 'United States', 'Las Vegas',  36.17490,-115.13720, 53667,  'FranTech'),
    ('103.224.80.0/22',  'CN', 'China',         'Beijing',    39.90420, 116.40740,  132203, 'Tencent'),
    ('58.218.198.0/24',  'CN', 'China',         'Nanjing',    32.06170, 118.76780,  4134,   'ChinaNet'),
    ('222.186.42.0/24',  'CN', 'China',         'Shanghai',   31.23040, 121.47370,  4812,   'ChinaTelecom'),
    ('218.92.0.0/16',    'CN', 'China',         'Jiangsu',    32.06170, 118.76780,  4134,   'ChinaNet'),
    -- Internal/private ranges for geo context
    ('10.0.0.0/8',       'US', 'United States', 'Virginia',   38.95070, -77.44720, 2914,   'NetVista America'),
    ('172.16.0.0/12',    'DE', 'Germany',       'Frankfurt',  50.11550,  8.68420,  2914,   'NetVista Europe'),
    ('192.168.0.0/16',   'JP', 'Japan',         'Tokyo',      35.68950, 139.69170, 2914,   'NetVista Japan'),
    ('10.128.0.0/16',    'US', 'United States', 'Oregon',     45.52350,-122.67620, 2914,   'NetVista America'),
    ('10.200.0.0/16',    'SG', 'Singapore',     'Singapore',   1.35210, 103.81980, 2914,   'NetVista Singapore'),
    ('10.50.0.0/16',     'BR', 'Brazil',        'São Paulo', -23.55050, -46.63330, 2914,   'NetVista LATAM');

-- ============================================================================
-- DONE — Reference data loaded
-- ============================================================================

