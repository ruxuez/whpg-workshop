#!/bin/bash
# Warm-boot startup script: starts WHPG cluster and recovers any failed mirrors.
# Called by whpg-start.service (when gpinitsystem_complete marker exists).
set -e

source /usr/local/greenplum-db/greenplum_path.sh
export MASTER_DATA_DIRECTORY=/data/master/gpseg-1
export COORDINATOR_DATA_DIRECTORY=/data/master/gpseg-1

# Only the coordinator runs startup
if [ "$(hostname)" != "cdw" ]; then
  exit 0
fi

# Wait for segment hosts to be reachable via SSH
ssh-keyscan -t rsa cdw sdw1 sdw2 > /home/gpadmin/.ssh/known_hosts 2>/dev/null
for h in sdw1 sdw2; do
  echo "Waiting for $h..."
  for i in $(seq 1 30); do
    ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no "$h" true 2>/dev/null && break
    sleep 2
  done
done

# Ensure pg_hba.conf on all segments allows cross-host connections.
# Without this, gprecoverseg fails with "no pg_hba.conf entry" because
# it connects from the coordinator to segment Postgres instances.
HBA_RULE='host all all 0.0.0.0/0 trust'
for host in cdw sdw1 sdw2; do
  ssh -o StrictHostKeyChecking=no "$host" bash -c "
    for f in /data*/primary/gpseg*/pg_hba.conf /data*/mirror/gpseg*/pg_hba.conf /data/master/gpseg-1/pg_hba.conf; do
      [ -f \"\$f\" ] && grep -qF '$HBA_RULE' \"\$f\" || echo '$HBA_RULE' >> \"\$f\"
    done
  " 2>/dev/null || true
done

# Start the cluster
gpstart -a
