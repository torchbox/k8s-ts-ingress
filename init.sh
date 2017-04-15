#! /bin/sh

set -e

mkdir -p /var/lib/trafficserver
mkdir -p /var/log/trafficserver

# Default to 128MB cache size.
CACHEFILE=/var/lib/trafficserver/cache.db
: ${TS_CACHE_SIZE=128}

if [ \( ! -f "$CACHEFILE" \) -o "$(stat -c%s $CACHEFILE)" != $(expr $TS_CACHE_SIZE '*' 1024 '*' 1024) ]; then
	echo 'init.sh: initialising cache file'
	rm -f $CACHEFILE
	dd if=/dev/zero of=$CACHEFILE bs=1M count=128
fi

cat >/usr/local/etc/trafficserver/storage.config <<__EOF__
${CACHEFILE} ${TS_CACHE_SIZE}M
__EOF__

echo "CONFIG proxy.config.proxy_name STRING $(hostname)" >>/usr/local/etc/trafficserver/records.config

chown -R nobody:nogroup /var/log/trafficserver /var/lib/trafficserver

# We are running.
touch /run/ts-alive

exec /usr/local/bin/traffic_cop -o
