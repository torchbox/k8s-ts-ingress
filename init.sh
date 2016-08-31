#! /bin/sh

CLUSTER_DNS_SUFFIX=$(sed -ne '/^search / { s/^search [a-zA-Z0-9-]*\.\([^ ]*\) .*$/\1/; p }' </etc/resolv.conf)
export CLUSTER_DNS_SUFFIX

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

chown -R nobody:nogroup /var/log/trafficserver /var/lib/trafficserver

/remap.pl

(
	while true; do
		sleep 30
		/remap.pl
	done
) &

# We are running.
touch /run/ts-alive

#exec su --preserve-environment -s /bin/sh nobody -c "exec /usr/local/bin/traffic_cop -o --debug"
exec /usr/local/bin/traffic_manager 
