#! /bin/sh
# vim:set sw=8 ts=8 noet:
#
# Copyright (c) 2016-2017 Torchbox Ltd.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


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

echo "CONFIG proxy.config.proxy_name STRING $(hostname)" \
    >>/usr/local/etc/trafficserver/records.config

chown -R nobody:nogroup /var/log/trafficserver /var/lib/trafficserver

exec /usr/local/bin/traffic_cop -o
