#! /bin/sh
# vim:set sw=8 ts=8 noet:

set -e

# We can't use 127.0.0.1 for test endpoints because the apiserver won't let us
# created an Endpoints with that address.  Pick up the first reasonable-looking
# address from the host instead; it doesn't need Internet connectivity, it just
# needs to exist.
TEST_IP_ADDRESS=$(/sbin/ip addr | awk '/ inet / && !/127.0.0/ { print $2 }' | head -1 | cut -d/ -f1)
if [ -z "$TEST_IP_ADDRESS" ]; then
	echo >&2 "$0: cannot determine external IP address for tests"
	exit 1
fi

if [ -z "$E2E_KUBERNETES_VERSION" ]; then
	E2E_KUBERNETES_VERSION=1.6.4
fi

if [ -z "$E2E_TS_VERSION" ]; then
	E2E_TS_VERSION=7.1
fi

printf 'Using Kubernetes version: %s (change with $E2E_KUBERNETES_VERSION)\n' $E2E_KUBERNETES_VERSION
printf 'Using Traffic Server version: %s (change with $E2E_TS_VERSION)\n' $E2E_TS_VERSION
printf 'Using test IP address: %s\n' $TEST_IP_ADDRESS

download_hyperkube() {
	if [ -e "$HYPERKUBE" ]; then
		return 0
	fi
	
	echo '>>> Downloading hyperkube'
	curl -Lo$HYPERKUBE https://storage.googleapis.com/kubernetes-release/release/v${E2E_KUBERNETES_VERSION}/bin/linux/amd64/hyperkube
	chmod 755 $HYPERKUBE
}

download_etcd() {
	if [ -e "$ETCD" ]; then
		return 0
	fi

	echo '>>> Downloading etcd'
	curl -L https://storage.googleapis.com/etcd/v${ETCD_VERSION}/etcd-v${ETCD_VERSION}-linux-amd64.tar.gz | gzip -dc | tar xf - --strip-components=1 -C _test etcd-v${ETCD_VERSION}-linux-amd64/etcd
	mv _test/etcd $ETCD
	chmod 755 $ETCD
}

start_etcd() {
	printf 'starting etcd: '
	mkdir -p $TESTDIR/etcd.data
	$ETCD --data-dir $TESTDIR/etcd.data --listen-client-urls=http://127.0.0.1:42379 --listen-peer-urls=http://127.0.0.1:42380 --advertise-client-urls=http://127.0.0.1:42379 >>$TESTDIR/log 2>&1 &
	pid=$!
	echo $pid > $TESTDIR/etcd.pid

	# wait a little bit for etcd to get started
	sleep 10
	printf 'ok, pid %d\n' $pid
}

stop_etcd() {
	printf 'stopping etcd: '
	pid=$(cat $TESTDIR/etcd.pid)
	kill $pid
	wait $pid || true
	printf 'ok\n'
}

start_httpd() {
	printf 'starting httpd: '
	tests/httpd.sh $TEST_IP_ADDRESS >>$TESTDIR/log 2>&1 &
	pid=$!
	echo $pid > $TESTDIR/httpd.pid
	printf 'ok, pid %d\n' $pid
}

start_ts() {
	idir=$(pwd)/_test/ts-install-${E2E_TS_VERSION}
	printf 'starting traffic_server: '
	cp tests/e2e-kubernetes.config $idir/etc/trafficserver/kubernetes.config
	cp tests/records.config $idir/etc/trafficserver/records.config
	cp tests/plugin.config $idir/etc/trafficserver/plugin.config

	$idir/bin/traffic_server >>$TESTDIR/log 2>&1 &
	pid=$!
	echo $pid > $TESTDIR/ts.pid
	printf 'ok, pid %d\n' $pid
}

stop_ts() {
	printf 'stopping traffic_server: '
	pid=$(cat $TESTDIR/ts.pid)
	kill $pid
	wait $pid || true
	printf 'ok\n'
}

stop_httpd() {
	printf 'stopping httpd: '
	pid=$(cat $TESTDIR/httpd.pid)
	kill $pid
	wait $pid || true
	printf 'ok\n'
}

start_apiserver() {
	printf 'starting apiserver: '
	ln -s $HYPERKUBE $TESTDIR/apiserver
	$TESTDIR/apiserver --etcd-servers http://127.0.0.1:42379 --service-cluster-ip-range=10.3.0.0/24 --cert-dir $TESTDIR/apiserver-certs --insecure-port=48888 --insecure-bind-address=127.0.0.1 --secure-port=48844 --bind-address=127.0.0.1 >>$TESTDIR/log 2>&1 &
	pid=$!
	echo $pid > $TESTDIR/apiserver.pid

	# apiserver takes a little while to get started
	sleep 15
	printf 'ok, pid %d\n' $pid

}

stop_apiserver() {
	printf 'stopping apiserver: '
	pid=$(cat $TESTDIR/apiserver.pid)
	kill $pid
	wait $pid || true
	printf 'ok\n'
}

install_ts() {
	if [ -e "_test/ts-install-${E2E_TS_VERSION}" ]; then
		return 0
	fi

	echo '>>> Installing Traffic Server'

	if [ ! -d "_test/${TS_DIR}" ]; then
		if [ ! -e "_test/${TS_ARCHIVE}" ]; then
			curl -Lo_test/${TS_ARCHIVE} ${TS_URL}
		fi

		gzip -dc _test/${TS_ARCHIVE} | tar xf - -C _test
	fi

	idir=$(pwd)/_test/ts-install-${E2E_TS_VERSION}
	(	cd _test/${TS_DIR}
		if [ $TS_AUTORECONF = true ]; then
			autoreconf -if >log 2>&1 || (cat log; exit 1)
		fi
		./configure --prefix=$idir --enable-asan >log 2>&1 || (cat log; exit 1)
		make >log 2>&1 || (cat log; exit 1)
		make install >log 2>&1 || (cat log; exit 1)
	)
}

install_plugin() {
	echo '>>> Building plugin'
	idir=$(pwd)/_test/ts-install-${E2E_TS_VERSION}
	(
		rm -rf _testbuild
		mkdir _testbuild
		cd _testbuild
		../configure --with-tsxs=$idir/bin/tsxs >$TESTDIR/blog 2>&1 \
			|| (cat $TESTDIR/blog; exit 1)
		make >$TESTDIR/blog 2>&1 || (cat $TESTDIR/blog; exit 1)
		cp kubernetes.so $idir/libexec/trafficserver/
		cd ..
		rm -rf _testbuild
	)
}

_actually_runtest() {
	test=$1

	printf 'Creating resources for test...\n'
	for resource in tests/e2e/$test/resources/*.json; do
		sed -e "s/\$TEST_IP_ADDRESS/$TEST_IP_ADDRESS/g" \
			$resource >$TESTDIR/tmp.json

		if ! $KUBECTL create -f $TESTDIR/tmp.json; then
			return 1
		fi
	done

	# wait a few seconds for TS to notice the resource changes
	sleep 5

	if tests/e2e/$test/run.sh; then
		return 0
	else
		return 1
	fi
}

_runtest() {
	test=$1
	status=0

	TESTS_RUN=$(expr $TESTS_RUN + 1)

	printf '\n\n'
	printf '#############################################################\n'
	printf '>>> Running test: %s\n\n' $test

	if _actually_runtest $1; then
		TESTS_OK=$(expr $TESTS_OK + 1)
	else
		TESTS_FAILED=$(expr $TESTS_FAILED + 1)
		printf '\n*** TEST FAILED ***\n'
		status=1
	fi

	printf '\n>>> Cleaning up.\n'
	$KUBECTL delete -f tests/e2e/$test/resources || true
	printf '\n>>> Finished test: %s\n' $test
	printf '#############################################################\n\n'
}

if [ -z "$E2E_KUBERNETES_VERSION" ]; then
	echo >&2 "$0: expected \$E2E_KUBERNETES_VERSION to be set"
	exit 1
fi

if [ -z "$E2E_TS_VERSION" ]; then
	echo >&2 "$0: expected \$E2E_TS_VERSION to be set"
	exit 1
fi

# Sometimes we need to build TS from Git.
case $E2E_TS_VERSION in
	7.1)
		TS_URL=https://github.com/apache/trafficserver/archive/7.1.x.tar.gz
		TS_ARCHIVE=trafficserver-7.1.x.tar.gz
		TS_DIR=trafficserver-7.1.x
		TS_AUTORECONF=true
		;;
	*)
		TS_URL=http://www-eu.apache.org/dist/trafficserver/trafficserver-${E2E_TS_VERSION}.tar.gz
		TS_ARCHIVE=trafficserver-${E2E_TS_VERSION}.tar.gz
		TS_DIR=trafficserver-$E2E_TS_VERSION
		TS_AUTORECONF=false
		;;
esac

case $E2E_KUBERNETES_VERSION in
	1.6.*)
		ETCD_VERSION=3.1.5
		;;
	*)
		echo >&2 "$0: unsupported Kubernetes version $E2E_KUBERNETES_VERSION"
		exit 1
		;;
esac

HYPERKUBE=$(pwd)/_test/hyperkube-$E2E_KUBERNETES_VERSION
ETCD=$(pwd)/_test/etcd-$ETCD_VERSION

TESTDIR=$(mktemp -d /tmp/test.XXXXXX)
ln -s $HYPERKUBE $TESTDIR/kubectl

TESTS_RUN=0
TESTS_OK=0
TESTS_FAILED=0

KUBECTL="$TESTDIR/kubectl --kubeconfig=$(pwd)/tests/kubeconfig"

mkdir -p _test
download_etcd
download_hyperkube
install_ts
install_plugin

cleanup() {
	stop_ts || true
	stop_httpd || true
	stop_apiserver || true
	stop_etcd || true
	rm -rf $TESTDIR
}
trap cleanup TERM INT

start_etcd
start_apiserver
start_httpd
start_ts

for test in $(cd tests/e2e; echo * | sort); do
	_runtest $test
done


printf '>>> Ran %d tests, %d ok, %d failed\n' $TESTS_RUN $TESTS_OK $TESTS_FAILED
exit=0
if [ $TESTS_RUN -ne $TESTS_OK ]; then
	printf '*** FAILED.\n\n'
	echo '------------------- log output: -------------------'
	cat $TESTDIR/log
	echo '---------------------------------------------------'
	exit=1
fi

cleanup
exit $exit
