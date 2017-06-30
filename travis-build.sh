#! /bin/sh
# vim:set sw=8 ts=8 noet:

set -e

if [ -n "$TRAVIS_TAG" ]; then
	VERSION="$TRAVIS_TAG"
else
	VERSION="v$(sed -ne '/AC_INIT/ {s/.*, \[\(.*\)\].*/\1/; p}' configure.ac)-dev"
fi

printf 'travis_fold:start:build-release\r'
printf '>>> Building release.\n\n'

# Always build from a release, so we know the release process works.
make -f Makefile.dist VERSION=$VERSION release

printf 'travis_fold:end:build-release\r'

cd k8s-ts-ingress-$VERSION

printf 'travis_fold:start:build-docker\r'
printf '>>> Building Docker image.\n\n'
# This tests the build and runs basic unit tests.
DOCKER_REPOSITORY=torchbox/k8s-ts-ingress
docker build --pull --build-arg build_id=${TRAVIS_BUILD_NUMBER} \
					     -t $DOCKER_REPOSITORY:$COMMIT .
printf 'travis_fold:end:build-docker\r'

printf 'travis_fold:start:test-e2e\r'
printf '>>> Running end-to-end tests.\n\n'
# Run e2e tests.
sudo apt-get -qq update
sudo apt-get -qy install libjson-c-dev libcurl4-openssl-dev libssl-dev \
	     netcat-traditional pkg-config
tests/e2erun.sh
printf 'travis_fold:end:test-e2e\r'

# If this is a release, push the Docker image to Docker Hub.
if [ "$TRAVIS_PULL_REQUEST" = "false" ]; then
	printf 'travis_fold:start:release\r'
	printf '>>> Creating release.\n\n'

	docker login -u $DOCKER_USER -p $DOCKER_PASSWORD
	docker tag $DOCKER_REPOSITORY:$COMMIT $DOCKER_REPOSITORY:$VERSION
	docker push $DOCKER_REPOSITORY:$VERSION
	printf 'travis_fold:end:release\r'
fi
