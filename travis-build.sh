#! /bin/sh
# vim:set sw=8 ts=8 noet:

set -ex

if [ -n "$TRAVIS_TAG" ]; then
	VERSION="$TRAVIS_TAG"
else
	VERSION=$COMMIT
fi

# Always build from a release, so we know the release process works.
make -f Makefile.dist VERSION=$VERSION release

cd k8s-ts-ingress-$VERSION

# This tests the build and runs basic unit tests.
DOCKER_REPOSITORY=torchbox/k8s-ts-ingress
docker build --pull -t $DOCKER_REPOSITORY:$COMMIT .

# Run e2e tests.
sudo apt-get -qq update
sudo apt-get -qy install libjson-c-dev libcurl4-openssl-dev libssl-dev pkg-config 
tests/e2erun.sh

# If this is a release, push the Docker image to Docker Hub.
if [ "$TRAVIS_PULL_REQUEST" = "false" -a -n "$TRAVIS_TAG" ]; then
	docker login -u $DOCKER_USER -p $DOCKER_PASSWORD
	docker tag $DOCKER_REPOSITORY:$COMMIT $DOCKER_REPOSITORY:$VERSION
	docker push $DOCKER_REPOSITORY:$VERSION
fi
