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

DOCKER_REPOSITORY=torchbox/k8s-ts-ingress
docker build --pull -t $DOCKER_REPOSITORY:$COMMIT .

if [ "$TRAVIS_PULL_REQUEST" = "false" -a -n "$TRAVIS_TAG" ]; then
	docker tag $DOCKER_REPOSITORY:$COMMIT $DOCKER_REPOSITORY:$VERSION
	docker push $DOCKER_REPOSITORY:$VERSION
fi
