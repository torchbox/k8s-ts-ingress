
TSDIR?=		/usr/local/trafficserver
CGO_CPPFLAGS?=	-I${TSDIR}/include

SRC=	main.go			\
	controller.go

kubernetes.so: ${SRC}
	CGO_CPPFLAGS="${CGO_CPPFLAGS}" go build -o kubernetes.so -buildmode=c-shared ${SRC}

build:
	#docker build --pull -t torchbox/trafficserver-ingress-controller:latest .

push:
	docker push torchbox/trafficserver-ingress-controller:latest
