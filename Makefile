build:
	docker build --pull -t torchbox/trafficserver-ingress-controller:latest .

push:
	docker push torchbox/trafficserver-ingress-controller:latest
