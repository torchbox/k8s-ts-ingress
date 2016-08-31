build:
	docker build -t torchbox/trafficserver-ingress-controller:latest .

push:
	docker push torchbox/trafficserver-ingress-controller:latest
