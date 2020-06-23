IMAGE_NAME := "slicen/cert-manager-webhook-linode"
IMAGE_TAG := "v0.1.0"

OUT := $(shell pwd)/_out

$(shell mkdir -p "$(OUT)")

.DEFAULT_GOAL := build

.PHONY: verify test build clean rendered-manifest.yaml

verify:
	go test -v .

test: verify

build:
	docker build --rm -t "$(IMAGE_NAME):$(IMAGE_TAG)" -t "$(IMAGE_NAME):latest" .

clean:
	rm -r "$(OUT)"

rendered-manifest.yaml:
	helm template \
        --set image.repository=$(IMAGE_NAME) \
        --set image.tag=$(IMAGE_TAG) \
        deploy/cert-manager-webhook-linode > "$(OUT)/rendered-manifest.yaml"
