IMAGE_NAME := "slicen/cert-manager-webhook-linode"
IMAGE_TAG := "v0.1.0"

K8S_VERSION := "1.22.0"

OUT := $(shell pwd)/_out

$(shell mkdir -p "$(OUT)")

.DEFAULT_GOAL := build

.PHONY: verify test build clean _out/kubebuilder rendered-manifest.yaml

verify: _out/kubebuilder
	TEST_ASSET_ETCD=_out/kubebuilder/bin/etcd \
	TEST_ASSET_KUBECTL=_out/kubebuilder/bin/kubectl \
	TEST_ASSET_KUBE_APISERVER=_out/kubebuilder/bin/kube-apiserver \
	go test -v

_out/kubebuilder:
	mkdir -p _out/kubebuilder
	curl -fsSLo envtest-bins.tar.gz "https://go.kubebuilder.io/test-tools/${K8S_VERSION}/$(shell go env GOOS)/$(shell go env GOARCH)"
	tar -C _out/kubebuilder --strip-components=1 -zvxf envtest-bins.tar.gz
	rm envtest-bins.tar.gz

test: verify

build:
	docker build --rm -t "${IMAGE_NAME}:${IMAGE_TAG}" -t "${IMAGE_NAME}:latest" .

clean:
	rm -r "${OUT}"

rendered-manifest.yaml:
	helm template \
        --set image.repository=${IMAGE_NAME} \
        --set image.tag=${IMAGE_TAG} \
        deploy/cert-manager-webhook-linode > "${OUT}/rendered-manifest.yaml"
