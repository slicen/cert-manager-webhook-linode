module github.com/slicen/cert-manager-webhook-linode

go 1.14

require (
	github.com/jetstack/cert-manager v0.15.0
	github.com/linode/linodego v0.19.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	k8s.io/apiextensions-apiserver v0.18.3
	k8s.io/apimachinery v0.18.3
	k8s.io/client-go v0.18.3
	k8s.io/klog v1.0.0
	sigs.k8s.io/external-dns v0.7.2
)

replace (
	github.com/Azure/go-autorest/autorest/azure/auth => github.com/Azure/go-autorest/autorest/azure/auth v0.3.0
	// bring external-dns up to cert-manager dependencies
	k8s.io/api => k8s.io/api v0.18.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.3
)
