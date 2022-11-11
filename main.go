package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/linode/linodego"
	"golang.org/x/oauth2"
)

// GroupName is the K8s API group
var GroupName = os.Getenv("GROUP_NAME")

// PodNamespace is the namespace of the webhook pod
var PodNamespace = os.Getenv("POD_NAMESPACE")

// PodSecretName is the name of the secret to obtain the Linode API token from
var PodSecretName = os.Getenv("POD_SECRET_NAME")

// PodSecretKey is the key of the Linode API token within the secret POD_SECRET_NAME
var PodSecretKey = os.Getenv("POD_SECRET_KEY")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	klog.InitFlags(nil)

	// This will register our external-dns DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&linodeDNSProviderSolver{},
	)
}

// linodeDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record to Linode.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type linodeDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
	ctx    context.Context
}

// linodeDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type linodeDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	// Expect apiKeySecretRef with name: <secret name> and key: <token field in secret>
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *linodeDNSProviderSolver) Name() string {
	return "linode"
}

// Returns a linodego Client object, with Oauth token configured
func (c *linodeDNSProviderSolver) getLinodeClient(ch *v1alpha1.ChallengeRequest) (*linodego.Client, error) {
	// Load config parsed from K8s
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	// Extract Linode token from K8s secret provided by config apiKeySecretRef
	apiKey, err := c.getAPIKey(&cfg, ch.ResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve Linode API token from secret: %v", err)
	}

	// Create Linodego Client
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *apiKey})

	oauth2Client := &http.Client{
		Transport: &oauth2.Transport{
			Source: tokenSource,
		},
	}

	linodeClient := linodego.NewClient(oauth2Client)
	linodeClient.SetUserAgent(fmt.Sprintf("cert-manager-webhook-linode/v0.2.0 linodego/%s", linodego.Version))

	return &linodeClient, nil
}

// Returns all record entries in a given Linode DNS Manager zone, specified by the domain parameter
func (c *linodeDNSProviderSolver) fetchZone(linodeClient *linodego.Client, domain string) (*linodego.Domain, error) {
	// List domains
	allZones, err := linodeClient.ListDomains(c.ctx, linodego.NewListOptions(0, ""))
	if err != nil {
		return nil, err
	}

	// Search for desired zone in domains
	for _, zone := range allZones {
		if zone.Domain == domain {
			return &zone, nil
		}
	}

	return nil, nil
}

// Returns the details of a given record entry in a given Linode DNS Manager zone, specified by the zone's ID and the record
func (c *linodeDNSProviderSolver) fetchRecord(linodeClient *linodego.Client, zoneID int, entry string) (*linodego.DomainRecord, error) {
	// List records in zone
	records, err := linodeClient.ListDomainRecords(c.ctx, zoneID, nil)
	if err != nil {
		return nil, err
	}

	// Find entry in zone records
	for _, record := range records {
		if record.Name == entry && string(record.Type) == "TXT" {
			return &record, nil
		}
	}

	return nil, nil
}

// Returns the details of a given record entry in Linode DNS Manager, specified by the domain and record
// Wraper for fetchZone and fetchRecord
func (c *linodeDNSProviderSolver) fetchZoneAndRecord(linodeClient *linodego.Client, domain string, entry string) (*linodego.Domain, *linodego.DomainRecord, error) {
	zone, err := c.fetchZone(linodeClient, domain)
	if err != nil {
		return zone, nil, fmt.Errorf("Failed to fetch zone `%s`: %v", domain, err)
	} else if zone == nil {
		return zone, nil, fmt.Errorf("Failed to find zone for `%s`", domain)
	}

	record, err := c.fetchRecord(linodeClient, zone.ID, entry)
	if err != nil {
		return zone, record, fmt.Errorf("Failed to fetch record `%s` in zone `%s`: %v", entry, domain, err)
	}

	return zone, record, nil
}

// Present is responsible for actually presenting the DNS record with the
// Linode DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *linodeDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("Presented with challenge for fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)

	linodeClient, err := c.getLinodeClient(ch)
	if err != nil {
		return err
	}

	entry, domain := c.getDomainAndEntry(ch)

	zone, record, err := c.fetchZoneAndRecord(linodeClient, domain, entry)
	if err != nil {
		return err
	}

	if record != nil {
		// If entry already exists, update it
		klog.V(6).Infof("Updating record for `%s` in zone `%s`", record.Name, zone.Domain)
		_, err := linodeClient.UpdateDomainRecord(
			c.ctx,
			zone.ID,
			record.ID,
			linodego.DomainRecordUpdateOptions{
				Name:     record.Name,
				Target:   ch.Key,
				Type:     linodego.RecordTypeTXT,
				Weight:   getWeight(),
				Port:     getPort(),
				Priority: getPriority(),
				TTLSec:   180,
			})
		if err != nil {
			return fmt.Errorf("Failed to update record: %v", err)
		}
	} else {
		// Create if it does not exist
		klog.V(6).Infof("Creating new record `%s` in zone `%s`", entry, zone.Domain)
		_, err := linodeClient.CreateDomainRecord(
			c.ctx,
			zone.ID,
			linodego.DomainRecordCreateOptions{
				Name:     entry,
				Target:   ch.Key,
				Type:     linodego.RecordTypeTXT,
				Weight:   getWeight(),
				Port:     getPort(),
				Priority: getPriority(),
				TTLSec:   180,
			})
		if err != nil {
			return fmt.Errorf("Failed to create record: %v", err)
		}
	}

	return nil
}

// Pointer int wrappers
func getWeight() *int {
	weight := 1
	return &weight
}

func getPort() *int {
	port := 0
	return &port
}

func getPriority() *int {
	priority := 0
	return &priority
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *linodeDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("Cleaning up challenge for fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)

	linodeClient, err := c.getLinodeClient(ch)
	if err != nil {
		return err
	}

	entry, domain := c.getDomainAndEntry(ch)

	zone, record, err := c.fetchZoneAndRecord(linodeClient, domain, entry)
	if err != nil {
		return err
	}

	if record != nil {
		// If entry already exists, delete it
		klog.V(6).Infof("Deleting record `%s` from zone `%s`", record.Name, zone.Domain)
		err := linodeClient.DeleteDomainRecord(c.ctx, zone.ID, record.ID)
		if err != nil {
			return fmt.Errorf("Failed to delete record: %v", err)
		}
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *linodeDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.V(6).Info("Initializing")

	// Make a Kubernetes clientset available
	var err error
	c.client, err = kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	// Make context
	c.ctx = context.Background()

	return nil
}

// Returns a given data key from a given secret as a string
func (c *linodeDNSProviderSolver) stringFromSecret(namespace, secretName, key string) (*string, error) {
	// Get secret
	secret, err := c.client.CoreV1().Secrets(namespace).Get(c.ctx,
		secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// Extract token from secret
	tokenBinary, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("Key `%q` not found in secret `%s/%s`",
			key, namespace, secretName)
	}

	token := string(tokenBinary)
	return &token, nil
}

func (c *linodeDNSProviderSolver) certNamespaceToken(namespace string, secretRef cmmeta.SecretKeySelector) (*string, error) {
	if secretRef.LocalObjectReference.Name == "" {
		return nil, fmt.Errorf("Linode API token secret in certificate namespace not specified")
	}

	token, err := c.stringFromSecret(namespace, secretRef.LocalObjectReference.Name, secretRef.Key)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (c *linodeDNSProviderSolver) podNamespaceToken() (*string, error) {
	// Get pod namespace
	namespace := PodNamespace
	if namespace == "" {
		data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return nil, fmt.Errorf("Failed to find the webhook pod namespace: %v", err)
		}
		namespace = strings.TrimSpace(string(data))
		if len(namespace) == 0 {
			return nil, fmt.Errorf("Invalid webhook pod namespace provided")
		}
	}

	// Get secret
	token, err := c.stringFromSecret(namespace, PodSecretName, PodSecretKey)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// Get Linode API token from Kubernetes secret.
func (c *linodeDNSProviderSolver) getAPIKey(cfg *linodeDNSProviderConfig, namespace string) (*string, error) {
	// Get token from secret in the same namespace as the certificate if possible
	token, err := c.certNamespaceToken(namespace, cfg.APIKeySecretRef)
	if err == nil {
		return token, nil
	}

	// Fallback to default secret in the same namespace as the webhook pod
	klog.V(6).Infof("Failed to use certificate namespace Linode API token secret: %v", err)
	klog.V(6).Info("Trying webhook pod namespace Linode API token secret")
	token, err = c.podNamespaceToken()
	if err == nil {
		return token, nil
	}

	return nil, fmt.Errorf("Failed to read Linode API token secret: %v", err)
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (linodeDNSProviderConfig, error) {
	cfg := linodeDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *linodeDNSProviderSolver) getDomainAndEntry(ch *v1alpha1.ChallengeRequest) (string, string) {
	// Strip the zone from the fqdn to yield the entry (subdomain)
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".") // Also remove any stray .

	// Remove trailing . from domain
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")

	return entry, domain
}
