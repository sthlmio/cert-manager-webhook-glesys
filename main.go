package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	v1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&glesysDNSProviderSolver{},
	)
}

// glesysDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type glesysDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// glesysDNSProviderConfig is a structure that is used to decode into when
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
type glesysDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.
	Project         string               `json:"project"`
	APIURL          string               `json:"apiURL,omitempty"`
	APIKeySecretRef v1.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *glesysDNSProviderSolver) Name() string {
	return "glesys"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *glesysDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("error loading config: %v", err)
	}

	apiKey, err := c.getAPIKey(ch.ResourceNamespace, cfg.APIKeySecretRef)
	if err != nil {
		return err
	}

	domain, host := prepareDomainAndHost(ch.ResolvedZone, ch.ResolvedFQDN)

	recordID, err := c.findRecord(&cfg, apiKey, domain, host, "TXT", ch.Key)
	if err != nil {
		return err
	}

	if recordID != 0 {
		return nil
	}

	addBody := map[string]string{
		"domainname": domain,
		"host":       host,
		"type":       "TXT",
		"data":       ch.Key,
		"ttl":        "300",
	}

	resp, err := c.makeRequest(http.MethodPost, "/domain/addrecord", addBody, &cfg, apiKey)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *glesysDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("error loading config: %v", err)
	}

	apiKey, err := c.getAPIKey(ch.ResourceNamespace, cfg.APIKeySecretRef)
	if err != nil {
		return err
	}

	domain, host := prepareDomainAndHost(ch.ResolvedZone, ch.ResolvedFQDN)

	recordID, err := c.findRecord(&cfg, apiKey, domain, host, "TXT", ch.Key)
	if err != nil {
		return err
	}

	if recordID == 0 {
		return nil
	}

	deleteBody := map[string]string{
		"recordid": fmt.Sprintf("%d", recordID),
	}

	resp, err := c.makeRequest(http.MethodPost, "/domain/deleterecord", deleteBody, &cfg, apiKey)
	if err != nil {
		return err
	}
	resp.Body.Close()
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
func (c *glesysDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (glesysDNSProviderConfig, error) {
	cfg := glesysDNSProviderConfig{
		APIURL: "https://api.glesys.com",
	}

	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *glesysDNSProviderSolver) findRecord(cfg *glesysDNSProviderConfig, apiKey, domain, host, recordType, data string) (int, error) {
	resp, err := c.makeRequest(
		http.MethodPost,
		"/domain/listrecords",
		map[string]string{"domainname": domain},
		cfg,
		apiKey,
	)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var listResp listRecordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return 0, fmt.Errorf("error decoding response: %v", err)
	}

	for _, record := range listResp.Response.Records {
		if record.Host == host && record.Type == recordType && record.Data == data {
			return record.RecordID, nil
		}
	}

	return 0, nil
}

type listRecordsResponse struct {
	Response struct {
		Records []struct {
			RecordID int    `json:"recordid"`
			Host     string `json:"host"`
			Type     string `json:"type"`
			Data     string `json:"data"`
		} `json:"records"`
	} `json:"response"`
}

func (c *glesysDNSProviderSolver) makeRequest(method, path string, body interface{}, cfg *glesysDNSProviderConfig, apiKey string) (*http.Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body: %v", err)
	}

	req, err := http.NewRequest(method, cfg.APIURL+path, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(cfg.Project, apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("error from API (status %d): %s", resp.StatusCode, string(body))
	}

	return resp, nil
}

func (c *glesysDNSProviderSolver) getAPIKey(namespace string, secretRef v1.SecretKeySelector) (string, error) {
	secret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secretRef.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting secret: %v", err)
	}

	apiKey := string(secret.Data[secretRef.Key])
	if apiKey == "" {
		return "", fmt.Errorf("secret %q does not contain key %q", secretRef.Name, secretRef.Key)
	}

	return apiKey, nil
}

func prepareDomainAndHost(resolvedZone, resolvedFQDN string) (string, string) {
	domain := resolvedZone
	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	recordName := resolvedFQDN
	if recordName[len(recordName)-1] == '.' {
		recordName = recordName[:len(recordName)-1]
	}

	host := recordName[:len(recordName)-len(domain)-1]
	return domain, host
}
