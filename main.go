package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"k8s.io/klog/v2"
	"net/http"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	//"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func login(config customDNSProviderConfig) (string, error) {
	klog.Info("Login to netcup")
	buffer := bytes.NewBufferString(fmt.Sprintf("{\"action\": \"login\", \"param\":{ \"apikey\":\"%s\", \"apipassword\":\"%s\",\"customernumber\":\"%s\"\n}}", config.ApiKey, config.ApiPw, config.CustomerNumber))
	res, err := http.Post("https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON", "application/json", buffer)
	if err != nil {
		return "", err
	}

	type response struct {
		ResponseData struct {
			ApiSessionId string `json:"apisessionid"`
		} `json:"responsedata"`
	}

	var data response

	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&data)
	if err != nil {
		return "", err
	}

	return data.ResponseData.ApiSessionId, nil
}

func logout(config customDNSProviderConfig, token string) error {
	klog.Info("Logout from netcup")
	buffer := bytes.NewBufferString(fmt.Sprintf("{\"action\": \"logout\", \"param\":{ \"apikey\":\"%s\", \"apisessionid\":\"%s\",\"customernumber\":\"%s\"\n}}", config.ApiKey, token, config.CustomerNumber))
	res, err := http.Post("https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON", "application/json", buffer)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusFound {
		return fmt.Errorf("failed to set txt record")
	}

	return nil
}

func setRecord(config customDNSProviderConfig, txtRecord, token, domainname string) error {
	klog.Info("Set dns record for domain " + domainname)
	splitDomainName := strings.Split(domainname, ".")
	host := strings.Join(splitDomainName[1:], ".")
	domain := ""
	if len(splitDomainName) == 2 {
		domain = "@"
	} else {
		domain = splitDomainName[0]
	}
	buffer := bytes.NewBufferString(fmt.Sprintf("{\n  \"action\": \"updateDnsRecords\",\n  \"param\": {\n    \"apikey\": \"%s\",\n    \"customernumber\": \"%s\",\n    \"apisessionid\": \"%s\",\n    \"domainname\": \"%s\",\n    \"dnsrecordset\": {\n      \"dnsrecords\": [\n        {\n          \"id\": \"\",\n          \"hostname\": \"%s.\",\n          \"type\": \"TXT\",\n          \"priority\": \"\",\n          \"destination\": \"%s\",\n          \"deleterecord\": \"false\",\n          \"state\": \"yes\"\n        }\n      ]\n    }\n  }\n}\n", config.ApiKey, config.CustomerNumber, token, domain, host, txtRecord))
	res, err := http.Post("https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON", "application/json", buffer)
	if err != nil {
		return err
	}

	if res.StatusCode < 300 && res.StatusCode >= 200 {
		body, err := ioutil.ReadAll(res.Body)
		if err == nil {
			return fmt.Errorf("failed to set txt record %s: %s", domainname, string(body))
		}

		return fmt.Errorf("failed to set txt record")
	}

	return nil
}

func removeRecord(config customDNSProviderConfig, txtRecord, token, domainname string) error {
	klog.Info("Remove dns record for domain " + domainname)
	splitDomainName := strings.Split(domainname, ".")
	host := strings.Join(splitDomainName[1:], ".")
	domain := ""
	if len(splitDomainName) == 2 {
		domain = "@"
	} else {
		domain = splitDomainName[0]
	}
	buffer := bytes.NewBufferString(fmt.Sprintf("{\n  \"action\": \"updateDnsRecords\",\n  \"param\": {\n    \"apikey\": \"%s\",\n    \"customernumber\": \"%s\",\n    \"apisessionid\": \"%s\",\n    \"domainname\": \"%s\",\n    \"dnsrecordset\": {\n      \"dnsrecords\": [\n        {\n          \"id\": \"\",\n          \"hostname\": \"%s.\",\n          \"type\": \"TXT\",\n          \"priority\": \"\",\n          \"destination\": \"%s\",\n          \"deleterecord\": \"true\",\n          \"state\": \"yes\"\n        }\n      ]\n    }\n  }\n}\n", config.ApiKey, config.CustomerNumber, token, domain, host, txtRecord))
	res, err := http.Post("https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON", "application/json", buffer)
	if err != nil {
		return err
	}

	if res.StatusCode < 300 && res.StatusCode >= 200 {
		body, err := ioutil.ReadAll(res.Body)
		if err == nil {
			return fmt.Errorf("failed to remove txt record %s: %s", domainname, string(body))
		}

		return fmt.Errorf("failed to remove txt record")
	}

	return nil
}

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
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	//client kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
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
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
	ApiKey         string `json:"apiKey"`
	ApiPw          string `json:"apiPw"`
	CustomerNumber string `json:"customerNumber"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "netcup"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	token, err := login(cfg)
	if err != nil {
		klog.Error(err)
		return err
	}

	err = setRecord(cfg, ch.Key, token, ch.ResolvedFQDN)
	if err != nil {
		klog.Error(err)
		return err
	}

	return logout(cfg, token)
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.Error(err)
		return err
	}

	token, err := login(cfg)
	if err != nil {
		klog.Error(err)
		return err
	}

	err = removeRecord(cfg, ch.Key, token, ch.ResolvedFQDN)
	if err != nil {
		klog.Error(err)
		return err
	}

	return logout(cfg, token)
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
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	//cl, err := kubernetes.NewForConfig(kubeClientConfig)
	//if err != nil {
	//	return err
	//}
	//
	//c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
