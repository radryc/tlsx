// Package pki generates a local certificate authority and short-lived
// SPIFFE-enabled certs for Strata services. It is intended for development and
// for bootstrapping a cluster; production PKI can be delivered by an external
// system (cert-manager, Vault, SPIFFE) and mounted at the same paths.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// ManifestFile is written next to the generated certificates so the
	// installer and later invocations do not need the original flags.
	ManifestFile = "bundle.json"
	// DefaultTrustDomain is the SPIFFE trust domain used by local clusters.
	DefaultTrustDomain = "strata.local"
)

// Service describes one workload certificate.
type Service struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	DNSNames  []string `json:"dns_names,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	SPIFFEID  string   `json:"spiffe_id,omitempty"`
}

// Options configures Generate.
type Options struct {
	Dir         string
	TrustDomain string
	Validity    time.Duration
	CAValidity  time.Duration
	Services    []Service
	// ReuseCA loads an existing ca.crt/ca.key instead of creating a new CA.
	ReuseCA bool
	// Force overwrites leaf certificates that already exist.
	Force bool
}

// ServiceBundle describes the files generated for one service.
type ServiceBundle struct {
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	CertFile  string    `json:"cert_file"`
	KeyFile   string    `json:"key_file"`
	CAFile    string    `json:"ca_file"`
	SPIFFEID  string    `json:"spiffe_id"`
	DNSNames  []string  `json:"dns_names"`
	NotAfter  time.Time `json:"not_after"`
}

// Bundle is the manifest written to <dir>/bundle.json.
type Bundle struct {
	Dir         string                   `json:"dir"`
	TrustDomain string                   `json:"trust_domain"`
	CAFile      string                   `json:"ca_file"`
	CAKeyFile   string                   `json:"ca_key_file"`
	CreatedAt   time.Time                `json:"created_at"`
	Services    map[string]ServiceBundle `json:"services"`
}

// Generate creates a CA (unless ReuseCA) and one certificate per service.
func Generate(opts Options) (*Bundle, error) {
	if strings.TrimSpace(opts.Dir) == "" {
		return nil, errors.New("pki: output directory is required")
	}
	if len(opts.Services) == 0 {
		return nil, errors.New("pki: at least one service is required")
	}
	if opts.TrustDomain == "" {
		opts.TrustDomain = DefaultTrustDomain
	}
	if opts.Validity <= 0 {
		opts.Validity = 30 * 24 * time.Hour
	}
	if opts.CAValidity <= 0 {
		opts.CAValidity = 365 * 24 * time.Hour
	}
	if opts.CAValidity < opts.Validity {
		opts.CAValidity = opts.Validity
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("pki: create output directory: %w", err)
	}

	caCert, caKey, err := loadOrCreateCA(opts)
	if err != nil {
		return nil, err
	}
	caFile := filepath.Join(opts.Dir, "ca.crt")
	caKeyFile := filepath.Join(opts.Dir, "ca.key")

	bundle := &Bundle{
		Dir:         opts.Dir,
		TrustDomain: opts.TrustDomain,
		CAFile:      caFile,
		CAKeyFile:   caKeyFile,
		CreatedAt:   time.Now().UTC(),
		Services:    make(map[string]ServiceBundle, len(opts.Services)),
	}

	for _, svc := range opts.Services {
		if err := validateService(svc); err != nil {
			return nil, err
		}
		svcDir := filepath.Join(opts.Dir, svc.Name)
		if err := os.MkdirAll(svcDir, 0o700); err != nil {
			return nil, fmt.Errorf("pki: create %s: %w", svcDir, err)
		}
		certFile := filepath.Join(svcDir, "tls.crt")
		keyFile := filepath.Join(svcDir, "tls.key")
		svcCAFile := filepath.Join(svcDir, "ca.crt")

		if !opts.Force {
			if _, err := os.Stat(certFile); err == nil {
				// Reuse an existing cert only when it still verifies under the CA.
				if pair, pairErr := tls.LoadX509KeyPair(certFile, keyFile); pairErr == nil && len(pair.Certificate) > 0 {
					leaf := pair.Leaf
					if leaf == nil {
						leaf, _ = x509.ParseCertificate(pair.Certificate[0])
					}
					if leaf != nil {
						if _, verifyErr := leaf.Verify(x509.VerifyOptions{
							Roots:     poolFor(caCert),
							KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
						}); verifyErr == nil && time.Now().Before(leaf.NotAfter) {
							bundle.Services[svc.Name] = bundleFor(svc, certFile, keyFile, svcCAFile, leaf)
							continue
						}
					}
				}
			}
		}

		leafPEM, keyPEM, leaf, err := issueLeaf(caCert, caKey, opts.TrustDomain, svc, opts.Validity)
		if err != nil {
			return nil, err
		}
		if err := writeFile(certFile, leafPEM, 0o644); err != nil {
			return nil, err
		}
		if err := writeFile(keyFile, keyPEM, 0o600); err != nil {
			return nil, err
		}
		if err := writeFile(svcCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), 0o644); err != nil {
			return nil, err
		}
		bundle.Services[svc.Name] = bundleFor(svc, certFile, keyFile, svcCAFile, leaf)
	}

	manifest, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("pki: encode manifest: %w", err)
	}
	if err := writeFile(filepath.Join(opts.Dir, ManifestFile), append(manifest, '\n'), 0o644); err != nil {
		return nil, err
	}
	return bundle, nil
}

// LoadManifest reads <dir>/bundle.json.
func LoadManifest(dir string) (*Bundle, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("pki: read manifest: %w", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("pki: decode manifest: %w", err)
	}
	return &bundle, nil
}

// Verify re-checks every certificate in the bundle against the CA, expiry,
// keypair and SPIFFE SAN. It returns one error per failing service.
func Verify(dir string) ([]error, error) {
	bundle, err := LoadManifest(dir)
	if err != nil {
		return nil, err
	}
	caRaw, err := os.ReadFile(bundle.CAFile)
	if err != nil {
		return nil, fmt.Errorf("pki: read CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		return nil, errors.New("pki: CA file contains no certificates")
	}
	var errs []error
	names := make([]string, 0, len(bundle.Services))
	for name := range bundle.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := bundle.Services[name]
		pair, err := tls.LoadX509KeyPair(svc.CertFile, svc.KeyFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: load keypair: %w", name, err))
			continue
		}
		leaf := pair.Leaf
		if leaf == nil && len(pair.Certificate) > 0 {
			if parsed, parseErr := x509.ParseCertificate(pair.Certificate[0]); parseErr == nil {
				leaf = parsed
			}
		}
		if leaf == nil {
			errs = append(errs, fmt.Errorf("%s: no leaf certificate", name))
			continue
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			errs = append(errs, fmt.Errorf("%s: chain verification: %w", name, err))
		}
		if time.Now().After(leaf.NotAfter) {
			errs = append(errs, fmt.Errorf("%s: certificate expired at %s", name, leaf.NotAfter.Format(time.RFC3339)))
		}
		if svc.SPIFFEID != "" && !hasURI(leaf, svc.SPIFFEID) {
			errs = append(errs, fmt.Errorf("%s: missing SPIFFE ID %s", name, svc.SPIFFEID))
		}
	}
	return errs, nil
}

func loadOrCreateCA(opts Options) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath := filepath.Join(opts.Dir, "ca.crt")
	keyPath := filepath.Join(opts.Dir, "ca.key")
	if opts.ReuseCA {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: reuse CA: %w", err)
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: reuse CA key: %w", err)
		}
		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil {
			return nil, nil, errors.New("pki: CA certificate is not PEM")
		}
		caCert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("pki: parse CA certificate: %w", err)
		}
		key, err := parseECPrivateKey(keyPEM)
		if err != nil {
			return nil, nil, err
		}
		if !key.PublicKey.Equal(caCert.PublicKey) {
			return nil, nil, errors.New("pki: CA key does not match CA certificate")
		}
		return caCert, key, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "strata-local-ca", Organization: []string{"Strata"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(opts.CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: marshal CA key: %w", err)
	}
	if err := writeFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, nil, err
	}
	if err := writeFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, nil, err
	}
	return caCert, key, nil
}

func issueLeaf(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, trustDomain string, svc Service, validity time.Duration) ([]byte, []byte, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pki: generate %s key: %w", svc.Name, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	spiffeID := svc.SPIFFEID
	if spiffeID == "" {
		spiffeID = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, svc.Namespace, svc.Name)
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pki: invalid SPIFFE ID %q: %w", spiffeID, err)
	}
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := time.Now().Add(validity)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: svc.Name, Organization: []string{"Strata"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              defaultDNSNames(svc),
		URIs:                  []*url.URL{uri},
	}
	for _, raw := range svc.IPs {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pki: create %s certificate: %w", svc.Name, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pki: parse %s certificate: %w", svc.Name, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pki: marshal %s key: %w", svc.Name, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, leaf, nil
}

func defaultDNSNames(svc Service) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 8)
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	add(svc.Name)
	add("localhost")
	if svc.Namespace != "" {
		add(svc.Name + "." + svc.Namespace)
		add(svc.Name + "." + svc.Namespace + ".svc")
		add(svc.Name + "." + svc.Namespace + ".svc.cluster.local")
	}
	for _, name := range svc.DNSNames {
		add(strings.TrimSpace(name))
	}
	return out
}

func bundleFor(svc Service, certFile, keyFile, caFile string, leaf *x509.Certificate) ServiceBundle {
	spiffeID := svc.SPIFFEID
	if spiffeID == "" && leaf != nil && len(leaf.URIs) > 0 {
		spiffeID = leaf.URIs[0].String()
	}
	dns := append([]string(nil), leaf.DNSNames...)
	notAfter := time.Time{}
	if leaf != nil {
		notAfter = leaf.NotAfter.UTC()
	}
	return ServiceBundle{
		Name:      svc.Name,
		Namespace: svc.Namespace,
		CertFile:  certFile,
		KeyFile:   keyFile,
		CAFile:    caFile,
		SPIFFEID:  spiffeID,
		DNSNames:  dns,
		NotAfter:  notAfter,
	}
}

func validateService(svc Service) error {
	if strings.TrimSpace(svc.Name) == "" {
		return errors.New("pki: service name is required")
	}
	if strings.ContainsAny(svc.Name, `/\`) || strings.Contains(svc.Name, "..") {
		return fmt.Errorf("pki: invalid service name %q", svc.Name)
	}
	if strings.ContainsAny(svc.Namespace, `/\`) || strings.Contains(svc.Namespace, "..") {
		return fmt.Errorf("pki: invalid namespace %q", svc.Namespace)
	}
	return nil
}

func parseECPrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("pki: CA key is not PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("pki: CA key is not ECDSA")
		}
		return ec, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("pki: unsupported CA key format")
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: generate serial: %w", err)
	}
	return serial, nil
}

func poolFor(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

func hasURI(cert *x509.Certificate, want string) bool {
	for _, uri := range cert.URIs {
		if uri.String() == want {
			return true
		}
	}
	return false
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("pki: write %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("pki: chmod %s: %w", path, err)
	}
	return nil
}
