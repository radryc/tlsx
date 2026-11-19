package pki

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateAndVerify(t *testing.T) {
	dir := t.TempDir()
	bundle, err := Generate(Options{
		Dir:         dir,
		TrustDomain: "strata.test",
		Validity:    time.Hour,
		Services: []Service{
			{Name: "router", Namespace: "monofs"},
			{Name: "server", Namespace: "monofs", DNSNames: []string{"node-a"}},
		},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(bundle.Services) != 2 {
		t.Fatalf("services = %d, want 2", len(bundle.Services))
	}
	router := bundle.Services["router"]
	if router.SPIFFEID != "spiffe://strata.test/ns/monofs/sa/router" {
		t.Fatalf("SPIFFE ID = %q", router.SPIFFEID)
	}
	if _, err := os.Stat(filepath.Join(dir, ManifestFile)); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	info, err := os.Stat(router.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", info.Mode().Perm())
	}
	if errs, err := Verify(dir); err != nil || len(errs) > 0 {
		t.Fatalf("Verify: %v %v", err, errs)
	}

	pair, err := tls.LoadX509KeyPair(router.CertFile, router.KeyFile)
	if err != nil {
		t.Fatalf("load pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, uri := range leaf.URIs {
		if uri.String() == router.SPIFFEID {
			found = true
		}
	}
	if !found {
		t.Fatalf("leaf is missing SPIFFE URI %s", router.SPIFFEID)
	}
	if len(leaf.DNSNames) == 0 {
		t.Fatal("leaf has no DNS names")
	}
}

func TestReuseCAKeepsIdentity(t *testing.T) {
	dir := t.TempDir()
	svc := []Service{{Name: "router", Namespace: "monofs"}}
	first, err := Generate(Options{Dir: dir, Validity: time.Hour, Services: svc})
	if err != nil {
		t.Fatal(err)
	}
	caBefore, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(first.Services["router"].CertFile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(Options{Dir: dir, Validity: time.Hour, Services: svc, ReuseCA: true})
	if err != nil {
		t.Fatal(err)
	}
	caAfter, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	certAfter, _ := os.ReadFile(second.Services["router"].CertFile)
	if string(caBefore) != string(caAfter) {
		t.Fatal("CA changed despite ReuseCA")
	}
	if string(certBefore) != string(certAfter) {
		t.Fatal("valid leaf was reissued")
	}
	third, err := Generate(Options{Dir: dir, Validity: time.Hour, Services: svc, ReuseCA: true, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	certForced, _ := os.ReadFile(third.Services["router"].CertFile)
	if string(certBefore) == string(certForced) {
		t.Fatal("Force did not reissue the leaf")
	}
}

func TestVerifyDetectsBrokenCertificate(t *testing.T) {
	dir := t.TempDir()
	bundle, err := Generate(Options{
		Dir:        dir,
		Validity:   time.Hour,
		CAValidity: time.Hour,
		Services:   []Service{{Name: "router", Namespace: "monofs"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := bundle.Services["router"]
	if err := os.WriteFile(svc.CertFile, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if errs, err := Verify(dir); err != nil {
		t.Fatal(err)
	} else if len(errs) == 0 {
		t.Fatal("Verify accepted a broken certificate")
	}
}
