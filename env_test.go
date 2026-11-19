package tlsx

import "testing"

func TestLoadEnvDefaults(t *testing.T) {
	t.Setenv("STRATA_TLS_MODE", "")
	t.Setenv("STRATA_TLS_CERT_FILE", "")
	t.Setenv("STRATA_TLS_KEY_FILE", "")
	t.Setenv("STRATA_TLS_CA_FILE", "")
	cfg, err := LoadEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeOff {
		t.Fatalf("mode = %q, want off", cfg.Mode)
	}
	if cfg.CertFile != DefaultCertFile || cfg.KeyFile != DefaultKeyFile || cfg.CAFile != DefaultCAFile {
		t.Fatalf("unexpected default paths: %+v", cfg)
	}
	if !cfg.RequireClientCert {
		t.Fatal("RequireClientCert should default true")
	}
}

func TestLoadEnvRequired(t *testing.T) {
	t.Setenv("STRATA_TLS_MODE", "REQUIRED")
	t.Setenv("STRATA_TLS_CERT_FILE", "/tmp/tls.crt")
	t.Setenv("STRATA_TLS_KEY_FILE", "/tmp/tls.key")
	t.Setenv("STRATA_TLS_CA_FILE", "/tmp/ca.crt")
	t.Setenv("STRATA_TLS_SERVER_NAME", "router.monofs.svc")
	t.Setenv("STRATA_TLS_REQUIRE_CLIENT_CERT", "false")
	t.Setenv("STRATA_TLS_ALLOWED_SPIFFE_IDS", "spiffe://a, spiffe://b ")
	t.Setenv("STRATA_TLS_EXPECTED_SPIFFE_IDS", "spiffe://c")
	cfg, err := LoadEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeRequired {
		t.Fatalf("mode = %q", cfg.Mode)
	}
	if cfg.ServerName != "router.monofs.svc" {
		t.Fatalf("server name = %q", cfg.ServerName)
	}
	if cfg.RequireClientCert {
		t.Fatal("RequireClientCert should be false")
	}
	if len(cfg.AllowedSPIFFEIDs) != 2 || cfg.AllowedSPIFFEIDs[0] != "spiffe://a" || cfg.AllowedSPIFFEIDs[1] != "spiffe://b" {
		t.Fatalf("allowed = %v", cfg.AllowedSPIFFEIDs)
	}
	if len(cfg.ExpectedSPIFFEIDs) != 1 || cfg.ExpectedSPIFFEIDs[0] != "spiffe://c" {
		t.Fatalf("expected = %v", cfg.ExpectedSPIFFEIDs)
	}
	server := cfg.ServerConfig()
	if server.CertFile != "/tmp/tls.crt" || server.RequireClientCert {
		t.Fatalf("server config = %+v", server)
	}
	client := cfg.ClientConfig()
	if client.ServerName != "router.monofs.svc" || len(client.ExpectedSPIFFEIDs) != 1 {
		t.Fatalf("client config = %+v", client)
	}
}

func TestLoadEnvInvalidMode(t *testing.T) {
	t.Setenv("STRATA_TLS_MODE", "sometimes")
	if _, err := LoadEnv(); err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestLoadEnvInvalidRequireClient(t *testing.T) {
	t.Setenv("STRATA_TLS_MODE", "required")
	t.Setenv("STRATA_TLS_REQUIRE_CLIENT_CERT", "maybe")
	if _, err := LoadEnv(); err == nil {
		t.Fatal("expected invalid boolean error")
	}
}
