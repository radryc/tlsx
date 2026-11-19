package tlsx

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Mode controls whether a service speaks plaintext, TLS, or mTLS.
type Mode string

const (
	// ModeOff disables TLS entirely (plaintext). Development only.
	ModeOff Mode = "off"
	// ModeOptional serves TLS when certificates are configured but keeps a
	// plaintext listener available for migration. Not for production.
	ModeOptional Mode = "optional"
	// ModeRequired serves TLS only and verifies peers.
	ModeRequired Mode = "required"
)

// Default paths used by the local PKI installer and the cluster mounts.
const (
	DefaultDir      = "/var/run/secrets/strata-tls"
	DefaultCertFile = DefaultDir + "/tls.crt"
	DefaultKeyFile  = DefaultDir + "/tls.key"
	DefaultCAFile   = DefaultDir + "/ca.crt"
)

// EnvConfig is the standard STRATA_TLS_* contract shared by all services.
type EnvConfig struct {
	Mode              Mode
	CertFile          string
	KeyFile           string
	CAFile            string
	ServerName        string
	RequireClientCert bool
	AllowedSPIFFEIDs  []string
	ExpectedSPIFFEIDs []string
}

// LoadEnv reads STRATA_TLS_* variables.
//
//	STRATA_TLS_MODE=off|optional|required
//	STRATA_TLS_CERT_FILE, STRATA_TLS_KEY_FILE, STRATA_TLS_CA_FILE
//	STRATA_TLS_SERVER_NAME
//	STRATA_TLS_REQUIRE_CLIENT_CERT=true|false
//	STRATA_TLS_ALLOWED_SPIFFE_IDS=spiffe://...,spiffe://...
//	STRATA_TLS_EXPECTED_SPIFFE_IDS=spiffe://...
func LoadEnv() (EnvConfig, error) {
	cfg := EnvConfig{
		Mode:       Mode(strings.ToLower(strings.TrimSpace(os.Getenv("STRATA_TLS_MODE")))),
		CertFile:   envOrDefault("STRATA_TLS_CERT_FILE", DefaultCertFile),
		KeyFile:    envOrDefault("STRATA_TLS_KEY_FILE", DefaultKeyFile),
		CAFile:     envOrDefault("STRATA_TLS_CA_FILE", DefaultCAFile),
		ServerName: strings.TrimSpace(os.Getenv("STRATA_TLS_SERVER_NAME")),
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeOff
	}
	switch cfg.Mode {
	case ModeOff, ModeOptional, ModeRequired:
	default:
		return EnvConfig{}, fmt.Errorf("tlsx: invalid STRATA_TLS_MODE %q (want off, optional or required)", cfg.Mode)
	}
	requireClient := envOrDefault("STRATA_TLS_REQUIRE_CLIENT_CERT", "true")
	value, err := strconv.ParseBool(requireClient)
	if err != nil {
		return EnvConfig{}, fmt.Errorf("tlsx: invalid STRATA_TLS_REQUIRE_CLIENT_CERT: %w", err)
	}
	cfg.RequireClientCert = value
	cfg.AllowedSPIFFEIDs = splitList(os.Getenv("STRATA_TLS_ALLOWED_SPIFFE_IDS"))
	cfg.ExpectedSPIFFEIDs = splitList(os.Getenv("STRATA_TLS_EXPECTED_SPIFFE_IDS"))
	return cfg, nil
}

// ServerConfig converts the environment contract into a ServerConfig.
func (c EnvConfig) ServerConfig() ServerConfig {
	return ServerConfig{
		CertFile:          c.CertFile,
		KeyFile:           c.KeyFile,
		CAFile:            c.CAFile,
		RequireClientCert: c.RequireClientCert,
		AllowedSPIFFEIDs:  c.AllowedSPIFFEIDs,
	}
}

// ClientConfig converts the environment contract into a ClientConfig.
func (c EnvConfig) ClientConfig() ClientConfig {
	return ClientConfig{
		CertFile:          c.CertFile,
		KeyFile:           c.KeyFile,
		CAFile:            c.CAFile,
		ServerName:        c.ServerName,
		ExpectedSPIFFEIDs: c.ExpectedSPIFFEIDs,
	}
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
