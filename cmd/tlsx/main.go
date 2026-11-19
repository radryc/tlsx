// Command tlsx generates a local SPIFFE-enabled PKI and installs it into a
// Kubernetes cluster. It is the "works locally" path for Strata mTLS; a
// production deployment can replace the generated certs with cert-manager or
// Vault output mounted at the same paths.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/radryc/tlsx/pki"
)

const secretPrefix = "strata-tls"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tlsx:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "gen":
		return runGen(args[1:])
	case "install":
		return runInstall(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "env":
		return runEnv(args[1:])
	case "list":
		return runList(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (want gen, install, verify, env, list)", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tlsx - local SPIFFE PKI for Strata

  tlsx gen       [--dir .tls] [--trust-domain strata.local] [--validity 720h]
                 [--reuse-ca] [--force]
  tlsx install   [--dir .tls] [--kubeconfig PATH] [--context NAME]
                 [--namespace-override NS] [--dry-run]
  tlsx verify    [--dir .tls]
  tlsx env       --dir .tls --service NAME [--mode required]
  tlsx list

Typical local flow:
  tlsx gen --dir .tls --reuse-ca
  tlsx install --dir .tls
  docker compose --env-file .tls/mtls.env up -d
`)
}

func runGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	dir := fs.String("dir", ".tls", "output directory")
	trustDomain := fs.String("trust-domain", pki.DefaultTrustDomain, "SPIFFE trust domain")
	validity := fs.Duration("validity", 30*24*time.Hour, "leaf certificate validity")
	caValidity := fs.Duration("ca-validity", 365*24*time.Hour, "CA validity")
	reuseCA := fs.Bool("reuse-ca", false, "reuse an existing ca.crt/ca.key in --dir")
	force := fs.Bool("force", false, "reissue leaf certificates even if present")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := pki.Generate(pki.Options{
		Dir:         *dir,
		TrustDomain: *trustDomain,
		Validity:    *validity,
		CAValidity:  *caValidity,
		Services:    defaultServices(),
		ReuseCA:     *reuseCA,
		Force:       *force,
	})
	if err != nil {
		return err
	}
	if err := writeEnvFiles(bundle); err != nil {
		return err
	}
	fmt.Printf("generated %d service certificates in %s (CA valid until %s)\n",
		len(bundle.Services), bundle.Dir, bundle.CreatedAt.Add(*caValidity).Format("2006-01-02"))
	return nil
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dir := fs.String("dir", ".tls", "certificate directory")
	kubeconfig := fs.String("kubeconfig", "", "kubectl kubeconfig path")
	context := fs.String("context", "", "kubectl context")
	namespace := fs.String("namespace-override", "", "install every secret into this namespace instead")
	dryRun := fs.Bool("dry-run", false, "print YAML instead of applying")
	prefix := fs.String("prefix", secretPrefix, "secret name prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := pki.LoadManifest(*dir)
	if err != nil {
		return err
	}
	if errs, verifyErr := pki.Verify(*dir); verifyErr != nil {
		return verifyErr
	} else if len(errs) > 0 {
		return errors.Join(errs...)
	}
	names := make([]string, 0, len(bundle.Services))
	for name := range bundle.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := bundle.Services[name]
		ns := svc.Namespace
		if strings.TrimSpace(*namespace) != "" {
			ns = strings.TrimSpace(*namespace)
		}
		secret := *prefix + "-" + name
		createArgs := []string{"create", "secret", "generic", secret,
			"--from-file=tls.crt=" + svc.CertFile,
			"--from-file=tls.key=" + svc.KeyFile,
			"--from-file=ca.crt=" + svc.CAFile,
			"--dry-run=client", "-o", "yaml",
		}
		if ns != "" {
			createArgs = append([]string{"-n", ns}, createArgs...)
		}
		yaml, err := kubectl(*kubeconfig, *context, createArgs...)
		if err != nil {
			return fmt.Errorf("create secret %s/%s: %w", ns, secret, err)
		}
		if *dryRun {
			fmt.Printf("# %s/%s\n%s\n", ns, secret, yaml)
			continue
		}
		if _, err := kubectlInput(*kubeconfig, *context, []byte(yaml), "apply", "-f", "-"); err != nil {
			return fmt.Errorf("apply secret %s/%s: %w", ns, secret, err)
		}
		fmt.Printf("installed %s/%s\n", ns, secret)
	}
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dir := fs.String("dir", ".tls", "certificate directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := pki.LoadManifest(*dir)
	if err != nil {
		return err
	}
	if errs, verifyErr := pki.Verify(*dir); verifyErr != nil {
		return verifyErr
	} else if len(errs) > 0 {
		return errors.Join(errs...)
	}
	names := make([]string, 0, len(bundle.Services))
	for name := range bundle.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := bundle.Services[name]
		fmt.Printf("OK  %-24s %-12s expires %s  %s\n", name, svc.Namespace, svc.NotAfter.Format(time.RFC3339), svc.SPIFFEID)
	}
	return nil
}

func runEnv(args []string) error {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	dir := fs.String("dir", ".tls", "certificate directory")
	service := fs.String("service", "", "service name (required)")
	mode := fs.String("mode", "required", "STRATA_TLS_MODE value")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *service == "" {
		return errors.New("--service is required")
	}
	bundle, err := pki.LoadManifest(*dir)
	if err != nil {
		return err
	}
	svc, ok := bundle.Services[*service]
	if !ok {
		return fmt.Errorf("service %q is not in %s", *service, filepath.Join(*dir, pki.ManifestFile))
	}
	abs, err := filepath.Abs(svc.CertFile)
	if err != nil {
		return err
	}
	fmt.Printf("STRATA_TLS_MODE=%s\n", *mode)
	fmt.Printf("STRATA_TLS_CERT_FILE=%s\n", abs)
	fmt.Printf("STRATA_TLS_KEY_FILE=%s\n", absKey(svc.KeyFile))
	fmt.Printf("STRATA_TLS_CA_FILE=%s\n", absCA(svc.CAFile))
	fmt.Printf("STRATA_TLS_REQUIRE_CLIENT_CERT=true\n")
	fmt.Printf("STRATA_TLS_ALLOWED_SPIFFE_IDS=%s\n", strings.Join(allowedIDs(bundle), ","))
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Printf("%-24s %s\n", "SERVICE", "NAMESPACE")
	for _, svc := range defaultServices() {
		fmt.Printf("%-24s %s\n", svc.Name, svc.Namespace)
	}
	return nil
}

func defaultServices() []pki.Service {
	return []pki.Service{
		{Name: "monofs-router", Namespace: "monofs"},
		{Name: "monofs-server", Namespace: "monofs"},
		{Name: "monofs-search", Namespace: "monofs"},
		{Name: "monofs-fetcher", Namespace: "monofs"},
		{Name: "monofs-registry", Namespace: "monofs"},
		{Name: "monofs-cache", Namespace: "monofs"},
		{Name: "kvs", Namespace: "monofs"},
		{Name: "guardiand", Namespace: "guardian"},
		{Name: "guardian-pusher-aws", Namespace: "guardian"},
		{Name: "guardian-pusher-gcp", Namespace: "guardian"},
		{Name: "guardian-pusher-k8s", Namespace: "guardian"},
		{Name: "doctor-query", Namespace: "doctor"},
		{Name: "doctor-ingest", Namespace: "doctor"},
		{Name: "doctor-rules", Namespace: "doctor"},
		{Name: "doctor-sentinel", Namespace: "doctor"},
		{Name: "lb-registry", Namespace: "lb-edge"},
		{Name: "lb-edge", Namespace: "lb-edge"},
		{Name: "agent", Namespace: "agent"},
	}
}

func allowedIDs(bundle *pki.Bundle) []string {
	ids := make([]string, 0, len(bundle.Services))
	for _, svc := range bundle.Services {
		if svc.SPIFFEID != "" {
			ids = append(ids, svc.SPIFFEID)
		}
	}
	sort.Strings(ids)
	return ids
}

func writeEnvFiles(bundle *pki.Bundle) error {
	var all bytes.Buffer
	names := make([]string, 0, len(bundle.Services))
	for name := range bundle.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := bundle.Services[name]
		fmt.Fprintf(&all, "# %s (%s)\n", name, svc.Namespace)
		fmt.Fprintf(&all, "%s_MODE=required\n", envKey(name))
		fmt.Fprintf(&all, "%s_CERT_FILE=%s\n", envKey(name), svc.CertFile)
		fmt.Fprintf(&all, "%s_KEY_FILE=%s\n", envKey(name), svc.KeyFile)
		fmt.Fprintf(&all, "%s_CA_FILE=%s\n", envKey(name), svc.CAFile)
	}
	path := filepath.Join(bundle.Dir, "mtls.env")
	if err := os.WriteFile(path, all.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func envKey(name string) string {
	return "STRATA_TLS_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))
}

func absKey(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func absCA(path string) string {
	return absKey(path)
}

func kubectl(kubeconfig, context string, args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	if kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", kubeconfig)
	}
	if context != "" {
		cmd.Args = append(cmd.Args, "--context", context)
	}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out.String(), nil
}

func kubectlInput(kubeconfig, context string, input []byte, args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	if kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", kubeconfig)
	}
	if context != "" {
		cmd.Args = append(cmd.Args, "--context", context)
	}
	cmd.Stdin = bytes.NewReader(input)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out.String(), nil
}
