package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// A Ziro OS host's API uses a self-signed certificate until you give it a real one. `zirocd trust`
// saves that certificate (after you've compared its fingerprint) in the user's config directory;
// `zirocd deploy` then verifies the host against it, name and all, like a pinned CA.

var trustNameRe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// hostPort is the host:port of an https API URL (port 443 when none is given).
func hostPort(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf("%q: want an https:// URL like https://10.0.0.5:8443", raw)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

func trustFile(hostport string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "zirocd", "trusted", trustNameRe.ReplaceAllString(hostport, "_")+".crt"), nil
}

// trustedCert is the certificate saved for the API at raw (nil when none).
func trustedCert(raw string) []byte {
	hp, err := hostPort(raw)
	if err != nil {
		return nil
	}
	p, err := trustFile(hp)
	if err != nil {
		return nil
	}
	b, _ := os.ReadFile(p)
	return b
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// peerCert fetches the certificate a server presents, without trusting it.
func peerCert(hostport string) (*x509.Certificate, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", hostport, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // #nosec G402 -- only reads the certificate to show it; nothing is sent
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("the server presented no certificate")
	}
	return certs[0], nil
}

func trustCmd() *cobra.Command {
	var want string
	var yes, remove bool
	c := &cobra.Command{
		Use:   "trust <https-url>",
		Short: "Trust a Ziro OS host's self-signed certificate",
		Long: `Fetches the certificate the host's API presents, shows its fingerprint and, once you confirm,
saves it so zirocd deploy verifies that host against it (the address must still match the
certificate). Compare the fingerprint with the one ziroctl api start prints on the host, or pass
it with --fingerprint to check it without a prompt.`,
		Example: `  zirocd trust https://10.0.0.5:8443
  zirocd trust https://10.0.0.5:8443 --fingerprint sha256:3f9c...
  zirocd trust https://10.0.0.5:8443 --remove`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hp, err := hostPort(args[0])
			if err != nil {
				return err
			}
			path, err := trustFile(hp)
			if err != nil {
				return err
			}
			if remove {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					return err
				}
				fmt.Printf("✓ no longer trusting %s\n", hp)
				return nil
			}
			cert, err := peerCert(hp)
			if err != nil {
				return err
			}
			fp := fingerprint(cert.Raw)
			var sans []string
			for _, ip := range cert.IPAddresses {
				sans = append(sans, ip.String())
			}
			sans = append(sans, cert.DNSNames...)
			fmt.Printf("%s presents:\n  fingerprint %s\n  subject     %s\n  names       %s\n  expires     %s\n",
				hp, fp, cert.Subject, strings.Join(sans, ", "), cert.NotAfter.Local().Format("2006-01-02"))
			switch {
			case want != "":
				if !strings.EqualFold(strings.TrimSpace(want), fp) {
					return fmt.Errorf("fingerprint mismatch: expected %s", want)
				}
			case yes:
			default:
				fmt.Print("Trust this certificate? [y/N] ")
				ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
					return errors.New("not trusted")
				}
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return err
			}
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
				return err
			}
			fmt.Printf("✓ trusted: %s\n", path)
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&want, "fingerprint", "", "trust only a certificate with this fingerprint (sha256:...)")
	f.BoolVar(&yes, "yes", false, "trust what the host presents without asking (use --fingerprint when you can)")
	f.BoolVar(&remove, "remove", false, "forget the saved certificate for this host")
	return c
}

// trustHint says what to do about a certificate error, the usual first-run failure against a host
// with a self-signed certificate.
func trustHint(err error, host string) error {
	if strings.Contains(err.Error(), "x509:") {
		return fmt.Errorf("%w\n  the host's certificate isn't trusted. If it is self-signed, trust it once: zirocd trust %s", err, host)
	}
	return err
}
