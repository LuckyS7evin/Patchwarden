// Package proxmox est un client minimal, en lecture seule, de l'API Proxmox VE.
package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
)

// Resource est une entrée de /cluster/resources?type=vm (LXC ou VM).
type Resource struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"` // "lxc" ou "qemu"
	VMID     int     `json:"vmid"`
	Node     string  `json:"node"`
	Name     string  `json:"name"`
	Status   string  `json:"status"`
	Tags     string  `json:"tags"` // séparés par ";"
	Template int     `json:"template"`
	Lock     string  `json:"lock"`
	MaxCPU   float64 `json:"maxcpu"`
	MaxMem   int64   `json:"maxmem"`
	Uptime   int64   `json:"uptime"`
}

// Client interroge un point d'accès.
type Client struct {
	name    string
	baseURL string
	auth    string
	http    *http.Client
}

// New construit un client à partir d'un point d'accès validé.
func New(ep config.Endpoint, timeout time.Duration) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case ep.Fingerprint != "":
		want, err := config.ParseFingerprint(ep.Fingerprint)
		if err != nil {
			return nil, err
		}
		// Épinglage : la chaîne n'est pas vérifiée (certificat auto-signé de
		// Proxmox), mais l'empreinte du certificat présenté doit correspondre
		// exactement. VerifyConnection est appelé même avec InsecureSkipVerify.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // remplacé par l'épinglage ci-dessous
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("aucun certificat présenté")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return fmt.Errorf("empreinte du certificat inattendue (%s) : vérifiez fingerprint", formatFingerprint(got[:]))
			}
			return nil
		}
	case ep.CAFile != "":
		pem, err := os.ReadFile(ep.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s ne contient aucun certificat PEM", ep.CAFile)
		}
		tlsCfg.RootCAs = pool
	default:
		return nil, errors.New("fingerprint ou ca_file requis")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.Proxy = nil // l'API Proxmox est sur le LAN : jamais via un proxy HTTP
	return &Client{
		name:    ep.Name,
		baseURL: strings.TrimRight(ep.URL, "/") + "/api2/json",
		auth:    "PVEAPIToken=" + ep.TokenID + "=" + ep.TokenSecret,
		http:    &http.Client{Transport: tr, Timeout: timeout},
	}, nil
}

// Name renvoie le nom du point d'accès.
func (c *Client) Name() string { return c.name }

// Guests renvoie tous les LXC et VM visibles depuis ce point d'accès : tout le
// cluster si le nœud en fait partie, sinon ce seul nœud.
func (c *Client) Guests(ctx context.Context) ([]Resource, error) {
	var out []Resource
	if err := c.get(ctx, "/cluster/resources?type=vm", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) get(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s : %w", c.name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("%s : lecture de la réponse : %w", c.name, err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%s : jeton refusé (401) : vérifiez token_id et le secret", c.name)
	case resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%s : droits insuffisants (403) : le jeton doit avoir le rôle PVEAuditor sur /", c.name)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s : HTTP %d : %s", c.name, resp.StatusCode, snippet(body))
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("%s : réponse illisible : %w", c.name, err)
	}
	if len(env.Data) == 0 || bytes.Equal(env.Data, []byte("null")) {
		return fmt.Errorf("%s : réponse sans données", c.name)
	}
	if err := json.Unmarshal(env.Data, dst); err != nil {
		return fmt.Errorf("%s : données illisibles : %w", c.name, err)
	}
	return nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}
