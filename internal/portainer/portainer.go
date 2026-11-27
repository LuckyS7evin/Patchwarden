// Package portainer est un client minimal de l'API Portainer : environnements,
// conteneurs (pour retrouver l'environnement d'un invité), stacks et leur
// re-déploiement avec téléchargement des images.
package portainer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/tlspin"
)

// Endpoint est un environnement Portainer (hôte Docker).
type Endpoint struct {
	ID     int    `json:"Id"`
	Name   string `json:"Name"`
	Type   int    `json:"Type"`   // 1 Docker local, 2 agent, 4 agent Edge…
	Status int    `json:"Status"` // 1 joignable, 2 injoignable
}

// Pair est une variable d'environnement de stack.
type Pair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// GitConfig : stack déployée depuis un dépôt Git.
type GitConfig struct {
	URL            string          `json:"URL"`
	ReferenceName  string          `json:"ReferenceName"`
	ConfigFilePath string          `json:"ConfigFilePath"`
	Authentication json.RawMessage `json:"Authentication"`
}

// Stack est une stack Portainer.
type Stack struct {
	ID         int        `json:"Id"`
	Name       string     `json:"Name"`
	Type       int        `json:"Type"`   // 1 swarm, 2 compose, 3 kubernetes
	Status     int        `json:"Status"` // 1 active, 2 arrêtée
	EndpointID int        `json:"EndpointId"`
	Env        []Pair     `json:"Env"`
	GitConfig  *GitConfig `json:"GitConfig"`
}

// Git dit si la stack vient d'un dépôt Git.
func (s Stack) Git() bool { return s.GitConfig != nil && s.GitConfig.URL != "" }

// Container est un conteneur vu par Portainer.
type Container struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"` // running, created, exited…
	Labels map[string]string `json:"Labels"`
}

// Name renvoie le nom du conteneur (sans « / »).
func (c Container) Name() string {
	if len(c.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// Client interroge une instance Portainer.
type Client struct {
	Name    string
	baseURL string
	token   string
	http    *http.Client
	// long : client des re-déploiements (téléchargement des images).
	long *http.Client
}

// New construit un client à partir de la configuration validée.
func New(p config.Portainer, timeout time.Duration) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // Portainer est sur le LAN : jamais via un proxy HTTP
	if strings.HasPrefix(p.URL, "https://") {
		tc, err := tlspin.Config(p.Fingerprint, p.CAFile)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = tc
	}
	return &Client{
		Name: p.Name, baseURL: strings.TrimRight(p.URL, "/") + "/api", token: p.Token,
		http: &http.Client{Transport: tr, Timeout: timeout},
		long: &http.Client{Transport: tr, Timeout: 30 * time.Minute},
	}, nil
}

// APIError est une erreur renvoyée par Portainer.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "Portainer refuse le jeton (HTTP 401) : vérifiez token_env"
	case http.StatusForbidden:
		return "Portainer : accès refusé (HTTP 403) : l'utilisateur du jeton doit avoir accès à cet environnement et à cette stack"
	}
	if e.Message != "" {
		return fmt.Sprintf("Portainer : HTTP %d : %s", e.Status, e.Message)
	}
	return fmt.Sprintf("Portainer : HTTP %d", e.Status)
}

func (c *Client) call(ctx context.Context, hc *http.Client, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("Portainer %s injoignable : %w", c.Name, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
			Details string `json:"details"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Message
		if e.Details != "" && e.Details != e.Message {
			msg = strings.TrimSpace(msg + " (" + e.Details + ")")
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("Portainer %s : réponse illisible : %w", c.Name, err)
	}
	return nil
}

// Endpoints liste les environnements.
func (c *Client) Endpoints(ctx context.Context) ([]Endpoint, error) {
	var out []Endpoint
	return out, c.call(ctx, c.http, http.MethodGet, "/endpoints", nil, &out)
}

// Containers liste les conteneurs d'un environnement (tous, arrêtés compris).
func (c *Client) Containers(ctx context.Context, endpoint int) ([]Container, error) {
	var out []Container
	return out, c.call(ctx, c.http, http.MethodGet, "/endpoints/"+strconv.Itoa(endpoint)+"/docker/containers/json?all=1", nil, &out)
}

// ProjectContainers liste les conteneurs d'un projet compose (stack) d'un environnement.
func (c *Client) ProjectContainers(ctx context.Context, endpoint int, project string) ([]Container, error) {
	f, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + project}})
	var out []Container
	return out, c.call(ctx, c.http, http.MethodGet, "/endpoints/"+strconv.Itoa(endpoint)+"/docker/containers/json?all=1&filters="+url.QueryEscape(string(f)), nil, &out)
}

// Stacks liste les stacks.
func (c *Client) Stacks(ctx context.Context) ([]Stack, error) {
	var out []Stack
	return out, c.call(ctx, c.http, http.MethodGet, "/stacks", nil, &out)
}

// Stack lit une stack.
func (c *Client) Stack(ctx context.Context, id int) (Stack, error) {
	var out Stack
	return out, c.call(ctx, c.http, http.MethodGet, "/stacks/"+strconv.Itoa(id), nil, &out)
}

// StackFile lit le fichier compose d'une stack.
func (c *Client) StackFile(ctx context.Context, id int) (string, error) {
	var out struct {
		StackFileContent string `json:"StackFileContent"`
	}
	err := c.call(ctx, c.http, http.MethodGet, "/stacks/"+strconv.Itoa(id)+"/file", nil, &out)
	return out.StackFileContent, err
}

// Redeploy re-déploie une stack compose avec téléchargement des images, sans
// rien changer à sa configuration : même fichier, mêmes variables, aucune
// suppression (prune désactivé). Pour une stack Git, la même référence est
// redéployée, avec les identifiants enregistrés dans Portainer.
func (c *Client) Redeploy(ctx context.Context, s Stack) error {
	if s.Type != 2 {
		return errors.New("seules les stacks docker compose sont prises en charge")
	}
	env := s.Env
	if env == nil {
		env = []Pair{}
	}
	q := "?endpointId=" + strconv.Itoa(s.EndpointID)
	if s.Git() {
		payload := map[string]any{
			"env": env, "prune": false, "pullImage": true,
			"repositoryReferenceName":  s.GitConfig.ReferenceName,
			"repositoryAuthentication": len(s.GitConfig.Authentication) > 0 && string(s.GitConfig.Authentication) != "null",
		}
		return c.call(ctx, c.long, http.MethodPut, "/stacks/"+strconv.Itoa(s.ID)+"/git/redeploy"+q, payload, nil)
	}
	file, err := c.StackFile(ctx, s.ID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(file) == "" {
		return errors.New("Portainer renvoie un fichier de stack vide : re-déploiement annulé")
	}
	payload := map[string]any{"stackFileContent": file, "env": env, "prune": false, "pullImage": true}
	return c.call(ctx, c.long, http.MethodPut, "/stacks/"+strconv.Itoa(s.ID)+q, payload, nil)
}
