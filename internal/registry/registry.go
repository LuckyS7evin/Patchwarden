// Package registry interroge les registres d'images (Docker Hub, ghcr.io,
// lscr.io, quay.io…) par l'API de distribution OCI, sans compte : empreinte
// actuelle d'un tag, et liste des tags pour repérer une version plus récente.
// Les réponses sont gardées en cache.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Ref est une référence d'image normalisée.
type Ref struct {
	Registry string // docker.io, ghcr.io…
	Repo     string // library/nginx, linuxserver/mealie…
	Tag      string // latest par défaut
	Digest   string // image épinglée par empreinte (sha256:…)
}

// String renvoie la forme complète (docker.io/library/nginx:latest).
func (r Ref) String() string {
	s := r.Registry + "/" + r.Repo
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// Name renvoie registre/dépôt, sans tag.
func (r Ref) Name() string { return r.Registry + "/" + r.Repo }

// Short renvoie le nom court affiché (nginx, linuxserver/mealie, ghcr.io/x/y).
func (r Ref) Short() string {
	if r.Registry == "docker.io" {
		return strings.TrimPrefix(r.Repo, "library/")
	}
	return r.Registry + "/" + r.Repo
}

var repoRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)

// Parse normalise une référence comme le fait docker (docker.io et library/ implicites).
func Parse(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ref{}, errors.New("référence d'image vide")
	}
	var r Ref
	if i := strings.Index(s, "@"); i >= 0 {
		r.Digest, s = s[i+1:], s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i+1:], "/") {
		r.Tag, s = s[i+1:], s[:i]
	}
	first, rest, ok := strings.Cut(s, "/")
	if ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.Registry, r.Repo = first, rest
	} else {
		r.Registry, r.Repo = "docker.io", s
	}
	if r.Registry == "index.docker.io" || r.Registry == "registry-1.docker.io" {
		r.Registry = "docker.io"
	}
	if r.Registry == "docker.io" && !strings.Contains(r.Repo, "/") {
		r.Repo = "library/" + r.Repo
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	if !repoRe.MatchString(r.Repo) {
		return Ref{}, fmt.Errorf("référence d'image invalide : %q", s)
	}
	return r, nil
}

// Same dit si deux références désignent le même dépôt.
func Same(a, b Ref) bool { return a.Registry == b.Registry && a.Repo == b.Repo }

// apiHost renvoie l'hôte de l'API du registre.
func apiHost(reg string) string {
	switch reg {
	case "docker.io":
		return "registry-1.docker.io"
	case "lscr.io":
		// lscr.io redirige vers ghcr.io (miroir des images linuxserver) ; le
		// jeton ne suivrait pas la redirection.
		return "ghcr.io"
	}
	return reg
}

// Client interroge les registres.
type Client struct {
	http *http.Client
	ttl  time.Duration
	now  func() time.Time
	// Scheme : https ; http seulement pour les tests.
	Scheme string
	// Hosts remplace l'hôte d'API d'un registre (tests).
	Hosts map[string]string

	mu     sync.Mutex
	digest map[string]cached
	tags   map[string]cachedTags
	tokens map[string]token
}

type cached struct {
	v   string
	err error
	at  time.Time
}

type cachedTags struct {
	v   []string
	err error
	at  time.Time
}

type token struct {
	v   string
	exp time.Time
}

// New crée un client ; ttl : durée de validité du cache (6 h par défaut).
func New(ttl time.Duration, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	return &Client{http: hc, ttl: ttl, now: time.Now, Scheme: "https",
		digest: map[string]cached{}, tags: map[string]cachedTags{}, tokens: map[string]token{}}
}

func (c *Client) base(reg string) string {
	h := apiHost(reg)
	if o, ok := c.Hosts[reg]; ok {
		h = o
	}
	return c.Scheme + "://" + h
}

const manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"

// ErrPrivate : le registre demande un compte (dépôt privé ou inexistant).
var ErrPrivate = errors.New("dépôt privé ou introuvable sur le registre (aucun compte configuré)")

// Digest renvoie l'empreinte actuelle du tag sur le registre (celle d'un
// index multi-architecture s'il y en a un, comme docker la conserve).
func (c *Client) Digest(ctx context.Context, r Ref) (string, error) {
	if r.Tag == "" {
		return "", errors.New("image épinglée par empreinte : pas de tag à suivre")
	}
	key := r.String()
	c.mu.Lock()
	if e, ok := c.digest[key]; ok && c.fresh(e.at, e.err) {
		c.mu.Unlock()
		return e.v, e.err
	}
	c.mu.Unlock()
	v, err := c.fetchDigest(ctx, r)
	c.mu.Lock()
	c.digest[key] = cached{v, err, c.now()}
	c.mu.Unlock()
	return v, err
}

func (c *Client) fresh(at time.Time, err error) bool {
	ttl := c.ttl
	if err != nil {
		ttl = 15 * time.Minute
	}
	return c.now().Sub(at) < ttl
}

func (c *Client) fetchDigest(ctx context.Context, r Ref) (string, error) {
	u := c.base(r.Registry) + "/v2/" + r.Repo + "/manifests/" + url.PathEscape(r.Tag)
	resp, err := c.do(ctx, http.MethodHead, u, r, manifestAccept)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if d := resp.Header.Get("Docker-Content-Digest"); strings.HasPrefix(d, "sha256:") {
		return d, nil
	}
	// Registre qui ne renvoie pas l'empreinte sur HEAD : elle est calculée sur le manifeste.
	resp, err = c.do(ctx, http.MethodGet, u, r, manifestAccept)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if d := resp.Header.Get("Docker-Content-Digest"); strings.HasPrefix(d, "sha256:") {
		return d, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(resp.Body, 4<<20)); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Tags renvoie les tags du dépôt (au plus 5 000).
func (c *Client) Tags(ctx context.Context, r Ref) ([]string, error) {
	key := r.Name()
	c.mu.Lock()
	if e, ok := c.tags[key]; ok && c.fresh(e.at, e.err) {
		c.mu.Unlock()
		return e.v, e.err
	}
	c.mu.Unlock()
	var all []string
	next := c.base(r.Registry) + "/v2/" + r.Repo + "/tags/list?n=1000"
	var err error
	for page := 0; page < 5 && next != ""; page++ {
		var resp *http.Response
		resp, err = c.do(ctx, http.MethodGet, next, r, "application/json")
		if err != nil {
			break
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&body)
		link := resp.Header.Get("Link")
		resp.Body.Close()
		if err != nil {
			break
		}
		all = append(all, body.Tags...)
		next = nextLink(c.base(r.Registry), link)
	}
	if err != nil && len(all) > 0 {
		err = nil // liste partielle : suffisante pour comparer
	}
	c.mu.Lock()
	c.tags[key] = cachedTags{all, err, c.now()}
	c.mu.Unlock()
	return all, err
}

var linkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(base, h string) string {
	m := linkRe.FindStringSubmatch(h)
	if m == nil {
		return ""
	}
	if strings.HasPrefix(m[1], "/") {
		return base + m[1]
	}
	if strings.HasPrefix(m[1], base+"/") {
		return m[1]
	}
	return "" // lien vers un autre hôte : ignoré
}

// do envoie la requête ; sur 401, obtient un jeton anonyme (WWW-Authenticate
// Bearer) et recommence une fois.
func (c *Client) do(ctx context.Context, method, u string, r Ref, accept string) (*http.Response, error) {
	tk := c.cachedToken(r.Name())
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("User-Agent", "PatchWarden")
		if tk != "" {
			req.Header.Set("Authorization", "Bearer "+tk)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("registre %s injoignable : %w", r.Registry, err)
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return resp, nil
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			ch := resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
			tk, err = c.anonToken(ctx, r, ch)
			if err != nil {
				return nil, err
			}
			continue
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
			resp.Body.Close()
			return nil, ErrPrivate
		case resp.StatusCode == http.StatusTooManyRequests:
			resp.Body.Close()
			return nil, fmt.Errorf("registre %s : trop de requêtes, nouvel essai plus tard", r.Registry)
		default:
			resp.Body.Close()
			return nil, fmt.Errorf("registre %s : HTTP %d", r.Registry, resp.StatusCode)
		}
	}
	return nil, ErrPrivate
}

func (c *Client) cachedToken(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[name]; ok && c.now().Before(t.exp) {
		return t.v
	}
	return ""
}

var challengeRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// anonToken demande un jeton de lecture anonyme au service indiqué par le registre.
func (c *Client) anonToken(ctx context.Context, r Ref, challenge string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return "", ErrPrivate
	}
	params := map[string]string{}
	for _, m := range challengeRe.FindAllStringSubmatch(challenge, -1) {
		params[strings.ToLower(m[1])] = m[2]
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || (realm.Scheme != "https" && realm.Scheme != c.Scheme) || realm.Host == "" {
		return "", fmt.Errorf("registre %s : service d'authentification invalide", r.Registry)
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", "repository:"+r.Repo+":pull")
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "PatchWarden")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("registre %s : jeton anonyme impossible : %w", r.Registry, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ErrPrivate
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", err
	}
	t := body.Token
	if t == "" {
		t = body.AccessToken
	}
	if t == "" {
		return "", ErrPrivate
	}
	life := time.Duration(body.ExpiresIn) * time.Second
	if life <= 0 || life > time.Hour {
		life = 5 * time.Minute
	}
	c.mu.Lock()
	c.tokens[r.Name()] = token{t, c.now().Add(life - 10*time.Second)}
	c.mu.Unlock()
	return t, nil
}

// ---------------------------------------------------------------------------
// Versions dans les tags

// tagShape découpe un tag de version : préfixe non numérique, nombres
// séparés par des points, suffixe dont les chiffres sont neutralisés.
var tagRe = regexp.MustCompile(`^(v|V|r|version-|release-)?(\d+(?:\.\d+)*)(.*)$`)

type parsed struct {
	prefix string
	nums   []int
	suffix string // suffixe tel quel
	shape  string // suffixe avec les chiffres remplacés par #
	snum   []int  // nombres du suffixe (ls45 → 45)
}

var digitsRe = regexp.MustCompile(`\d+`)

func parseTag(t string) (parsed, bool) {
	m := tagRe.FindStringSubmatch(t)
	if m == nil {
		return parsed{}, false
	}
	p := parsed{prefix: m[1], suffix: m[3]}
	for _, s := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(s)
		if err != nil || n > 1_000_000 {
			return parsed{}, false
		}
		p.nums = append(p.nums, n)
	}
	// Les dates (20240101) et les empreintes ne sont pas des versions.
	if len(p.nums) == 1 && p.nums[0] > 9999 {
		return parsed{}, false
	}
	p.shape = digitsRe.ReplaceAllString(p.suffix, "#")
	for _, s := range digitsRe.FindAllString(p.suffix, -1) {
		n, _ := strconv.Atoi(s)
		p.snum = append(p.snum, n)
	}
	return p, true
}

var preRe = regexp.MustCompile(`(?i)(alpha|beta|rc|dev|nightly|pre|test|snapshot|unstable|preview|canary)`)

func less(a, b []int) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// IsVersionTag dit si un tag ressemble à un numéro de version (1.8.0, v5, 2.1-alpine).
func IsVersionTag(t string) bool {
	_, ok := parseTag(t)
	return ok
}

// Newer renvoie le tag le plus récent de même forme que current (même
// préfixe, même nombre de composants, même suffixe aux chiffres près), s'il
// est plus récent ; vide sinon. Les préversions sont ignorées, sauf si le tag
// actuel en est une. Le tag n'est jamais changé automatiquement : c'est une
// information pour l'utilisateur.
func Newer(current string, tags []string) string {
	cur, ok := parseTag(current)
	if !ok {
		return ""
	}
	curPre := preRe.MatchString(cur.suffix)
	best, bestTag := cur, ""
	for _, t := range tags {
		p, ok := parseTag(t)
		if !ok || p.prefix != cur.prefix || len(p.nums) != len(cur.nums) || p.shape != cur.shape {
			continue
		}
		if !curPre && preRe.MatchString(p.suffix) {
			continue
		}
		switch {
		case less(best.nums, p.nums):
		case !less(p.nums, best.nums) && less(best.snum, p.snum):
		default:
			continue
		}
		best, bestTag = p, t
	}
	return bestTag
}

// ---------------------------------------------------------------------------
// Liens

var forgeRe = regexp.MustCompile(`^https?://(github\.com|gitlab\.com|codeberg\.org)/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$`)

// ChangelogURL propose le lien le plus utile pour une image : dépôt GitHub
// connu (ghcr.io, linuxserver), puis label org.opencontainers.image.source
// s'il désigne bien ce projet, sinon la page du registre.
func ChangelogURL(r Ref, source string) string {
	parts := strings.Split(r.Repo, "/")
	last := parts[len(parts)-1]
	switch {
	case r.Registry == "ghcr.io" && len(parts) >= 2:
		return "https://github.com/" + parts[0] + "/" + parts[1] + "/releases"
	case (r.Registry == "lscr.io" || r.Registry == "docker.io") && parts[0] == "linuxserver" && len(parts) == 2:
		return "https://github.com/linuxserver/docker-" + last + "/releases"
	}
	if m := forgeRe.FindStringSubmatch(strings.TrimSpace(source)); m != nil {
		// Label hérité d'une image de base (ex. ErsatzTV-ffmpeg pour ErsatzTV) :
		// on ne garde le lien que si le dépôt porte le nom de l'image.
		repo := strings.TrimPrefix(strings.ToLower(m[3]), "docker-")
		if repo == strings.ToLower(last) {
			base := "https://" + m[1] + "/" + m[2] + "/" + m[3]
			if m[1] == "gitlab.com" {
				return base + "/-/releases"
			}
			return base + "/releases"
		}
	}
	switch r.Registry {
	case "docker.io":
		if parts[0] == "library" {
			return "https://hub.docker.com/_/" + last + "/tags"
		}
		return "https://hub.docker.com/r/" + r.Repo + "/tags"
	case "quay.io":
		return "https://quay.io/repository/" + r.Repo + "?tab=tags"
	case "lscr.io":
		return "https://github.com/linuxserver/docker-" + last + "/releases"
	}
	return ""
}
