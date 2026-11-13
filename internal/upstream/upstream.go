// Package upstream interroge les forges (GitHub, Codeberg, GitLab) pour
// connaître la dernière version publiée d'une application, avec un cache.
package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Query décrit ce qu'on cherche.
type Query struct {
	Forge  string // github, codeberg, gitlab
	Host   string // hôte GitLab auto-hébergé, vide = gitlab.com
	Repo   string // propriétaire/dépôt
	Kind   string // release ou tag
	Prefix string // seuls les tags commençant par ce préfixe
	Pre    bool   // préversions acceptées
}

// Release est le résultat.
type Release struct {
	Tag          string
	ChangelogURL string
}

// Client interroge les forges.
type Client struct {
	http        *http.Client
	githubToken string
	ttl         time.Duration
	now         func() time.Time
	// Bases d'API, modifiables pour les tests.
	GitHubAPI, CodebergAPI, GitLabAPI string

	mu    sync.Mutex
	cache map[Query]cacheEntry
}

type cacheEntry struct {
	r   Release
	err error
	at  time.Time
}

// New crée un client. githubToken est facultatif (lecture seule suffit).
func New(githubToken string, ttl time.Duration, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{
		http: hc, githubToken: githubToken, ttl: ttl, now: time.Now,
		GitHubAPI: "https://api.github.com", CodebergAPI: "https://codeberg.org/api/v1", GitLabAPI: "https://gitlab.com/api/v4",
		cache: map[Query]cacheEntry{},
	}
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+$`)

// Latest renvoie la dernière version publiée (erreurs mises en cache moins longtemps).
func (c *Client) Latest(ctx context.Context, q Query) (Release, error) {
	if !repoRe.MatchString(q.Repo) {
		return Release{}, fmt.Errorf("dépôt invalide : %q", q.Repo)
	}
	c.mu.Lock()
	if e, ok := c.cache[q]; ok {
		ttl := c.ttl
		if e.err != nil {
			ttl = 15 * time.Minute
		}
		if c.now().Sub(e.at) < ttl {
			c.mu.Unlock()
			return e.r, e.err
		}
	}
	c.mu.Unlock()

	r, err := c.fetch(ctx, q)
	c.mu.Lock()
	c.cache[q] = cacheEntry{r: r, err: err, at: c.now()}
	c.mu.Unlock()
	return r, err
}

func (c *Client) fetch(ctx context.Context, q Query) (Release, error) {
	switch q.Forge {
	case "github":
		return c.github(ctx, q)
	case "codeberg":
		return c.gitea(ctx, c.CodebergAPI, "https://codeberg.org", q)
	case "gitlab":
		return c.gitlab(ctx, q)
	default:
		return Release{}, fmt.Errorf("forge inconnue : %s", q.Forge)
	}
}

type ghRelease struct {
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Prerelease bool   `json:"prerelease"`
	Draft      bool   `json:"draft"`
}

type namedTag struct {
	Name string `json:"name"`
}

func (c *Client) github(ctx context.Context, q Query) (Release, error) {
	web := "https://github.com/" + q.Repo
	if q.Kind == "tag" {
		var tags []namedTag
		if err := c.getJSON(ctx, c.GitHubAPI+"/repos/"+q.Repo+"/tags?per_page=100", true, &tags); err != nil {
			return Release{}, err
		}
		names := make([]string, len(tags))
		for i, t := range tags {
			names[i] = t.Name
		}
		tag, err := pickTag(names, q)
		if err != nil {
			return Release{}, err
		}
		return Release{Tag: tag, ChangelogURL: web + "/releases/tag/" + url.PathEscape(tag)}, nil
	}
	if q.Prefix == "" && !q.Pre {
		var r ghRelease
		if err := c.getJSON(ctx, c.GitHubAPI+"/repos/"+q.Repo+"/releases/latest", true, &r); err != nil {
			return Release{}, err
		}
		return Release{Tag: r.TagName, ChangelogURL: firstNonEmpty(r.HTMLURL, web+"/releases")}, nil
	}
	var list []ghRelease
	if err := c.getJSON(ctx, c.GitHubAPI+"/repos/"+q.Repo+"/releases?per_page=50", true, &list); err != nil {
		return Release{}, err
	}
	for _, r := range list { // l'API renvoie les plus récentes en premier
		if r.Draft || (r.Prerelease && !q.Pre) || !strings.HasPrefix(r.TagName, q.Prefix) {
			continue
		}
		return Release{Tag: r.TagName, ChangelogURL: firstNonEmpty(r.HTMLURL, web+"/releases")}, nil
	}
	return Release{}, fmt.Errorf("aucune version publiée correspondante sur %s", web)
}

func (c *Client) gitea(ctx context.Context, api, webBase string, q Query) (Release, error) {
	web := webBase + "/" + q.Repo
	if q.Kind == "tag" {
		var tags []namedTag
		if err := c.getJSON(ctx, api+"/repos/"+q.Repo+"/tags?limit=50", false, &tags); err != nil {
			return Release{}, err
		}
		names := make([]string, len(tags))
		for i, t := range tags {
			names[i] = t.Name
		}
		tag, err := pickTag(names, q)
		if err != nil {
			return Release{}, err
		}
		return Release{Tag: tag, ChangelogURL: web + "/releases/tag/" + url.PathEscape(tag)}, nil
	}
	var list []ghRelease
	if err := c.getJSON(ctx, api+"/repos/"+q.Repo+"/releases?limit=50", false, &list); err != nil {
		return Release{}, err
	}
	for _, r := range list {
		if r.Draft || (r.Prerelease && !q.Pre) || !strings.HasPrefix(r.TagName, q.Prefix) {
			continue
		}
		return Release{Tag: r.TagName, ChangelogURL: firstNonEmpty(r.HTMLURL, web+"/releases")}, nil
	}
	return Release{}, fmt.Errorf("aucune version publiée sur %s", web)
}

func (c *Client) gitlab(ctx context.Context, q Query) (Release, error) {
	api, web := c.GitLabAPI, "https://gitlab.com"
	if q.Host != "" {
		api, web = "https://"+q.Host+"/api/v4", "https://"+q.Host
	}
	var list []struct {
		TagName  string `json:"tag_name"`
		Upcoming bool   `json:"upcoming_release"`
	}
	if err := c.getJSON(ctx, api+"/projects/"+url.PathEscape(q.Repo)+"/releases?per_page=50", false, &list); err != nil {
		return Release{}, err
	}
	for _, r := range list {
		if r.Upcoming || !strings.HasPrefix(r.TagName, q.Prefix) || (!q.Pre && isPre(r.TagName)) {
			continue
		}
		return Release{Tag: r.TagName, ChangelogURL: web + "/" + q.Repo + "/-/releases/" + url.PathEscape(r.TagName)}, nil
	}
	return Release{}, fmt.Errorf("aucune version publiée sur %s/%s", web, q.Repo)
}

func (c *Client) getJSON(ctx context.Context, u string, github bool, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "PatchWarden")
	if github {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if c.githubToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.githubToken)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("requête vers %s : %w", hostOf(u), err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("introuvable sur %s (dépôt renommé, ou aucune version publiée)", hostOf(u))
	case github && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) && resp.Header.Get("X-RateLimit-Remaining") == "0":
		return fmt.Errorf("limite de l'API GitHub atteinte : configurez upstream.github_token")
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s : HTTP %d", hostOf(u), resp.StatusCode)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("réponse illisible de %s : %w", hostOf(u), err)
	}
	return nil
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	return p.Host
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

var preRe = regexp.MustCompile(`(?i)(alpha|beta|rc|pre|dev|nightly|snapshot)`)

func isPre(tag string) bool { return preRe.MatchString(tag) }

// pickTag choisit le tag le plus élevé (comparaison numérique des composants),
// hors préversions sauf demande contraire.
func pickTag(names []string, q Query) (string, error) {
	var cands []string
	for _, n := range names {
		if strings.HasPrefix(n, q.Prefix) && (q.Pre || !isPre(n)) {
			cands = append(cands, n)
		}
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("aucun tag correspondant pour %s", q.Repo)
	}
	sort.SliceStable(cands, func(i, j int) bool { return versionLess(cands[j], cands[i]) })
	return cands[0], nil
}

var numRe = regexp.MustCompile(`\d+`)

func versionLess(a, b string) bool {
	na, nb := numRe.FindAllString(a, -1), numRe.FindAllString(b, -1)
	for i := 0; i < len(na) && i < len(nb); i++ {
		x, _ := strconv.Atoi(na[i])
		y, _ := strconv.Atoi(nb[i])
		if x != y {
			return x < y
		}
	}
	if len(na) != len(nb) {
		return len(na) < len(nb)
	}
	return a < b
}
