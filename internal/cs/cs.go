// Package cs lit et analyse les scripts community-scripts (ct/<nom>.sh) pour
// savoir quelles applications ils suivent, d'où viennent leurs versions, ce
// qu'ils exigent (CPU, RAM) et s'ils posent des questions sans terminal.
package cs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// App est une application dont le script vérifie la version.
type App struct {
	Name   string // nom passé à check_for_*, qui donne le fichier /root/.<nom>
	Forge  string // github, gitlab, codeberg
	Host   string // hôte de la forge (gitlab auto-hébergé), vide = défaut
	Repo   string // propriétaire/dépôt
	Kind   string // release, tag, branch
	Pinned string // version imposée par le script (prioritaire sur la dernière publiée)
	Branch string // branche suivie (check_for_*_branch)
	Prefix string // préfixe de tag filtré par le script
	Pre    bool   // préversions acceptées
}

// VersionFile renvoie le nom utilisé par le moteur : minuscules, sans espaces.
func (a App) VersionFile() string { return strings.ReplaceAll(strings.ToLower(a.Name), " ", "") }

// Script est le résultat de l'analyse d'un ct/<nom>.sh.
type Script struct {
	Name      string
	URL       string
	NeedCPU   int
	NeedRAMMB int
	Apps      []App
	// Prompts : questions posées par `read -p` dans update_script(). Sans
	// terminal, elles font échouer ou bloquer la mise à jour.
	Prompts []string
	// OSOnly : update_script() ne fait qu'une mise à jour de l'OS.
	OSOnly bool
}

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	varCPURe = regexp.MustCompile(`(?m)^var_cpu="\$\{var_cpu:-(\d+)\}"`)
	varRAMRe = regexp.MustCompile(`(?m)^var_ram="\$\{var_ram:-(\d+)\}"`)
	checkRe  = regexp.MustCompile(`(?:GITLAB_URL="(https://[^"]+)"\s+)?(?:GH_INCLUDE_PRERELEASE=(1)\s+)?check_for_(gh|gl|codeberg)_(release|tag|branch)\s+"([^"$]+)"\s+"([^"$]+)"((?:\s+"[^"]*")*)`)
	argRe    = regexp.MustCompile(`"([^"]*)"`)
	promptRe = regexp.MustCompile(`\bread\b[^\n#]*?-[A-Za-z]*p[A-Za-z]*\s+"([^"]*)"`)
	updFnRe  = regexp.MustCompile(`(?ms)^(?:function\s+update_script\s*(?:\(\))?|update_script\s*\(\))\s*\{\n(.*?)^\}`)
	appWork  = regexp.MustCompile(`check_for_|fetch_and_deploy|npm (?:install|update)|pip install|uv |docker|git (?:pull|clone)|curl `)
)

// Analyze extrait les informations utiles du texte d'un script.
func Analyze(body string) Script {
	var s Script
	if m := varCPURe.FindStringSubmatch(body); m != nil {
		s.NeedCPU, _ = strconv.Atoi(m[1])
	}
	if m := varRAMRe.FindStringSubmatch(body); m != nil {
		s.NeedRAMMB, _ = strconv.Atoi(m[1])
	}
	upd := body
	if m := updFnRe.FindStringSubmatch(body); m != nil {
		upd = m[1]
		s.OSOnly = !appWork.MatchString(upd) && (strings.Contains(upd, "run_os_update") || regexp.MustCompile(`apt(-get)? .*upgrade`).MatchString(upd))
	}
	seen := map[string]bool{}
	for _, m := range checkRe.FindAllStringSubmatch(upd, -1) {
		app := App{Name: m[5], Repo: m[6], Kind: m[4], Host: strings.TrimPrefix(m[1], "https://"), Pre: m[2] == "1"}
		switch m[3] {
		case "gh":
			app.Forge = "github"
		case "gl":
			app.Forge = "gitlab"
		default:
			app.Forge = "codeberg"
		}
		args := argRe.FindAllStringSubmatch(m[7], -1)
		if len(args) >= 1 {
			if app.Kind == "branch" {
				app.Branch = resolveVar(upd, args[0][1])
			} else {
				app.Pinned = resolveVar(upd, args[0][1])
			}
		}
		if len(args) >= 3 {
			app.Prefix = args[2][1]
		}
		if seen[app.Name] || !nameRe.MatchString(app.VersionFile()) {
			continue
		}
		seen[app.Name] = true
		s.Apps = append(s.Apps, app)
	}
	for _, m := range promptRe.FindAllStringSubmatch(upd, -1) {
		p := strings.TrimSpace(strings.ReplaceAll(m[1], "${TAB3}", ""))
		if p != "" {
			s.Prompts = append(s.Prompts, p)
		}
	}
	return s
}

// resolveVar remplace "${VAR}" par la valeur VAR="…" affectée dans le script.
func resolveVar(body, v string) string {
	name := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(v, "${"), "$"), "}")
	if name == v || name == "" {
		return v // valeur littérale (ou vide)
	}
	re := regexp.MustCompile(`(?m)^\s*(?:local\s+)?` + regexp.QuoteMeta(name) + `="([^"$]*)"`)
	if m := re.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return "" // variable non résolue : on se rabat sur la dernière version publiée
}

// ErrBaseNotAllowed : la source du script n'est pas dans la liste autorisée.
var ErrBaseNotAllowed = errors.New("source de scripts non autorisée (community_scripts.allowed_bases)")

// Fetcher télécharge les scripts depuis des sources autorisées, avec un cache.
type Fetcher struct {
	http    *http.Client
	allowed []string
	ttl     time.Duration
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	s  Script
	at time.Time
}

// NewFetcher crée un lecteur de scripts.
func NewFetcher(allowed []string, ttl time.Duration, client *http.Client) *Fetcher {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	clean := make([]string, len(allowed))
	for i, b := range allowed {
		clean[i] = strings.TrimRight(b, "/")
	}
	return &Fetcher{http: client, allowed: clean, ttl: ttl, now: time.Now, cache: map[string]cached{}}
}

// Allowed indique si une base de scripts est autorisée.
func (f *Fetcher) Allowed(base string) bool {
	base = strings.TrimRight(base, "/")
	for _, a := range f.allowed {
		if base == a {
			return true
		}
	}
	return false
}

// Get renvoie l'analyse du script <base>/ct/<name>.sh.
func (f *Fetcher) Get(ctx context.Context, base, name string) (Script, error) {
	if !f.Allowed(base) {
		return Script{}, fmt.Errorf("%w : %s", ErrBaseNotAllowed, base)
	}
	if !nameRe.MatchString(name) {
		return Script{}, fmt.Errorf("nom de script invalide : %q", name)
	}
	url := strings.TrimRight(base, "/") + "/ct/" + name + ".sh"
	f.mu.Lock()
	if c, ok := f.cache[url]; ok && f.now().Sub(c.at) < f.ttl {
		f.mu.Unlock()
		return c.s, nil
	}
	f.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Script{}, err
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return Script{}, fmt.Errorf("téléchargement de %s : %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Script{}, fmt.Errorf("script introuvable (renommé ou retiré ?) : %s", url)
	}
	if resp.StatusCode != http.StatusOK {
		return Script{}, fmt.Errorf("téléchargement de %s : HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Script{}, err
	}
	s := Analyze(string(b))
	s.Name, s.URL = name, url
	f.mu.Lock()
	f.cache[url] = cached{s: s, at: f.now()}
	f.mu.Unlock()
	return s, nil
}

// ScriptPageURL renvoie la page du script sur le site community-scripts.
func ScriptPageURL(website, slug string) string {
	if slug == "" || !nameRe.MatchString(slug) {
		return ""
	}
	return strings.TrimRight(website, "/") + "/scripts/" + slug
}
