package web

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
)

// Icônes des applications et des OS : collection selfh.st/icons (CC BY 4.0),
// téléchargées par PatchWarden puis servies depuis son propre disque. Le
// navigateur ne contacte aucun site tiers, et le format WebP (image
// matricielle) ne peut contenir aucun script.

var iconNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,48}$`)

// iconAliases : nom de script, d'invité ou d'OS → nom dans selfh.st/icons.
var iconAliases = map[string]string{
	"adguard":               "adguard-home",
	"teamspeak-server":      "teamspeak",
	"alpine":                "alpine-linux",
	"pbs":                   "proxmox",
	"proxmox-backup-server": "proxmox",
	"pve":                   "proxmox",
	"omv":                   "openmediavault",
	"nextcloudpi":           "nextcloud",
	"homeassistant":         "home-assistant",
	"haos":                  "home-assistant",
	"vaultwarden":           "vaultwarden",
	"npm":                   "nginx-proxy-manager",
	"nginxproxymanager":     "nginx-proxy-manager",
	"pihole":                "pi-hole",
	"uptimekuma":            "uptime-kuma",
	"paperless-ngx":         "paperless-ngx",
}

var nameCleanRe = regexp.MustCompile(`[^a-z0-9-]+`)

func iconName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = nameCleanRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if a, ok := iconAliases[s]; ok {
		return a
	}
	return s
}

// iconCandidates : script community-scripts, nom de l'invité (sans chiffres
// finaux : « OMV6 » → « omv »), puis OS détecté.
func iconCandidates(g inventory.Guest, det *detect.Result) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		n := iconName(s)
		if n != "" && iconNameRe.MatchString(n) && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if det != nil && det.CS.Script != "" && det.CS.Script != det.OSID && !det.CS.OSOnly {
		add(det.CS.Script)
	}
	add(g.Name)
	add(strings.TrimRight(strings.ToLower(g.Name), "0123456789-_ "))
	if det != nil {
		add(det.OSID)
	}
	return out
}

// iconURL renvoie l'adresse de l'icône d'un invité (avec repli sur l'initiale).
func iconURL(g inventory.Guest, det *detect.Result) string {
	v := url.Values{}
	for _, c := range iconCandidates(g, det) {
		v.Add("n", c)
	}
	label := g.Name
	if label == "" {
		label = "?"
	}
	v.Set("l", label)
	return "/icones?" + v.Encode()
}

// iconStore télécharge et met en cache les icônes.
type iconStore struct {
	dir     string
	base    string // ex. https://cdn.jsdelivr.net/gh/selfhst/icons/webp
	enabled bool
	http    *http.Client

	mu       sync.Mutex
	inflight map[string]*sync.WaitGroup
}

func newIconStore(dir, base string, enabled bool) *iconStore {
	return &iconStore{
		dir: filepath.Join(dir, "icons"), base: strings.TrimRight(base, "/"), enabled: enabled,
		http: &http.Client{Timeout: 10 * time.Second}, inflight: map[string]*sync.WaitGroup{},
	}
}

const missingTTL = 7 * 24 * time.Hour

// get renvoie l'image d'un nom (téléchargée au premier appel), ou une erreur si
// l'icône n'existe pas. Les absences sont mémorisées 7 jours.
func (s *iconStore) get(ctx context.Context, name string) ([]byte, error) {
	if !s.enabled || !iconNameRe.MatchString(name) {
		return nil, os.ErrNotExist
	}
	path := filepath.Join(s.dir, name+".webp")
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	}
	if st, err := os.Stat(path + ".absent"); err == nil && time.Since(st.ModTime()) < missingTTL {
		return nil, os.ErrNotExist
	}

	// Un seul téléchargement à la fois par nom.
	s.mu.Lock()
	if wg, ok := s.inflight[name]; ok {
		s.mu.Unlock()
		wg.Wait()
		if b, err := os.ReadFile(path); err == nil {
			return b, nil
		}
		return nil, os.ErrNotExist
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	s.inflight[name] = wg
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.inflight, name)
		s.mu.Unlock()
		wg.Done()
	}()

	b, err := s.fetch(ctx, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_ = os.MkdirAll(s.dir, 0o750)
			_ = os.WriteFile(path+".absent", nil, 0o640)
		}
		return nil, err
	}
	if err := os.MkdirAll(s.dir, 0o750); err == nil {
		tmp := path + ".tmp"
		if os.WriteFile(tmp, b, 0o640) == nil {
			_ = os.Rename(tmp, path)
		}
	}
	return b, nil
}

func (s *iconStore) fetch(ctx context.Context, name string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/"+name+".webp", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "PatchWarden")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("icône %s : HTTP %d", name, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return nil, err
	}
	// Signature WebP : « RIFF....WEBP ».
	if len(b) < 12 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WEBP" {
		return nil, fmt.Errorf("icône %s : contenu inattendu", name)
	}
	return b, nil
}

// iconHandler sert la première icône disponible parmi les candidats, sinon
// une pastille avec l'initiale (SVG produit ici, texte échappé).
func (s *Server) iconHandler(w http.ResponseWriter, r *http.Request, _ *session) {
	q := r.URL.Query()
	for _, n := range q["n"] {
		if len(n) > 60 {
			continue
		}
		if b, err := s.icons.get(r.Context(), n); err == nil {
			w.Header().Set("Content-Type", "image/webp")
			w.Header().Set("Cache-Control", "private, max-age=86400")
			_, _ = w.Write(b)
			return
		}
	}
	label := []rune(strings.TrimSpace(q.Get("l")))
	initial := "?"
	if len(label) > 0 {
		initial = strings.ToUpper(string(label[0]))
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(q.Get("l")))
	hue := h.Sum32() % 360
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	fmt.Fprintf(w, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="hsl(%d,45%%,45%%)"/><text x="16" y="21.5" font-family="system-ui,sans-serif" font-size="15" font-weight="600" fill="#fff" text-anchor="middle">%s</text></svg>`,
		hue, html.EscapeString(initial))
}
