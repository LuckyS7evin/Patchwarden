// Package web sert l'interface de PatchWarden.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Inventory est la partie du service d'inventaire utilisée par l'interface.
type Inventory interface {
	Current() (inventory.Snapshot, bool)
	TriggerRefresh()
}

// Server porte l'état de l'interface.
type Server struct {
	cfg     *config.Config
	inv     Inventory
	log     *slog.Logger
	version string
	now     func() time.Time
	sess    *sessions
	thr     *throttle
	pages   map[string]*template.Template
}

// New prépare le serveur (gabarits compris).
func New(cfg *config.Config, inv Inventory, log *slog.Logger, version string) (*Server, error) {
	s := &Server{cfg: cfg, inv: inv, log: log, version: version, now: time.Now}
	s.sess = newSessions(cfg.Auth.SessionDuration.Duration, func() time.Time { return s.now() })
	s.thr = newThrottle(func() time.Time { return s.now() })
	funcs := template.FuncMap{"join": strings.Join}
	s.pages = map[string]*template.Template{}
	for _, p := range []string{"connexion", "inventaire"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("gabarit %s : %w", p, err)
		}
		s.pages[p] = t
	}
	return s, nil
}

// Handler renvoie le routeur HTTP complet.
func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /sante", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /connexion", s.loginForm)
	mux.HandleFunc("POST /connexion", s.sameOrigin(s.loginSubmit))
	mux.HandleFunc("POST /deconnexion", s.sameOrigin(s.authed(s.csrf(s.logout))))
	mux.HandleFunc("GET /{$}", s.authed(s.inventoryPage))
	mux.HandleFunc("POST /inventaire/rafraichir", s.sameOrigin(s.authed(s.csrf(s.refresh))))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// sameOrigin refuse les POST venant d'un autre site (en plus du jeton CSRF et
// du cookie SameSite=Strict).
func (s *Server) sameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && o != "null" {
			u, err := url.Parse(o)
			if err != nil || u.Host != r.Host {
				http.Error(w, "Origine refusée", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) currentSession(r *http.Request) (string, *session) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", nil
	}
	return c.Value, s.sess.get(c.Value)
}

func (s *Server) authed(next func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, se := s.currentSession(r)
		if se == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/connexion", http.StatusSeeOther)
				return
			}
			http.Error(w, "Session expirée : reconnectez-vous", http.StatusUnauthorized)
			return
		}
		next(w, r, se)
	}
}

func (s *Server) csrf(next func(http.ResponseWriter, *http.Request, *session)) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, se *session) {
		if !equalTokens(r.PostFormValue("csrf"), se.csrf) {
			http.Error(w, "Jeton de formulaire invalide : rechargez la page", http.StatusForbidden)
			return
		}
		next(w, r, se)
	}
}

func (s *Server) render(w http.ResponseWriter, page string, status int, data any) {
	var buf strings.Builder
	if err := s.pages[page].ExecuteTemplate(&buf, "layout.html", data); err != nil {
		s.log.Error("rendu de page", "page", page, "erreur", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(buf.String()))
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type loginData struct {
	Title, Error, Username, Version string
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if _, se := s.currentSession(r); se != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "connexion", http.StatusOK, loginData{Title: "Connexion", Version: s.version})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	data := loginData{Title: "Connexion", Version: s.version, Username: r.PostFormValue("username")}
	if blocked, until := s.thr.blocked(ip); blocked {
		data.Error = fmt.Sprintf("Trop d'essais. Réessayez après %s.", until.Format("15:04"))
		s.render(w, "connexion", http.StatusTooManyRequests, data)
		return
	}
	if !checkCredentials(s.cfg.Auth.Username, s.cfg.Auth.PasswordHash, data.Username, r.PostFormValue("password")) {
		s.thr.fail(ip)
		s.log.Warn("échec de connexion", "ip", ip)
		data.Error = "Identifiant ou mot de passe incorrect."
		s.render(w, "connexion", http.StatusUnauthorized, data)
		return
	}
	s.thr.success(ip)
	if old, _ := s.currentSession(r); old != "" {
		s.sess.delete(old)
	}
	id, _ := s.sess.create(s.cfg.Auth.Username)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: s.cfg.Server.CookieSecure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(s.cfg.Auth.SessionDuration.Seconds()),
	})
	s.log.Info("connexion réussie", "ip", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ *session) {
	if id, _ := s.currentSession(r); id != "" {
		s.sess.delete(id)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/connexion", http.StatusSeeOther)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request, _ *session) {
	s.inv.TriggerRefresh()
	http.Redirect(w, r, "/?"+r.URL.RawQuery, http.StatusSeeOther)
}

type nodeGroup struct {
	Node   string
	Guests []inventory.Guest
}

type counts struct{ Total, LXC, VM, Running, CommunityScript, Critical int }

type filter struct{ Node, Type, Tag, Q string }

func (f filter) Active() bool { return f.Node != "" || f.Type != "" || f.Tag != "" || f.Q != "" }

func (f filter) match(g inventory.Guest) bool {
	if f.Node != "" && g.Node != f.Node {
		return false
	}
	if f.Type != "" && g.Type != f.Type {
		return false
	}
	if f.Tag != "" {
		found := false
		for _, t := range g.Tags {
			if t == f.Tag {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.Q != "" && !strings.Contains(strings.ToLower(g.Name), strings.ToLower(f.Q)) &&
		!strings.Contains(fmt.Sprint(g.VMID), f.Q) {
		return false
	}
	return true
}

type inventoryData struct {
	Title, User, CSRF, Version string
	Loaded, Refreshing         bool
	Age, FetchedAt             string
	Errors                     []string
	Counts                     counts
	Shown                      int
	Groups                     []nodeGroup
	Nodes, Tags                []string
	Filter                     filter
	Query                      string
}

func (s *Server) inventoryPage(w http.ResponseWriter, r *http.Request, se *session) {
	snap, refreshing := s.inv.Current()
	q := r.URL.Query()
	f := filter{Node: q.Get("noeud"), Type: q.Get("type"), Tag: q.Get("tag"), Q: strings.TrimSpace(q.Get("q"))}
	d := inventoryData{
		Title: "Inventaire", User: se.user, CSRF: se.csrf, Version: s.version,
		Loaded: !snap.FetchedAt.IsZero(), Refreshing: refreshing,
		Nodes: snap.Nodes(), Filter: f, Query: r.URL.RawQuery,
	}
	if d.Loaded {
		d.Age = humanAge(s.now().Sub(snap.FetchedAt))
		d.FetchedAt = snap.FetchedAt.Format("02/01/2006 15:04:05")
	}
	for name, e := range snap.Errors {
		d.Errors = append(d.Errors, name+" : "+e)
	}
	sort.Strings(d.Errors)

	tags := map[string]bool{}
	groups := map[string]*nodeGroup{}
	for _, g := range snap.Guests {
		for _, t := range g.Tags {
			tags[t] = true
		}
		d.Counts.Total++
		if g.Type == "lxc" {
			d.Counts.LXC++
		} else {
			d.Counts.VM++
		}
		if g.Status == "running" {
			d.Counts.Running++
		}
		if g.CommunityScript {
			d.Counts.CommunityScript++
		}
		if g.Critical {
			d.Counts.Critical++
		}
		if !f.match(g) {
			continue
		}
		d.Shown++
		ng, ok := groups[g.Node]
		if !ok {
			ng = &nodeGroup{Node: g.Node}
			groups[g.Node] = ng
		}
		ng.Guests = append(ng.Guests, g)
	}
	for _, n := range d.Nodes {
		if ng, ok := groups[n]; ok {
			d.Groups = append(d.Groups, *ng)
		}
	}
	for t := range tags {
		d.Tags = append(d.Tags, t)
	}
	sort.Strings(d.Tags)
	s.render(w, "inventaire", http.StatusOK, d)
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "à l'instant"
	case d < time.Hour:
		return fmt.Sprintf("il y a %d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("il y a %d h", int(d.Hours()))
	default:
		return fmt.Sprintf("il y a %d jours", int(d.Hours()/24))
	}
}
