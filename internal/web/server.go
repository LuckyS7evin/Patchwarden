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
	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/eol"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/window"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Inventory est la partie du service d'inventaire utilisée par l'interface.
type Inventory interface {
	Current() (inventory.Snapshot, bool)
	TriggerRefresh()
}

// Engine lance les tâches (détection, mises à jour).
type Engine interface {
	CanDetect(g inventory.Guest) error
	Detect(g inventory.Guest, user string) (jobs.Job, error)
	DetectAll(guests []inventory.Guest, user string) (started, skipped int)
	PlanFor(g inventory.Guest, a engine.Action) engine.Plan
	Execute(g inventory.Guest, a engine.Action, dryRun bool, user string, confirmed bool, typedName string, snapshot bool) (jobs.Job, error)
	SetAnswers(key string, answers map[string]string) error
	CanSnapAction(g inventory.Guest) error
	Rollback(g inventory.Guest, name, user, typedName string) (jobs.Job, error)
	DeleteSnapshot(g inventory.Guest, name, user string, confirmed bool) (jobs.Job, error)
	SnapPref(key string) string
	SetSnapPref(key, v string) error
	SnapDefaults() engine.SnapConfig
	PlanRestart(g inventory.Guest) engine.RestartPlan
	RestartServices(g inventory.Guest, user string, confirmed bool) (jobs.Job, error)
	Reboot(g inventory.Guest, user string, confirmed bool, typedName string) (jobs.Job, error)
	PreviewBatch(reqs []engine.BatchRequest) []string
	StartBatch(reqs []engine.BatchRequest, dryRun, stopOnFail bool, user string) (engine.Batch, error)
	OSSupport(r detect.Result) eol.Status
	PlanDocker(g inventory.Guest, keys []string) engine.DockerPlan
	SyncSnapshots(guests []inventory.Guest)
	CheckURL(key string) string
	SetCheckURL(key, raw string) error
	ScheduleBatch(reqs []engine.BatchRequest, stopOnFail bool, user, windowName string) (engine.Batch, error)
	CancelBatch(id, user string) error
	WindowFor(g inventory.Guest, now time.Time) engine.WindowStatus
	MaintenanceWindows() []window.Window
	NextAuto(now time.Time) time.Time
	AutoCandidates() []inventory.Guest
	ExecuteDocker(g inventory.Guest, keys []string, dryRun bool, user string, confirmed bool, typedName string, snapshot bool) (jobs.Job, error)
}

// Batches donne accès aux lots.
type Batches interface {
	Get(id string) (engine.Batch, bool)
	List(limit int) []engine.Batch
}

// Jobs donne accès aux tâches et à leur journal.
type Jobs interface {
	Get(id string) (jobs.Job, bool)
	List(targetKey string, limit int) []jobs.Job
	ActiveFor(t jobs.Target) (jobs.Job, bool)
	Log(id string) ([]jobs.Line, error)
	Subscribe(id string) ([]jobs.Line, <-chan jobs.Event, func(), error)
}

// Detections donne le dernier résultat de détection par invité.
type Detections interface {
	Get(key string) (detect.Result, bool)
	All() map[string]detect.Result
}

// Deps regroupe ce dont l'interface a besoin en plus de l'inventaire.
type Deps struct {
	Engine     Engine
	Jobs       Jobs
	Detections Detections
	Batches    Batches
	// NextDetection renvoie la prochaine détection planifiée (zéro : aucune).
	NextDetection func() time.Time
}

// Server porte l'état de l'interface.
type Server struct {
	cfg     *config.Config
	inv     Inventory
	deps    Deps
	log     *slog.Logger
	version string
	now     func() time.Time
	sess    *sessions
	thr     *throttle
	icons   *iconStore
	pages   map[string]*template.Template
}

// New prépare le serveur (gabarits compris).
func New(cfg *config.Config, inv Inventory, deps Deps, log *slog.Logger, version string) (*Server, error) {
	s := &Server{cfg: cfg, inv: inv, deps: deps, log: log, version: version, now: time.Now}
	s.sess = newSessions(cfg.Auth.SessionDuration.Duration, func() time.Time { return s.now() })
	s.thr = newThrottle(func() time.Time { return s.now() })
	icons := cfg.UI.Icons == nil || *cfg.UI.Icons
	s.icons = newIconStore(cfg.Jobs.DataDir, cfg.UI.IconBase, icons && cfg.Jobs.DataDir != "")
	funcs := template.FuncMap{
		"join":  strings.Join,
		"age":   func(t time.Time) string { return humanAge(s.now().Sub(t)) },
		"clock": func(t time.Time) string { return t.Local().Format("15:04:05") },
		"date":  func(t time.Time) string { return t.Local().Format("02/01/2006 15:04") },
		"answerLabel": func(v string) string {
			switch v {
			case "y":
				return "oui"
			case "n":
				return "non"
			default:
				return "réponse par défaut (Entrée)"
			}
		},
		"statusLabel": func(st string) string {
			switch st {
			case "running":
				return "démarré"
			case "stopped":
				return "arrêté"
			case "paused":
				return "en pause"
			case "", "unknown":
				return "inconnu"
			default:
				return st
			}
		},
		"statusClass": func(st jobs.Status) string {
			switch st {
			case jobs.Success:
				return "ok"
			case jobs.Failed:
				return "c"
			case jobs.Interrupted:
				return "w"
			default:
				return "a"
			}
		},
		"evClass": func(st jobs.Status) string {
			switch st {
			case jobs.Success:
				return ""
			case jobs.Failed:
				return "f"
			case jobs.Interrupted:
				return "w"
			default:
				return "r"
			}
		},
		"when": func(t time.Time) string {
			lt, now := t.Local(), s.now().Local()
			if lt.Year() == now.Year() && lt.YearDay() == now.YearDay() {
				return lt.Format("15:04")
			}
			return lt.Format("02/01 15:04")
		},
		"inc":       func(i int) int { return i + 1 },
		"sub":       func(a, b int) int { return a - b },
		"lineClass": lineClass,
		"itemClass": func(st string) string {
			switch st {
			case engine.ItemSuccess:
				return "ok"
			case engine.ItemFailed:
				return "c"
			case engine.ItemRunning:
				return "a"
			case engine.ItemCancelled:
				return "w"
			}
			return ""
		},
	}
	funcs["upper"] = strings.ToUpper
	funcs["hasPrefix"] = strings.HasPrefix
	funcs["guestNoun"] = func(typ string) string {
		if typ == "qemu" {
			return "la VM"
		}
		return "le CT"
	}
	funcs["level"] = level
	funcs["bar"] = barSVG
	funcs["initials"] = initials
	funcs["plural"] = plural
	funcs["pct"] = func(f float64) string { return fmt.Sprintf("%.0f", f) }
	funcs["since"] = func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return sinceLabel(s.now().Sub(t))
	}
	s.pages = map[string]*template.Template{}
	for _, p := range []string{"connexion", "traiter", "inventaire", "invite", "taches", "tache", "action", "restaurer", "snapshots", "reglages", "lot", "lots", "redemarrage", "docker"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/partiels.html", "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("gabarit %s : %w", p, err)
		}
		s.pages[p] = t
	}
	frag, err := template.New("apercu.html").Funcs(funcs).ParseFS(assets, "templates/partiels.html", "templates/apercu.html")
	if err != nil {
		return nil, fmt.Errorf("gabarit apercu : %w", err)
	}
	s.pages["apercu"] = frag
	return s, nil
}

// Handler renvoie le routeur HTTP complet.
func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /icones", s.authed(s.iconHandler))
	mux.HandleFunc("GET /sante", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /connexion", s.loginForm)
	mux.HandleFunc("POST /connexion", s.sameOrigin(s.loginSubmit))
	mux.HandleFunc("POST /deconnexion", s.sameOrigin(s.authed(s.csrf(s.logout))))
	mux.HandleFunc("GET /{$}", s.authed(s.todoPage))
	mux.HandleFunc("GET /inventaire", s.authed(s.inventoryPage))
	mux.HandleFunc("GET /lot", s.authed(s.batchPrepare))
	mux.HandleFunc("POST /lot", s.sameOrigin(s.authed(s.csrf(s.batchSubmit))))
	mux.HandleFunc("GET /lots/{id}", s.authed(s.batchPage))
	mux.HandleFunc("POST /lots/{id}/annuler", s.sameOrigin(s.authed(s.csrf(s.batchCancel))))
	mux.HandleFunc("GET /invites/{node}/{vmid}/redemarrage", s.authed(s.restartPage))
	mux.HandleFunc("POST /invites/{node}/{vmid}/redemarrage", s.sameOrigin(s.authed(s.csrf(s.restartSubmit))))
	mux.HandleFunc("GET /invites/{node}/{vmid}/docker", s.authed(s.dockerPage))
	mux.HandleFunc("POST /invites/{node}/{vmid}/docker", s.sameOrigin(s.authed(s.csrf(s.dockerSubmit))))
	mux.HandleFunc("GET /snapshots", s.authed(s.snapshotsPage))
	mux.HandleFunc("GET /reglages", s.authed(s.settingsPage))
	mux.HandleFunc("GET /invites/{node}/{vmid}/apercu", s.authed(s.previewFragment))
	mux.HandleFunc("POST /inventaire/rafraichir", s.sameOrigin(s.authed(s.csrf(s.refresh))))
	mux.HandleFunc("POST /inventaire/detecter", s.sameOrigin(s.authed(s.csrf(s.detectAll))))
	mux.HandleFunc("GET /invites/{node}/{vmid}", s.authed(s.guestPage))
	mux.HandleFunc("POST /invites/{node}/{vmid}/detecter", s.sameOrigin(s.authed(s.csrf(s.detectOne))))
	mux.HandleFunc("GET /invites/{node}/{vmid}/action/{action}", s.authed(s.actionPage))
	mux.HandleFunc("POST /invites/{node}/{vmid}/action/{action}", s.sameOrigin(s.authed(s.csrf(s.actionSubmit))))
	mux.HandleFunc("POST /invites/{node}/{vmid}/reponses", s.sameOrigin(s.authed(s.csrf(s.saveAnswers))))
	mux.HandleFunc("POST /invites/{node}/{vmid}/snapshots/reglage", s.sameOrigin(s.authed(s.csrf(s.saveSnapPref))))
	mux.HandleFunc("POST /invites/{node}/{vmid}/verification", s.sameOrigin(s.authed(s.csrf(s.saveCheckURL))))
	mux.HandleFunc("GET /invites/{node}/{vmid}/snapshots/{name}/restaurer", s.authed(s.rollbackPage))
	mux.HandleFunc("POST /invites/{node}/{vmid}/snapshots/{name}/restaurer", s.sameOrigin(s.authed(s.csrf(s.rollbackSubmit))))
	mux.HandleFunc("POST /invites/{node}/{vmid}/snapshots/{name}/supprimer", s.sameOrigin(s.authed(s.csrf(s.deleteSnapshot))))
	mux.HandleFunc("GET /securite", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusMovedPermanently) })
	mux.HandleFunc("GET /taches", s.authed(s.jobsPage))
	mux.HandleFunc("GET /taches/{id}", s.authed(s.jobPage))
	mux.HandleFunc("GET /taches/{id}/flux", s.authed(s.jobStream))
	mux.HandleFunc("GET /taches/{id}/etat", s.authed(s.jobState))
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
	// Pages dynamiques : jamais réaffichées depuis le cache (bouton Retour
	// du navigateur, onglet restauré), sinon une tâche finie paraît en cours.
	w.Header().Set("Cache-Control", "no-store")
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

// base contient ce que le gabarit commun affiche sur chaque page.
type base struct {
	Title, User, CSRF, Version, Nav string
	Search                          string
	Shell                           shell
}

func (s *Server) base(title, nav string, se *session) base {
	b := base{Title: title, Version: s.version, Nav: nav}
	if se != nil {
		b.User, b.CSRF = se.user, se.csrf
		b.Shell = s.shellFor()
	}
	return b
}

func (s *Server) allDetections() map[string]detect.Result {
	if s.deps.Detections == nil {
		return map[string]detect.Result{}
	}
	return s.deps.Detections.All()
}

// isSelf : invité qui héberge PatchWarden (aucune mise à jour lancée d'ici).
func (s *Server) isSelf(g inventory.Guest) bool {
	if e, ok := s.deps.Engine.(interface{ IsSelf(inventory.Guest) bool }); ok {
		return e.IsSelf(g)
	}
	return false
}

type loginData struct {
	base
	Error, Username string
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if _, se := s.currentSession(r); se != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "connexion", http.StatusOK, loginData{base: s.base("Connexion", "", nil)})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	data := loginData{base: s.base("Connexion", "", nil), Username: r.PostFormValue("username")}
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
	http.Redirect(w, r, "/inventaire?"+r.URL.RawQuery, http.StatusSeeOther)
}

type nodeGroup struct {
	Node string // nœud, ou tag quand l'inventaire est groupé par tag
	Rows []row
	Sec  int // invités avec des correctifs de sécurité (groupe par tag)
	Upd  int // invités avec des mises à jour
}

// row est un invité tel qu'affiché : sa dernière détection, sa tâche en cours
// et ce qui est possible.
type row struct {
	inventory.Guest
	Icon      string
	ShownTags []string // tags affichés (sans le tag community-scripts, déjà en badge)
	Det       *detect.Result
	Active    *jobs.Job
	CanDetect bool
	Why       string
	Self      bool
	OS        eol.Status // support du système (vide sans détection)
}

// OSName : système de l'invité, court (« Debian 12 »), vide sans détection.
func (r row) OSName() string {
	if r.Det == nil {
		return ""
	}
	if r.OS.Name != "" {
		return r.OS.Name
	}
	if r.Det.OSPretty != "" {
		return r.Det.OSPretty
	}
	return strings.TrimSpace(r.Det.OSID + " " + r.Det.OSVersion)
}

// Pending : la dernière détection signale quelque chose à faire.
func (r row) Pending() bool {
	return r.Det != nil && (r.Det.Apt.Total > 0 || r.Det.AppUpdates() > 0 || r.Det.RebootRequired || r.Det.DockerInfo.Updates() > 0)
}

// Major : une version majeure est disponible.
func (r row) Major() bool {
	if r.Det == nil {
		return false
	}
	for _, a := range r.Det.Apps {
		if a.UpdateAvailable() && a.MajorChange() {
			return true
		}
	}
	return false
}

func (s *Server) rowFor(g inventory.Guest) row {
	r := row{Guest: g, Self: s.isSelf(g)}
	t := jobs.Target{Node: g.Node, VMID: g.VMID}
	if s.deps.Detections != nil {
		if d, ok := s.deps.Detections.Get(t.Key()); ok {
			r.Det = &d
		}
	}
	if s.deps.Jobs != nil {
		if j, ok := s.deps.Jobs.ActiveFor(t); ok {
			r.Active = &j
		}
	}
	r.Icon = iconURL(g, r.Det)
	if r.Det != nil && s.deps.Engine != nil {
		r.OS = s.deps.Engine.OSSupport(*r.Det)
	}
	for _, t := range g.Tags {
		if !strings.EqualFold(t, s.cfg.Policy.CommunityScriptTag) || s.cfg.Policy.CommunityScriptTag == "" {
			r.ShownTags = append(r.ShownTags, t)
		}
	}
	if s.deps.Engine != nil {
		if err := s.deps.Engine.CanDetect(g); err != nil {
			r.Why = err.Error()
		} else {
			r.CanDetect = r.Active == nil
		}
	}
	return r
}

// view : filtre rapide de l'inventaire (puces).
type view struct {
	Key, Label string
	Count      int
	Current    bool
	URL        string
}

var views = []struct{ key, label string }{
	{"", "Tous"}, {"maj", "À mettre à jour"}, {"securite", "Sécurité"}, {"majeures", "Versions majeures"}, {"arretes", "Arrêtés"},
}

func viewMatch(key string, r row) bool {
	switch key {
	case "maj":
		return r.Pending()
	case "securite":
		return r.Det != nil && r.Det.Apt.Security > 0
	case "majeures":
		return r.Major()
	case "arretes":
		return r.Status != "running"
	}
	return true
}

type filter struct{ Node, Type, Tag, Q, View, OS string }

func (f filter) Active() bool {
	return f.Node != "" || f.Type != "" || f.Tag != "" || f.Q != "" || f.View != "" || f.OS != ""
}

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

func (f filter) query(view string) string {
	v := url.Values{}
	for k, x := range map[string]string{"noeud": f.Node, "type": f.Type, "tag": f.Tag, "q": f.Q, "vue": view, "os": f.OS} {
		if x != "" {
			v.Set(k, x)
		}
	}
	if len(v) == 0 {
		return "/inventaire"
	}
	return "/inventaire?" + v.Encode()
}

type kpis struct {
	Running, Total int
	Sec, SecGuests int
	Apps, Majors   int
	Snapshots      int
	Storage        string
	StoragePct     int
}

type inventoryData struct {
	base
	Loaded, Refreshing  bool
	Age, FetchedAt      string
	Errors              []string
	K                   kpis
	Views               []view
	Shown               int
	Groups              []nodeGroup
	Nodes, Tags, OSes   []string
	Filter              filter
	Query               string
	ByTag               bool
	GroupNode, GroupTag string // liens « grouper par »
}

func (s *Server) inventoryPage(w http.ResponseWriter, r *http.Request, se *session) {
	snap, refreshing := s.inv.Current()
	q := r.URL.Query()
	f := filter{Node: q.Get("noeud"), Type: q.Get("type"), Tag: q.Get("tag"), Q: strings.TrimSpace(q.Get("q")), View: q.Get("vue"), OS: q.Get("os")}
	d := inventoryData{
		base:   s.base("Inventaire", "inventaire", se),
		Loaded: !snap.FetchedAt.IsZero(), Refreshing: refreshing,
		Nodes: snap.Nodes(), Filter: f, Query: r.URL.RawQuery,
	}
	d.Search = f.Q
	d.ByTag = q.Get("grouper") == "tag"
	{
		v := r.URL.Query()
		v.Del("grouper")
		d.GroupNode = "/inventaire?" + v.Encode()
		v.Set("grouper", "tag")
		d.GroupTag = "/inventaire?" + v.Encode()
	}
	if d.Loaded {
		d.Age = humanAge(s.now().Sub(snap.FetchedAt))
		d.FetchedAt = snap.FetchedAt.Local().Format("02/01/2006 15:04:05")
	}
	for name, e := range snap.Errors {
		d.Errors = append(d.Errors, name+" : "+e)
	}
	sort.Strings(d.Errors)

	tags := map[string]bool{}
	oses := map[string]bool{}
	groups := map[string]*nodeGroup{}
	counts := make([]int, len(views))
	for _, g := range snap.Guests {
		for _, t := range g.Tags {
			tags[t] = true
		}
		rw := s.rowFor(g)
		d.K.Total++
		if g.Status == "running" {
			d.K.Running++
		}
		if rw.Det != nil {
			if rw.Det.Apt.Security > 0 {
				d.K.Sec += rw.Det.Apt.Security
				d.K.SecGuests++
			}
			for _, a := range rw.Det.Apps {
				if a.UpdateAvailable() {
					d.K.Apps++
					if a.MajorChange() {
						d.K.Majors++
					}
				}
			}
			d.K.Snapshots += len(rw.Det.Snap.PW)
		}
		if n := rw.OSName(); n != "" {
			oses[n] = true
		}
		if !f.match(g) || (f.OS != "" && rw.OSName() != f.OS) {
			continue
		}
		for i, v := range views {
			if viewMatch(v.key, rw) {
				counts[i]++
			}
		}
		if !viewMatch(f.View, rw) {
			continue
		}
		d.Shown++
		keys := []string{g.Node}
		if d.ByTag {
			keys = nil
			for _, t := range rw.ShownTags {
				keys = append(keys, t)
			}
			if len(keys) == 0 {
				keys = []string{"sans tag"}
			}
		}
		for _, k := range keys {
			ng, ok := groups[k]
			if !ok {
				ng = &nodeGroup{Node: k}
				groups[k] = ng
			}
			ng.Rows = append(ng.Rows, rw)
			if rw.Det != nil && !g.Critical && rw.Det.Special == "" {
				if rw.Det.Apt.Security > 0 {
					ng.Sec++
				}
				if rw.Det.Apt.Total > 0 || rw.Det.AppUpdates() > 0 || rw.Det.DockerInfo.Updates() > 0 {
					ng.Upd++
				}
			}
		}
	}
	for i, v := range views {
		d.Views = append(d.Views, view{Key: v.key, Label: v.label, Count: counts[i], Current: v.key == f.View, URL: f.query(v.key)})
	}
	best := -1
	inUse := storagesInUse(s.allDetections())
	for n, st := range snap.NodeStats {
		if stor, ok := st.PickStorage(inUse[n]); ok && stor.Pct() > best {
			best = stor.Pct()
			d.K.Storage, d.K.StoragePct = stor.Name+" ("+n+")", best
		}
	}
	if d.ByTag {
		names := make([]string, 0, len(groups))
		for k := range groups {
			if k != "sans tag" {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		if _, ok := groups["sans tag"]; ok {
			names = append(names, "sans tag")
		}
		for _, k := range names {
			d.Groups = append(d.Groups, *groups[k])
		}
	} else {
		for _, n := range d.Nodes {
			if ng, ok := groups[n]; ok {
				d.Groups = append(d.Groups, *ng)
			}
		}
	}
	for t := range tags {
		d.Tags = append(d.Tags, t)
	}
	sort.Strings(d.Tags)
	for o := range oses {
		d.OSes = append(d.OSes, o)
	}
	sort.Strings(d.OSes)
	s.render(w, "inventaire", http.StatusOK, d)
}

// sinceLabel : « depuis 3 j », pour l'ancienneté d'une mise à jour en attente.
func sinceLabel(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("depuis %d min", max(1, int(d.Minutes())))
	case d < 48*time.Hour:
		return fmt.Sprintf("depuis %d h", int(d.Hours()))
	default:
		return fmt.Sprintf("depuis %d j", int(d.Hours()/24))
	}
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
