// Package config charge et valide la configuration de PatchWarden.
//
// La configuration est un fichier TOML exclu de Git. Les secrets (jetons API)
// peuvent y figurer directement, ou être lus dans une variable d'environnement
// désignée par le fichier, pour rester hors du disque.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Duration accepte en TOML une chaîne comme "5m" ou "12h".
type Duration struct{ time.Duration }

// UnmarshalText implémente encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("durée invalide %q (exemples : 30s, 5m, 12h)", string(b))
	}
	d.Duration = v
	return nil
}

// MarshalText implémente encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Config est la configuration complète.
type Config struct {
	Server    Server     `toml:"server"`
	Auth      Auth       `toml:"auth"`
	Proxmox   []Endpoint `toml:"proxmox"`
	Policy    Policy     `toml:"policy"`
	Inventory Inventory  `toml:"inventory"`
	SSH       SSH        `toml:"ssh"`
	Jobs      Jobs       `toml:"jobs"`
	Detection Detection  `toml:"detection"`
	CS        CS         `toml:"community_scripts"`
	Upstream  Upstream   `toml:"upstream"`
	Schedule  Schedule   `toml:"schedule"`
	UI        UI         `toml:"ui"`
	Notify    []Notify   `toml:"notify"`
}

// UI règle l'interface.
type UI struct {
	// Icons : icônes des applications et des OS (selfh.st/icons, CC BY 4.0),
	// téléchargées par PatchWarden et mises en cache. Défaut : true.
	Icons    *bool  `toml:"icons"`
	IconBase string `toml:"icon_base"`
}

// Schedule règle la détection automatique (lecture seule).
type Schedule struct {
	// DetectAt : heures locales (« HH:MM ») de détection de tous les LXC démarrés.
	DetectAt []string `toml:"detect_at"`
}

// Notify est une cible de notification.
type Notify struct {
	Type     string `toml:"type"` // ntfy, gotify, webhook
	URL      string `toml:"url"`
	Token    string `toml:"token"`
	TokenEnv string `toml:"token_env"`
	// Events : securite, applis, echec, succes (défaut : securite, applis, echec).
	Events []string `toml:"events"`
}

// SSH règle l'accès aux nœuds (wrapper à commande forcée). Sans nœud déclaré,
// PatchWarden reste en lecture seule : aucune détection ni action.
type SSH struct {
	User           string   `toml:"user"`
	KeyFile        string   `toml:"key_file"`
	KnownHosts     string   `toml:"known_hosts"`
	ConnectTimeout Duration `toml:"connect_timeout"`
	// Nodes associe le nom du nœud Proxmox à son adresse SSH (hôte ou hôte:port).
	Nodes map[string]string `toml:"nodes"`
}

// Enabled indique si l'accès SSH est configuré.
func (s SSH) Enabled() bool { return len(s.Nodes) > 0 }

// Jobs règle l'exécution des tâches.
type Jobs struct {
	// DataDir contient l'historique des tâches et l'état de la détection.
	DataDir string `toml:"data_dir"`
	// MaxParallel limite le nombre de tâches simultanées (une seule par invité, toujours).
	MaxParallel int `toml:"max_parallel"`
	// Retention : nombre de tâches gardées dans l'historique.
	Retention int `toml:"retention"`
}

// Detection règle la détection des mises à jour.
type Detection struct {
	// AptRefresh lance `apt-get update` avant la simulation (index souvent vieux de plusieurs semaines).
	AptRefresh *bool    `toml:"apt_refresh"`
	Timeout    Duration `toml:"timeout"`
}

// CS règle l'usage des scripts community-scripts.
type CS struct {
	// AllowedBases : seules sources de scripts que PatchWarden accepte de lire.
	// La base vient de l'invité ; la restreindre évite qu'un invité compromis
	// fasse télécharger n'importe quelle URL à PatchWarden.
	AllowedBases []string `toml:"allowed_bases"`
	WebsiteURL   string   `toml:"website_url"`
}

// Upstream règle l'interrogation des forges (dernières versions).
type Upstream struct {
	// Jeton GitHub facultatif en lecture seule (sinon 60 requêtes/heure).
	GitHubToken    string `toml:"github_token"`
	GitHubTokenEnv string `toml:"github_token_env"`
	// GitHubAPI : base de l'API (à changer seulement pour GitHub Enterprise).
	GitHubAPI string   `toml:"github_api"`
	CacheTTL  Duration `toml:"cache_ttl"`
}

// Server règle le serveur HTTP.
type Server struct {
	// Listen est l'adresse d'écoute, par exemple "0.0.0.0:8080".
	Listen string `toml:"listen"`
	// PublicURL : adresse de l'interface, pour les liens des notifications
	// (ex. « http://192.168.0.19:8094 »). Facultatif.
	PublicURL string `toml:"public_url"`
	// CookieSecure ajoute l'attribut Secure au cookie de session. À activer
	// dès que l'interface est servie en HTTPS (directement ou derrière un proxy).
	CookieSecure bool `toml:"cookie_secure"`
}

// Auth règle l'authentification de l'interface (un seul compte).
type Auth struct {
	Username string `toml:"username"`
	// PasswordHash est un hachage bcrypt produit par `patchwarden hash-password`.
	PasswordHash    string   `toml:"password_hash"`
	SessionDuration Duration `toml:"session_duration"`
}

// Endpoint est un point d'accès à l'API Proxmox. En cluster, un seul suffit
// (en mettre plusieurs donne de la redondance) ; avec des nœuds autonomes, il
// en faut un par nœud, chacun avec son propre jeton.
type Endpoint struct {
	Name           string `toml:"name"`
	URL            string `toml:"url"`
	TokenID        string `toml:"token_id"`
	TokenSecret    string `toml:"token_secret"`
	TokenSecretEnv string `toml:"token_secret_env"`
	// Fingerprint est l'empreinte SHA-256 du certificat du nœud (épinglage,
	// indépendant du nom d'hôte et de l'IP). Alternative : CAFile.
	Fingerprint string `toml:"fingerprint"`
	// CAFile est un fichier PEM d'autorité (par exemple pve-root-ca.pem du
	// cluster). Le nom d'hôte de l'URL doit alors figurer dans le certificat.
	CAFile string `toml:"ca_file"`
}

// Policy règle la classification des invités.
type Policy struct {
	// CommunityScriptTag est le tag Proxmox posé par community-scripts.
	CommunityScriptTag string `toml:"community_script_tag"`
	// CriticalTags : un invité portant l'un de ces tags exige une confirmation renforcée.
	CriticalTags []string `toml:"critical_tags"`
	// SpecialNames : fragments de nom (insensibles à la casse) qui signalent
	// OMV, PBS, etc. Confirmation renforcée également.
	SpecialNames []string `toml:"special_names"`
	// SelfGuest : invité qui héberge PatchWarden (« nœud/vmid », ex. « loki/103 »).
	// Aucune mise à jour n'y est lancée depuis PatchWarden (elle le couperait).
	// Vide : l'invité dont le nom égale le nom d'hôte de PatchWarden.
	SelfGuest string `toml:"self_guest"`
}

// Inventory règle la lecture de l'inventaire.
type Inventory struct {
	Refresh Duration `toml:"refresh"`
	Timeout Duration `toml:"timeout"`
}

var (
	nameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	selfRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*/[1-9][0-9]*$`)
	tokenIDRe = regexp.MustCompile(`^[^@!\s]+@[^@!\s]+![A-Za-z][A-Za-z0-9._-]*$`)
)

// Load lit, complète et valide le fichier. Les avertissements (non bloquants)
// sont renvoyés à part, par exemple des droits trop ouverts sur le fichier.
func Load(path string) (*Config, []string, error) {
	var cfg Config
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("lecture de %s : %w", path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return nil, nil, fmt.Errorf("clés inconnues dans %s : %s", path, strings.Join(keys, ", "))
	}
	cfg.applyDefaults()
	if err := cfg.resolveSecrets(os.Getenv); err != nil {
		return nil, nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	var warnings []string
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o007 != 0 {
		warnings = append(warnings, fmt.Sprintf("%s est lisible par tous les utilisateurs (droits %o) : utilisez chmod 640 (root:patchwarden) ou 600", path, st.Mode().Perm()))
	}
	return &cfg, warnings, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "0.0.0.0:8080"
	}
	if c.Auth.SessionDuration.Duration == 0 {
		c.Auth.SessionDuration.Duration = 12 * time.Hour
	}
	if c.Policy.CommunityScriptTag == "" {
		c.Policy.CommunityScriptTag = "community-script"
	}
	if c.Policy.CriticalTags == nil {
		c.Policy.CriticalTags = []string{"critique"}
	}
	if c.Policy.SpecialNames == nil {
		c.Policy.SpecialNames = []string{"omv", "pbs", "proxmox-backup"}
	}
	if c.Inventory.Refresh.Duration == 0 {
		c.Inventory.Refresh.Duration = 5 * time.Minute
	}
	if c.Inventory.Timeout.Duration == 0 {
		c.Inventory.Timeout.Duration = 15 * time.Second
	}
	if c.SSH.User == "" {
		c.SSH.User = "root"
	}
	if c.SSH.ConnectTimeout.Duration == 0 {
		c.SSH.ConnectTimeout.Duration = 10 * time.Second
	}
	for n, a := range c.SSH.Nodes {
		if _, _, err := net.SplitHostPort(a); err != nil {
			c.SSH.Nodes[n] = net.JoinHostPort(a, "22")
		}
	}
	if c.Jobs.DataDir == "" {
		c.Jobs.DataDir = "/var/lib/patchwarden"
	}
	if c.Jobs.MaxParallel == 0 {
		c.Jobs.MaxParallel = 2
	}
	if c.Jobs.Retention == 0 {
		c.Jobs.Retention = 500
	}
	if c.Detection.AptRefresh == nil {
		t := true
		c.Detection.AptRefresh = &t
	}
	if c.Detection.Timeout.Duration == 0 {
		c.Detection.Timeout.Duration = 15 * time.Minute
	}
	if c.CS.AllowedBases == nil {
		c.CS.AllowedBases = []string{"https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main"}
	}
	if c.CS.WebsiteURL == "" {
		c.CS.WebsiteURL = "https://community-scripts.org"
	}
	if c.UI.Icons == nil {
		t := true
		c.UI.Icons = &t
	}
	if c.UI.IconBase == "" {
		c.UI.IconBase = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp"
	}
	if c.Upstream.GitHubAPI == "" {
		c.Upstream.GitHubAPI = "https://api.github.com"
	}
	if c.Upstream.CacheTTL.Duration == 0 {
		c.Upstream.CacheTTL.Duration = 6 * time.Hour
	}
}

// resolveSecrets remplit TokenSecret depuis l'environnement quand c'est demandé.
func (c *Config) resolveSecrets(getenv func(string) string) error {
	for i := range c.Proxmox {
		ep := &c.Proxmox[i]
		if ep.TokenSecretEnv == "" {
			continue
		}
		if ep.TokenSecret != "" {
			return fmt.Errorf("proxmox %q : token_secret et token_secret_env sont exclusifs", ep.Name)
		}
		ep.TokenSecret = getenv(ep.TokenSecretEnv)
		if ep.TokenSecret == "" {
			return fmt.Errorf("proxmox %q : la variable d'environnement %s est vide ou absente", ep.Name, ep.TokenSecretEnv)
		}
	}
	for i := range c.Notify {
		n := &c.Notify[i]
		if n.TokenEnv == "" {
			continue
		}
		if n.Token != "" {
			return fmt.Errorf("notify n° %d : token et token_env sont exclusifs", i+1)
		}
		n.Token = getenv(n.TokenEnv)
		if n.Token == "" {
			return fmt.Errorf("notify n° %d : la variable d'environnement %s est vide ou absente", i+1, n.TokenEnv)
		}
	}
	if c.Upstream.GitHubTokenEnv != "" {
		if c.Upstream.GitHubToken != "" {
			return errors.New("upstream : github_token et github_token_env sont exclusifs")
		}
		c.Upstream.GitHubToken = getenv(c.Upstream.GitHubTokenEnv)
	}
	return nil
}

// Validate vérifie la cohérence de la configuration.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if _, _, err := net.SplitHostPort(c.Server.Listen); err != nil {
		add("server.listen invalide (%q) : attendu hôte:port", c.Server.Listen)
	}
	if strings.TrimSpace(c.Auth.Username) == "" {
		add("auth.username est obligatoire")
	}
	if !strings.HasPrefix(c.Auth.PasswordHash, "$2") {
		add("auth.password_hash doit être un hachage bcrypt (générez-le avec : patchwarden hash-password)")
	}
	if c.Auth.SessionDuration.Duration < time.Minute {
		add("auth.session_duration doit valoir au moins 1m")
	}
	if len(c.Proxmox) == 0 {
		add("au moins une section [[proxmox]] est obligatoire")
	}
	seen := map[string]bool{}
	for i, ep := range c.Proxmox {
		label := ep.Name
		if label == "" {
			label = fmt.Sprintf("n° %d", i+1)
		}
		if !nameRe.MatchString(ep.Name) {
			add("proxmox %s : name doit être court, en minuscules, chiffres et tirets", label)
		}
		if seen[ep.Name] {
			add("proxmox %s : nom en double", label)
		}
		seen[ep.Name] = true
		u, err := url.Parse(ep.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			add("proxmox %s : url doit être de la forme https://hôte:8006", label)
		}
		if !tokenIDRe.MatchString(ep.TokenID) {
			add("proxmox %s : token_id doit être de la forme utilisateur@royaume!nom (ex. patchwarden@pve!inventaire)", label)
		}
		if ep.TokenSecret == "" {
			add("proxmox %s : token_secret ou token_secret_env est obligatoire", label)
		}
		switch {
		case ep.Fingerprint == "" && ep.CAFile == "":
			add("proxmox %s : fingerprint ou ca_file est obligatoire (pas de connexion TLS non vérifiée)", label)
		case ep.Fingerprint != "" && ep.CAFile != "":
			add("proxmox %s : fingerprint et ca_file sont exclusifs", label)
		case ep.Fingerprint != "":
			if _, err := ParseFingerprint(ep.Fingerprint); err != nil {
				add("proxmox %s : %v", label, err)
			}
		default:
			if _, err := os.Stat(ep.CAFile); err != nil {
				add("proxmox %s : ca_file illisible : %v", label, err)
			}
		}
	}
	if c.Inventory.Refresh.Duration < 30*time.Second {
		add("inventory.refresh doit valoir au moins 30s")
	}
	if c.Inventory.Timeout.Duration <= 0 {
		add("inventory.timeout doit être positif")
	}
	if u, err := url.Parse(c.UI.IconBase); err != nil || u.Scheme != "https" || u.Host == "" {
		add("ui.icon_base : URL https attendue, obtenu %q", c.UI.IconBase)
	}
	for _, t := range c.Schedule.DetectAt {
		if _, err := time.Parse("15:04", t); err != nil {
			add("schedule.detect_at : heure « HH:MM » attendue, obtenu %q", t)
		}
	}
	if c.Server.PublicURL != "" {
		if u, err := url.Parse(c.Server.PublicURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("server.public_url : URL http(s) attendue, obtenu %q", c.Server.PublicURL)
		}
	}
	for i, n := range c.Notify {
		switch n.Type {
		case "ntfy", "gotify", "webhook":
		default:
			add("notify n° %d : type attendu ntfy, gotify ou webhook, obtenu %q", i+1, n.Type)
		}
		if u, err := url.Parse(n.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			add("notify n° %d : url http(s) attendue, obtenu %q", i+1, n.URL)
		} else if strings.HasSuffix(u.Host, ":") || strings.Contains(u.Path, "://") || strings.HasPrefix(u.Path, "//") {
			add("notify n° %d : url mal formée %q : un seul préfixe http(s)://, par exemple https://ntfy.sh/mon-sujet", i+1, n.URL)
		} else if n.Type == "ntfy" && strings.Trim(u.Path, "/") == "" {
			add("notify n° %d : l'url ntfy doit contenir le sujet (ex. https://ntfy.sh/mon-sujet)", i+1)
		}
		if n.Type == "gotify" && n.Token == "" {
			add("notify n° %d : gotify exige token ou token_env (jeton d'application)", i+1)
		}
		for _, e := range n.Events {
			switch e {
			case "securite", "applis", "echec", "succes":
			default:
				add("notify n° %d : événement inconnu %q (securite, applis, echec, succes)", i+1, e)
			}
		}
	}
	if c.Policy.SelfGuest != "" && !selfRe.MatchString(c.Policy.SelfGuest) {
		add("policy.self_guest : format « nœud/vmid » attendu (ex. loki/103), obtenu %q", c.Policy.SelfGuest)
	}
	if c.SSH.Enabled() {
		if c.SSH.KeyFile == "" {
			add("ssh.key_file est obligatoire (générez la clé avec : patchwarden ssh-keygen)")
		} else if _, err := os.Stat(c.SSH.KeyFile); err != nil {
			add("ssh.key_file illisible : %v (créez la clé avec « patchwarden ssh-keygen », étape 6 du README, ou commentez [ssh.nodes] pour rester en lecture seule)", err)
		}
		if c.SSH.KnownHosts == "" {
			add("ssh.known_hosts est obligatoire : les clés d'hôte des nœuds sont toujours vérifiées")
		} else if _, err := os.Stat(c.SSH.KnownHosts); err != nil {
			add("ssh.known_hosts illisible : %v (remplissez-le avec ssh-keyscan, étape 6 du README, ou commentez [ssh.nodes] pour rester en lecture seule)", err)
		}
		for n, a := range c.SSH.Nodes {
			if !nameRe.MatchString(n) {
				add("ssh.nodes : nom de nœud invalide %q (minuscules, chiffres, tirets)", n)
			}
			if h, p, err := net.SplitHostPort(a); err != nil || h == "" || p == "" {
				add("ssh.nodes.%s : adresse invalide %q", n, a)
			}
		}
	}
	if c.Jobs.MaxParallel < 1 || c.Jobs.MaxParallel > 16 {
		add("jobs.max_parallel doit être compris entre 1 et 16")
	}
	if c.Jobs.Retention < 10 {
		add("jobs.retention doit valoir au moins 10")
	}
	if u, err := url.Parse(c.Upstream.GitHubAPI); err != nil || u.Scheme != "https" || u.Host == "" {
		add("upstream.github_api : URL https attendue, obtenu %q", c.Upstream.GitHubAPI)
	}
	for _, b := range c.CS.AllowedBases {
		if u, err := url.Parse(b); err != nil || u.Scheme != "https" || u.Host == "" {
			add("community_scripts.allowed_bases : URL https attendue, obtenu %q", b)
		}
	}
	return errors.Join(errs...)
}

// ParseFingerprint accepte une empreinte SHA-256 en hexadécimal, avec ou sans
// deux-points (format affiché par Proxmox et par openssl).
func ParseFingerprint(s string) ([]byte, error) {
	clean := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(s))
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("fingerprint invalide : attendu une empreinte SHA-256 (64 caractères hexadécimaux, deux-points facultatifs)")
	}
	return b, nil
}
