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
}

// Server règle le serveur HTTP.
type Server struct {
	// Listen est l'adresse d'écoute, par exemple "0.0.0.0:8080".
	Listen string `toml:"listen"`
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
}

// Inventory règle la lecture de l'inventaire.
type Inventory struct {
	Refresh Duration `toml:"refresh"`
	Timeout Duration `toml:"timeout"`
}

var (
	nameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
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
