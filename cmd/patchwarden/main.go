// Commande patchwarden : interface web de suivi et de mise à jour d'un homelab Proxmox VE.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/cs"
	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/proxmox"
	"github.com/LuckyS7evin/patchwarden/internal/sshx"
	"github.com/LuckyS7evin/patchwarden/internal/upstream"
	"github.com/LuckyS7evin/patchwarden/internal/web"
)

// version est fixée à la compilation : -ldflags "-X main.version=…".
var version = "dev"

const defaultConfig = "/etc/patchwarden/config.toml"

const usage = `PatchWarden %s

Usage :
  patchwarden [serve] [-config FICHIER]   lance l'interface web (par défaut)
  patchwarden check-config [-config FICHIER]
                                         valide la configuration et teste chaque point d'accès Proxmox
  patchwarden hash-password              produit le hachage bcrypt à mettre dans auth.password_hash
  patchwarden ssh-keygen -key FICHIER -from IP
                                         crée la clé SSH dédiée et affiche la ligne authorized_keys des nœuds
  patchwarden version

Fichier de configuration par défaut : %s
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "check-config":
		err = checkConfig(args)
	case "hash-password":
		err = hashPassword()
	case "ssh-keygen":
		err = sshKeygen(args)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Printf(usage, version, defaultConfig)
	default:
		fmt.Fprintf(os.Stderr, usage, version, defaultConfig)
		err = fmt.Errorf("commande inconnue : %s", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		os.Exit(1)
	}
}

func configFlag(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("config", defaultConfig, "fichier de configuration")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *path, nil
}

func loadConfig(path string, log *slog.Logger) (*config.Config, error) {
	cfg, warnings, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		log.Warn(w)
	}
	return cfg, nil
}

func sources(cfg *config.Config) ([]inventory.Source, error) {
	var out []inventory.Source
	for _, ep := range cfg.Proxmox {
		c, err := proxmox.New(ep, cfg.Inventory.Timeout.Duration)
		if err != nil {
			return nil, fmt.Errorf("proxmox %q : %w", ep.Name, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func serve(args []string) error {
	path, err := configFlag("serve", args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := loadConfig(path, log)
	if err != nil {
		return err
	}
	srcs, err := sources(cfg)
	if err != nil {
		return err
	}
	inv := inventory.New(srcs, cfg.Policy, cfg.Inventory.Timeout.Duration, log)

	jm, err := jobs.New(cfg.Jobs.DataDir, cfg.Jobs.MaxParallel, cfg.Jobs.Retention, log)
	if err != nil {
		return err
	}
	defer jm.Close()
	store, err := detect.OpenStore(cfg.Jobs.DataDir)
	if err != nil {
		return fmt.Errorf("état de la détection : %w", err)
	}
	up := upstream.New(cfg.Upstream.GitHubToken, cfg.Upstream.CacheTTL.Duration, nil)
	up.GitHubAPI = strings.TrimRight(cfg.Upstream.GitHubAPI, "/")
	eng := &engine.Engine{
		Jobs: jm, Store: store, Log: log,
		Scripts:    cs.NewFetcher(cfg.CS.AllowedBases, cfg.Upstream.CacheTTL.Duration, nil),
		Upstream:   up,
		Website:    cfg.CS.WebsiteURL,
		AptRefresh: *cfg.Detection.AptRefresh,
		Timeout:    cfg.Detection.Timeout.Duration,
	}
	if cfg.SSH.Enabled() {
		ex, err := sshx.New(cfg.SSH)
		if err != nil {
			return err
		}
		eng.Runner, eng.HasNode = ex, ex.HasNode
	} else {
		log.Warn("aucune section [ssh.nodes] : PatchWarden reste en lecture seule (ni détection ni action)")
	}
	ui, err := web.New(cfg, inv, web.Deps{Engine: eng, Jobs: jm, Detections: store}, log, version)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go inv.Run(ctx, cfg.Inventory.Refresh.Duration)

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           ui.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// Pas de WriteTimeout : les journaux en direct (SSE) resteront ouverts.
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("PatchWarden démarré", "version", version, "écoute", cfg.Server.Listen, "points_d_accès", len(srcs))
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("arrêt demandé")
	shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func checkConfig(args []string) error {
	path, err := configFlag("check-config", args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg, err := loadConfig(path, log)
	if err != nil {
		return err
	}
	fmt.Printf("Configuration valide : %s\n", path)
	srcs, err := sources(cfg)
	if err != nil {
		return err
	}
	failed := 0
	for _, s := range srcs {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Inventory.Timeout.Duration)
		guests, err := s.Guests(ctx)
		cancel()
		if err != nil {
			failed++
			fmt.Printf("  ✘ %s\n", err)
			continue
		}
		nodes := map[string]int{}
		total := 0
		for _, g := range guests {
			if g.Type == "lxc" || g.Type == "qemu" {
				nodes[g.Node]++
				total++
			}
		}
		fmt.Printf("  ✔ %s : %d invités sur %d nœud(s) %v\n", s.Name(), total, len(nodes), nodes)
	}
	if cfg.SSH.Enabled() {
		ex, err := sshx.New(cfg.SSH)
		if err != nil {
			return err
		}
		fmt.Println("Nœuds SSH (wrapper) :")
		for node := range cfg.SSH.Nodes {
			ctx, cancel := context.WithTimeout(context.Background(), cfg.SSH.ConnectTimeout.Duration+5*time.Second)
			var out []string
			code, err := ex.Run(ctx, node, "ping", func(l sshx.Line) { out = append(out, l.Text) })
			cancel()
			switch {
			case err != nil:
				failed++
				fmt.Printf("  ✘ %s : %v\n", node, err)
			case code != 0:
				failed++
				fmt.Printf("  ✘ %s : code %d %s\n", node, code, strings.Join(out, " "))
			default:
				fmt.Printf("  ✔ %s : %s\n", node, strings.Join(out, " "))
			}
		}
	} else {
		fmt.Println("Pas de section [ssh.nodes] : lecture seule.")
	}
	if failed > 0 {
		return fmt.Errorf("%d vérification(s) en erreur", failed)
	}
	return nil
}

// sshKeygen crée la clé ed25519 dédiée et affiche la ligne à ajouter dans
// /root/.ssh/authorized_keys des nœuds (partagé par tout le cluster).
func sshKeygen(args []string) error {
	fs := flag.NewFlagSet("ssh-keygen", flag.ContinueOnError)
	keyPath := fs.String("key", "/etc/patchwarden/id_ed25519", "fichier de clé privée à créer")
	from := fs.String("from", "", "IP de PatchWarden (seule source autorisée à utiliser la clé)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if net.ParseIP(*from) == nil {
		return errors.New("-from doit être l'adresse IP du LXC PatchWarden (ex. -from 192.168.0.20)")
	}
	if _, err := os.Stat(*keyPath); err == nil {
		return fmt.Errorf("%s existe déjà : supprimez-le d'abord si vous voulez une nouvelle clé", *keyPath)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "patchwarden")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	line := fmt.Sprintf(`command="/usr/local/sbin/patchwarden-wrapper",from="%s",restrict %s patchwarden`, *from, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))))
	fmt.Fprintf(os.Stderr, "Clé privée écrite dans %s (droits 600). Donnez-la à l'utilisateur du service :\n  chown patchwarden:patchwarden %s\n\n", *keyPath, *keyPath)
	fmt.Fprintln(os.Stderr, "Ligne à ajouter à /root/.ssh/authorized_keys des nœuds :")
	fmt.Println(line)
	return nil
}

func hashPassword() error {
	var pw string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Mot de passe : ")
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, "Confirmation : ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		if string(a) != string(b) {
			return errors.New("les deux saisies diffèrent")
		}
		pw = string(a)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("mot de passe attendu sur l'entrée standard")
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if len(pw) < 12 {
		return errors.New("12 caractères minimum")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return err
	}
	fmt.Println(string(h))
	return nil
}
