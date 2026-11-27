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
	"strconv"
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
	"github.com/LuckyS7evin/patchwarden/internal/eol"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/notify"
	"github.com/LuckyS7evin/patchwarden/internal/portainer"
	"github.com/LuckyS7evin/patchwarden/internal/proxmox"
	"github.com/LuckyS7evin/patchwarden/internal/registry"
	"github.com/LuckyS7evin/patchwarden/internal/schedule"
	"github.com/LuckyS7evin/patchwarden/internal/sshx"
	"github.com/LuckyS7evin/patchwarden/internal/upstream"
	"github.com/LuckyS7evin/patchwarden/internal/web"
)

// version est fixée à la compilation : -ldflags "-X main.version=…".
var version = "dev"

const defaultConfig = "/etc/patchwarden/config.toml"

const usage = `PatchWarden %s

Usage :
  patchwarden [serve] [-config FICHIER] [-env FICHIER]
                                         lance l'interface web (par défaut)
  patchwarden check-config [-config FICHIER]
                                         valide la configuration et teste chaque point d'accès Proxmox
  patchwarden notify-test [-config FICHIER]
                                         envoie un message de test à chaque cible [[notify]]
  patchwarden hash-password              produit le hachage bcrypt à mettre dans auth.password_hash
  patchwarden ssh-keygen -key FICHIER -from IP
                                         crée la clé SSH dédiée et affiche la ligne authorized_keys des nœuds
  patchwarden version

Fichier de configuration par défaut : %s
Les secrets (variables *_env de la configuration) sont lus dans l'environnement,
puis dans /etc/patchwarden/patchwarden.env (option -env pour un autre fichier).
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
	case "notify-test":
		err = notifyTest(args)
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

const defaultEnvFile = "/etc/patchwarden/patchwarden.env"

// configFlag lit -config et -env, puis charge le fichier d'environnement (les
// secrets désignés par *_env dans la configuration), comme le fait systemd :
// check-config et notify-test fonctionnent ainsi sans « source » préalable.
func configFlag(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("config", defaultConfig, "fichier de configuration")
	env := fs.String("env", defaultEnvFile, "fichier d'environnement (secrets) ; vide pour ne rien charger")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "env" {
			explicit = true
		}
	})
	if *env != "" {
		warn, err := config.LoadEnvFile(*env, !explicit)
		if err != nil {
			return "", err
		}
		if warn != "" {
			fmt.Fprintln(os.Stderr, "Avertissement :", warn)
		}
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
	answers, err := engine.OpenAnswers(cfg.Jobs.DataDir)
	if err != nil {
		return fmt.Errorf("réponses aux questions des scripts : %w", err)
	}
	snapPrefs, err := engine.OpenPrefs(cfg.Jobs.DataDir, "snapshots.json")
	if err != nil {
		return fmt.Errorf("réglages de snapshot des invités : %w", err)
	}
	batches, err := engine.OpenBatches(cfg.Jobs.DataDir)
	if err != nil {
		return fmt.Errorf("lots : %w", err)
	}
	hostname, _ := os.Hostname()
	up := upstream.New(cfg.Upstream.GitHubToken, cfg.Upstream.CacheTTL.Duration, nil)
	up.GitHubAPI = strings.TrimRight(cfg.Upstream.GitHubAPI, "/")
	eng := &engine.Engine{
		Jobs: jm, Store: store, Log: log,
		Scripts:    cs.NewFetcher(cfg.CS.AllowedBases, cfg.Upstream.CacheTTL.Duration, nil),
		Upstream:   up,
		Website:    cfg.CS.WebsiteURL,
		AptRefresh: *cfg.Detection.AptRefresh,
		Timeout:    cfg.Detection.Timeout.Duration,
		Answers:    answers,
		SelfGuest:  cfg.Policy.SelfGuest,
		Hostname:   hostname,
		Notify:     notify.New(cfg.Notify, nil, log),
		PublicURL:  cfg.Server.PublicURL,
		Snap:       engine.SnapConfig{Default: cfg.Snapshots.Default, Keep: cfg.Snapshots.Keep, MaxPct: cfg.Snapshots.MaxStoragePct},
		SnapPrefs:  snapPrefs,
		Batches:    batches,
		EOL:        eol.New(cfg.EOL.Source, nil),
	}
	if *cfg.Docker.RegistryCheck {
		eng.Registry = registry.New(cfg.Docker.CacheTTL.Duration, nil)
	}
	if len(cfg.Portainer) > 0 {
		eng.Portainers = map[string]engine.Portainer{}
		for _, pc := range cfg.Portainer {
			c, err := portainer.New(pc, 30*time.Second)
			if err != nil {
				return fmt.Errorf("portainer %s : %w", pc.Name, err)
			}
			eng.Portainers[pc.Name] = c
			eng.PortainerOrder = append(eng.PortainerOrder, pc.Name)
		}
	}
	jm.OnFinish = eng.NotifyJob
	eng.ListSnapshots = func(ctx context.Context, node, typ string, vmid int) ([]proxmox.Snapshot, error) {
		var last error
		for _, s := range srcs {
			if c, ok := s.(*proxmox.Client); ok {
				l, err := c.Snapshots(ctx, node, typ, vmid)
				if err == nil {
					return l, nil
				}
				last = err
			}
		}
		return nil, last
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
	sched := schedule.New(cfg.Schedule.DetectAt, func(ctx context.Context) {
		snap, _ := inv.Current()
		eng.ScheduledDetection(ctx, snap.Guests)
	}, log)
	ui, err := web.New(cfg, inv, web.Deps{Engine: eng, Jobs: jm, Detections: store, Batches: batches, NextDetection: sched.Next}, log, version)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go inv.Run(ctx, cfg.Inventory.Refresh.Duration)
	if sched.Enabled() {
		if eng.Runner == nil {
			log.Warn("détection planifiée ignorée : pas d'accès SSH ([ssh.nodes])")
		} else {
			go sched.Run(ctx)
		}
	}

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
				v := 0
				for _, l := range out {
					if n, ok := strings.CutPrefix(l, "pw.wrapper_version="); ok {
						v, _ = strconv.Atoi(n)
					}
				}
				if v < engine.WrapperVersion {
					failed++
					fmt.Printf("    ✘ wrapper version %d sur %s, version %d attendue : réinstallez deploy/patchwarden-wrapper (README, étape 6)\n", v, node, engine.WrapperVersion)
				}
			}
		}
	} else {
		fmt.Println("Pas de section [ssh.nodes] : lecture seule.")
	}
	if len(cfg.Portainer) > 0 {
		fmt.Println("Portainer :")
	}
	for _, pc := range cfg.Portainer {
		c, err := portainer.New(pc, 15*time.Second)
		if err != nil {
			failed++
			fmt.Printf("  ✘ %s : %v\n", pc.Name, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		eps, err := c.Endpoints(ctx)
		var stacks []portainer.Stack
		if err == nil {
			stacks, err = c.Stacks(ctx)
		}
		cancel()
		if err != nil {
			failed++
			fmt.Printf("  ✘ %s : %v\n", pc.Name, err)
			continue
		}
		up := 0
		for _, ep := range eps {
			if ep.Status == 1 {
				up++
			}
		}
		fmt.Printf("  ✔ %s : %d environnement(s) dont %d joignable(s), %d stack(s) visibles par le jeton\n", pc.Name, len(eps), up, len(stacks))
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

func notifyTest(args []string) error {
	path, err := configFlag("notify-test", args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg, err := loadConfig(path, log)
	if err != nil {
		return err
	}
	hub := notify.New(cfg.Notify, nil, log)
	if !hub.Enabled() {
		return errors.New("aucune cible [[notify]] dans la configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	link := ""
	if cfg.Server.PublicURL != "" {
		link = cfg.Server.PublicURL
	}
	errs := hub.Send(ctx, notify.Message{Event: notify.EvTest, Priority: 3, URL: link,
		Title: "PatchWarden : notification de test", Body: "Si vous lisez ce message, les notifications fonctionnent."})
	for _, e := range errs {
		fmt.Println("  ✘", e)
	}
	fmt.Printf("%d cible(s), %d en erreur : %s\n", len(hub.Targets()), len(errs), strings.Join(hub.Targets(), ", "))
	if len(errs) > 0 {
		return fmt.Errorf("%d cible(s) en erreur", len(errs))
	}
	return nil
}
