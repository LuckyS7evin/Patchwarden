// Package sshx exécute les verbes du wrapper sur les nœuds Proxmox par SSH.
//
// La clé d'hôte de chaque nœud est toujours vérifiée (fichier known_hosts) et
// la sortie est remise ligne par ligne, nettoyée pour l'affichage.
package sshx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/LuckyS7evin/patchwarden/internal/config"
)

// Line est une ligne de sortie d'une commande distante.
type Line struct {
	Stderr bool
	Text   string
}

// Runner exécute une commande sur un nœud. Interface pour pouvoir simuler l'exécution.
type Runner interface {
	Run(ctx context.Context, node, command string, out func(Line)) (exitCode int, err error)
}

// Executor est l'implémentation SSH de Runner.
type Executor struct {
	user        string
	signer      ssh.Signer
	hostKey     ssh.HostKeyCallback
	nodes       map[string]string
	dialTimeout time.Duration
}

// New charge la clé privée et le fichier known_hosts.
func New(cfg config.SSH) (*Executor, error) {
	pem, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("clé SSH : %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("clé SSH %s : %w (une clé sans phrase de passe est attendue)", cfg.KeyFile, err)
	}
	cb, err := knownhosts.New(cfg.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("known_hosts : %w", err)
	}
	return NewWith(cfg.User, signer, cb, cfg.Nodes, cfg.ConnectTimeout.Duration), nil
}

// NewWith construit un exécuteur à partir d'éléments déjà chargés (tests).
func NewWith(user string, signer ssh.Signer, hostKey ssh.HostKeyCallback, nodes map[string]string, dialTimeout time.Duration) *Executor {
	return &Executor{user: user, signer: signer, hostKey: hostKey, nodes: nodes, dialTimeout: dialTimeout}
}

// HasNode indique si un nœud est joignable par SSH selon la configuration.
func (e *Executor) HasNode(node string) bool { _, ok := e.nodes[node]; return ok }

// ErrUnknownNode : le nœud n'est pas déclaré dans [ssh.nodes].
var ErrUnknownNode = errors.New("nœud absent de [ssh.nodes]")

// Run exécute command sur le nœud et appelle out pour chaque ligne reçue.
// Le code de sortie distant est renvoyé ; err ne concerne que les échecs de
// connexion ou de transport.
func (e *Executor) Run(ctx context.Context, node, command string, out func(Line)) (int, error) {
	addr, ok := e.nodes[node]
	if !ok {
		return -1, fmt.Errorf("%s : %w", node, ErrUnknownNode)
	}
	d := net.Dialer{Timeout: e.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return -1, fmt.Errorf("connexion à %s (%s) : %w", node, addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(e.dialTimeout))
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              e.user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(e.signer)},
		HostKeyCallback:   e.hostKey,
		HostKeyAlgorithms: knownAlgorithms(e.hostKey, addr),
		Timeout:           e.dialTimeout,
	})
	if err != nil {
		conn.Close()
		var kerr *knownhosts.KeyError
		if errors.As(err, &kerr) {
			if len(kerr.Want) == 0 {
				return -1, fmt.Errorf("%s : clé d'hôte inconnue, ajoutez-la à known_hosts (voir README)", node)
			}
			return -1, fmt.Errorf("%s : CLÉ D'HÔTE DIFFÉRENTE de celle enregistrée dans known_hosts, connexion refusée", node)
		}
		return -1, fmt.Errorf("SSH vers %s : %w", node, err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return -1, fmt.Errorf("session SSH vers %s : %w", node, err)
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return -1, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return -1, err
	}

	var mu sync.Mutex
	emit := func(l Line) {
		mu.Lock()
		defer mu.Unlock()
		out(l)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); readLines(stdout, false, emit) }()
	go func() { defer wg.Done(); readLines(stderr, true, emit) }()

	if err := sess.Start(command); err != nil {
		return -1, fmt.Errorf("lancement sur %s : %w", node, err)
	}
	done := make(chan error, 1)
	go func() { wg.Wait(); done <- sess.Wait() }()

	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGTERM)
		client.Close()
		<-done
		return -1, fmt.Errorf("interrompu : %w", ctx.Err())
	}
	if err == nil {
		return 0, nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), nil
	}
	return -1, fmt.Errorf("exécution sur %s : %w", node, err)
}

// probeKey est une fausse clé d'un type qui ne figure jamais dans known_hosts :
// la présenter au rappel de vérification renvoie la liste des clés connues
// pour cet hôte (knownhosts.KeyError.Want), sans rien accepter.
type probeKey struct{}

func (probeKey) Type() string                        { return "patchwarden-sonde" }
func (probeKey) Marshal() []byte                     { return []byte("patchwarden-sonde") }
func (probeKey) Verify([]byte, *ssh.Signature) error { return errors.New("sonde") }

// knownAlgorithms renvoie les algorithmes de clé d'hôte à demander au nœud :
// ceux des clés enregistrées dans known_hosts. Sans cela, le client Go demande
// d'abord ECDSA ; un nœud Proxmox ayant aussi une clé ECDSA, elle serait
// comparée à la clé ed25519 enregistrée et refusée comme « différente ».
// Renvoie nil (algorithmes par défaut) si l'hôte est inconnu ou si le rappel
// n'est pas un known_hosts.
func knownAlgorithms(cb ssh.HostKeyCallback, addr string) []string {
	if cb == nil {
		return nil
	}
	tcp, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil
	}
	var kerr *knownhosts.KeyError
	if err := cb(addr, tcp, probeKey{}); !errors.As(err, &kerr) || len(kerr.Want) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var algos []string
	add := func(a ...string) {
		for _, x := range a {
			if !seen[x] {
				seen[x] = true
				algos = append(algos, x)
			}
		}
	}
	for _, k := range kerr.Want {
		switch t := k.Key.Type(); t {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA)
		default:
			add(t)
		}
	}
	return algos
}

const maxLine = 64 << 10

func readLines(r io.Reader, isErr bool, emit func(Line)) {
	br := bufio.NewReaderSize(r, 32<<10)
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) && len(buf) < maxLine {
			continue
		}
		if len(buf) > 0 {
			emit(Line{Stderr: isErr, Text: Clean(string(buf))})
			buf = buf[:0]
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]`)

// Clean prépare une ligne pour l'affichage : séquences ANSI retirées, retour
// chariot interprété (seul le dernier segment non vide est gardé, comme dans un
// terminal), UTF-8 invalide remplacé, fin de ligne supprimée.
func Clean(s string) string {
	s = strings.TrimRight(s, "\n")
	s = strings.TrimRight(s, "\r")
	s = ansiRe.ReplaceAllString(s, "")
	if i := strings.LastIndexByte(s, '\r'); i >= 0 {
		s = s[i+1:]
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return s
}
