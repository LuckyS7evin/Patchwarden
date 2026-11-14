package sshx

import (
	"encoding/pem"
	"os"

	"golang.org/x/crypto/ssh/knownhosts"

	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/LuckyS7evin/patchwarden/internal/config"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/LuckyS7evin/patchwarden/internal/sshx/sshtest"
)

func pinned(want ssh.PublicKey) ssh.HostKeyCallback { return ssh.FixedHostKey(want) }

func TestRunStreamsLinesAndExitCode(t *testing.T) {
	srv := sshtest.Start(t, func(cmd string, stdout, stderr io.Writer) int {
		fmt.Fprintf(stdout, "reçu: %s\n", cmd)
		fmt.Fprint(stdout, "\x1b[32m✔\x1b[0m vert\n")
		fmt.Fprint(stdout, "Lecture 10%\rLecture 100%\n")
		fmt.Fprint(stderr, "avertissement\n")
		fmt.Fprint(stdout, "sans fin de ligne")
		return 7
	})
	e := NewWith("root", srv.ClientKey, pinned(srv.HostKey), map[string]string{"loki": srv.Addr}, 5*time.Second)
	var lines []Line
	code, err := e.Run(context.Background(), "loki", "ping", func(l Line) { lines = append(lines, l) })
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Errorf("code de sortie : %d", code)
	}
	var out, errs []string
	for _, l := range lines {
		if l.Stderr {
			errs = append(errs, l.Text)
		} else {
			out = append(out, l.Text)
		}
	}
	want := []string{"reçu: ping", "✔ vert", "Lecture 100%", "sans fin de ligne"}
	if strings.Join(out, "|") != strings.Join(want, "|") {
		t.Errorf("sortie : %q", out)
	}
	if len(errs) != 1 || errs[0] != "avertissement" {
		t.Errorf("erreurs : %q", errs)
	}
	if got := srv.Seen(); len(got) != 1 || got[0] != "ping" {
		t.Errorf("commandes reçues : %q", got)
	}
}

func TestWrongHostKeyIsRefused(t *testing.T) {
	srv := sshtest.Start(t, func(string, io.Writer, io.Writer) int { return 0 })
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _ := ssh.NewPublicKey(other.Public())
	e := NewWith("root", srv.ClientKey, pinned(otherPub), map[string]string{"loki": srv.Addr}, 5*time.Second)
	if _, err := e.Run(context.Background(), "loki", "ping", func(Line) {}); err == nil {
		t.Fatal("clé d'hôte inattendue acceptée")
	}
	if len(srv.Seen()) != 0 {
		t.Error("une commande a été envoyée malgré la clé d'hôte refusée")
	}
}

func TestUnknownNode(t *testing.T) {
	e := NewWith("root", nil, nil, map[string]string{}, time.Second)
	if _, err := e.Run(context.Background(), "tyr", "ping", func(Line) {}); err == nil || !strings.Contains(err.Error(), "[ssh.nodes]") {
		t.Errorf("nœud inconnu : %v", err)
	}
}

func TestContextCancel(t *testing.T) {
	release := make(chan struct{})
	srv := sshtest.Start(t, func(_ string, stdout, _ io.Writer) int {
		fmt.Fprintln(stdout, "début")
		<-release
		return 0
	})
	defer close(release)
	e := NewWith("root", srv.ClientKey, pinned(srv.HostKey), map[string]string{"loki": srv.Addr}, 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := e.Run(ctx, "loki", "long", func(Line) {})
	if err == nil || !strings.Contains(err.Error(), "interrompu") {
		t.Errorf("interruption attendue : %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("l'interruption a pris trop de temps")
	}
}

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"simple\n":                        "simple",
		"crlf\r\n":                        "crlf",
		"a\rb\rc\n":                       "c",
		"\x1b[1;92m✔\x1b[0m ok":           "✔ ok",
		"Reading... 50%\rReading... 100%": "Reading... 100%",
		"inval\xffide":                    "inval�ide",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, attendu %q", in, got, want)
		}
	}
}

func TestKnownHostsFileMessages(t *testing.T) {
	srv := sshtest.Start(t, func(string, io.Writer, io.Writer) int { return 0 })
	dir := t.TempDir()
	keyFile := dir + "/id"
	pemBlock, err := ssh.MarshalPrivateKey(mustEd25519(t), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _ := ssh.NewPublicKey(other.Public())
	cases := map[string]string{
		"": "clé d'hôte inconnue",
		knownhosts.Line([]string{srv.Addr}, otherPub) + "\n": "CLÉ D'HÔTE DIFFÉRENTE",
	}
	for content, want := range cases {
		kh := dir + "/known_hosts"
		if err := os.WriteFile(kh, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := config.SSH{User: "root", KeyFile: keyFile, KnownHosts: kh, Nodes: map[string]string{"loki": srv.Addr}}
		cfg.ConnectTimeout.Duration = 5 * time.Second
		e, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Run(context.Background(), "loki", "ping", func(Line) {}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("attendu %q, obtenu %v", want, err)
		}
	}
}

func mustEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Régression : un nœud Proxmox présente plusieurs clés d'hôte (ed25519, ECDSA,
// RSA). known_hosts n'en contient qu'une (ed25519) : la connexion doit réussir
// en négociant ce type, et non échouer en « clé différente ».
func TestKnownHostsWithSeveralHostKeys(t *testing.T) {
	srv := sshtest.StartMultiKey(t, func(_ string, stdout, _ io.Writer) int {
		fmt.Fprintln(stdout, "pw.wrapper_version=1")
		return 0
	})
	dir := t.TempDir()
	keyFile, kh := dir+"/id", dir+"/known_hosts"
	blk, _ := ssh.MarshalPrivateKey(srv.ClientPriv, "test")
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(blk), 0o600)
	cfg := config.SSH{User: "root", KeyFile: keyFile, KnownHosts: kh, Nodes: map[string]string{"loki": srv.Addr}}
	cfg.ConnectTimeout.Duration = 5 * time.Second

	for name, key := range map[string]ssh.PublicKey{"ed25519": srv.HostKey, "ecdsa": srv.ExtraHostKey, "rsa": srv.RSAHostKey} {
		_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{srv.Addr}, key)+"\n"), 0o600)
		e, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		code, err := e.Run(context.Background(), "loki", "ping", func(l Line) { out = append(out, l.Text) })
		if err != nil || code != 0 || len(out) != 1 {
			t.Errorf("known_hosts avec la seule clé %s : %v (code %d, %q)", name, err, code, out)
		}
	}

	// Une vraie clé différente reste refusée.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _ := ssh.NewPublicKey(other.Public())
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{srv.Addr}, otherPub)+"\n"), 0o600)
	e, _ := New(cfg)
	if _, err := e.Run(context.Background(), "loki", "ping", func(Line) {}); err == nil || !strings.Contains(err.Error(), "DIFFÉRENTE") {
		t.Errorf("clé usurpée acceptée : %v", err)
	}
}
