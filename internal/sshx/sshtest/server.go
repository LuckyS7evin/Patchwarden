// Package sshtest fournit un serveur SSH en mémoire pour les tests. Il imite
// une clé à commande forcée : la commande demandée est passée au gestionnaire,
// qui joue le rôle du wrapper.
package sshtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Handler reçoit la commande demandée (SSH_ORIGINAL_COMMAND) et renvoie le code de sortie.
type Handler func(command string, stdout, stderr io.Writer) int

// Server est un serveur SSH de test.
type Server struct {
	Addr    string
	HostKey ssh.PublicKey
	// ExtraHostKey : clé ECDSA supplémentaire (StartMultiKey uniquement).
	ExtraHostKey ssh.PublicKey
	ClientKey    ssh.Signer
	ClientPriv   ed25519.PrivateKey
	Commands     []string
	mu           sync.Mutex
	listener     net.Listener
	authorized   ssh.PublicKey
}

// Start démarre un serveur qui n'accepte que la clé cliente générée.
func Start(t *testing.T, h Handler) *Server { return start(t, h, false) }

// StartMultiKey démarre un serveur qui présente, comme un nœud Proxmox, une
// clé d'hôte ECDSA en plus de la clé ed25519 (HostKey). ExtraHostKey est l'ECDSA.
func StartMultiKey(t *testing.T, h Handler) *Server { return start(t, h, true) }

func start(t *testing.T, h Handler, multi bool) *Server {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	cliSigner, err := ssh.NewSignerFromKey(cliPriv)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{HostKey: hostSigner.PublicKey(), ClientKey: cliSigner, ClientPriv: cliPriv, authorized: cliSigner.PublicKey()}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), s.authorized.Marshal()) {
				return nil, nil
			}
			return nil, io.EOF
		},
	}
	cfg.AddHostKey(hostSigner)
	if multi {
		ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		es, err := ssh.NewSignerFromKey(ek)
		if err != nil {
			t.Fatal(err)
		}
		cfg.AddHostKey(es)
		s.ExtraHostKey = es.PublicKey()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	s.Addr = ln.Addr().String()
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg, h)
		}
	}()
	return s
}

// Seen renvoie les commandes reçues.
func (s *Server) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Commands...)
}

func (s *Server) serve(c net.Conn, cfg *ssh.ServerConfig, h Handler) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "session uniquement")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
					_ = req.Reply(false, nil)
					return
				}
				_ = req.Reply(true, nil)
				s.mu.Lock()
				s.Commands = append(s.Commands, payload.Command)
				s.mu.Unlock()
				code := h(payload.Command, ch, ch.Stderr())
				status := make([]byte, 4)
				binary.BigEndian.PutUint32(status, uint32(code))
				_, _ = ch.SendRequest("exit-status", false, status)
				return
			}
		}()
	}
}
