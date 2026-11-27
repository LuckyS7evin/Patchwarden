package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookie = "pw_session"

type session struct {
	user    string
	csrf    string
	expires time.Time
}

// sessions est un magasin de sessions en mémoire : un redémarrage du service
// déconnecte l'utilisateur, ce qui est acceptable pour un compte unique.
type sessions struct {
	mu  sync.Mutex
	m   map[string]*session
	ttl time.Duration
	now func() time.Time
}

func newSessions(ttl time.Duration, now func() time.Time) *sessions {
	return &sessions{m: map[string]*session{}, ttl: ttl, now: now}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("source aléatoire indisponible : " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *sessions) create(user string) (string, *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, se := range s.m { // ménage des sessions expirées
		if now.After(se.expires) {
			delete(s.m, id)
		}
	}
	id := randomToken()
	se := &session{user: user, csrf: randomToken(), expires: now.Add(s.ttl)}
	s.m[id] = se
	return id, se
}

func (s *sessions) get(id string) *session {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	se, ok := s.m[id]
	if !ok {
		return nil
	}
	if s.now().After(se.expires) {
		delete(s.m, id)
		return nil
	}
	return se
}

func (s *sessions) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// throttle limite les essais de connexion par adresse IP.
type throttle struct {
	mu       sync.Mutex
	m        map[string]*attempts
	max      int
	window   time.Duration
	blockFor time.Duration
	now      func() time.Time
}

type attempts struct {
	count        int
	first        time.Time
	blockedUntil time.Time
}

func newThrottle(now func() time.Time) *throttle {
	return &throttle{m: map[string]*attempts{}, max: 5, window: 15 * time.Minute, blockFor: 15 * time.Minute, now: now}
}

// blocked indique si l'IP doit attendre, et jusqu'à quand.
func (t *throttle) blocked(ip string) (bool, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.m[ip]
	if !ok {
		return false, time.Time{}
	}
	return t.now().Before(a.blockedUntil), a.blockedUntil
}

func (t *throttle) fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if len(t.m) > 1000 { // ménage : la table ne grossit pas sans limite
		for k, a := range t.m {
			if now.Sub(a.first) > t.window && now.After(a.blockedUntil) {
				delete(t.m, k)
			}
		}
	}
	a, ok := t.m[ip]
	if !ok || now.Sub(a.first) > t.window {
		a = &attempts{first: now}
		t.m[ip] = a
	}
	a.count++
	if a.count >= t.max {
		a.blockedUntil = now.Add(t.blockFor)
		a.count = 0
		a.first = now
	}
}

func (t *throttle) success(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, ip)
}

// checkCredentials compare en temps constant : le hachage bcrypt est toujours
// calculé, même si l'identifiant est faux, pour ne pas révéler s'il existe.
func checkCredentials(wantUser, wantHash, user, pass string) bool {
	a := sha256.Sum256([]byte(wantUser))
	b := sha256.Sum256([]byte(user))
	userOK := subtle.ConstantTimeCompare(a[:], b[:]) == 1
	passOK := bcrypt.CompareHashAndPassword([]byte(wantHash), []byte(pass)) == nil
	return userOK && passOK
}

func equalTokens(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
