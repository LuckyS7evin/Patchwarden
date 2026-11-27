package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

// Délais de la vérification après mise à jour (modifiables pour les tests).
var (
	// verifyRetry : attente avant une nouvelle détection quand un problème
	// peut être passager (conteneur qui démarre, service qui redémarre).
	verifyRetry    = 30 * time.Second
	verifyAttempts = 3
	// httpWait : durée pendant laquelle l'adresse de vérification est
	// réessayée ; httpPoll : intervalle entre deux essais.
	httpWait = 2 * time.Minute
	httpPoll = 10 * time.Second
)

// ErrVerify : la mise à jour est faite, mais la vérification a échoué.
var ErrVerify = errors.New("la vérification après l'opération a échoué")

// CheckURL renvoie l'adresse de vérification HTTP d'un invité ("" : aucune).
func (e *Engine) CheckURL(key string) string {
	if e.Checks == nil {
		return ""
	}
	return e.Checks.Get(key)
}

// SetCheckURL enregistre l'adresse de vérification HTTP d'un invité ("" l'efface).
func (e *Engine) SetCheckURL(key, raw string) error {
	if e.Checks == nil {
		return errors.New("réglages de vérification indisponibles")
	}
	raw = strings.TrimSpace(raw)
	if raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("adresse invalide : %q (attendu : http://… ou https://…)", raw)
		}
	}
	return e.Checks.Set(key, raw)
}

// afterOp lance la détection qui suit une opération réelle, puis la
// vérification. Une détection impossible fait échouer la vérification.
func (e *Engine) afterOp(ctx context.Context, g inventory.Guest, before *detect.Result, job jobs.Job, log jobs.Logger) (detect.Result, error) {
	log(false, "")
	res, err := e.detectRun(ctx, g, job.ID, log)
	if err != nil {
		return res, fmt.Errorf("%w : détection après l'opération impossible : %v", ErrVerify, err)
	}
	if err := e.checkAfter(ctx, g, before, res, job, log); err != nil {
		return res, err
	}
	return res, nil
}

// problems compare l'état d'un invité avant et après une opération : services
// systemd nouvellement en échec, conteneurs qui tournaient et ne tournent
// plus, conteneurs devenus « unhealthy » (ou encore « starting »).
func problems(before *detect.Result, after detect.Result) (list []string, transient bool) {
	known := map[string]bool{}
	wasRunning := map[string]bool{}
	wasHealth := map[string]string{}
	if before != nil {
		for _, u := range before.FailedUnits {
			known[u] = true
		}
		for _, c := range before.DockerInfo.List {
			if c.Running() {
				wasRunning[c.Name] = true
			}
			wasHealth[c.Name] = c.Health
		}
	}
	for _, u := range after.FailedUnits {
		if !known[u] {
			list = append(list, "service en échec : "+u)
			transient = true
		}
	}
	now := map[string]detect.Container{}
	for _, c := range after.DockerInfo.List {
		now[c.Name] = c
	}
	names := make([]string, 0, len(wasRunning))
	for n := range wasRunning {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c, ok := now[n]
		switch {
		case !ok:
			list = append(list, "conteneur disparu : "+n)
			transient = true
		case !c.Running():
			list = append(list, fmt.Sprintf("conteneur arrêté : %s (%s)", n, c.State))
			transient = true
		case c.Health == "starting":
			list = append(list, "conteneur en cours de démarrage : "+n)
			transient = true
		case c.Health == "unhealthy" && wasHealth[n] != "unhealthy":
			list = append(list, "conteneur en mauvaise santé (healthcheck) : "+n)
			transient = true
		}
	}
	return list, transient
}

// checkAfter vérifie un invité après une opération réelle. after : détection
// déjà faite juste après l'opération ; elle est refaite (jusqu'à trois fois,
// à 30 s d'intervalle) tant qu'un problème peut être passager. Puis
// l'adresse HTTP de l'invité, si elle est réglée, doit répondre.
func (e *Engine) checkAfter(ctx context.Context, g inventory.Guest, before *detect.Result, after detect.Result, job jobs.Job, log jobs.Logger) error {
	log(false, "▶ vérification après l'opération")
	list, transient := problems(before, after)
	for attempt := 1; len(list) > 0 && transient && attempt < verifyAttempts; attempt++ {
		for _, p := range list {
			log(false, "  "+p)
		}
		log(false, fmt.Sprintf("  nouvel essai dans %s (démarrage en cours ?)", verifyRetry))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(verifyRetry):
		}
		res, err := e.detectRun(ctx, g, job.ID, log)
		if err != nil {
			return fmt.Errorf("%w : détection impossible : %v", ErrVerify, err)
		}
		list, transient = problems(before, res)
	}
	if len(list) > 0 {
		for _, p := range list {
			log(true, "  ✘ "+p)
		}
		return fmt.Errorf("%w : %s", ErrVerify, strings.Join(list, " ; "))
	}
	log(false, "  services et conteneurs : comme avant l'opération")
	if u := e.CheckURL(target(g).Key()); u != "" {
		if err := e.checkHTTP(ctx, u, log); err != nil {
			return fmt.Errorf("%w : %v", ErrVerify, err)
		}
	}
	return nil
}

// checkHTTP attend que l'adresse réponde avec un statut inférieur à 400. Les
// certificats ne sont pas vérifiés (certificats auto-signés du homelab) : il
// s'agit seulement de savoir si le service répond.
func (e *Engine) checkHTTP(ctx context.Context, u string, log jobs.Logger) error {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // vérification de disponibilité seulement
	tr.Proxy = nil
	hc := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	deadline := time.Now().Add(httpWait)
	var last string
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "PatchWarden")
		resp, err := hc.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode < 400 {
				log(false, fmt.Sprintf("  %s répond (HTTP %d)", u, resp.StatusCode))
				return nil
			}
			last = fmt.Sprintf("HTTP %d", resp.StatusCode)
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s ne répond pas correctement après %s (%s)", u, httpWait, last)
		}
		log(false, fmt.Sprintf("  %s : %s, nouvel essai dans %s", u, last, httpPoll))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(httpPoll):
		}
	}
}
