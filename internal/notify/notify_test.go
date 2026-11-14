package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/LuckyS7evin/patchwarden/internal/config"
)

type captured struct {
	path, auth, gotify string
	body               map[string]any
}

func capture(t *testing.T, status int) (*httptest.Server, *[]captured, *sync.Mutex) {
	t.Helper()
	var got []captured
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		got = append(got, captured{path: r.URL.Path, auth: r.Header.Get("Authorization"), gotify: r.Header.Get("X-Gotify-Key"), body: b})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &mu
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestFormats(t *testing.T) {
	srv, got, _ := capture(t, 200)
	h := New([]config.Notify{
		{Type: "ntfy", URL: srv.URL + "/patchwarden", Token: "tk"},
		{Type: "gotify", URL: srv.URL + "/gotify/", Token: "app"},
		{Type: "webhook", URL: srv.URL + "/hook"},
	}, srv.Client(), quiet())
	errs := h.Send(context.Background(), Message{Event: EvSecurity, Title: "Sécurité : 3 correctifs", Body: "termix : 3", Priority: 4, URL: "http://pw/securite"})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(*got) != 3 {
		t.Fatalf("3 envois attendus, %d", len(*got))
	}
	n, g, w := (*got)[0], (*got)[1], (*got)[2]
	if n.path != "/" || n.body["topic"] != "patchwarden" || n.body["title"] != "Sécurité : 3 correctifs" || n.auth != "Bearer tk" || n.body["priority"] != 4.0 || n.body["click"] != "http://pw/securite" {
		t.Errorf("ntfy : %+v", n)
	}
	if !strings.Contains(n.body["message"].(string), "http://pw/securite") {
		t.Errorf("le lien doit figurer dans le message ntfy : %v", n.body["message"])
	}
	if g.path != "/gotify/message" || g.gotify != "app" || g.body["priority"] != 8.0 {
		t.Errorf("gotify : %+v", g)
	}
	if w.path != "/hook" || w.body["event"] != "securite" || w.body["source"] != "patchwarden" || w.auth != "" {
		t.Errorf("webhook : %+v", w)
	}
}

func TestEventFilter(t *testing.T) {
	srv, got, _ := capture(t, 200)
	h := New([]config.Notify{
		{Type: "webhook", URL: srv.URL + "/defaut"}, // securite, applis, echec
		{Type: "webhook", URL: srv.URL + "/succes", Events: []string{"succes"}},
	}, srv.Client(), quiet())
	ctx := context.Background()
	h.Send(ctx, Message{Event: EvSuccess, Title: "ok"})
	h.Send(ctx, Message{Event: EvFailure, Title: "ko"})
	h.Send(ctx, Message{Event: EvTest, Title: "test"})
	var paths []string
	for _, c := range *got {
		paths = append(paths, c.path+":"+c.body["title"].(string))
	}
	want := "/succes:ok|/defaut:ko|/defaut:test|/succes:test"
	if strings.Join(paths, "|") != want {
		t.Errorf("filtrage : %v, attendu %s", paths, want)
	}
}

func TestHTTPError(t *testing.T) {
	srv, _, _ := capture(t, 403)
	h := New([]config.Notify{{Type: "webhook", URL: srv.URL + "/x"}}, srv.Client(), quiet())
	errs := h.Send(context.Background(), Message{Event: EvFailure, Title: "ko"})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "HTTP 403") {
		t.Errorf("erreur attendue : %v", errs)
	}
	var none *Hub
	if none.Enabled() {
		t.Error("hub nil")
	}
	none.Notify(Message{}) // ne doit pas paniquer
}
