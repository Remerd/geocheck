package access

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClassifyLovable(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   State
	}{
		{name: "authentication required means available", status: 401, want: StateAvailable},
		{name: "IP refusal means blocked", status: 403, want: StateBlocked},
		{name: "unexpected success is inconclusive", status: 200, want: StateError},
		{name: "unexpected server error is inconclusive", status: 502, want: StateError},
		{
			name:   "challenge is not an IP refusal",
			status: 403,
			body:   challengePage("/realtime"),
			want:   StateError,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyLovable(c.status, c.body)
			if got.State != c.want {
				t.Errorf("state = %v, want %v (detail %q)", got.State, c.want, got.Detail)
			}
			wantStatus := "HTTP " + itoa(c.status)
			if !containsFold(got.Detail, wantStatus) {
				t.Errorf("detail = %q, want it to contain %q", got.Detail, wantStatus)
			}
		})
	}
}

func TestLovableHandshake(t *testing.T) {
	var keys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/realtime" {
			t.Errorf("path = %q, want /realtime", r.URL.Path)
		}
		for header, want := range map[string]string{
			"Connection":             "Upgrade",
			"Upgrade":                "websocket",
			"Origin":                 "https://lovable.dev",
			"Sec-WebSocket-Protocol": "bearer, invalid",
			"Sec-WebSocket-Version":  "13",
		} {
			if got := r.Header.Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}

		key := r.Header.Get("Sec-WebSocket-Key")
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			t.Errorf("Sec-WebSocket-Key %q is not valid base64: %v", key, err)
		} else if len(decoded) != 16 {
			t.Errorf("decoded Sec-WebSocket-Key is %d bytes, want 16", len(decoded))
		}
		keys = append(keys, key)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	check := lovableAt(srv.URL + "/realtime")
	for i := 0; i < 2; i++ {
		got := check.Run(context.Background(), testEnv(t))
		if got.State != StateAvailable {
			t.Fatalf("run %d state = %v, want available (detail %q, err %v)",
				i+1, got.State, got.Detail, got.Err)
		}
	}
	if len(keys) != 2 {
		t.Fatalf("server received %d requests, want 2", len(keys))
	}
	if keys[0] == keys[1] {
		t.Errorf("successive requests reused Sec-WebSocket-Key %q", keys[0])
	}
}

func TestLovableDoesNotFollowRedirects(t *testing.T) {
	redirectTargetHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/followed" {
			redirectTargetHit = true
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/followed", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	got := lovableAt(srv.URL+"/realtime").Run(context.Background(), testEnv(t))
	if got.State != StateError || !containsFold(got.Detail, "HTTP 302") {
		t.Errorf("result = %+v, want an HTTP 302 error", got)
	}
	if redirectTargetHit {
		t.Error("Lovable check followed a redirect")
	}
}

func TestLovableNetworkErrorIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := srv.URL + "/realtime"
	srv.Close()

	got := lovableAt(endpoint).Run(context.Background(), testEnv(t))
	if got.State != StateError || got.Err == nil {
		t.Errorf("result = %+v, want an error carrying the network failure", got)
	}
}
