package openrouter

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestTransportSNI: SNI берётся из host URL (openrouter.ai) — на этом держится серверное имя в правилах
// CiliumNetworkPolicy (toPorts.serverNames). Явного ServerName и ECH в конфигурации TLS быть не должно.
func TestTransportSNI(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) }))
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		seen = append(seen, h.ServerName)
		mu.Unlock()
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()

	tr := NewHTTPTransport().(*httpTransport)
	ht := tr.c.Transport.(*http.Transport)
	// Проверяем боевую конфигурацию до тестовых подмен.
	cfg := ht.TLSClientConfig
	if cfg.ServerName != "" {
		t.Errorf("ServerName задан явно: %q (SNI должен идти из host URL)", cfg.ServerName)
	}
	if cfg.EncryptedClientHelloConfigList != nil {
		t.Error("включён ECH: SNI во внешнем ClientHello не совпадёт с именем в serverNames")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion=%x", cfg.MinVersion)
	}
	// Тестовые подмены: адрес сервера и проверка сертификата (сертификат httptest выдан не на openrouter.ai), прокси.
	addr := srv.Listener.Addr().String()
	ht.DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, addr)
	}
	ht.Proxy = nil
	ht.TLSClientConfig = cfg.Clone()
	ht.TLSClientConfig.InsecureSkipVerify = true

	ctx := context.Background()
	if _, err := tr.Post(ctx, APIURL, http.Header{"Authorization": {"Bearer x"}}, []byte(`{}`)); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if _, err := tr.Get(ctx, getPrefix+"models", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("рукопожатий не было")
	}
	for i, sni := range seen {
		if sni != "openrouter.ai" {
			t.Errorf("рукопожатие %d: SNI %q, ожидается openrouter.ai", i, sni)
		}
	}
}
