package s3

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestClientSNI: SNI равен host из URL запроса. Path-style: storage.yandexcloud.net (то, что разрешает
// serverNames в CiliumNetworkPolicy); virtual-hosted дал бы bucket.storage.yandexcloud.net, и политика его отклонила бы.
func TestClientSNI(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pathStyle bool
		want      string
	}{
		{"path-style", true, "storage.yandexcloud.net"},
		{"virtual-hosted", false, "bkt.storage.yandexcloud.net"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen []string
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
			srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				mu.Lock()
				seen = append(seen, h.ServerName)
				mu.Unlock()
				return nil, nil
			}}
			srv.StartTLS()
			defer srv.Close()

			h, err := NewHTTPClient("", 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			tr := h.Transport.(*http.Transport)
			if tr.TLSClientConfig.ServerName != "" {
				t.Errorf("ServerName задан явно: %q", tr.TLSClientConfig.ServerName)
			}
			if tr.TLSClientConfig.EncryptedClientHelloConfigList != nil {
				t.Error("включён ECH")
			}
			addr := srv.Listener.Addr().String()
			tr.DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, n, addr)
			}
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
			tr.TLSClientConfig.InsecureSkipVerify = true // только тест: сертификат httptest выдан не на это имя

			d := t.TempDir()
			os.WriteFile(filepath.Join(d, "id"), []byte("AK\n"), 0o600)
			os.WriteFile(filepath.Join(d, "sk"), []byte("SK\n"), 0o600)
			c := &Client{Cfg: Config{Endpoint: "https://storage.yandexcloud.net", Region: "ru-central1", Bucket: "bkt", Key: "k.json", PathStyle: tc.pathStyle},
				Creds: CredFiles{AccessKeyIDFile: filepath.Join(d, "id"), SecretKeyFile: filepath.Join(d, "sk")}, HTTP: h, MaxBytes: 1024,
				Now: func() time.Time { return time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC) }}
			if _, err := c.Get(context.Background(), "k.json"); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) == 0 {
				t.Fatal("рукопожатий не было")
			}
			for _, sni := range seen {
				if sni != tc.want {
					t.Errorf("SNI %q, ожидается %q", sni, tc.want)
				}
			}
		})
	}
}
