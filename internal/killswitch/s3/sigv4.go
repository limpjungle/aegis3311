// Package s3 — минимальный клиент S3 (AWS S3, Yandex Object Storage и совместимые): GET и PUT объекта с подписью
// AWS Signature Version 4 по заголовку Authorization, только stdlib. Ключи доступа читаются из файлов на каждый запрос.
package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Credentials — ключи доступа. SessionToken необязателен (временные ключи).
type Credentials struct{ AccessKeyID, SecretAccessKey, SessionToken string }

// CredFiles — файлы с ключами; читаются на каждый запрос, поэтому ротация не требует перезапуска.
type CredFiles struct{ AccessKeyIDFile, SecretKeyFile, SessionTokenFile string }

// Load читает ключи: значения обрезаются по краям, пустое значение — ошибка; токен сессии необязателен.
func (f CredFiles) Load() (Credentials, error) {
	read := func(name, path string, required bool) (string, error) {
		if path == "" {
			if required {
				return "", fmt.Errorf("s3: не задан файл %s", name)
			}
			return "", nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			var pe *os.PathError
			if errors.As(err, &pe) {
				err = pe.Err
			}
			return "", fmt.Errorf("s3: файл %s: %w", name, err)
		}
		v := strings.TrimSpace(string(b))
		if v == "" || strings.ContainsAny(v, "\r\n") {
			return "", fmt.Errorf("s3: файл %s пуст или некорректен", name)
		}
		return v, nil
	}
	var c Credentials
	var err error
	if c.AccessKeyID, err = read("access key id", f.AccessKeyIDFile, true); err != nil {
		return Credentials{}, err
	}
	if c.SecretAccessKey, err = read("secret key", f.SecretKeyFile, true); err != nil {
		return Credentials{}, err
	}
	if c.SessionToken, err = read("session token", f.SessionTokenFile, false); err != nil {
		return Credentials{}, err
	}
	return c, nil
}

const algorithm = "AWS4-HMAC-SHA256"

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// uriEncode кодирует по RFC 3986 (unreserved не трогаем); '/' сохраняется, если keepSlash.
func uriEncode(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// canonicalURI — путь, закодированный по сегментам; для S3 двойного кодирования нет.
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return uriEncode(path, true)
}

func canonicalQuery(req *http.Request) string {
	q := req.URL.Query()
	type kv struct{ k, v string }
	var kvs []kv
	for k, vs := range q {
		for _, v := range vs {
			kvs = append(kvs, kv{uriEncode(k, false), uriEncode(v, false)})
		}
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].k != kvs[j].k {
			return kvs[i].k < kvs[j].k
		}
		return kvs[i].v < kvs[j].v
	})
	parts := make([]string, len(kvs))
	for i, p := range kvs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

func headerValue(req *http.Request, name string) string {
	if name == "host" {
		return req.URL.Host
	}
	vs := req.Header.Values(name)
	for i, v := range vs {
		vs[i] = strings.Join(strings.Fields(v), " ")
	}
	return strings.Join(vs, ",")
}

// canonicalRequest — канонический запрос: метод, URI, query, заголовки, список подписанных заголовков, хеш тела.
func canonicalRequest(req *http.Request, payloadSHA256 string, signed []string) string {
	var h strings.Builder
	for _, n := range signed {
		h.WriteString(n + ":" + headerValue(req, n) + "\n")
	}
	return strings.Join([]string{req.Method, canonicalURI(req.URL.Path), canonicalQuery(req), h.String(),
		strings.Join(signed, ";"), payloadSHA256}, "\n")
}

func stringToSign(amzDate, scope, canonical string) string {
	return algorithm + "\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
}

func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

// SignV4 подписывает запрос: ставит x-amz-date, x-amz-content-sha256 и (при наличии) x-amz-security-token, подписывает
// host, все x-amz-* и extraSigned (имена заголовков, уже выставленных в запросе), затем ставит Authorization.
func SignV4(req *http.Request, payloadSHA256 string, c Credentials, region, service string, now time.Time, extraSigned ...string) error {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return errors.New("s3: пустые ключи доступа")
	}
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadSHA256)
	if c.SessionToken != "" {
		req.Header.Set("x-amz-security-token", c.SessionToken)
	}
	set := map[string]bool{"host": true}
	for k := range req.Header {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-amz-") {
			set[lk] = true
		}
	}
	for _, n := range extraSigned {
		set[strings.ToLower(n)] = true
	}
	signed := make([]string, 0, len(set))
	for n := range set {
		signed = append(signed, n)
	}
	sort.Strings(signed)
	scope := date + "/" + region + "/" + service + "/aws4_request"
	sts := stringToSign(amzDate, scope, canonicalRequest(req, payloadSHA256, signed))
	sig := hex.EncodeToString(hmacSHA256(signingKey(c.SecretAccessKey, date, region, service), sts))
	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, c.AccessKeyID, scope, strings.Join(signed, ";"), sig))
	return nil
}
