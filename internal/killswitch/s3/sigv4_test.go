package s3

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var refCreds = Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
var refNow = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

// Эталоны AWS «Signature Calculations for the Authorization Header: Transferring Payload in a Single Chunk».
func TestSignV4AWSReferenceGet(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if err := SignV4(req, empty, refCreds, "us-east-1", "s3", refNow, "range"); err != nil {
		t.Fatal(err)
	}
	signed := []string{"host", "range", "x-amz-content-sha256", "x-amz-date"}
	wantCanon := "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:" + empty +
		"\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\n" + empty
	canon := canonicalRequest(req, empty, signed)
	if canon != wantCanon {
		t.Fatalf("канонический запрос:\n%s", canon)
	}
	sts := stringToSign("20130524T000000Z", "20130524/us-east-1/s3/aws4_request", canon)
	if sts != "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972" {
		t.Errorf("строка для подписи: %q", sts)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := strings.ReplaceAll(req.Header.Get("Authorization"), ", ", ","); got != want {
		t.Errorf("Authorization: %s", got)
	}
}

func TestSignV4AWSReferencePut(t *testing.T) {
	req, _ := http.NewRequest("PUT", "https://examplebucket.s3.amazonaws.com/test$file.text", nil)
	req.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
	req.Header.Set("x-amz-storage-class", "REDUCED_REDUNDANCY")
	const payload = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
	if payload != sha256Hex([]byte("Welcome to Amazon S3.")) {
		t.Fatal("sha256 тела")
	}
	if err := SignV4(req, payload, refCreds, "us-east-1", "s3", refNow, "date"); err != nil {
		t.Fatal(err)
	}
	canon := canonicalRequest(req, payload, []string{"date", "host", "x-amz-content-sha256", "x-amz-date", "x-amz-storage-class"})
	if !strings.HasPrefix(canon, "PUT\n/test%24file.text\n\ndate:Fri, 24 May 2013 00:00:00 GMT\nhost:examplebucket.s3.amazonaws.com\n") {
		t.Errorf("канонический запрос:\n%s", canon)
	}
	if !strings.HasSuffix(req.Header.Get("Authorization"), "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd") ||
		!strings.Contains(req.Header.Get("Authorization"), "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class") {
		t.Errorf("Authorization: %s", req.Header.Get("Authorization"))
	}
}

func TestSignV4TokenKeyEncodingPort(t *testing.T) {
	c := refCreds
	c.SessionToken = "tok123"
	req, _ := http.NewRequest("GET", "https://127.0.0.1:9000/b/dir/a%20b.json?z=1&a=2%203", nil)
	if err := SignV4(req, sha256Hex(nil), c, "r", "s3", refNow); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("x-amz-security-token") != "tok123" || !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Error("токен сессии не выставлен или не подписан")
	}
	canon := canonicalRequest(req, sha256Hex(nil), []string{"host"})
	if !strings.HasPrefix(canon, "GET\n/b/dir/a%20b.json\na=2%203&z=1\nhost:127.0.0.1:9000\n") {
		t.Errorf("канонический запрос:\n%s", canon)
	}
	if err := SignV4(req, "x", Credentials{}, "r", "s3", refNow); err == nil {
		t.Error("пустые ключи приняты")
	}
}

func TestCredFiles(t *testing.T) {
	d := t.TempDir()
	w := func(n, v string) string { p := filepath.Join(d, n); os.WriteFile(p, []byte(v), 0o600); return p }
	f := CredFiles{AccessKeyIDFile: w("id", " AK\n"), SecretKeyFile: w("sk", "sec\n")}
	c, err := f.Load()
	if err != nil || c.AccessKeyID != "AK" || c.SecretAccessKey != "sec" || c.SessionToken != "" {
		t.Fatalf("%+v %v", c, err)
	}
	f.SecretKeyFile = w("empty", "\n")
	if _, err := f.Load(); err == nil {
		t.Error("пустой секрет принят")
	}
	f.SecretKeyFile = filepath.Join(d, "нет")
	if _, err := f.Load(); err == nil || strings.Contains(err.Error(), d) {
		t.Errorf("ошибка: %v (путь не должен попадать в текст)", err)
	}
}
