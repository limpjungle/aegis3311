package sbom

import (
	"bytes"
	"encoding/json"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
)

const binSum = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func sampleInfo() *debug.BuildInfo {
	return &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Path: "example.com/m"},
		Deps: []*debug.Module{
			{Path: "gopkg.in/yaml.v3", Version: "v3.0.1", Sum: "h1:abc="},
			{Path: "example.com/orig", Version: "v1.0.0", Sum: "h1:orig=", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1", Sum: "h1:fork="}}},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc"}, {Key: "vcs.modified", Value: "false"},
			{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"}, {Key: "CGO_ENABLED", Value: "0"}, {Key: "-trimpath", Value: "true"}}}
}

var uuidRe = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestCycloneDX(t *testing.T) {
	b, err := CycloneDX(sampleInfo(), "aegis-intake", binSum)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BOMFormat, SpecVersion, SerialNumber string
		Version                              int
		Metadata                             struct {
			Component struct {
				Type, Name string
				Hashes     []struct{ Alg, Content string }
				Properties []struct{ Name, Value string }
			}
			Tools struct{ Components []struct{ Name string } }
		}
		Components []struct {
			Name, Version, PURL string
			Properties          []struct{ Name, Value string }
		}
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || doc.Version != 1 || !uuidRe.MatchString(doc.SerialNumber) {
		t.Errorf("шапка: %+v", doc)
	}
	mc := doc.Metadata.Component
	if mc.Type != "application" || mc.Name != "aegis-intake" || len(mc.Hashes) != 1 || mc.Hashes[0].Alg != "SHA-256" || mc.Hashes[0].Content != binSum {
		t.Errorf("metadata.component: %+v", mc)
	}
	props := map[string]string{}
	for _, p := range mc.Properties {
		props[p.Name] = p.Value
	}
	for k, v := range map[string]string{"vcs.revision": "abc", "vcs.modified": "false", "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "-trimpath": "true"} {
		if props[k] != v {
			t.Errorf("свойство %s = %q", k, props[k])
		}
	}
	if len(doc.Metadata.Tools.Components) != 1 || doc.Metadata.Tools.Components[0].Name != "aegis-ci" {
		t.Errorf("tools: %+v", doc.Metadata.Tools)
	}
	got := map[string]string{}
	for _, c := range doc.Components {
		got[c.Name] = c.PURL
		if c.Name == "gopkg.in/yaml.v3" && (len(c.Properties) != 1 || c.Properties[0].Name != "go.sum.h1" || c.Properties[0].Value != "h1:abc=") {
			t.Errorf("yaml.v3: %+v", c)
		}
	}
	if got["gopkg.in/yaml.v3"] != "pkg:golang/gopkg.in/yaml.v3@v3.0.1" || got["stdlib"] != "pkg:golang/stdlib@1.27.3" {
		t.Errorf("purl: %v", got)
	}
	if got["example.com/orig"] != "pkg:golang/example.com/fork@v1.0.1" { // Replace учтён
		t.Errorf("replace: %v", got)
	}
	if strings.Contains(string(b), "timestamp") {
		t.Error("в SBOM не должно быть времени")
	}
}

func TestDeterministic(t *testing.T) {
	a, _ := CycloneDX(sampleInfo(), "x", binSum)
	b, _ := CycloneDX(sampleInfo(), "x", binSum)
	if !bytes.Equal(a, b) {
		t.Error("SBOM недетерминирован")
	}
	c, _ := CycloneDX(sampleInfo(), "x", strings.Repeat("ab", 32))
	var x, y struct{ SerialNumber string }
	json.Unmarshal(a, &x)
	json.Unmarshal(c, &y)
	if x.SerialNumber == y.SerialNumber {
		t.Error("serialNumber не зависит от хеша бинаря")
	}
}

func TestBadInput(t *testing.T) {
	if _, err := CycloneDX(nil, "x", binSum); err == nil {
		t.Error("nil BuildInfo должен быть ошибкой")
	}
	for _, s := range []string{"", "abc", strings.Repeat("z", 64)} {
		if _, err := CycloneDX(sampleInfo(), "x", s); err == nil {
			t.Errorf("хеш %q должен быть отказом", s)
		}
	}
}

// На реальном BuildInfo тестового бинаря: структура валидна и содержит stdlib.
func TestRealBuildInfo(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("нет сведений о сборке")
	}
	b, err := CycloneDX(bi, "sbom.test", binSum)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) || !bytes.Contains(b, []byte(`"stdlib"`)) {
		t.Error("SBOM невалиден или без stdlib")
	}
}
