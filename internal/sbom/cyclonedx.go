// Package sbom строит SBOM в формате CycloneDX 1.5 по сведениям о сборке Go-бинаря (debug/buildinfo). Результат
// детерминирован: без времени, serialNumber выводится из sha256 бинаря.
package sbom

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
)

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	BOMRef     string     `json:"bom-ref,omitempty"`
	Hashes     []hash     `json:"hashes,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type tool struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type bom struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

type metadata struct {
	Tools struct {
		Components []tool `json:"components"`
	} `json:"tools"`
	Component component `json:"component"`
}

// serial — UUID версии 5-подобного вида из sha256 бинаря: первые 16 байт хеша, биты версии (5) и варианта (RFC 4122).
func serial(binSHA256 string) (string, error) {
	if len(binSHA256) != 64 {
		return "", fmt.Errorf("sbom: sha256 бинаря: ожидается 64 hex, получено %d символов", len(binSHA256))
	}
	var b [16]byte
	for i := range b {
		var v byte
		if _, err := fmt.Sscanf(binSHA256[2*i:2*i+2], "%02x", &v); err != nil {
			return "", fmt.Errorf("sbom: sha256 бинаря: %w", err)
		}
		b[i] = v
	}
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func purl(path, version string) string {
	return "pkg:golang/" + path + "@" + version
}

// CycloneDX строит SBOM бинаря name с хешем binSHA256 (hex) по сведениям сборки bi.
func CycloneDX(bi *debug.BuildInfo, name string, binSHA256 string) ([]byte, error) {
	if bi == nil {
		return nil, fmt.Errorf("sbom: нет сведений о сборке")
	}
	sn, err := serial(binSHA256)
	if err != nil {
		return nil, err
	}
	setting := map[string]string{}
	for _, s := range bi.Settings {
		setting[s.Key] = s.Value
	}
	main := component{Type: "application", Name: name, BOMRef: "bin:" + name,
		Hashes: []hash{{Alg: "SHA-256", Content: binSHA256}}}
	if bi.Main.Path != "" {
		main.Properties = append(main.Properties, property{"go.main.module", bi.Main.Path})
	}
	for _, k := range []struct{ prop, key string }{{"vcs.revision", "vcs.revision"}, {"vcs.modified", "vcs.modified"},
		{"GOOS", "GOOS"}, {"GOARCH", "GOARCH"}, {"CGO_ENABLED", "CGO_ENABLED"}, {"-trimpath", "-trimpath"}} {
		if v, ok := setting[k.key]; ok {
			main.Properties = append(main.Properties, property{k.prop, v})
		}
	}
	var out bom
	out.BOMFormat, out.SpecVersion, out.SerialNumber, out.Version = "CycloneDX", "1.5", sn, 1
	out.Metadata.Tools.Components = []tool{{Type: "application", Name: "aegis-ci"}}
	out.Metadata.Component = main
	out.Components = []component{}
	for _, d := range bi.Deps {
		eff := d
		if d.Replace != nil {
			eff = d.Replace
		}
		c := component{Type: "library", Name: d.Path, Version: eff.Version, PURL: purl(eff.Path, eff.Version),
			BOMRef: "go:" + d.Path + "@" + eff.Version}
		if eff.Sum != "" {
			c.Properties = append(c.Properties, property{"go.sum.h1", eff.Sum})
		}
		if d.Replace != nil {
			c.Properties = append(c.Properties, property{"go.replace", d.Replace.Path})
		}
		out.Components = append(out.Components, c)
	}
	if v := strings.TrimPrefix(bi.GoVersion, "go"); v != "" {
		out.Components = append(out.Components, component{Type: "library", Name: "stdlib", Version: v,
			PURL: "pkg:golang/stdlib@" + v, BOMRef: "go:stdlib@" + v})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
