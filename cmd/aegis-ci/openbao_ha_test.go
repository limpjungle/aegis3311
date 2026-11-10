package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	haValuesFile = "server/openbao-ha.yaml"
	devRunScript = "../../deploy/vault/dev/run.sh"
)

var (
	// Образ OpenBao в строке `openbao) … digest=sha256:…` стенда run.sh: боевые values обязаны указывать тот же digest.
	reRunDigest   = regexp.MustCompile(`(?s)\n\s*openbao\)[^\n]*\n[^\n]*digest=(sha256:[0-9a-f]{64})`)
	reTLSDisable  = regexp.MustCompile(`tls_disable\s*=\s*(1|true|"true")`)
	reTLSCert     = regexp.MustCompile(`tls_cert_file\s*=`)
	reStorageRaft = regexp.MustCompile(`storage\s+"raft"`)
	reAudit       = regexp.MustCompile(`\baudit\s+"[^"]+"\s+"([^"]+)"`)
	reUnsafeAudit = regexp.MustCompile(`unsafe_allow_api_audit_creation\s*=\s*true`)
	reSealBlock   = regexp.MustCompile(`(?m)^\s*seal\s+"`)
	reRetryJoin   = regexp.MustCompile(`\bretry_join\s*\{`)
)

// at идёт по вложенным картам YAML; ok=false, если ключа нет или промежуточное значение — не карта.
func at(m map[string]any, path ...string) (any, bool) {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// stripHCLComments убирает строки-комментарии, чтобы закомментированное `tls_disable = 1` не засчитывалось.
func stripHCLComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// checkHAValues проверяет боевые values Helm-чарта OpenBao (HA, Raft, TLS, Shamir): ошибка называет нарушенное свойство.
func checkHAValues(raw []byte, wantDigest string) error {
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return err
	}
	isTrue := func(path ...string) bool { v, _ := at(m, path...); return v == true }
	isFalse := func(path ...string) bool { v, _ := at(m, path...); return v == false } // ключ обязан быть задан явно

	if isTrue("server", "dev", "enabled") {
		return errors.New("server.dev.enabled: dev-режим (in-memory, root-токен) недопустим")
	}
	if !isTrue("server", "ha", "enabled") || !isTrue("server", "ha", "raft", "enabled") || !isTrue("server", "ha", "raft", "setNodeId") {
		return errors.New("server.ha.enabled, server.ha.raft.enabled и server.ha.raft.setNodeId должны быть true")
	}
	replicas, _ := at(m, "server", "ha", "replicas")
	if replicas != 3 && replicas != 5 {
		return fmt.Errorf("server.ha.replicas: %v, ожидается 3 или 5 (кворум Raft)", replicas)
	}
	if !isFalse("global", "tlsDisable") {
		return errors.New("global.tlsDisable должен быть явно false")
	}
	if !isFalse("injector", "enabled") || !isFalse("csi", "enabled") {
		return errors.New("injector.enabled и csi.enabled должны быть false (агент работает init-контейнером)")
	}
	if tag, _ := at(m, "server", "image", "tag"); tag != "2.7.2@"+wantDigest {
		return fmt.Errorf("server.image.tag: %v, ожидается 2.7.2@%s (digest как в dev/run.sh)", tag, wantDigest)
	}
	if v, _ := at(m, "server", "ha", "disruptionBudget", "maxUnavailable"); v != 1 {
		return fmt.Errorf("server.ha.disruptionBudget.maxUnavailable: %v, ожидается 1", v)
	}
	if v, _ := at(m, "server", "updateStrategyType"); v != "OnDelete" {
		return fmt.Errorf("server.updateStrategyType: %v, ожидается OnDelete (обновление по одному с unseal)", v)
	}
	aff, _ := at(m, "server", "affinity")
	if s, _ := aff.(string); !strings.Contains(s, "podAntiAffinity") || !strings.Contains(s, "requiredDuringScheduling") {
		return errors.New("server.affinity: нужен podAntiAffinity с requiredDuringScheduling (узлы Raft на разных хостах)")
	}

	cfgAny, _ := at(m, "server", "ha", "raft", "config")
	cfg, _ := cfgAny.(string)
	if cfg == "" {
		return errors.New("server.ha.raft.config: нет HCL-конфигурации")
	}
	cfg = stripHCLComments(cfg)
	if !reStorageRaft.MatchString(cfg) {
		return errors.New(`server.ha.raft.config: нет storage "raft"`)
	}
	if reTLSDisable.MatchString(cfg) {
		return errors.New("server.ha.raft.config: tls_disable включён")
	}
	if !reTLSCert.MatchString(cfg) {
		return errors.New("server.ha.raft.config: у listener нет tls_cert_file")
	}
	paths := map[string]bool{}
	for _, a := range reAudit.FindAllStringSubmatch(cfg, -1) {
		paths[a[1]] = true
	}
	if len(paths) < 2 {
		return fmt.Errorf("server.ha.raft.config: audit device с разными path: %d, нужно не меньше двух (§5: два audit device)", len(paths))
	}
	if reUnsafeAudit.MatchString(cfg) {
		return errors.New("server.ha.raft.config: unsafe_allow_api_audit_creation = true (CVE-2025-54997)")
	}
	if reSealBlock.MatchString(cfg) {
		return errors.New("server.ha.raft.config: блок seal — решено Shamir (identity-secrets-mvp-a.md §9); смена способа unseal — через пересмотр §9")
	}
	if n := len(reRetryJoin.FindAllString(cfg, -1)); n != replicas {
		return fmt.Errorf("server.ha.raft.config: retry_join %d, а replicas %v", n, replicas)
	}
	return nil
}

func runDigest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(devRunScript)
	if err != nil {
		t.Fatal(err)
	}
	mm := reRunDigest.FindSubmatch(raw)
	if mm == nil {
		t.Fatal("в dev/run.sh не найден digest образа openbao")
	}
	return string(mm[1])
}

func TestOpenBaoHAValues(t *testing.T) {
	if err := checkHAValues(readVault(t, haValuesFile), runDigest(t)); err != nil {
		t.Error(err)
	}
}

// Мутации реальных values: каждая проверка обязана их отвергнуть.
func TestOpenBaoHANegativeCases(t *testing.T) {
	raw, digest := readVault(t, haValuesFile), runDigest(t)
	yamlMut := func(f func(m map[string]any)) func() error {
		return func() error {
			var m map[string]any
			if err := yaml.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			f(m)
			out, err := yaml.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			return checkHAValues(out, digest)
		}
	}
	set := func(m map[string]any, v any, path ...string) {
		cur := m
		for _, p := range path[:len(path)-1] {
			cur = cur[p].(map[string]any)
		}
		cur[path[len(path)-1]] = v
	}
	cfgMut := func(f func(cfg string) string) func() error {
		return yamlMut(func(m map[string]any) {
			c, _ := at(m, "server", "ha", "raft", "config")
			set(m, f(c.(string)), "server", "ha", "raft", "config")
		})
	}
	needs := func(cfg, sub string) string {
		if !strings.Contains(cfg, sub) {
			t.Fatalf("в реальной конфигурации нет %q: мутация ничего не проверяет", sub)
		}
		return cfg
	}

	cases := []struct {
		name string
		want string // подстрока причины ошибки
		run  func() error
	}{
		{"dev-режим включён", "dev-режим", yamlMut(func(m map[string]any) { set(m, true, "server", "dev", "enabled") })},
		{"tlsDisable true", "global.tlsDisable", yamlMut(func(m map[string]any) { set(m, true, "global", "tlsDisable") })},
		{"tls_disable = 1", "tls_disable", cfgMut(func(c string) string {
			return strings.Replace(needs(c, "tls_min_version"), "tls_min_version", "tls_disable = 1\n  tls_min_version", 1)
		})},
		{`seal "static"`, "§9", cfgMut(func(c string) string { return c + "\nseal \"static\" {\n  current_key_id = \"k\"\n}\n" })},
		{"один audit device", "audit device", cfgMut(func(c string) string {
			return strings.Replace(needs(c, `audit "file" "stdout"`), `audit "file" "stdout"`, `xaudit "file" "stdout"`, 1)
		})},
		{"два audit с одним path", "audit device", cfgMut(func(c string) string {
			return strings.Replace(needs(c, `audit "file" "stdout"`), `audit "file" "stdout"`, `audit "file" "file"`, 1)
		})},
		{"replicas 2", "replicas", yamlMut(func(m map[string]any) { set(m, 2, "server", "ha", "replicas") })},
		{"retry_join меньше replicas", "retry_join", yamlMut(func(m map[string]any) { set(m, 5, "server", "ha", "replicas") })},
		{"unsafe_allow_api_audit_creation", "CVE-2025-54997", cfgMut(func(c string) string { return c + "\nunsafe_allow_api_audit_creation = true\n" })},
		{"тег без digest", "server.image.tag", yamlMut(func(m map[string]any) { set(m, "2.7.2", "server", "image", "tag") })},
		{"другой digest", "server.image.tag", yamlMut(func(m map[string]any) {
			set(m, "2.7.2@sha256:"+strings.Repeat("0", 64), "server", "image", "tag")
		})},
		{"PDB maxUnavailable 0", "maxUnavailable", yamlMut(func(m map[string]any) { set(m, 0, "server", "ha", "disruptionBudget", "maxUnavailable") })},
		{"RollingUpdate вместо OnDelete", "OnDelete", yamlMut(func(m map[string]any) { set(m, "RollingUpdate", "server", "updateStrategyType") })},
		{"без anti-affinity", "podAntiAffinity", yamlMut(func(m map[string]any) { set(m, "", "server", "affinity") })},
		{"injector включён", "injector", yamlMut(func(m map[string]any) { set(m, true, "injector", "enabled") })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run()
			if err == nil {
				t.Fatalf("мутация %q прошла проверку", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("мутация %q отвергнута по другой причине: %v (ожидалось %q)", c.name, err, c.want)
			}
		})
	}
}
