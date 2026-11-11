package main

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// T-36: манифесты deploy/vault/network/. Проверка строгая по структуре, общая часть (checkCNP, checkDefaultDeny) — с intake
// (netpol_test.go): разрешено ровно то, что перечислено в wantOpenBao. Порты и имя headless-сервиса берутся из values чарта.

const openbaoNetDir = "../../deploy/vault/network"

var (
	obReAPI     = regexp.MustCompile(`(?m)^\s*address\s*=\s*"\[::\]:([0-9]+)"`)
	obReCluster = regexp.MustCompile(`(?m)^\s*cluster_address\s*=\s*"\[::\]:([0-9]+)"`)
	obReJoin    = regexp.MustCompile(`(?m)^\s*leader_api_addr\s*=\s*"https://openbao-[0-9]+\.([a-z0-9-]+):([0-9]+)"`)
	obReTelem   = regexp.MustCompile(`(?m)^\s*telemetry\s*\{`)
)

const obPeers = "app.kubernetes.io/name=openbao,component=server"

// obValuesPorts: порт API, порт кластера (Raft) и имя headless-сервиса из конфигурации OpenBao в values.
func obValuesPorts(values string) (api, cluster int, svc string, err error) {
	a, c := obReAPI.FindAllStringSubmatch(values, -1), obReCluster.FindAllStringSubmatch(values, -1)
	if len(a) != 1 || len(c) != 1 {
		return 0, 0, "", fmt.Errorf("values: нужен ровно один listener с address и cluster_address, найдено %d и %d", len(a), len(c))
	}
	api, _ = strconv.Atoi(a[0][1])
	cluster, _ = strconv.Atoi(c[0][1])
	joins := obReJoin.FindAllStringSubmatch(values, -1)
	if len(joins) == 0 {
		return 0, 0, "", errors.New("values: нет retry_join с leader_api_addr")
	}
	for _, j := range joins {
		if svc != "" && j[1] != svc {
			return 0, 0, "", fmt.Errorf("values: retry_join указывает на разные сервисы (%s, %s)", svc, j[1])
		}
		svc = j[1]
		if p, _ := strconv.Atoi(j[2]); p != api {
			return 0, 0, "", fmt.Errorf("values: retry_join на порт %d, а address слушает %d", p, api)
		}
	}
	return api, cluster, svc, nil
}

func wantOpenBao(ns string, api, cluster int, svc string) []string {
	peers := "ns=" + ns + ";" + obPeers
	return []string{
		fmt.Sprintf("from ns=aegis-system;app=aegis-intake TCP %d", api),
		fmt.Sprintf("from %s TCP %d", peers, api),
		fmt.Sprintf("from %s TCP %d", peers, cluster),
		"endpoints ns=kube-system;k8s-app=kube-dns ANY 53",
		"dns kubernetes.default.svc.cluster.local",
		fmt.Sprintf("dns *.%s.%s.svc.cluster.local", svc, ns),
		fmt.Sprintf("endpoints %s TCP %d", peers, api),
		fmt.Sprintf("endpoints %s TCP %d", peers, cluster),
		"entity kube-apiserver TCP 443",
	}
}

// checkOpenBaoNetpols возвращает также найденные назначения CNP — для сверки со стороной intake.
func checkOpenBaoNetpols(nps []npDoc, cnps []cnpDoc, ns string, api, cluster int, svc string, valuesHasTelemetry bool) (map[string]bool, error) {
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	byName := map[string]npDoc{}
	for _, p := range nps {
		if _, dup := byName[p.Metadata.Name]; dup {
			bad("NetworkPolicy %s: повтор имени", p.Metadata.Name)
		}
		byName[p.Metadata.Name] = p
		if p.Metadata.Namespace != ns {
			bad("NetworkPolicy %s: namespace %q, нужен %s", p.Metadata.Name, p.Metadata.Namespace, ns)
		}
		if p.Metadata.Name != "vault-default-deny" {
			bad("лишняя NetworkPolicy %s", p.Metadata.Name)
		}
		// Egress в стандартных политиках запрещён: L4-разрешение DNS слилось бы с L7-правилом CNP и сняло фильтр имён.
		if len(p.Spec.Egress) > 0 {
			bad("NetworkPolicy %s: egress-правила запрещены (весь egress — в CiliumNetworkPolicy)", p.Metadata.Name)
		}
	}
	if len(nps) != 1 {
		bad("NetworkPolicy должна быть ровно одна (vault-default-deny), найдено %d", len(nps))
	}
	if p, ok := byName["vault-default-deny"]; !ok {
		bad("нет NetworkPolicy vault-default-deny")
	} else {
		checkDefaultDeny(p, bad)
	}
	if len(cnps) != 1 {
		bad("CiliumNetworkPolicy должна быть ровно одна (openbao-server), найдено %d", len(cnps))
		return nil, npJoin(errs)
	}
	peers := "ns=" + ns + ";" + obPeers
	cerrs, dests := checkCNP(cnps[0], cnpSpec{
		Name: "openbao-server", Namespace: ns, Selector: map[string]string{"app.kubernetes.io/name": "openbao", "component": "server"},
		DNSPatterns: map[string]bool{"*." + svc + "." + ns + ".svc.cluster.local": true},
		DNSNames:    map[string]bool{"kubernetes.default.svc.cluster.local": true},
		Want:        wantOpenBao(ns, api, cluster, svc), RaftPort: cluster, RaftTarget: peers,
	})
	errs = append(errs, cerrs...)
	if valuesHasTelemetry {
		bad("в values включена telemetry: нужно ingress-правило для Prometheus в cilium-openbao.yaml")
	}
	return dests, npJoin(errs)
}

// obLink: обе стороны связи intake -> OpenBao описаны (egress в CNP intake и ingress в CNP OpenBao).
func obLink(ob, intake map[string]bool, ns string, api int) error {
	out := fmt.Sprintf("endpoints ns=%s;%s TCP %d", ns, obPeers, api)
	in := fmt.Sprintf("from ns=aegis-system;app=aegis-intake TCP %d", api)
	var errs []string
	if !intake[out] {
		errs = append(errs, "в CNP intake нет egress "+out)
	}
	if !ob[in] {
		errs = append(errs, "в CNP OpenBao нет ingress "+in)
	}
	return npJoin(errs)
}

func obRun(m *npMut) error {
	nps, cnps, err := npParseAll(map[string][]byte{"networkpolicy.yaml": []byte(m.netpol), "cilium-openbao.yaml": []byte(m.cilium)})
	if err != nil {
		return err
	}
	ns, port, err := npAgentVault([]byte(m.agent))
	if err != nil {
		return err
	}
	api, cluster, svc, err := obValuesPorts(m.values)
	if err != nil {
		return err
	}
	if port != api {
		return fmt.Errorf("агент ходит на порт %d, а OpenBao слушает %d", port, api)
	}
	dests, err := checkOpenBaoNetpols(nps, cnps, ns, api, cluster, svc, obReTelem.MatchString(m.values))
	if err != nil {
		return err
	}
	_, icnps, err := npParseAll(npReadDir(m.t))
	if err != nil {
		return err
	}
	if len(icnps) != 1 {
		return errors.New("в deploy/intake нет CNP")
	}
	_, idests := checkCNP(icnps[0], intakeCNPSpec(ns, port))
	return obLink(dests, idests, ns, api)
}

func obMutBase(t *testing.T) *npMut {
	files := npReadDirAt(t, openbaoNetDir)
	return &npMut{t: t, netpol: string(files["networkpolicy.yaml"]), cilium: string(files["cilium-openbao.yaml"]),
		agent: string(readVault(t, "agent/aegis-intake.json")), values: string(readVault(t, "server/openbao-ha.yaml"))}
}

func TestOpenBaoNetworkPolicy(t *testing.T) {
	if err := obRun(obMutBase(t)); err != nil {
		t.Fatal(err)
	}
	// Файлы каталога — ровно эти два.
	files := npReadDirAt(t, openbaoNetDir)
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "cilium-openbao.yaml,networkpolicy.yaml" {
		t.Fatalf("состав deploy/vault/network: %v", names)
	}
}

func TestOpenBaoNetworkPolicyNegativeCases(t *testing.T) {
	const (
		i1      = "            app: aegis-intake\n      toPorts:\n        - ports:\n            - port: \"8200\"\n              protocol: TCP\n"
		ing     = "  ingress:\n"
		nsAEG   = "            k8s:io.kubernetes.pod.namespace: aegis-system\n"
		dnsOB   = `- matchPattern: "*.openbao-internal.vault.svc.cluster.local"`
		dnsK8s  = "              - matchName: kubernetes.default.svc.cluster.local\n"
		anyRule = "      toPorts: [{ports: [{port: \"8200\", protocol: TCP}]}]\n"
	)
	cases := []struct {
		name, want string
		mutate     func(m *npMut)
	}{
		{"fromEntities world", "fromEntities", func(m *npMut) { m.sub(&m.cilium, ing, ing+"    - fromEntities: [world]\n"+anyRule) }},
		{"fromEntities host", "fromEntities", func(m *npMut) { m.sub(&m.cilium, ing, ing+"    - fromEntities: [host]\n"+anyRule) }},
		{"fromEndpoints reserved:host", "reserved:", func(m *npMut) {
			m.sub(&m.cilium, ing, ing+"    - fromEndpoints: [{matchLabels: {\"k8s:io.kubernetes.pod.namespace\": vault, \"reserved:host\": \"\"}}]\n"+anyRule)
		}},
		{"fromEndpoints пустой селектор", "пустой селектор", func(m *npMut) { m.sub(&m.cilium, ing, ing+"    - fromEndpoints: [{}]\n"+anyRule) }},
		{"I1 без метки namespace", "метки namespace", func(m *npMut) { m.sub(&m.cilium, nsAEG, "") }},
		{"I1 namespace nettest", "не совпадают с таблицей", func(m *npMut) {
			m.sub(&m.cilium, nsAEG, "            k8s:io.kubernetes.pod.namespace: nettest\n")
		}},
		{"I1 порт 8201", "8201", func(m *npMut) { m.sub(&m.cilium, i1, i1+"            - port: \"8201\"\n              protocol: TCP\n") }},
		{"ingress из prometheus :8200", "не совпадают", func(m *npMut) {
			m.sub(&m.cilium, ing, ing+"    - fromEndpoints: [{matchLabels: {\"k8s:io.kubernetes.pod.namespace\": monitoring, app.kubernetes.io/name: prometheus}}]\n"+anyRule)
		}},
		{"fromCIDR", "fromCIDR", func(m *npMut) { m.sub(&m.cilium, ing, ing+"    - fromCIDR: [\"0.0.0.0/0\"]\n"+anyRule) }},
		{"egress toEntities world", "toEntities", func(m *npMut) { m.sub(&m.cilium, "        - kube-apiserver\n", "        - world\n") }},
		{"egress toFQDNs example.com", "не совпадают", func(m *npMut) {
			m.sub(&m.cilium, dnsK8s, dnsK8s+"              - matchName: example.com\n")
			m.cilium += "    - toFQDNs:\n        - matchName: example.com\n      toPorts:\n        - ports:\n            - port: \"443\"\n              protocol: TCP\n          serverNames:\n            - example.com\n"
		}},
		{"DNS matchPattern *.*.svc", "не из разрешённых", func(m *npMut) { m.sub(&m.cilium, dnsOB, `- matchPattern: "*.*.svc.cluster.local"`) }},
		{"DNS matchPattern *", "разрешает все имена", func(m *npMut) { m.sub(&m.cilium, dnsOB, `- matchPattern: "*"`) }},
		{"удалён E3", "kube-apiserver", func(m *npMut) { m.cilium = m.cilium[:strings.Index(m.cilium, "    # E3.")] }},
		{"serverNames на I1", "serverNames", func(m *npMut) { m.sub(&m.cilium, i1, i1+"          serverNames:\n            - x.example\n") }},
		{"rules.http на ingress", "L7", func(m *npMut) {
			m.sub(&m.cilium, i1, i1+"          rules:\n            http:\n              - method: GET\n")
		}},
		{"enableDefaultDeny.ingress false", "enableDefaultDeny.ingress", func(m *npMut) {
			m.sub(&m.cilium, "spec:\n  endpointSelector:", "spec:\n  enableDefaultDeny:\n    ingress: false\n  endpointSelector:")
		}},
		{"endpointSelector пуст", "endpointSelector", func(m *npMut) {
			m.sub(&m.cilium, "  endpointSelector:\n    matchLabels:\n      app.kubernetes.io/name: openbao\n      component: server\n", "  endpointSelector: {}\n")
		}},
		{"ingressDeny", "ingressDeny", func(m *npMut) { m.cilium += "  ingressDeny:\n    - fromEntities: [world]\n" }},
		{"порт числом", "строка в кавычках", func(m *npMut) { m.sub(&m.cilium, i1, strings.Replace(i1, `"8200"`, "8200", 1)) }},
		{"удалён vault-default-deny", "vault-default-deny", func(m *npMut) { m.netpol = "" }},
		{"default-deny без Egress", "policyTypes", func(m *npMut) { m.sub(&m.netpol, "policyTypes: [Ingress, Egress]", "policyTypes: [Ingress]") }},
		{"в агенте namespace other", "namespace", func(m *npMut) { m.sub(&m.agent, "vault.vault.svc", "vault.other.svc") }},
		{"в values cluster_address 8301", "8301", func(m *npMut) { m.sub(&m.values, `cluster_address = "[::]:8201"`, `cluster_address = "[::]:8301"`) }},
		{"в values telemetry", "telemetry", func(m *npMut) {
			m.sub(&m.values, `service_registration "kubernetes" {}`, "service_registration \"kubernetes\" {}\n\n        telemetry {}")
		}},
		{"в агенте другой порт", "порт", func(m *npMut) { m.sub(&m.agent, "svc:8200", "svc:8300") }},
		{"metadata.uid", "metadata.uid запрещено", func(m *npMut) { m.sub(&m.cilium, "  name: openbao-server\n", "  name: openbao-server\n  uid: x\n") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := obMutBase(t)
			m.t = t
			tc.mutate(m)
			err := obRun(m)
			if err == nil {
				t.Fatal("мутация не обнаружена")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ошибка не называет нарушение %q: %v", tc.want, err)
			}
		})
	}
}
