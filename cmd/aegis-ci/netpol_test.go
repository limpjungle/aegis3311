package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// T-17: манифесты deploy/intake/. Проверка строгая по структуре (не по подстрокам): разрешено ровно то, что перечислено в wantIntakeEgress,
// остальное — ошибка. Запрещённые поля объявлены в типах явно, чтобы сообщение называло нарушение.

const (
	intakeDeployDir = "../../deploy/intake"
	npNamespace     = "aegis-system"
	npNSLabel       = "k8s:io.kubernetes.pod.namespace"
)

// Единственный шаблон DNS, кроме точных имён из toFQDNs.
var npAllowedDNSPatterns = map[string]bool{"*.*.svc.cluster.local": true}

var (
	npReAgentAddr = regexp.MustCompile(`^https://[a-z0-9-]+\.([a-z0-9-]+)\.svc(?:\.cluster\.local)?:([0-9]+)$`)
	npRePort      = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
)

type npSel struct {
	MatchLabels      map[string]string `yaml:"matchLabels"`
	MatchExpressions []any             `yaml:"matchExpressions"`
}

type npRule struct {
	From  []npPeer `yaml:"from"`
	To    []npPeer `yaml:"to"`
	Ports []struct {
		Protocol string `yaml:"protocol"`
		Port     int    `yaml:"port"`
		EndPort  *int   `yaml:"endPort"`
	} `yaml:"ports"`
}

type npPeer struct {
	NamespaceSelector *npSel `yaml:"namespaceSelector"`
	PodSelector       *npSel `yaml:"podSelector"`
	IPBlock           *struct {
		CIDR   string   `yaml:"cidr"`
		Except []string `yaml:"except"`
	} `yaml:"ipBlock"`
}

// npMeta: метки и аннотации допустимы, остальное (uid, resourceVersion, ownerReferences, finalizers, generateName) — нет, см. npCheckMeta.
type npMeta struct {
	Name, Namespace string
	Labels          map[string]string `yaml:"labels"`
	Annotations     map[string]string `yaml:"annotations"`
}

type npDoc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   npMeta `yaml:"metadata"`
	Spec       struct {
		PodSelector npSel    `yaml:"podSelector"`
		PolicyTypes []string `yaml:"policyTypes"`
		Ingress     []npRule `yaml:"ingress"`
		Egress      []npRule `yaml:"egress"`
	} `yaml:"spec"`
}

type cnpFQDN struct {
	MatchName    string `yaml:"matchName"`
	MatchPattern string `yaml:"matchPattern"`
}

type cnpPort struct {
	Port     string `yaml:"port"`
	EndPort  int    `yaml:"endPort"`
	Protocol string `yaml:"protocol"`
}

type cnpPortRule struct {
	Ports []cnpPort `yaml:"ports"`
	Rules *struct {
		DNS     []cnpFQDN `yaml:"dns"`
		HTTP    []any     `yaml:"http"`
		Kafka   []any     `yaml:"kafka"`
		L7      []any     `yaml:"l7"`
		L7Proto string    `yaml:"l7proto"`
	} `yaml:"rules"`
	ServerNames    []string `yaml:"serverNames"`
	Listener       any      `yaml:"listener"`
	TerminatingTLS any      `yaml:"terminatingTLS"`
	OriginatingTLS any      `yaml:"originatingTLS"`
}

type cnpEgress struct {
	ToEndpoints    []npSel       `yaml:"toEndpoints"`
	ToEntities     []string      `yaml:"toEntities"`
	ToFQDNs        []cnpFQDN     `yaml:"toFQDNs"`
	ToCIDR         []string      `yaml:"toCIDR"`
	ToCIDRSet      []any         `yaml:"toCIDRSet"`
	ToServices     []any         `yaml:"toServices"`
	ToGroups       []any         `yaml:"toGroups"`
	ToNodes        []any         `yaml:"toNodes"`
	ToRequires     []any         `yaml:"toRequires"`
	ICMPs          []any         `yaml:"icmps"`
	Authentication any           `yaml:"authentication"`
	ToPorts        []cnpPortRule `yaml:"toPorts"`
}

type cnpIngress struct {
	FromEndpoints  []npSel       `yaml:"fromEndpoints"`
	FromEntities   []string      `yaml:"fromEntities"`
	FromCIDR       []string      `yaml:"fromCIDR"`
	FromCIDRSet    []any         `yaml:"fromCIDRSet"`
	FromRequires   []any         `yaml:"fromRequires"`
	FromGroups     []any         `yaml:"fromGroups"`
	FromNodes      []any         `yaml:"fromNodes"`
	ICMPs          []any         `yaml:"icmps"`
	Authentication any           `yaml:"authentication"`
	ToPorts        []cnpPortRule `yaml:"toPorts"`
}

type cnpDoc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   npMeta `yaml:"metadata"`
	Specs      []any  `yaml:"specs"`
	Spec       struct {
		Description       string       `yaml:"description"`
		EndpointSelector  npSel        `yaml:"endpointSelector"`
		NodeSelector      *npSel       `yaml:"nodeSelector"`
		Ingress           []cnpIngress `yaml:"ingress"`
		IngressDeny       []any        `yaml:"ingressDeny"`
		EgressDeny        []any        `yaml:"egressDeny"`
		Egress            []cnpEgress  `yaml:"egress"`
		EnableDefaultDeny *struct {
			Ingress *bool `yaml:"ingress"`
			Egress  *bool `yaml:"egress"`
		} `yaml:"enableDefaultDeny"`
	} `yaml:"spec"`
}

// Kind ∈ {"endpoints","entity","fqdn","dns","from"}; Target — "ns=…;k=v,…" (отсортировано), имя entity, FQDN или DNS-шаблон;
// Proto/Port — для dns пусто; SNI — serverNames правила toFQDNs.
type npDest struct {
	Kind, Target, Proto string
	Port                int
	SNI                 string
}

func (d npDest) String() string {
	if d.Kind == "dns" {
		return "dns " + d.Target
	}
	s := fmt.Sprintf("%s %s %s %d", d.Kind, d.Target, d.Proto, d.Port)
	if d.SNI != "" {
		s += " sni=" + d.SNI
	}
	return s
}

// npCheckMeta: в metadata допустимы только name, namespace, labels, annotations. Метки и аннотации на объекте политики не влияют
// на селекцию; uid, resourceVersion, ownerReferences, finalizers, generateName — признак выгрузки из кластера или подмены.
func npCheckMeta(n *yaml.Node) error {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value != "metadata" {
			continue
		}
		m := n.Content[i+1]
		for j := 0; m.Kind == yaml.MappingNode && j+1 < len(m.Content); j += 2 {
			k, v := m.Content[j], m.Content[j+1]
			switch k.Value {
			case "name", "namespace":
			case "labels", "annotations":
				for q := 0; v.Kind == yaml.MappingNode && q+1 < len(v.Content); q += 2 {
					if e := v.Content[q+1]; e.Kind != yaml.ScalarNode || e.Tag != "!!str" {
						return fmt.Errorf("metadata.%s.%s (строка %d): значение должно быть строкой", k.Value, v.Content[q].Value, e.Line)
					}
				}
			default:
				return fmt.Errorf("metadata.%s запрещено (допустимы name, namespace, labels, annotations)", k.Value)
			}
		}
	}
	return nil
}

// cnpCheckPortTags: CRD Cilium принимает port только строкой; число в YAML kubectl отклонит, а тест должен сказать об этом раньше.
func cnpCheckPortTags(n *yaml.Node) []string {
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if v := n.Content[i+1]; n.Content[i].Value == "port" && v.Kind == yaml.ScalarNode && v.Tag != "!!str" {
					out = append(out, fmt.Sprintf("порт %s (строка %d): число, нужна строка в кавычках — CRD Cilium принимает только string", v.Value, v.Line))
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(n)
	return out
}

// npParse разбирает документы одного файла; name нужен только для сообщений.
func npParse(name string, raw []byte) (nps []npDoc, cnps []cnpDoc, err error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for i := 1; ; i++ {
		var n yaml.Node
		if err := dec.Decode(&n); errors.Is(err, io.EOF) {
			return nps, cnps, nil
		} else if err != nil {
			return nil, nil, fmt.Errorf("%s: документ %d: %w", name, i, err)
		}
		if n.Kind == yaml.DocumentNode && (len(n.Content) == 0 || n.Content[0].Tag == "!!null") {
			continue
		}
		var h struct {
			APIVersion string `yaml:"apiVersion"`
			Kind       string `yaml:"kind"`
		}
		if err := n.Decode(&h); err != nil {
			return nil, nil, fmt.Errorf("%s: документ %d: %w", name, i, err)
		}
		if err := npCheckMeta(&n); err != nil {
			return nil, nil, fmt.Errorf("%s: документ %d: %w", name, i, err)
		}
		if h.Kind == "CiliumNetworkPolicy" {
			if bad := cnpCheckPortTags(&n); len(bad) > 0 {
				return nil, nil, fmt.Errorf("%s: документ %d: %s", name, i, strings.Join(bad, "; "))
			}
		}
		b, err := yaml.Marshal(&n)
		if err != nil {
			return nil, nil, err
		}
		strict := yaml.NewDecoder(bytes.NewReader(b))
		strict.KnownFields(true)
		switch {
		case h.Kind == "NetworkPolicy" && h.APIVersion == "networking.k8s.io/v1":
			var d npDoc
			if err := strict.Decode(&d); err != nil {
				return nil, nil, fmt.Errorf("%s: документ %d (NetworkPolicy): %w", name, i, err)
			}
			nps = append(nps, d)
		case h.Kind == "CiliumNetworkPolicy" && h.APIVersion == "cilium.io/v2":
			var d cnpDoc
			if err := strict.Decode(&d); err != nil {
				return nil, nil, fmt.Errorf("%s: документ %d (CiliumNetworkPolicy): %w", name, i, err)
			}
			cnps = append(cnps, d)
		default:
			return nil, nil, fmt.Errorf("%s: документ %d: недопустимый kind %q (%q): разрешены только NetworkPolicy и CiliumNetworkPolicy", name, i, h.Kind, h.APIVersion)
		}
	}
}

func npReadDir(t *testing.T) map[string][]byte { t.Helper(); return npReadDirAt(t, intakeDeployDir) }

// npDirEntryErr проверяет запись каталога манифестов. `kubectl apply -f <каталог>` применяет
// .yaml, .yml и .json, а тест читает только *.yaml, поэтому любой другой файл — ошибка, а не
// тихий пропуск: иначе x.yml с allow-all попал бы в кластер мимо проверки. Допустимы *.yaml,
// README.md и подкаталог dev/ (без -R kubectl в подкаталоги не заходит).
func npDirEntryErr(name string, isDir bool) error {
	switch {
	case isDir && name == "dev":
		return nil
	case isDir:
		return fmt.Errorf("%s/: в каталоге манифестов подкаталоги, кроме dev/, запрещены", name)
	case name == "README.md", filepath.Ext(name) == ".yaml" && !strings.HasPrefix(name, "."):
		return nil
	}
	return fmt.Errorf("%s: в каталоге манифестов допустимы только *.yaml, README.md и dev/ — kubectl apply -f применит и .yml/.json, а тест их не проверяет", name)
}

// npReadDirAt читает все *.yaml каталога (dev/ не входит); любой посторонний файл — ошибка.
func npReadDirAt(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, e := range ents {
		if err := npDirEntryErr(e.Name(), e.IsDir()); err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if e.IsDir() || e.Name() == "README.md" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = b
	}
	return files
}

func npParseAll(files map[string][]byte) (nps []npDoc, cnps []cnpDoc, err error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a, c, err := npParse(n, files[n])
		if err != nil {
			return nil, nil, err
		}
		nps, cnps = append(nps, a...), append(cnps, c...)
	}
	return nps, cnps, nil
}

func npLoadDir(t *testing.T) (nps []npDoc, cnps []cnpDoc) {
	t.Helper()
	nps, cnps, err := npParseAll(npReadDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return nps, cnps
}

// npAgentVault достаёт namespace и порт сервера из vault.address агента: https://<svc>.<ns>.svc[.cluster.local]:<port>.
func npAgentVault(raw []byte) (ns string, port int, err error) {
	var c struct {
		Vault struct {
			Address string `json:"address"`
		} `json:"vault"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", 0, err
	}
	m := npReAgentAddr.FindStringSubmatch(c.Vault.Address)
	if m == nil {
		return "", 0, fmt.Errorf("vault.address %q: ожидается https://<svc>.<ns>.svc[.cluster.local]:<port>", c.Vault.Address)
	}
	port, _ = strconv.Atoi(m[2])
	return m[1], port, nil
}

func npSelEmpty(s npSel) bool { return len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 }

func npLabels(m map[string]string) string {
	kv := make([]string, 0, len(m))
	for k, v := range m {
		kv = append(kv, k+"="+v)
	}
	sort.Strings(kv)
	return strings.Join(kv, ",")
}

// npSelTarget: "ns=<namespace>;k=v,…" без метки namespace; ok=false, если селектор не годится для toEndpoints.
func npSelTarget(s npSel, field string) (target string, problem string) {
	if npSelEmpty(s) {
		return "", "пустой селектор " + field + " разрешает любые поды"
	}
	if len(s.MatchExpressions) > 0 {
		return "", "matchExpressions в " + field + " запрещены"
	}
	ns, ok := s.MatchLabels[npNSLabel]
	if !ok {
		return "", "в " + field + " нет метки namespace " + npNSLabel
	}
	rest := map[string]string{}
	for k, v := range s.MatchLabels {
		if strings.HasPrefix(k, "reserved:") {
			return "", "ключи reserved: в " + field + " запрещены (" + k + ")"
		}
		if k != npNSLabel {
			rest[k] = v
		}
	}
	if len(rest) == 0 {
		return "", "в " + field + " нет метки пода, только namespace"
	}
	return "ns=" + ns + ";" + npLabels(rest), ""
}

func wantIntakeEgress(vaultNS string, vaultPort int) []string {
	return []string{
		"endpoints ns=kube-system;k8s-app=kube-dns ANY 53",
		"dns openrouter.ai",
		"dns storage.yandexcloud.net",
		"dns *.*.svc.cluster.local",
		fmt.Sprintf("endpoints ns=%s;app.kubernetes.io/name=openbao,component=server TCP %d", vaultNS, vaultPort),
		"endpoints ns=monitoring;app.kubernetes.io/name=alertmanager TCP 9093",
		"endpoints ns=monitoring;app.kubernetes.io/name=prometheus TCP 9090",
		"entity kube-apiserver TCP 443",
		"fqdn openrouter.ai TCP 443 sni=openrouter.ai",
		"fqdn storage.yandexcloud.net TCP 443 sni=storage.yandexcloud.net",
	}
}

const npKubeDNS = "ns=kube-system;k8s-app=kube-dns"

func checkIntakeNetpols(nps []npDoc, cnps []cnpDoc, vaultNS string, vaultPort int) error {
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	// 1. Состав.
	byName := map[string]npDoc{}
	for _, p := range nps {
		if _, dup := byName[p.Metadata.Name]; dup {
			bad("NetworkPolicy %s: повтор имени", p.Metadata.Name)
		}
		byName[p.Metadata.Name] = p
		if p.Metadata.Namespace != npNamespace {
			bad("NetworkPolicy %s: namespace %q, нужен %s", p.Metadata.Name, p.Metadata.Namespace, npNamespace)
		}
		if p.Metadata.Name != "aegis-system-default-deny" && p.Metadata.Name != "aegis-intake-metrics" {
			bad("лишняя NetworkPolicy %s", p.Metadata.Name)
		}
		// 3. Egress в стандартных политиках запрещён: L4-разрешение DNS слилось бы с L7-правилом CNP и сняло фильтр имён.
		if len(p.Spec.Egress) > 0 {
			bad("NetworkPolicy %s: egress-правила запрещены (весь egress — в CiliumNetworkPolicy)", p.Metadata.Name)
		}
		for _, r := range p.Spec.Ingress {
			for _, pt := range r.Ports {
				if pt.Port == 8201 {
					bad("NetworkPolicy %s: порт 8201 (Raft) не разрешается", p.Metadata.Name)
				}
			}
		}
	}
	if len(nps) != 2 {
		bad("NetworkPolicy должно быть ровно две (aegis-system-default-deny, aegis-intake-metrics), найдено %d", len(nps))
	}
	if len(cnps) != 1 {
		bad("CiliumNetworkPolicy должна быть ровно одна (aegis-intake-egress), найдено %d", len(cnps))
	}

	// 2. default-deny.
	if p, ok := byName["aegis-system-default-deny"]; !ok {
		bad("нет NetworkPolicy aegis-system-default-deny")
	} else {
		checkDefaultDeny(p, bad)
	}

	// 3. metrics.
	if p, ok := byName["aegis-intake-metrics"]; !ok {
		bad("нет NetworkPolicy aegis-intake-metrics")
	} else {
		if len(p.Spec.PodSelector.MatchExpressions) > 0 || len(p.Spec.PodSelector.MatchLabels) != 1 || p.Spec.PodSelector.MatchLabels["app"] != "aegis-intake" {
			bad("metrics: podSelector должен быть ровно {app: aegis-intake}")
		}
		if len(p.Spec.PolicyTypes) != 1 || p.Spec.PolicyTypes[0] != "Ingress" {
			bad("metrics: policyTypes должны быть ровно [Ingress], а не %v", p.Spec.PolicyTypes)
		}
		if len(p.Spec.Ingress) != 1 || len(p.Spec.Ingress[0].From) != 1 {
			bad("metrics: нужно одно правило с одним peer")
		} else {
			r, peer := p.Spec.Ingress[0], p.Spec.Ingress[0].From[0]
			ns, pod := peer.NamespaceSelector, peer.PodSelector
			switch {
			case peer.IPBlock != nil:
				bad("metrics: ipBlock запрещён")
			case ns == nil || pod == nil:
				bad("metrics: peer должен содержать и namespaceSelector, и podSelector (одиночный селектор открывает весь namespace или все поды)")
			default:
				if len(ns.MatchExpressions) > 0 || len(ns.MatchLabels) != 1 || ns.MatchLabels["kubernetes.io/metadata.name"] != "monitoring" {
					bad("metrics: namespaceSelector должен быть ровно {kubernetes.io/metadata.name: monitoring}")
				}
				if len(pod.MatchExpressions) > 0 || len(pod.MatchLabels) != 1 || pod.MatchLabels["app.kubernetes.io/name"] != "prometheus" {
					bad("metrics: podSelector должен быть ровно {app.kubernetes.io/name: prometheus}")
				}
			}
			if len(r.Ports) != 1 || r.Ports[0].Port != 9464 || r.Ports[0].Protocol != "TCP" || r.Ports[0].EndPort != nil {
				bad("metrics: порт должен быть ровно TCP 9464 без endPort")
			}
		}
	}

	if len(cnps) != 1 {
		return npJoin(errs)
	}
	cerrs, _ := checkCNP(cnps[0], intakeCNPSpec(vaultNS, vaultPort))
	errs = append(errs, cerrs...)
	return npJoin(errs)
}

func intakeCNPSpec(vaultNS string, vaultPort int) cnpSpec {
	return cnpSpec{
		Name: "aegis-intake-egress", Namespace: npNamespace, Selector: map[string]string{"app": "aegis-intake"},
		DNSPatterns: npAllowedDNSPatterns, DNSNames: map[string]bool{}, Want: wantIntakeEgress(vaultNS, vaultPort), RaftPort: 8201,
	}
}

// cnpSpec — что должна разрешать одна CiliumNetworkPolicy; всё сверх Want — ошибка.
type cnpSpec struct {
	Name, Namespace string
	Selector        map[string]string // точный endpointSelector.matchLabels
	DNSPatterns     map[string]bool   // разрешённые rules.dns.matchPattern
	DNSNames        map[string]bool   // matchName без парного toFQDNs (имена кластера)
	Want            []string          // точная таблица назначений: egress и ingress
	RaftPort        int               // порт, который разрешён только RaftTarget; 0 — не проверяется
	RaftTarget      string            // npSelTarget узлов, которым разрешён RaftPort; "" — не разрешается никому
}

// checkDefaultDeny: default-deny namespace — пустой podSelector, ровно [Ingress, Egress], без правил.
func checkDefaultDeny(p npDoc, bad func(string, ...any)) {
	types := map[string]bool{}
	for _, ty := range p.Spec.PolicyTypes {
		types[ty] = true
	}
	if !npSelEmpty(p.Spec.PodSelector) {
		bad("default-deny: podSelector должен быть пустым (весь namespace)")
	}
	if len(types) != 2 || !types["Ingress"] || !types["Egress"] || len(p.Spec.PolicyTypes) != 2 {
		bad("default-deny: policyTypes должны быть ровно [Ingress, Egress], а не %v", p.Spec.PolicyTypes)
	}
	if len(p.Spec.Ingress) > 0 {
		bad("default-deny: правил быть не должно")
	}
}

// checkCNP проверяет одну CiliumNetworkPolicy по спецификации; возвращает ошибки и множество найденных назначений.
func checkCNP(c cnpDoc, s cnpSpec) (errs []string, dests map[string]bool) {
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	dests = map[string]bool{}
	hasFrom := false
	for _, w := range s.Want {
		if strings.HasPrefix(w, "from ") {
			hasFrom = true
		}
	}

	// 4. Общие поля CNP.
	if c.Metadata.Name != s.Name {
		bad("CNP: имя %q, нужно %s", c.Metadata.Name, s.Name)
	}
	if c.Metadata.Namespace != s.Namespace {
		bad("CNP: namespace %q, нужен %s", c.Metadata.Namespace, s.Namespace)
	}
	if len(c.Specs) > 0 {
		bad("CNP: specs запрещены")
	}
	if c.Spec.NodeSelector != nil {
		bad("CNP: nodeSelector запрещён")
	}
	if es := c.Spec.EndpointSelector; len(es.MatchExpressions) > 0 || npLabels(es.MatchLabels) != npLabels(s.Selector) {
		bad("CNP: endpointSelector должен быть ровно {%s}", npLabels(s.Selector))
	}
	if len(c.Spec.IngressDeny) > 0 || len(c.Spec.EgressDeny) > 0 {
		bad("CNP: ingressDeny и egressDeny запрещены")
	}
	if len(c.Spec.Ingress) > 0 && !hasFrom {
		bad("CNP: ingress запрещены")
	}
	if d := c.Spec.EnableDefaultDeny; d != nil {
		if d.Egress != nil && !*d.Egress {
			bad("CNP: enableDefaultDeny.egress: false запрещён")
		}
		if d.Ingress != nil && !*d.Ingress {
			bad("CNP: enableDefaultDeny.ingress: false запрещён")
		}
	}

	// checkPorts — порты и L7 одного правила (egress или ingress); targets — адресаты для таблицы назначений.
	checkPorts := func(id, kind string, targets []string, toPorts []cnpPortRule, isDNS bool, fqdn string) {
		for _, p := range toPorts {
			if len(p.Ports) == 0 {
				bad("%s: в toPorts нет ports", id)
			}
			sni := ""
			if kind == "fqdn" {
				if fqdn != "" {
					wild := false
					for _, n := range p.ServerNames {
						wild = wild || strings.Contains(n, "*")
					}
					switch {
					case wild:
						bad("%s: serverNames: шаблоны запрещены", id)
					case len(p.ServerNames) != 1 || p.ServerNames[0] != fqdn:
						bad("%s: serverNames обязателен и равен matchName %q, а не %q", id, fqdn, p.ServerNames)
					}
				}
				if len(p.ServerNames) == 1 {
					sni = p.ServerNames[0]
				}
			} else if len(p.ServerNames) > 0 {
				bad("%s: serverNames допустим только в правиле toFQDNs", id)
			}
			if p.Listener != nil || p.TerminatingTLS != nil || p.OriginatingTLS != nil {
				bad("%s: listener, terminatingTLS и originatingTLS запрещены", id)
			}
			for _, pt := range p.Ports {
				if !npRePort.MatchString(pt.Port) || atoiOr0(pt.Port) > 65535 {
					bad("%s: порт %q: нужно число 1–65535 без ведущих нулей", id, pt.Port)
				}
				if pt.EndPort != 0 {
					bad("%s: endPort запрещён", id)
				}
				switch {
				case pt.Protocol == "TCP" || pt.Protocol == "UDP":
				case pt.Protocol == "ANY" && pt.Port == "53" && isDNS:
				default:
					bad("%s: протокол %q порта %s недопустим (ANY — только 53 в правиле DNS, иначе TCP/UDP)", id, pt.Protocol, pt.Port)
				}
				if s.RaftPort != 0 && atoiOr0(pt.Port) == s.RaftPort {
					if s.RaftTarget == "" {
						bad("%s: порт %d (Raft) не разрешается", id, s.RaftPort)
					}
					for _, tgt := range targets {
						if s.RaftTarget != "" && (tgt != s.RaftTarget || (kind != "endpoints" && kind != "from")) {
							bad("%s: порт %d (Raft) только между узлами OpenBao", id, s.RaftPort)
						}
					}
				}
				if pt.Port != "53" && isDNS {
					bad("%s: в правиле DNS допустим только порт 53", id)
				}
				for _, tgt := range targets {
					dests[npDest{kind, tgt, pt.Protocol, atoiOr0(pt.Port), sni}.String()] = true
				}
			}
			// 9. L7.
			if p.Rules != nil {
				if !isDNS {
					bad("%s: L7 rules допустимы только в правиле к kube-dns", id)
				}
				if len(p.Rules.HTTP) > 0 || len(p.Rules.Kafka) > 0 || len(p.Rules.L7) > 0 || p.Rules.L7Proto != "" {
					bad("%s: L7 rules http/kafka/l7/l7proto запрещены, допустим только dns", id)
				}
			}
		}
	}

	// Множество FQDN из toFQDNs — для парности с DNS.
	fqdns := map[string]bool{}
	for _, r := range c.Spec.Egress {
		for _, f := range r.ToFQDNs {
			if f.MatchName != "" {
				fqdns[f.MatchName] = true
			}
		}
	}

	dnsRules := 0
	for i, r := range c.Spec.Egress {
		id := fmt.Sprintf("CNP egress[%d]", i)
		// 5. Тип назначения и запрещённые поля.
		n := 0
		for _, nonEmpty := range []bool{len(r.ToEndpoints) > 0, len(r.ToEntities) > 0, len(r.ToFQDNs) > 0} {
			if nonEmpty {
				n++
			}
		}
		if n != 1 {
			bad("%s: нужен ровно один из toEndpoints/toEntities/toFQDNs, найдено %d", id, n)
		}
		for name, used := range map[string]bool{
			"toCIDR": len(r.ToCIDR) > 0, "toCIDRSet": len(r.ToCIDRSet) > 0, "toServices": len(r.ToServices) > 0, "toGroups": len(r.ToGroups) > 0,
			"toNodes": len(r.ToNodes) > 0, "toRequires": len(r.ToRequires) > 0, "icmps": len(r.ICMPs) > 0, "authentication": r.Authentication != nil,
		} {
			if used {
				bad("%s: %s запрещён", id, name)
			}
		}
		if len(r.ToPorts) == 0 {
			bad("%s: toPorts обязателен и не пуст", id)
		}

		// 6. toEndpoints.
		isDNS := false
		var epTargets []string
		for _, sel := range r.ToEndpoints {
			tgt, problem := npSelTarget(sel, "toEndpoints")
			if problem != "" {
				bad("%s: %s", id, problem)
				continue
			}
			epTargets = append(epTargets, tgt)
			if tgt == npKubeDNS {
				isDNS = true
			}
		}
		if isDNS {
			dnsRules++
			if len(r.ToEndpoints) != 1 {
				bad("%s: правило DNS не должно содержать других назначений", id)
			}
		}
		// 7. toEntities.
		var entTargets []string
		for _, e := range r.ToEntities {
			if e != "kube-apiserver" {
				bad("%s: toEntities %q запрещён, разрешён только kube-apiserver", id, e)
				continue
			}
			entTargets = append(entTargets, e)
		}
		// 8. toFQDNs.
		var fqTargets []string
		for _, f := range r.ToFQDNs {
			switch {
			case f.MatchPattern != "":
				bad("%s: toFQDNs.matchPattern %q запрещён, только matchName", id, f.MatchPattern)
			case f.MatchName == "":
				bad("%s: toFQDNs без matchName", id)
			case f.MatchName != strings.ToLower(f.MatchName) || strings.Contains(f.MatchName, "*") || strings.HasSuffix(f.MatchName, ".") || !strings.Contains(f.MatchName, "."):
				bad("%s: toFQDNs.matchName %q: нужно имя в нижнем регистре, без *, без завершающей точки, с точкой", id, f.MatchName)
			default:
				fqTargets = append(fqTargets, f.MatchName)
			}
		}
		fqName := ""
		if len(r.ToFQDNs) > 1 {
			bad("%s: toFQDNs: одно имя на правило, иначе SNI не сопоставить", id)
		} else if len(fqTargets) == 1 {
			fqName = fqTargets[0]
		}
		switch {
		case len(r.ToFQDNs) > 0:
			checkPorts(id, "fqdn", fqTargets, r.ToPorts, false, fqName)
		case len(r.ToEntities) > 0:
			checkPorts(id, "entity", entTargets, r.ToPorts, false, "")
		default:
			checkPorts(id, "endpoints", epTargets, r.ToPorts, isDNS, "")
		}

		if isDNS {
			for _, p := range r.ToPorts {
				if p.Rules == nil || len(p.Rules.DNS) == 0 {
					bad("%s: у правила DNS rules.dns пуст (без него toFQDNs не узнает IP, а фильтра имён нет)", id)
					continue
				}
				seen := map[string]bool{}
				for _, d := range p.Rules.DNS {
					switch {
					case d.MatchName != "" && d.MatchPattern != "":
						bad("%s: dns-элемент с matchName и matchPattern одновременно", id)
					case d.MatchName != "":
						seen[d.MatchName] = true
						dests[npDest{Kind: "dns", Target: d.MatchName}.String()] = true
						if !fqdns[d.MatchName] && !s.DNSNames[d.MatchName] {
							bad("%s: dns matchName %q без парного toFQDNs", id, d.MatchName)
						}
					case d.MatchPattern == "*":
						bad("%s: dns matchPattern \"*\" разрешает все имена", id)
					case strings.Contains(d.MatchPattern, "**"):
						bad("%s: dns matchPattern %q: шаблоны с ** запрещены", id, d.MatchPattern)
					case d.MatchPattern != "":
						dests[npDest{Kind: "dns", Target: d.MatchPattern}.String()] = true
						if !s.DNSPatterns[d.MatchPattern] {
							if strings.Contains(strings.TrimSuffix(d.MatchPattern, ".svc.cluster.local"), "*") && !strings.HasSuffix(d.MatchPattern, ".svc.cluster.local") {
								bad("%s: dns matchPattern %q: * вне .svc.cluster.local запрещена", id, d.MatchPattern)
							} else {
								bad("%s: dns matchPattern %q не из разрешённых", id, d.MatchPattern)
							}
						}
					default:
						bad("%s: пустой элемент dns", id)
					}
				}
				for f := range fqdns {
					if !seen[f] {
						bad("%s: toFQDNs %q без парного matchName в rules.dns", id, f)
					}
				}
			}
		}
	}
	if dnsRules != 1 {
		bad("DNS-правило (toEndpoints kube-system/k8s-app=kube-dns) должно быть ровно одно, найдено %d", dnsRules)
	}

	// Ingress.
	for i, r := range c.Spec.Ingress {
		if !hasFrom {
			break
		}
		id := fmt.Sprintf("CNP ingress[%d]", i)
		for name, used := range map[string]bool{
			"fromEntities": len(r.FromEntities) > 0, "fromCIDR": len(r.FromCIDR) > 0, "fromCIDRSet": len(r.FromCIDRSet) > 0,
			"fromRequires": len(r.FromRequires) > 0, "fromGroups": len(r.FromGroups) > 0, "fromNodes": len(r.FromNodes) > 0,
			"icmps": len(r.ICMPs) > 0, "authentication": r.Authentication != nil,
		} {
			if used {
				bad("%s: %s запрещён (источник — только fromEndpoints с меткой namespace)", id, name)
			}
		}
		if len(r.FromEndpoints) == 0 {
			bad("%s: нужен fromEndpoints", id)
		}
		if len(r.ToPorts) == 0 {
			bad("%s: toPorts обязателен и не пуст", id)
		}
		var targets []string
		for _, sel := range r.FromEndpoints {
			tgt, problem := npSelTarget(sel, "fromEndpoints")
			if problem != "" {
				bad("%s: %s", id, problem)
				continue
			}
			targets = append(targets, tgt)
		}
		checkPorts(id, "from", targets, r.ToPorts, false, "")
	}

	// 10. Точная таблица назначений.
	want := map[string]bool{}
	for _, w := range s.Want {
		want[w] = true
	}
	var missing, extra []string
	for w := range want {
		if !dests[w] {
			missing = append(missing, w)
		}
	}
	for d := range dests {
		if !want[d] {
			extra = append(extra, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		bad("назначения CNP не совпадают с таблицей: не хватает %q, лишнее %q", missing, extra)
	}
	return errs, dests
}

func npJoin(errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

func atoiOr0(s string) int { n, _ := strconv.Atoi(s); return n }

func TestIntakeNetworkPolicy(t *testing.T) {
	nps, cnps := npLoadDir(t)
	ns, port, err := npAgentVault(readVault(t, "agent/aegis-intake.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkIntakeNetpols(nps, cnps, ns, port); err != nil {
		t.Fatal(err)
	}
}

// npMut — копия файлов манифестов и конфигурации агента, которую правит мутация.
type npMut struct {
	t              *testing.T
	netpol, cilium string
	agent          string
	values         string // server/openbao-ha.yaml (только для тестов OpenBao)
}

func (m *npMut) sub(dst *string, old, new string) {
	m.t.Helper()
	if c := strings.Count(*dst, old); c != 1 {
		m.t.Fatalf("фрагмент для мутации встречается %d раз (нужен 1): %q", c, old)
	}
	*dst = strings.Replace(*dst, old, new, 1)
}

func (m *npMut) cut(dst *string, from, to string) {
	m.t.Helper()
	i, j := strings.Index(*dst, from), strings.Index(*dst, to)
	if i < 0 || j < i {
		m.t.Fatalf("границы вырезания не найдены: %q … %q", from, to)
	}
	*dst = (*dst)[:i] + (*dst)[j:]
}

func TestIntakeNetworkPolicyNegativeCases(t *testing.T) {
	const (
		fqOR   = "- toFQDNs:\n        - matchName: openrouter.ai"
		dnsOR  = "              - matchName: openrouter.ai\n"
		dnsS3  = "              - matchName: storage.yandexcloud.net\n"
		dnsPat = `- matchPattern: "*.*.svc.cluster.local"`
		okPort = "      toPorts:\n        - ports:\n            - port: \"443\"\n              protocol: TCP\n"
		snOR   = "          serverNames:\n            - openrouter.ai\n"
		six    = "    # 6. OpenRouter"
	)
	cases := []struct {
		name, want string
		mutate     func(m *npMut)
	}{
		{"DNS matchPattern *", "разрешает все имена", func(m *npMut) { m.sub(&m.cilium, dnsPat, `- matchPattern: "*"`) }},
		{"DNS matchPattern **.", "**", func(m *npMut) { m.sub(&m.cilium, dnsPat, `- matchPattern: "**.yandexcloud.net"`) }},
		{"DNS matchPattern *.yandexcloud.net", "вне .svc.cluster.local", func(m *npMut) { m.sub(&m.cilium, dnsPat, `- matchPattern: "*.yandexcloud.net"`) }},
		{"DNS лишний example.com", "без парного toFQDNs", func(m *npMut) { m.sub(&m.cilium, dnsS3, dnsS3+"              - matchName: example.com\n") }},
		{"toFQDNs с matchPattern", "matchPattern", func(m *npMut) { m.sub(&m.cilium, fqOR, "- toFQDNs:\n        - matchPattern: openrouter.ai") }},
		{"toFQDNs api.github.com", "без парного matchName", func(m *npMut) { m.sub(&m.cilium, fqOR, "- toFQDNs:\n        - matchName: api.github.com") }},
		{"из DNS удалён openrouter.ai", "без парного matchName", func(m *npMut) { m.sub(&m.cilium, dnsOR, "") }},
		{"удалено DNS-правило", "DNS-правило", func(m *npMut) { m.cut(&m.cilium, "    # 1. DNS", "    # 2.") }},
		{"rules.dns пуст", "rules.dns пуст", func(m *npMut) {
			m.cut(&m.cilium, dnsOR, "    # 2.")
			m.sub(&m.cilium, "            dns:\n", "            dns: []\n")
		}},
		{"rules.http на OpenRouter", "L7", func(m *npMut) {
			m.sub(&m.cilium, fqOR+"\n"+okPort, fqOR+"\n"+okPort+"          rules:\n            http:\n              - method: GET\n")
		}},
		{"toEntities world", "toEntities", func(m *npMut) { m.sub(&m.cilium, "        - kube-apiserver\n", "        - world\n") }},
		{"toEntities cluster", "toEntities", func(m *npMut) { m.sub(&m.cilium, "        - kube-apiserver\n", "        - cluster\n") }},
		{"toCIDR 0.0.0.0/0", "toCIDR", func(m *npMut) {
			m.sub(&m.cilium, six, "    - toCIDR: [\"0.0.0.0/0\"]\n      toPorts: [{ports: [{port: \"443\", protocol: TCP}]}]\n"+six)
		}},
		{"toServices", "toServices", func(m *npMut) {
			m.sub(&m.cilium, six, "    - toServices: [{k8sService: {serviceName: x, namespace: y}}]\n      toPorts: [{ports: [{port: \"443\", protocol: TCP}]}]\n"+six)
		}},
		{"toEndpoints пустой селектор", "пустой селектор", func(m *npMut) {
			m.sub(&m.cilium, six, "    - toEndpoints: [{}]\n      toPorts: [{ports: [{port: \"443\", protocol: TCP}]}]\n"+six)
		}},
		{"toEndpoints без метки namespace", "метки namespace", func(m *npMut) {
			m.sub(&m.cilium, "            k8s:io.kubernetes.pod.namespace: monitoring\n            app.kubernetes.io/name: alertmanager", "            app.kubernetes.io/name: alertmanager")
		}},
		{"toPorts удалён", "toPorts", func(m *npMut) {
			m.sub(&m.cilium, "app.kubernetes.io/name: prometheus\n      toPorts:\n        - ports:\n            - port: \"9090\"\n              protocol: TCP\n", "app.kubernetes.io/name: prometheus\n")
		}},
		{"порт 0", "порт", func(m *npMut) { m.sub(&m.cilium, `port: "9090"`, `port: "0"`) }},
		{"ANY на 443", "ANY", func(m *npMut) {
			m.sub(&m.cilium, "storage.yandexcloud.net\n"+okPort, "storage.yandexcloud.net\n      toPorts:\n        - ports:\n            - port: \"443\"\n              protocol: ANY\n")
		}},
		{"endPort", "endPort", func(m *npMut) {
			m.sub(&m.cilium, "port: \"9093\"\n              protocol: TCP\n", "port: \"9093\"\n              endPort: 9094\n              protocol: TCP\n")
		}},
		{"enableDefaultDeny.egress false", "enableDefaultDeny", func(m *npMut) {
			m.sub(&m.cilium, "spec:\n  endpointSelector:", "spec:\n  enableDefaultDeny:\n    egress: false\n  endpointSelector:")
		}},
		{"endpointSelector пуст", "endpointSelector", func(m *npMut) {
			m.sub(&m.cilium, "  endpointSelector:\n    matchLabels:\n      app: aegis-intake\n", "  endpointSelector: {}\n")
		}},
		{"лишнее правило OpenBao на 8201", "8201", func(m *npMut) {
			m.cilium += "    - toEndpoints:\n        - matchLabels:\n            k8s:io.kubernetes.pod.namespace: vault\n            app.kubernetes.io/name: openbao\n            component: server\n      toPorts:\n        - ports:\n            - port: \"8201\"\n              protocol: TCP\n"
		}},
		{"в агенте другой namespace", "ns=other", func(m *npMut) { m.sub(&m.agent, "vault.vault.svc", "vault.other.svc") }},
		{"egress в NetworkPolicy к kube-dns", "egress", func(m *npMut) {
			m.netpol += "  egress:\n    - to:\n        - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}\n          podSelector: {matchLabels: {k8s-app: kube-dns}}\n      ports: [{port: 53, protocol: UDP}]\n"
		}},
		{"удалён default-deny", "default-deny", func(m *npMut) { m.netpol = m.netpol[strings.Index(m.netpol, "---\n")+4:] }},
		{"default-deny без Egress", "policyTypes", func(m *npMut) { m.sub(&m.netpol, "policyTypes: [Ingress, Egress]", "policyTypes: [Ingress]") }},
		{"metrics открыт для всего monitoring", "podSelector", func(m *npMut) {
			m.sub(&m.netpol, "          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: prometheus\n", "")
		}},
		{"документ CiliumClusterwideNetworkPolicy", "недопустимый kind", func(m *npMut) {
			m.cilium += "---\napiVersion: cilium.io/v2\nkind: CiliumClusterwideNetworkPolicy\nmetadata: {name: x}\nspec: {}\n"
		}},
		{"порт числом", "нужна строка в кавычках", func(m *npMut) { m.sub(&m.cilium, `port: "9090"`, `port: 9090`) }},
		{"enableDefaultDeny.ingress false", "enableDefaultDeny.ingress", func(m *npMut) {
			m.sub(&m.cilium, "spec:\n  endpointSelector:", "spec:\n  enableDefaultDeny:\n    ingress: false\n  endpointSelector:")
		}},
		{"metadata.uid в CNP", "metadata.uid запрещено", func(m *npMut) {
			m.sub(&m.cilium, "  name: aegis-intake-egress\n", "  name: aegis-intake-egress\n  uid: x\n")
		}},
		{"metadata.resourceVersion в NetworkPolicy", "metadata.resourceVersion запрещено", func(m *npMut) {
			m.sub(&m.netpol, "  name: aegis-system-default-deny\n", "  name: aegis-system-default-deny\n  resourceVersion: \"1\"\n")
		}},
		{"удалён serverNames у OpenRouter", "serverNames обязателен", func(m *npMut) { m.sub(&m.cilium, snOR, "") }},
		{"serverNames *.openrouter.ai", "шаблоны запрещены", func(m *npMut) {
			m.sub(&m.cilium, snOR, "          serverNames:\n            - \"*.openrouter.ai\"\n")
		}},
		{"serverNames *", "шаблоны запрещены", func(m *npMut) { m.sub(&m.cilium, snOR, "          serverNames:\n            - \"*\"\n") }},
		{"serverNames чужого правила", "равен matchName", func(m *npMut) {
			m.sub(&m.cilium, snOR, "          serverNames:\n            - storage.yandexcloud.net\n")
		}},
		{"serverNames с лишним именем", "равен matchName", func(m *npMut) {
			m.sub(&m.cilium, snOR, snOR+"            - evil.example\n")
		}},
		{"serverNames на kube-apiserver", "только в правиле toFQDNs", func(m *npMut) {
			m.sub(&m.cilium, "              protocol: TCP\n    # 6. OpenRouter", "              protocol: TCP\n          serverNames:\n            - kubernetes.default.svc\n    # 6. OpenRouter")
		}},
		{"два matchName в toFQDNs", "одно имя на правило", func(m *npMut) { m.sub(&m.cilium, fqOR, fqOR+"\n        - matchName: example.com") }},
		{"ingress fromEntities world в CNP intake", "ingress запрещены", func(m *npMut) {
			m.cilium += "  ingress:\n    - fromEntities: [world]\n      toPorts: [{ports: [{port: \"8200\", protocol: TCP}]}]\n"
		}},
		{"опечатка в поле toFQDN", "toFQDN", func(m *npMut) { m.sub(&m.cilium, fqOR, "- toFQDN:\n        - matchName: openrouter.ai") }},
	}
	files := npReadDir(t)
	agent := readVault(t, "agent/aegis-intake.json")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &npMut{t: t, netpol: string(files["networkpolicy.yaml"]), cilium: string(files["cilium-egress.yaml"]), agent: string(agent)}
			tc.mutate(m)
			nps, cnps, err := npParseAll(map[string][]byte{"networkpolicy.yaml": []byte(m.netpol), "cilium-egress.yaml": []byte(m.cilium)})
			if err == nil {
				var ns string
				var port int
				if ns, port, err = npAgentVault([]byte(m.agent)); err == nil {
					err = checkIntakeNetpols(nps, cnps, ns, port)
				}
			}
			if err == nil {
				t.Fatal("мутация не обнаружена")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ошибка не называет нарушение %q: %v", tc.want, err)
			}
		})
	}
}

// Метки и аннотации на объектах политик допустимы.
func TestNetpolMetadataLabelsAllowed(t *testing.T) {
	const old, meta = "  namespace: aegis-system\nspec:", "  namespace: aegis-system\n  labels:\n    app.kubernetes.io/part-of: aegis\n  annotations:\n    note: x\nspec:"
	files := npReadDir(t)
	mut := map[string][]byte{}
	for _, n := range []string{"networkpolicy.yaml", "cilium-egress.yaml"} {
		src := string(files[n])
		if !strings.Contains(src, old) {
			t.Fatalf("%s: нет фрагмента metadata для подстановки", n)
		}
		mut[n] = []byte(strings.ReplaceAll(src, old, meta))
	}
	nps, cnps, err := npParseAll(mut)
	if err != nil {
		t.Fatal(err)
	}
	ns, port, err := npAgentVault(readVault(t, "agent/aegis-intake.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkIntakeNetpols(nps, cnps, ns, port); err != nil {
		t.Fatal(err)
	}
	if nps[0].Metadata.Labels["app.kubernetes.io/part-of"] != "aegis" {
		t.Fatal("метки не разобраны")
	}
}

func TestNetpolDirEntries(t *testing.T) {
	for _, c := range []struct {
		name  string
		isDir bool
		ok    bool
	}{
		{"networkpolicy.yaml", false, true},
		{"cilium-egress.yaml", false, true},
		{"README.md", false, true},
		{"dev", true, true},
		{"allow-all.yml", false, false},
		{"allow-all.json", false, false},
		{"allow-all.YAML", false, false},
		{"notes.txt", false, false},
		{".hidden.yaml", false, false},
		{"kustomization", true, false},
	} {
		err := npDirEntryErr(c.name, c.isDir)
		if (err == nil) != c.ok {
			t.Errorf("%s (каталог=%v): ошибка %v, ожидалось допустимо=%v", c.name, c.isDir, err, c.ok)
		}
	}
	// Реальные каталоги манифестов не содержат посторонних файлов.
	npReadDirAt(t, intakeDeployDir)
	npReadDirAt(t, openbaoNetDir)
}
