// Package kube — read-only источник данных Kubernetes без client-go: собственный REST-клиент (только GET) к API-серверу
// с токеном ServiceAccount. Нужные права — ClusterRole только get/list (docs/04-operations/intake-deploy.md); secrets и exec
// в роль не входят. Разбор ответов нестрогий (внешний API): берутся только нужные поля; message событий, аннотации
// ресурсов (кроме одной, заданной в конфигурации) и тексты коммитов в доменные типы не попадают вообще.
package kube

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/limpjungle/aegis3311/internal/intake"
	"github.com/limpjungle/aegis3311/internal/intake/httpget"
)

type Client struct {
	c      *httpget.Client
	author string // аннотация ReplicaSet с автором деплоя
}

// New: src — адрес API-сервера, CA и аннотация автора; tokenFile — AEGIS_KUBE_TOKEN_FILE (обязателен).
func New(src intake.KubeSource, tokenFile string, timeout time.Duration) (*Client, error) {
	if tokenFile == "" {
		return nil, errors.New("kube: нужен файл токена ServiceAccount")
	}
	c, err := httpget.New(src.APIURL, src.CAFile, tokenFile, nil, httpget.MaxBytesKube, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{c: c, author: src.AuthorAnnotation}, nil
}

type meta struct {
	Name              string            `json:"name"`
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
	OwnerReferences   []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"ownerReferences"`
}

type labelSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"` // In | NotIn | Exists | DoesNotExist
	Values   []string `json:"values"`
}

type selector struct {
	MatchLabels      map[string]string          `json:"matchLabels"`
	MatchExpressions []labelSelectorRequirement `json:"matchExpressions"`
}

// Правила имён меток Kubernetes: допустимые символы исключают `, ( ) ! = пробел`, поэтому инъекция в labelSelector
// через ключ или значение невозможна.
var (
	lblNameRe   = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
	lblPrefixRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	lblValueRe  = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)
)

// validKey: [prefix/]name; префикс непуст, не длиннее 253 байт.
func validKey(k string) bool {
	if i := strings.IndexByte(k, '/'); i >= 0 {
		p := k[:i]
		if p == "" || len(p) > 253 || !lblPrefixRe.MatchString(p) {
			return false
		}
		k = k[i+1:]
	}
	return lblNameRe.MatchString(k)
}

func validValue(v string) bool { return lblValueRe.MatchString(v) }

func badSelector() error { return &httpget.Error{Kind: "decode"} }

// labelSelector строит значение labelSelector (требования соединяются по И). Пустой селектор (выбрал бы весь
// namespace), неизвестный оператор и некорректные ключ/значение — ошибка decode (fail-closed).
func (s selector) labelSelector() (string, error) {
	if len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 {
		return "", badSelector()
	}
	var reqs []string
	for k, v := range s.MatchLabels {
		if !validKey(k) || !validValue(v) {
			return "", badSelector()
		}
		reqs = append(reqs, k+"="+v)
	}
	for _, e := range s.MatchExpressions {
		if !validKey(e.Key) {
			return "", badSelector()
		}
		switch e.Operator {
		case "In", "NotIn":
			if len(e.Values) == 0 {
				return "", badSelector()
			}
			vs := append([]string(nil), e.Values...)
			for _, v := range vs {
				if v == "" || !validValue(v) {
					return "", badSelector()
				}
			}
			sort.Strings(vs)
			vs = slices.Compact(vs)
			op := "in"
			if e.Operator == "NotIn" {
				op = "notin"
			}
			reqs = append(reqs, e.Key+" "+op+" ("+strings.Join(vs, ",")+")")
		case "Exists", "DoesNotExist":
			if len(e.Values) != 0 {
				return "", badSelector()
			}
			if e.Operator == "Exists" {
				reqs = append(reqs, e.Key)
			} else {
				reqs = append(reqs, "!"+e.Key)
			}
		default:
			return "", badSelector()
		}
	}
	sort.Strings(reqs)
	return strings.Join(reqs, ","), nil
}

// matches — семантика селектора Kubernetes на метках l. Пустой селектор и неизвестный оператор не совпадают ни с чем.
func (s selector) matches(l map[string]string) bool {
	if len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 {
		return false
	}
	for k, v := range s.MatchLabels {
		if got, ok := l[k]; !ok || got != v {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		got, has := l[e.Key]
		switch e.Operator {
		case "In":
			if !has || !slices.Contains(e.Values, got) {
				return false
			}
		case "NotIn":
			if has && slices.Contains(e.Values, got) {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// andLabel дописывает к labelSelector пару k=v (пара валидируется, плохая — decode).
func andLabel(ls, k, v string) (string, error) {
	if !validKey(k) || !validValue(v) {
		return "", badSelector()
	}
	return ls + "," + k + "=" + v, nil
}

type workload struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Selector selector `json:"selector"`
		Template struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
		} `json:"template"` // только для сопоставления с PDB
	} `json:"spec"`
	Status struct {
		Replicas int `json:"replicas"`
	} `json:"status"`
}

func (c *Client) workload(ctx context.Context, svc intake.ServiceConfig) (workload, error) {
	path := "/apis/apps/v1/namespaces/" + url.PathEscape(svc.Namespace) + "/deployments/" + url.PathEscape(svc.Workload.Name)
	if svc.Workload.Kind == "Rollout" {
		path = "/apis/argoproj.io/v1alpha1/namespaces/" + url.PathEscape(svc.Namespace) + "/rollouts/" + url.PathEscape(svc.Workload.Name)
	}
	var w workload
	err := c.c.GetJSON(ctx, path, nil, &w)
	return w, err
}

type pod struct {
	Metadata meta `json:"metadata"`
	Status   struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			ImageID   string `json:"imageID"`
			LastState struct {
				Terminated *struct {
					Reason     string    `json:"reason"`
					FinishedAt time.Time `json:"finishedAt"`
				} `json:"terminated"`
			} `json:"lastState"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

// pods читает поды по labelSelector ls (пустой — ошибка decode: иначе весь namespace). truncated — сработал потолок.
func (c *Client) pods(ctx context.Context, ns, ls string) ([]pod, bool, error) {
	if ls == "" {
		return nil, false, badSelector()
	}
	return list[pod](ctx, c.c, "/api/v1/namespaces/"+url.PathEscape(ns)+"/pods", url.Values{"labelSelector": {ls}}, capPods)
}
