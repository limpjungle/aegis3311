package kube

import (
	"context"
	"net/url"
	"regexp"
	"strconv"

	"github.com/limpjungle/aegis3311/internal/intake"
)

var digestRe = regexp.MustCompile(`sha256:([0-9a-f]{64})`)

type replicaSet struct {
	Metadata meta `json:"metadata"`
}

func revisionKey(kind string) string {
	if kind == "Rollout" {
		return "rollout.argoproj.io/revision"
	}
	return "deployment.kubernetes.io/revision"
}

// replicaSets возвращает ReplicaSet'ы workload'а, использованный labelSelector и признак усечения листа.
func (c *Client) replicaSets(ctx context.Context, svc intake.ServiceConfig, w workload) ([]replicaSet, string, bool, error) {
	ls, err := w.Spec.Selector.labelSelector()
	if err != nil {
		return nil, "", false, err
	}
	items, tr, err := list[replicaSet](ctx, c.c, "/apis/apps/v1/namespaces/"+url.PathEscape(svc.Namespace)+"/replicasets", url.Values{"labelSelector": {ls}}, capReplicaSets)
	return items, ls, tr, err
}

// LastDeploy: ReplicaSet с наибольшей ревизией; время — creationTimestamp, digest образа — из imageID пода этого
// ReplicaSet (нет подов — "unknown"), автор — из аннотации, заданной в конфигурации (нет — "unknown").
func (c *Client) LastDeploy(ctx context.Context, svc intake.ServiceConfig) (*intake.Deploy, error) {
	w, err := c.workload(ctx, svc)
	if err != nil {
		return nil, err
	}
	l, ls, rsTr, err := c.replicaSets(ctx, svc, w)
	if err != nil {
		return nil, err
	}
	key, best, bestRev := revisionKey(svc.Workload.Kind), -1, -1
	for i, rs := range l {
		if rev, err := strconv.Atoi(rs.Metadata.Annotations[key]); err == nil && rev > bestRev {
			best, bestRev = i, rev
		}
	}
	if best < 0 {
		return nil, truncErr(rsTr)
	}
	rs := l[best].Metadata
	d := &intake.Deploy{Revision: bestRev, ImageDigest: "unknown", AuthorID: "unknown", At: rs.CreationTimestamp.UTC()}
	if c.author != "" {
		if a := rs.Annotations[c.author]; a != "" {
			d.AuthorID = a
		}
	}
	if h := rs.Labels["pod-template-hash"]; h != "" {
		sel, err := andLabel(ls, "pod-template-hash", h)
		if err != nil { // невалидный хеш: digest не ищем
			return d, truncErr(rsTr)
		}
		pods, _, err := c.pods(ctx, svc.Namespace, sel) // усечение не важно: нужен любой под с digest'ом
		if err != nil {
			return nil, err
		}
		for _, p := range pods {
			for _, cs := range p.Status.ContainerStatuses {
				if m := digestRe.FindStringSubmatch(cs.ImageID); m != nil {
					d.ImageDigest = "sha256:" + m[1][:16]
					return d, truncErr(rsTr)
				}
			}
		}
	}
	return d, truncErr(rsTr)
}
