package killswitch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

// RenewSigSchema — схема объекта с подписью renewer'а, который renewer'ы передают друг другу через S3.
const RenewSigSchema = "aegisops/kill-switch-renew-sig/v1"

// RenewSig — подпись документа часового слота одним renewer'ом.
type RenewSig struct {
	Schema        string    `json:"schema"`
	Slot          string    `json:"slot"` // начало слота, RFC 3339 UTC
	ContentSHA256 string    `json:"content_sha256"`
	Signature     Signature `json:"signature"`
}

// RenewConfig — параметры продления.
type RenewConfig struct {
	Slot   time.Duration // 1h
	TTL    time.Duration // 6h (на учении 5m)
	Prefix string        // renew/
}

// ChannelIO — канал, в который renewer читает и публикует.
type ChannelIO interface {
	Read(ctx context.Context) ([]byte, error)
	Publish(ctx context.Context, doc []byte) error
	Name() string
}

// SigStore — хранилище подписей renewer'ов (S3).
type SigStore interface {
	Put(ctx context.Context, key string, b []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// RenewResult — итог Renew. Action: published | waiting_peer | up_to_date.
type RenewResult struct {
	Action    string   `json:"action"`
	Slot      string   `json:"slot"`
	DocSHA256 string   `json:"doc_sha256,omitempty"`
	Signers   []string `json:"signers,omitempty"`
}

// SlotDocument — детерминированный документ слота: все renewer'ы получают одни и те же байты и подписывают их независимо.
func SlotDocument(now time.Time, slot, ttl time.Duration) Document {
	return Document{Schema: DocSchema, Clusters: []string{}, Actions: []string{},
		IssuedAt: now.UTC().Truncate(slot).Format("2006-01-02T15:04:05Z"), TTL: ttl.String(), Issuer: "renewer", Signatures: []Signature{}}
}

// isNotFound: подписи пира пока нет. S3 без права ListBucket отвечает 403 на несуществующий ключ, поэтому 403 — то же, что 404.
func isNotFound(err error) bool {
	var k kinder
	return errors.As(err, &k) && (k.ErrKind() == "http_404" || k.ErrKind() == "http_403")
}

// Renew продлевает подтверждение «не остановлен». Отказывается (ошибка), если любой канал не читается, в любом из
// них stop-эффект (даже с одной подписью) или документ не разбирается, если ключ me не renewer или подпись коллеги
// не сходится с нашим документом. Первый renewer только кладёт подпись (waiting_peer); второй собирает документ с двумя
// подписями и публикует его в каналы, где issued_at старше начала слота. Повтор идемпотентен.
func Renew(ctx context.Context, now time.Time, cfg RenewConfig, me audit.Signer, keys Keyring, chans []ChannelIO, sigs SigStore, o ParseOptions) (RenewResult, error) {
	self, ok := keys[me.KeyID()]
	if !ok || self.Role != RoleRenewer {
		return RenewResult{}, fmt.Errorf("renew: ключ %s не принадлежит роли renewer", me.KeyID())
	}
	if cfg.Slot <= 0 || cfg.TTL < minTTL || cfg.TTL > maxTTL || cfg.Prefix == "" {
		return RenewResult{}, errors.New("renew: некорректные slot, ttl или prefix")
	}
	doc := SlotDocument(now, cfg.Slot, cfg.TTL)
	slotStart, _ := time.Parse(time.RFC3339, doc.IssuedAt)
	res := RenewResult{Slot: doc.IssuedAt}
	var stale []ChannelIO
	for _, ch := range chans {
		raw, err := ch.Read(ctx)
		var k kinder
		if err != nil && errors.As(err, &k) && (k.ErrKind() == "http_404" || k.ErrKind() == "no_document") {
			stale = append(stale, ch) // канал пуст (нет объекта или ConfigMap без document): stop в нём нет
			continue
		}
		if err != nil {
			return res, fmt.Errorf("renew: канал %s не читается: %w", ch.Name(), err)
		}
		v, err := Parse(raw, keys, o)
		if err != nil {
			return res, fmt.Errorf("renew: канал %s: %w", ch.Name(), err)
		}
		if v.Doc.Global || len(v.Doc.Clusters) > 0 || len(v.Doc.Actions) > 0 {
			return res, fmt.Errorf("renew: в канале %s действует stop (%s): продление отказано, снимает только release двух дежурных", ch.Name(), v.SHA256)
		}
		if v.IssuedAt.Before(slotStart) {
			stale = append(stale, ch)
		}
	}
	if len(stale) == 0 {
		res.Action = "up_to_date"
		return res, nil
	}
	content, _ := Content(doc)
	contentSHA := sha256Hex(content)
	mine, err := SignatureFor(doc, me, self.Issuer)
	if err != nil {
		return res, err
	}
	key := func(id string) string { return cfg.Prefix + doc.IssuedAt + "/" + id + ".json" }
	b, _ := json.Marshal(RenewSig{Schema: RenewSigSchema, Slot: doc.IssuedAt, ContentSHA256: contentSHA, Signature: mine})
	if err := sigs.Put(ctx, key(me.KeyID()), b); err != nil {
		return res, fmt.Errorf("renew: сохранение подписи: %w", err)
	}
	full, err := AddSignature(doc, mine)
	if err != nil {
		return res, err
	}
	var peers []string
	for id, k := range keys {
		if k.Role == RoleRenewer && id != me.KeyID() {
			peers = append(peers, id)
		}
	}
	sort.Strings(peers)
	for _, id := range peers {
		raw, err := sigs.Get(ctx, key(id))
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return res, fmt.Errorf("renew: чтение подписи %s: %w", id, err)
		}
		var rs RenewSig
		if err := strictjson.Decode(raw, &rs); err != nil {
			return res, fmt.Errorf("renew: подпись %s не разбирается: %w", id, err)
		}
		if rs.Schema != RenewSigSchema || rs.Slot != doc.IssuedAt || rs.ContentSHA256 != contentSHA || rs.Signature.KeyID != id {
			return res, fmt.Errorf("renew: подпись %s не сходится с документом слота по content_sha256", id)
		}
		if full, err = AddSignature(full, rs.Signature); err != nil {
			return res, err
		}
	}
	v, err := Parse(Marshal(full), keys, o)
	if err != nil {
		return res, fmt.Errorf("renew: собранный документ: %w", err)
	}
	if v.Tainted {
		return res, errors.New("renew: подпись коллеги не прошла проверку")
	}
	res.DocSHA256, res.Signers = v.SHA256, v.SignerIssuers()
	if v.Confirmation("") == "none" {
		res.Action = "waiting_peer"
		return res, nil
	}
	pub := Marshal(full)
	for _, ch := range stale {
		if err := ch.Publish(ctx, pub); err != nil {
			return res, fmt.Errorf("renew: публикация в %s: %w", ch.Name(), err)
		}
	}
	res.Action = "published"
	return res, nil
}
