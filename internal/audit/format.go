package audit

import (
	"errors"
	"regexp"
	"sort"
)

// ChainFormat — уровень формата цепочки, который понимает сборка. История:
//
//	1 — decision-record/v1 и checkpoint;
//	2 — router-event/v1 и блок intake в decision record;
//	3 — killswitch-event/v1 (поле bootstrap), блок kill_switch в decision record, intake.source = replay.snapshot;
//	4 — router_halted.reason = egress_canary, llm.reason = egress_canary (not_sent).
//
// Новое поле, новая схема записи или новое значение перечисления, отвергаемое старой сборкой, повышает уровень. Порядок развёртывания: сначала верификаторы (aegis-audit и всё,
// что вызывает Verify), потом писатели. Писатель уровня N на той же цепочке не откатывается к сборке ниже N: она
// не пройдёт собственную проверку при открытии (OpenWriter строг).
const ChainFormat = 4

// ErrNewerFormat — цепочка содержит запись, которую эта сборка не понимает: неизвестную схему aegisops/* или поле,
// которого нет в известной схеме. Скорее всего, запись сделана более новой сборкой.
var ErrNewerFormat = errors.New("цепочка содержит записи формата новее этой сборки")

// aegisSchemaRe — форма имени схемы проекта: только такие схемы считаются «более новыми», а не мусором.
var aegisSchemaRe = regexp.MustCompile(`^aegisops/[a-z0-9-]+/v[0-9]+$`)

// SchemaFromProject — имя схемы имеет форму схем проекта (aegisops/<имя>/v<N>): такая неизвестная схема — запись
// новее сборки, а не мусор.
func SchemaFromProject(s string) bool { return aegisSchemaRe.MatchString(s) }

// KnownSchemas — схемы записей цепочки, которые понимает сборка (отсортированы).
func KnownSchemas() []string {
	s := []string{RecordSchema, RouterEventSchema, KillSwitchEventSchema}
	sort.Strings(s)
	return s
}
