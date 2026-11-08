package llmrouter

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// Тесты итерации 4: удаление только цепочки аудита при живом store (есть учёт) — якорь и halt chain_lost.

// usedRigChainRemoved: роутер с расходом в store; цепочка удалена после остановки процесса.
func usedRigChainRemoved(t *testing.T) (*stateRig, int64) {
	t.Helper()
	rg := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
	if res, err := rg.route("inc-1"); err != nil || res.Outcome != "sent" {
		t.Fatalf("подготовка: %v %+v", err, res)
	}
	spent := spentTotal(rg.fst.Snapshot())
	if spent == 0 {
		t.Fatal("подготовка: расход не записан в store")
	}
	rg.closeAll()
	if err := os.Remove(rg.chain); err != nil {
		t.Fatal(err)
	}
	return rg, spent
}

func TestChainDeletedWithLiveStoreHalts(t *testing.T) {
	rg, spent := usedRigChainRemoved(t)
	rg.boot()
	if st := rg.r.State(); !st.Halted || st.HaltReason != "chain_lost" {
		t.Fatalf("после удаления цепочки: %+v, ожидается halt chain_lost", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:chain_lost"}) {
		t.Errorf("события в новой цепочке: %v", got)
	}
	if got := spentTotal(rg.fst.Snapshot()); got != spent {
		t.Errorf("бюджет не сохранён: %d, было %d", got, spent)
	}
	if res, err := rg.route("inc-1"); err != nil || res.Outcome != "not_sent" || res.Reason != "halted" {
		t.Errorf("запрос при chain_lost: %v %+v", err, res)
	}
	if err := rg.r.Resume(context.Background(), "op-1"); err != nil {
		t.Fatal(err)
	}
	if st := rg.r.State(); st.Halted {
		t.Errorf("после Resume роутер остановлен: %+v", st)
	}
	if got := spentTotal(rg.fst.Snapshot()); got != spent {
		t.Errorf("бюджет после Resume: %d, было %d", got, spent)
	}
	// Рестарт: цепочка непуста, повторной остановки нет.
	rg.closeAll()
	rg.boot()
	if st := rg.r.State(); st.Halted {
		t.Errorf("после рестарта: %+v", st)
	}
}

// Крах между intent якоря и событием: остановка не теряется.
func TestChainLostHaltSurvivesCrash(t *testing.T) {
	for _, kind := range []string{"state_created", "router_halted"} {
		t.Run("до "+kind, func(t *testing.T) {
			rg, spent := usedRigChainRemoved(t)
			if hit := rg.crashBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: kind} }); !hit {
				t.Fatal("крах не произошёл")
			}
			rg.closeAll()
			rg.boot()
			if st := rg.r.State(); !st.Halted || st.HaltReason != "chain_lost" {
				t.Errorf("после краха и рестарта: %+v, ожидается chain_lost", st)
			}
			if got := spentTotal(rg.fst.Snapshot()); got != spent {
				t.Errorf("бюджет: %d, было %d", got, spent)
			}
			if got := chainKinds(t, rg.chain, rg.keys); len(got) == 0 || got[0] != "state_created:store_created" {
				t.Errorf("события: %v, якорь первый", got)
			}
		})
	}
}

// Первый старт (store и цепочка пусты): якорь без остановки.
func TestFirstStartNoChainLost(t *testing.T) {
	rg := bareStateRig(t, fakeProviders(newProviderCounts(), nil))
	rg.boot()
	if st := rg.r.State(); st.Halted {
		t.Errorf("первый старт остановлен: %+v", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created"}) {
		t.Errorf("события: %v", got)
	}
}
