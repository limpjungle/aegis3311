#!/usr/bin/env python3
"""Тесты формата ответа v2 и метрики decision_agreement (без сети). Запуск: python3 -m unittest -v test_format_v2"""
import json
import math
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generate  # noqa: E402
import score  # noqa: E402
import selftest  # noqa: E402


def ans(root="pool_undersized", a_type="pgbouncer.resize_pool", params=None, fmt="v2", cls="RB-001"):
    p = selftest.blank(fmt)
    p.update(params or {})
    return selftest.answer(cls, root, a_type, p)


class TestValidateFormats(unittest.TestCase):
    def test_v1_and_v2_are_valid(self):
        self.assertEqual(score.validate(ans(fmt="v1")), [])
        self.assertEqual(score.validate(ans(fmt="v2")), [])

    def test_mixed_or_unknown_params_rejected(self):
        a = ans(fmt="v2")
        a["action"]["params"]["new_pool_size"] = 40  # ключ v1 в ответе v2
        self.assertTrue(score.validate(a))
        a = ans(fmt="v2")
        del a["action"]["params"]["reason"]
        self.assertTrue(score.validate(a))

    def test_v2_enum_checked(self):
        self.assertTrue(score.validate(ans(a_type="workload.restart", params={"scope": "cluster"})))


class TestDecisionAgreement(unittest.TestCase):
    def setUp(self):
        self.cases = generate.build("dev", generate.DEFAULT_SEED["dev"], "v2")[:3]

    def rows(self, answers):
        return [{"id": c["id"], "answer": a} for c, a in zip(self.cases, answers)]

    def test_same_decision_different_choice_params(self):
        ref = self.rows([ans(a_type="workload.restart", params={"scope": "pod", "pod_name": "p-1"})] * 3)
        pred = self.rows([ans(a_type="workload.restart", params={"scope": "deployment"})] * 3)
        rows = score.score(self.cases, pred, ref)
        self.assertTrue(all(r["decision_agreement"] for r in rows))
        self.assertFalse(any(r["agreement"] for r in rows))

    def test_different_type_or_root_breaks_decision_agreement(self):
        ref = self.rows([ans()] * 3)
        pred = self.rows([ans(a_type="recommend"), ans(root="db_slow_queries"), ans()])
        got = [r["decision_agreement"] for r in score.score(self.cases, pred, ref)]
        self.assertEqual(got, [False, False, True])

    def test_metric_in_aggregate(self):
        ref = self.rows([ans()] * 3)
        agg = score.aggregate(score.score(self.cases, ref, ref))
        self.assertEqual(agg["all:all"]["decision_agreement"]["p"], 1.0)


class TestStepRules(unittest.TestCase):
    def test_step_values_within_v1_bounds(self):
        for cur in range(2, 40):
            for declared in range(1, cur + 1):
                for mx in range(cur, cur * 6 + 1, 3):
                    asc = {"current_min": cur, "declared_min": declared, "max": mx}
                    if cur + 1 <= min(mx, 2 * cur):
                        v = generate.step_scale_out(asc)
                        self.assertTrue(cur + 1 <= v <= min(mx, 2 * cur), (asc, v))
                    lo = max(declared, math.ceil(cur * 0.5))
                    if lo <= cur - 1:
                        v = generate.step_scale_in(asc)
                        self.assertTrue(lo <= v <= cur - 1, (asc, v))
        for pool in (5, 20, 33, 80):
            for cap in range(pool + 1, pool * 2):
                v = generate.step_resize_pool({"pool_size": pool, "resize_cap": cap})
                self.assertTrue(pool + 1 <= v <= cap)

    def test_v2_cases_have_no_magnitude_choice(self):
        for c in generate.build("probe", generate.DEFAULT_SEED["probe"], "v2"):
            self.assertEqual(c["answer_format"], "v2")
            for a in c["input"]["allowed_actions"]:
                self.assertTrue(set(a["params"]) <= {"scope", "pod_name", "reason", "parameter"}, (c["id"], a))
            for acc in c["expected"]["acceptable"]:
                self.assertTrue(set(acc["params"]) <= {"scope", "pod_name", "reason", "parameter"}, (c["id"], acc))

    def test_schema_file_matches_score_param_keys(self):
        sch = json.load(open(os.path.join(HERE, "schema", "answer.schema-v2.json"), encoding="utf-8"))
        keys = sch["properties"]["action"]["properties"]["params"]["required"]
        self.assertEqual(set(keys), set(score.PARAM_TYPES_V2))


if __name__ == "__main__":
    unittest.main()
