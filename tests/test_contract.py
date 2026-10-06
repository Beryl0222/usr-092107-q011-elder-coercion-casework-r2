import json
import unittest
from copy import deepcopy
from pathlib import Path

from src.validator import validate_event, validate_stream

ROOT = Path(__file__).parents[1]


def load(name: str) -> list[dict] | dict:
    return json.loads((ROOT / "data" / name).read_text(encoding="utf-8"))


def base_record(**overrides) -> dict:
    rec = {
        "event_id": "evt-test-1",
        "event_type": "REPORT_RECEIVED",
        "aggregate_type": "incident_report",
        "aggregate_id": "INC-T",
        "occurred_at": "2026-09-18T09:00:00+08:00",
        "version": 1,
        "summary": "测试记录",
        "payload": {"source_channel": "police", "source_record_id": "X-1"},
    }
    rec.update(overrides)
    return rec


class SampleContractTest(unittest.TestCase):
    def test_sample_matches_envelope(self) -> None:
        self.assertEqual(validate_event(load("sample.json")), [])

    def test_scenario_each_event_valid(self) -> None:
        for rec in load("scenario.json"):
            self.assertEqual(validate_event(rec), [], f"{rec['event_id']} 单条校验失败")

    def test_scenario_stream_valid(self) -> None:
        self.assertEqual(validate_stream(load("scenario.json")), [])


class EnvelopeRejectionTest(unittest.TestCase):
    def test_missing_fields_reported(self) -> None:
        errors = validate_event({})
        self.assertTrue(any("缺少字段" in e for e in errors))

    def test_event_aggregate_must_match(self) -> None:
        rec = base_record(event_type="EVIDENCE_SEALED", aggregate_type="incident_report",
                          payload={"evidence_kind": "video_sealed", "obtained_how": "x",
                                   "custodian": "y", "usage_scope": "z"})
        self.assertTrue(any("aggregate_type 必须是 evidence_item" in e for e in validate_event(rec)))

    def test_unknown_event_type_rejected(self) -> None:
        self.assertTrue(any("未知事件类型" in e for e in validate_event(base_record(event_type="NOPE"))))

    def test_bad_datetime_rejected(self) -> None:
        self.assertTrue(any("date-time" in e for e in validate_event(base_record(occurred_at="昨天"))))


class DeduplicationAndAmendmentTest(unittest.TestCase):
    def test_merge_without_retain_original_rejected(self) -> None:
        rec = base_record(event_type="REPORT_LINKED_TO_INCIDENT", version=2,
                          payload={"source_event_id": "evt-src", "incident_id": "INC-T",
                                   "retain_original": False})
        self.assertTrue(any("retain_original" in e for e in validate_event(rec)))

    def test_amendment_without_preserving_original_rejected(self) -> None:
        rec = base_record(event_type="STATEMENT_AMENDED", version=2,
                          payload={"supersedes_event_id": "evt-src",
                                   "amendment_kind": "correction", "original_preserved": False})
        self.assertTrue(any("original_preserved" in e for e in validate_event(rec)))

    def test_amendment_must_reference_existing_original(self) -> None:
        amend = base_record(event_id="evt-amend", event_type="STATEMENT_AMENDED", version=2,
                            payload={"supersedes_event_id": "evt-missing",
                                     "amendment_kind": "correction", "original_preserved": True})
        errors = validate_stream([amend])
        self.assertTrue(any("原始口述 evt-missing 不存在" in e for e in errors))

    def test_duplicate_event_id_rejected(self) -> None:
        r1 = base_record()
        r2 = base_record(aggregate_id="INC-2", occurred_at="2026-09-18T10:00:00+08:00",
                         payload={"source_channel": "bank", "source_record_id": "X-2"})
        errors = validate_stream([r1, r2])
        self.assertTrue(any("事件标识重复" in e for e in errors))

    def test_version_gap_rejected(self) -> None:
        r1 = base_record()
        r2 = base_record(event_id="evt-test-2", version=3,
                         occurred_at="2026-09-18T10:00:00+08:00",
                         payload={"source_channel": "bank", "source_record_id": "X-2"})
        errors = validate_stream([r1, r2])
        self.assertTrue(any("版本断裂" in e for e in errors))


class RiskModelBoundaryTest(unittest.TestCase):
    def test_model_link_must_be_hint_only(self) -> None:
        rec = base_record(event_id="evt-l", event_type="LINK_SUGGESTED",
                          aggregate_type="subject_link", aggregate_id="L-1",
                          payload={"link_id": "L-1", "adjudication": "guilty",
                                   "basis": ["vehicle_track"]})
        self.assertTrue(any("hint_only" in e for e in validate_event(rec)))

    def test_model_link_requires_basis(self) -> None:
        rec = base_record(event_id="evt-l", event_type="LINK_SUGGESTED",
                          aggregate_type="subject_link", aggregate_id="L-1",
                          payload={"link_id": "L-1", "adjudication": "hint_only", "basis": []})
        self.assertTrue(any("basis" in e for e in validate_event(rec)))

    def test_confirmation_without_suggestion_rejected(self) -> None:
        confirm = base_record(event_id="evt-c", event_type="LINK_CONFIRMED",
                              aggregate_type="subject_link", aggregate_id="L-9",
                              payload={"link_id": "L-9", "confirmed_by": "民警甲",
                                       "network_id": "N-1",
                                       "members": [{"person_ref": "S-1", "role": "driver"}]})
        self.assertTrue(any("未经模型提示" in e for e in validate_stream([confirm])))

    def test_model_cannot_confirm_link(self) -> None:
        rec = base_record(event_id="evt-c", event_type="LINK_CONFIRMED",
                          aggregate_type="subject_link", aggregate_id="L-1",
                          payload={"link_id": "L-1", "confirmed_by": "risk_model",
                                   "network_id": "N-1",
                                   "members": [{"person_ref": "S-1", "role": "talker"}]})
        self.assertTrue(any("不得是模型" in e for e in validate_event(rec)))

    def test_double_adjudication_rejected(self) -> None:
        suggest = base_record(event_id="evt-s", event_type="LINK_SUGGESTED",
                              aggregate_type="subject_link", aggregate_id="L-1",
                              payload={"link_id": "L-1", "adjudication": "hint_only",
                                       "basis": ["speech_pattern"]})
        confirm = base_record(event_id="evt-c1", event_type="LINK_CONFIRMED", version=2,
                              aggregate_type="subject_link", aggregate_id="L-1",
                              occurred_at="2026-09-19T10:00:00+08:00",
                              payload={"link_id": "L-1", "confirmed_by": "民警甲",
                                       "network_id": "N-1",
                                       "members": [{"person_ref": "S-1", "role": "driver"}]})
        exclude = base_record(event_id="evt-c2", event_type="LINK_EXCLUDED", version=3,
                              aggregate_type="subject_link", aggregate_id="L-1",
                              occurred_at="2026-09-20T10:00:00+08:00",
                              payload={"link_id": "L-1", "reason": "后来发现不对"})
        errors = validate_stream([suggest, confirm, exclude])
        self.assertTrue(any("禁止重复定性" in e for e in errors))

    def test_excluded_link_keeps_reason(self) -> None:
        rec = base_record(event_type="LINK_EXCLUDED", event_id="evt-e",
                          aggregate_type="subject_link", aggregate_id="L-1", version=2,
                          payload={"link_id": "L-1", "reason": "   "})
        self.assertTrue(any("reason" in e for e in validate_event(rec)))


class EvidenceChainTest(unittest.TestCase):
    def _sealed(self) -> dict:
        return base_record(event_id="evt-seal", event_type="EVIDENCE_SEALED",
                           aggregate_type="evidence_item", aggregate_id="EV-1",
                           payload={"evidence_kind": "video_sealed",
                                    "obtained_how": "持协查函调取", "custodian": "周某",
                                    "usage_scope": "本案使用"})

    def test_seal_requires_chain_fields(self) -> None:
        rec = base_record(event_id="evt-seal", event_type="EVIDENCE_SEALED",
                          aggregate_type="evidence_item", aggregate_id="EV-1",
                          payload={"evidence_kind": "video_sealed"})
        self.assertTrue(any("取得方式、保管人、使用范围" in e for e in validate_event(rec)))

    def test_assessment_before_seal_rejected(self) -> None:
        assess = base_record(event_id="evt-a", event_type="EVIDENCE_ASSESSED",
                             aggregate_type="evidence_item", aggregate_id="EV-1",
                             payload={"result": "不合格"})
        self.assertTrue(any("未先封存" in e for e in validate_stream([assess])))

    def test_custody_transfer_requires_scope(self) -> None:
        rec = base_record(event_id="evt-x", event_type="EVIDENCE_CUSTODY_TRANSFERRED",
                          aggregate_type="evidence_item", aggregate_id="EV-1", version=2,
                          payload={"to_custodian": "李某", "legal_basis": "协查函",
                                   "cross_district": True})
        self.assertTrue(any("usage_scope" in e for e in validate_event(rec)))

    def test_transfer_with_unsealed_evidence_rejected(self) -> None:
        transfer = base_record(event_id="evt-t", event_type="CASE_TRANSFERRED",
                               aggregate_type="case_transfer", aggregate_id="CT-1",
                               payload={"target_authority": "公安分局", "usage_scope": "刑诉",
                                        "transferred_evidence": ["EV-GHOST"]})
        errors = validate_stream([transfer])
        self.assertTrue(any("未封存的证据 EV-GHOST" in e for e in errors))

    def test_valid_chain_passes(self) -> None:
        sealed = self._sealed()
        transfer = base_record(event_id="evt-t", event_type="CASE_TRANSFERRED",
                               aggregate_type="case_transfer", aggregate_id="CT-1",
                               occurred_at="2026-09-20T10:00:00+08:00",
                               payload={"target_authority": "公安分局", "usage_scope": "刑诉",
                                        "transferred_evidence": ["EV-1"]})
        self.assertEqual(validate_stream([sealed, transfer]), [])


class EmergencyAndPaymentTest(unittest.TestCase):
    def test_emergency_requires_legal_authority(self) -> None:
        rec = base_record(event_id="evt-p", event_type="PROTECTIVE_ACTIONED",
                          aggregate_type="protective_action", aggregate_id="PA-1",
                          payload={"action_type": "EMERGENCY_CONTACT",
                                   "legal_authority": "  ", "duty_officer": "郑某"})
        self.assertTrue(any("法定权限" in e for e in validate_event(rec)))

    def test_hold_without_legal_basis_rejected(self) -> None:
        rec = base_record(event_id="evt-h", event_type="PAYMENT_HOLD_DECIDED",
                          aggregate_type="payment_dispute", aggregate_id="PD-1",
                          payload={"hold": True})
        self.assertTrue(any("无依据冻结" in e for e in validate_event(rec)))

    def test_no_hold_without_basis_is_allowed(self) -> None:
        rec = base_record(event_id="evt-h", event_type="PAYMENT_HOLD_DECIDED",
                          aggregate_type="payment_dispute", aggregate_id="PD-1",
                          payload={"hold": False})
        self.assertEqual(validate_event(rec), [])


class AccessScopeTest(unittest.TestCase):
    def _grant(self, role: str, targets: list[str]) -> dict:
        return base_record(event_id=f"ag-{role}", event_type="ACCESS_GRANTED",
                           aggregate_type="access_grant", aggregate_id=f"AG-{role}",
                           payload={"role": role, "grantee_id": "u1", "purpose": "履职",
                                    "targets": targets})

    def test_social_worker_cannot_get_full_casework(self) -> None:
        self.assertTrue(any("social_worker" in e for e in validate_event(
            self._grant("social_worker", ["casework_full"]))))

    def test_family_cannot_get_full_casework(self) -> None:
        self.assertTrue(any("family" in e for e in validate_event(
            self._grant("family", ["casework_full"]))))

    def test_investigator_full_access_allowed(self) -> None:
        self.assertEqual(validate_event(self._grant("investigator", ["casework_full"])), [])

    def test_public_only_notice(self) -> None:
        self.assertTrue(any("public" in e for e in validate_event(
            self._grant("public", ["family_status"]))))

    def test_public_notice_rejects_nonpublic_details(self) -> None:
        rec = base_record(event_id="evt-n", event_type="PUBLIC_NOTICE_PUBLISHED",
                          aggregate_type="public_notice", aggregate_id="PN-1",
                          payload={"warning_text": "社区提示", "victim_ref": "V-1001",
                                   "vehicle_plate": "京A12345"})
        errors = validate_event(rec)
        self.assertTrue(any("社区公告不得携带未公开案情字段" in e for e in errors))


class ScenarioImmutabilityTest(unittest.TestCase):
    def test_validator_does_not_mutate_records(self) -> None:
        records = load("scenario.json")
        snapshot = deepcopy(records)
        validate_event(records[0])
        validate_stream(records)
        self.assertEqual(records, snapshot)


if __name__ == "__main__":
    unittest.main()
