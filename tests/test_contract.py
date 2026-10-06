import json
import unittest
from pathlib import Path

from src.validator import validate_event, validate_stream

DATA = Path(__file__).parents[1] / "data"


def base_event(**overrides) -> dict:
    record = {
        "event_id": "evt-test-1",
        "event_type": "REPORT_RECEIVED",
        "aggregate_type": "incident_report",
        "aggregate_id": "R-1",
        "occurred_at": "2026-09-20T10:00:00+08:00",
        "version": 1,
        "summary": "测试事件",
        "source": {"channel": "police_hotline", "source_ref": "110-0001"},
    }
    record.update(overrides)
    return record


class EnvelopeTest(unittest.TestCase):
    def test_sample_matches_envelope(self) -> None:
        sample = json.loads((DATA / "sample.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_event(sample), [])

    def test_full_flow_sample_is_valid(self) -> None:
        flow = json.loads((DATA / "flow.sample.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_stream(flow), [])

    def test_missing_fields_reported(self) -> None:
        errors = validate_event({})
        self.assertTrue(any("event_id" in e for e in errors))
        self.assertTrue(any("source" in e for e in errors))

    def test_version_must_be_positive_int(self) -> None:
        self.assertTrue(validate_event(base_event(version=0)))
        self.assertTrue(validate_event(base_event(version="1")))
        self.assertTrue(validate_event(base_event(version=True)))


class SourceRetentionTest(unittest.TestCase):
    def test_record_without_source_rejected(self) -> None:
        record = base_event()
        del record["source"]
        errors = validate_event(record)
        self.assertTrue(any("source" in e for e in errors))

    def test_source_ref_must_keep_original_number(self) -> None:
        record = base_event(source={"channel": "community_visit", "source_ref": ""})
        self.assertTrue(any("原始单号" in e for e in validate_event(record)))

    def test_dedup_keeps_warehouse_event_id(self) -> None:
        record = base_event(event_type="REPORT_DEDUPED", payload={})
        errors = validate_event(record)
        self.assertTrue(any("duplicate_of_event_ids" in e for e in errors))


class ModelBoundaryTest(unittest.TestCase):
    def test_model_suggestion_cannot_carry_conviction(self) -> None:
        record = base_event(
            event_type="LINK_SUGGESTED",
            aggregate_type="subject_link",
            payload={"suggested_by": "risk_model", "guilty": True},
        )
        errors = validate_event(record)
        self.assertTrue(any("定罪" in e for e in errors))

    def test_model_suggestion_cannot_self_confirm(self) -> None:
        record = base_event(
            event_type="LINK_SUGGESTED",
            aggregate_type="subject_link",
            payload={"suggested_by": "risk_model", "confirmed_by": "系统"},
        )
        self.assertTrue(validate_event(record))

    def test_rejected_link_must_keep_reason(self) -> None:
        record = base_event(
            event_type="LINK_REJECTED",
            aggregate_type="subject_link",
            payload={},
        )
        errors = validate_event(record)
        self.assertTrue(any("排除理由" in e for e in errors))


class StatementVersioningTest(unittest.TestCase):
    def test_amendment_must_reference_original(self) -> None:
        record = base_event(
            event_type="STATEMENT_AMENDED",
            aggregate_type="victim_statement",
            payload={},
        )
        self.assertTrue(any("原始口述" in e for e in validate_event(record)))

    def test_amendment_requires_prior_original_in_stream(self) -> None:
        amendment = base_event(
            event_id="evt-2",
            event_type="STATEMENT_AMENDED",
            aggregate_type="victim_statement",
            aggregate_id="ST-1",
            version=2,
            payload={"supersedes_event_id": "evt-missing"},
        )
        errors = validate_stream([amendment])
        self.assertTrue(any("原始版本必须先行留存" in e for e in errors))

    def test_access_log_requires_reader_and_purpose(self) -> None:
        record = base_event(
            event_type="STATEMENT_ACCESSED",
            aggregate_type="victim_statement",
            payload={"reader": "检察官高蕾"},
        )
        self.assertTrue(any("调阅事由" in e for e in validate_event(record)))


class EvidenceCustodyTest(unittest.TestCase):
    def test_sealed_evidence_requires_three_elements(self) -> None:
        record = base_event(event_type="EVIDENCE_SEALED", aggregate_type="evidence_item", payload={})
        errors = validate_event(record)
        self.assertTrue(any("取得方式" in e for e in errors))
        self.assertTrue(any("保管人" in e for e in errors))
        self.assertTrue(any("使用范围" in e for e in errors))

    def test_merge_without_sealed_evidence_chain_rejected(self) -> None:
        merge = base_event(
            event_type="CASE_MERGED",
            aggregate_type="case_merge",
            payload={
                "merged_district_case_refs": ["东城区-A", "西城区-B"],
                "evidence_refs": ["evt-sealed-x"],
            },
        )
        errors = validate_stream([merge])
        self.assertTrue(any("先行封存" in e for e in errors))

    def test_merge_rejects_evidence_missing_custody_elements(self) -> None:
        sealed = base_event(
            event_id="evt-sealed-1",
            event_type="EVIDENCE_SEALED",
            aggregate_type="evidence_item",
            aggregate_id="E-1",
            payload={},  # 三要素缺失
        )
        merge = base_event(
            event_id="evt-merge-1",
            event_type="CASE_MERGED",
            aggregate_type="case_merge",
            payload={
                "merged_district_case_refs": ["东城区-A", "西城区-B"],
                "evidence_refs": ["evt-sealed-1"],
            },
        )
        errors = validate_stream([sealed, merge])
        self.assertTrue(any("取得方式" in e and "并案证据" in e for e in errors))


class EmergencyAndFundControlTest(unittest.TestCase):
    def test_emergency_contact_requires_legal_authority(self) -> None:
        record = base_event(
            event_type="EMERGENCY_CONTACT_STARTED",
            aggregate_type="protective_action",
            payload={"duty_officer": "值班员周敏"},
        )
        self.assertTrue(any("法定权限" in e for e in validate_event(record)))

    def test_similar_transaction_alone_cannot_freeze(self) -> None:
        request = base_event(
            event_type="FUND_CONTROL_REQUESTED",
            aggregate_type="fund_control",
            payload={"action": "freeze", "reason_code": "SIMILAR_TRANSACTION_ONLY"},
        )
        self.assertTrue(any("不得" in e and "冻结" in e for e in validate_event(request)))

    def test_freeze_decision_requires_human_authorizer_and_basis(self) -> None:
        decision = base_event(
            event_type="FUND_CONTROL_DECIDED",
            aggregate_type="fund_control",
            payload={"action": "freeze", "reason_code": "ONGOING_COERCION_OBSERVED"},
        )
        errors = validate_event(decision)
        self.assertTrue(any("批准人" in e for e in errors))
        self.assertTrue(any("法律依据" in e for e in errors))

    def test_model_cannot_auto_freeze(self) -> None:
        decision = base_event(
            event_type="FUND_CONTROL_DECIDED",
            aggregate_type="fund_control",
            payload={"action": "freeze", "suggested_by": "risk_model"},
        )
        self.assertTrue(any("不得自动触发冻结" in e for e in validate_event(decision)))


class AccessScopeTest(unittest.TestCase):
    def grant(self, role: str, fields: list[str]) -> dict:
        return base_event(
            event_type="ACCESS_GRANTED",
            aggregate_type="access_grant",
            payload={
                "access_role": role,
                "reader": "某人",
                "purpose": "履职需要",
                "fields_granted": fields,
            },
        )

    def test_social_worker_minimum_necessary_only(self) -> None:
        record = self.grant("social_worker", ["victim_contact", "sealed_evidence"])
        errors = validate_event(record)
        self.assertTrue(any("社工" in e and "sealed_evidence" in e for e in errors))

    def test_family_only_sees_acceptance_and_recovery(self) -> None:
        record = self.grant("family", ["acceptance_status", "nonpublic_case_detail"])
        errors = validate_event(record)
        self.assertTrue(any("家属" in e and "nonpublic_case_detail" in e for e in errors))

    def test_least_privilege_grant_passes(self) -> None:
        self.assertEqual(validate_event(self.grant("social_worker", ["protection_need"])), [])


class PublicNoticeTest(unittest.TestCase):
    def test_notice_must_be_public_level(self) -> None:
        record = base_event(
            event_type="RISK_NOTICE_PUBLISHED",
            aggregate_type="risk_notice",
            payload={"disclosure_level": "internal"},
        )
        self.assertTrue(any("公开级" in e for e in validate_event(record)))

    def test_notice_cannot_contain_nonpublic_case_detail(self) -> None:
        record = base_event(
            event_type="RISK_NOTICE_PUBLISHED",
            aggregate_type="risk_notice",
            payload={"disclosure_level": "public", "statement_text": "老人原话……"},
        )
        errors = validate_event(record)
        self.assertTrue(any("statement_text" in e for e in errors))


class StreamIntegrityTest(unittest.TestCase):
    def test_duplicate_event_id_rejected(self) -> None:
        a = base_event(event_id="evt-dup", aggregate_id="R-1", version=1)
        b = base_event(event_id="evt-dup", aggregate_id="R-2", version=1)
        errors = validate_stream([a, b])
        self.assertTrue(any("event_id 重复" in e for e in errors))

    def test_version_must_be_contiguous(self) -> None:
        a = base_event(event_id="evt-a", aggregate_id="R-9", version=1)
        b = base_event(event_id="evt-b", aggregate_id="R-9", version=3)
        errors = validate_stream([a, b])
        self.assertTrue(any("版本应为 2" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
