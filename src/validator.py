"""校验领域事件信封与涉老强迫交易线索网的关键办案规则。

边界原则：
- 记录只可追加；标识、发生时间、版本不得原地改写，更正使用后继事件。
- 风险模型只能提示关联，确认/排除由人作出，排除也必须留理由。
- 紧急联络与资金冻结须有法定权限和人工授权；普通相似交易不得冻结。
- 口述可补充更正，但原件与每次访问都保留。
- 跨区并案的每份证据须可回溯取得方式、保管人、使用范围。
- 社工、家属按最小必要授权；公开公告不得含未公开案情。
"""

REQUIRED = ("event_id", "event_type", "aggregate_type", "aggregate_id", "occurred_at", "version", "summary")

EVENT_TYPES = {
    "REPORT_RECEIVED",
    "REPORT_DEDUPED",
    "SUBJECT_ROLE_NOTED",
    "VEHICLE_TRACKED",
    "MERCHANT_RECORDED",
    "LINK_SUGGESTED",
    "LINK_CONFIRMED",
    "LINK_REJECTED",
    "STATEMENT_RECORDED",
    "STATEMENT_AMENDED",
    "STATEMENT_ACCESSED",
    "EVIDENCE_SEALED",
    "EVIDENCE_ACCESSED",
    "EMERGENCY_CONTACT_STARTED",
    "FUND_CONTROL_REQUESTED",
    "FUND_CONTROL_DECIDED",
    "CASE_MERGED",
    "CASE_TRANSFERRED",
    "ASSET_RECOVERY_UPDATED",
    "ACCESS_GRANTED",
    "RISK_NOTICE_PUBLISHED",
}

AGGREGATE_TYPES = {
    "incident_report",
    "subject_person",
    "vehicle",
    "merchant",
    "subject_link",
    "victim_statement",
    "evidence_item",
    "protective_action",
    "fund_control",
    "case_merge",
    "case_transfer",
    "asset_recovery",
    "access_grant",
    "risk_notice",
}

SOURCE_CHANNELS = {
    "police_hotline",
    "community_visit",
    "family_report",
    "payment_dispute",
    "risk_model",
    "caseworker",
    "bank_counter",
    "court_transfer",
}

# 社工为保护老人可获取的最小字段集
SOCIAL_WORKER_ALLOWED_FIELDS = {
    "victim_contact",
    "protection_need",
    "emergency_status",
    "service_plan",
}

# 老人及家属可查询的范围：受理进度与财物追缴进度
FAMILY_ALLOWED_FIELDS = {
    "acceptance_status",
    "asset_recovery_progress",
    "next_contact",
}


def validate_event(record: dict) -> list[str]:
    """校验单条事件的信封与业务规则。"""
    errors = [f"缺少字段：{name}" for name in REQUIRED if name not in record]

    event_id = record.get("event_id")
    if not isinstance(event_id, str) or not (event_id or "").strip():
        errors.append("event_id 必须是非空字符串")
    if record.get("event_type") not in EVENT_TYPES:
        errors.append(f"未知事件类型：{record.get('event_type')}")
    if record.get("aggregate_type") not in AGGREGATE_TYPES:
        errors.append(f"未知聚合类型：{record.get('aggregate_type')}")
    if not isinstance(record.get("aggregate_id"), str) or not (record.get("aggregate_id") or "").strip():
        errors.append("aggregate_id 必须是非空字符串")
    version = record.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        errors.append("version 必须是正整数")
    if not isinstance(record.get("summary"), str) or not (record.get("summary") or "").strip():
        errors.append("summary 必须是非空字符串")

    errors.extend(_validate_source(record))
    errors.extend(_validate_payload_rules(record))
    return errors


def validate_stream(records: list[dict]) -> list[str]:
    """校验整段事件流：去重、版本连续、引用完整与跨事件的授权边界。"""
    errors: list[str] = []

    seen_event_ids: set[str] = set()
    versions: dict[str, int] = {}
    sealed_evidence: dict[str, dict] = {}

    for index, record in enumerate(records):
        prefix = f"第{index + 1}条"
        for err in validate_event(record):
            errors.append(f"{prefix}（{record.get('event_id', '?')}）：{err}")

        event_id = record.get("event_id")
        if isinstance(event_id, str):
            if event_id in seen_event_ids:
                errors.append(f"{prefix}：event_id 重复：{event_id}（仓库以事件标识去重）")
            seen_event_ids.add(event_id)

        agg_id = record.get("aggregate_id")
        if isinstance(agg_id, str):
            expected = versions.get(agg_id, 0) + 1
            actual = record.get("version")
            if isinstance(actual, int) and actual != expected:
                errors.append(
                    f"{prefix}：聚合 {agg_id} 版本应为 {expected}，实际为 {actual}（版本须连续递增、不复用）"
                )
            versions[agg_id] = actual if isinstance(actual, int) else expected

        if record.get("event_type") == "EVIDENCE_SEALED":
            sealed_evidence[event_id] = record

        payload = record.get("payload") or {}
        if record.get("event_type") == "CASE_MERGED":
            for ref in payload.get("evidence_refs", []):
                ev = sealed_evidence.get(ref)
                if ev is None:
                    errors.append(f"{prefix}：并案证据 {ref} 缺少先行封存记录")
                    continue
                ev_payload = ev.get("payload") or {}
                for field in ("obtained_by_method", "custodian", "scope_of_use"):
                    if not ev_payload.get(field):
                        errors.append(
                            f"{prefix}：并案证据 {ref} 缺少{_FIELD_LABELS[field]}，跨区使用前必须补齐"
                        )

        if record.get("event_type") in {"STATEMENT_AMENDED"}:
            superseded = payload.get("supersedes_event_id")
            if superseded and superseded not in seen_event_ids:
                errors.append(f"{prefix}：被更正的口述 {superseded} 不在事件流中，原始版本必须先行留存")

    return errors


_FIELD_LABELS = {
    "obtained_by_method": "取得方式",
    "custodian": "保管人",
    "scope_of_use": "使用范围",
}


def _validate_source(record: dict) -> list[str]:
    errors: list[str] = []
    source = record.get("source")
    if source is None:
        # 风险模型自动生成的关联提示也必须登记来源；不允许无来源记录进入仓库
        return ["缺少 source：任何记录都须保留原始来源渠道与原始单号"]
    if not isinstance(source, dict):
        return ["source 必须是对象"]
    channel = source.get("channel")
    if channel not in SOURCE_CHANNELS:
        errors.append(f"source.channel 非法：{channel}")
    if not isinstance(source.get("source_ref"), str) or not source.get("source_ref", "").strip():
        errors.append("source.source_ref 必须记录来源系统的原始单号")
    return errors


def _validate_payload_rules(record: dict) -> list[str]:
    event_type = record.get("event_type")
    payload = record.get("payload") or {}
    if payload is None:
        return ["payload 必须是对象"] if "payload" in record else []
    if not isinstance(payload, dict):
        return ["payload 必须是对象"]

    checker = _PAYLOAD_RULES.get(event_type)
    return checker(payload) if checker else []


def _require(payload: dict, field: str, label: str) -> list[str]:
    value = payload.get(field)
    if isinstance(value, str) and not value.strip():
        return [f"{label}不得为空"]
    if value is None:
        return [f"缺少{label}：{field}"]
    return []


def _check_report_deduped(payload: dict) -> list[str]:
    refs = payload.get("duplicate_of_event_ids")
    if not isinstance(refs, list) or not refs:
        return ["去重记录必须在 duplicate_of_event_ids 中指明被合并的仓库事件标识"]
    return []


def _check_subject_role(payload: dict) -> list[str]:
    errors = _require(payload, "role", "嫌疑人在共同作案中的角色")
    if not payload.get("network_refs"):
        errors.append("缺少 network_refs：须能从角色回看共同作案网络")
    return errors


def _check_link_suggested(payload: dict) -> list[str]:
    errors = _require(payload, "suggested_by", "关联来源")
    # 模型只提示关联：不得携带任何定论字段
    if payload.get("confirmed_by"):
        errors.append("风险模型仅可提示关联，confirmed_by 只能出现在人工确认事件中")
    if payload.get("conviction") or payload.get("guilty"):
        errors.append("不得在关联提示阶段对个人定罪")
    return errors


def _check_link_confirmed(payload: dict) -> list[str]:
    errors = _require(payload, "confirmed_by", "人工确认人")
    if payload.get("suggested_by") == "risk_model" and not payload.get("confirmed_by"):
        errors.append("模型提示不得自动升级为确认关联")
    return errors


def _check_link_rejected(payload: dict) -> list[str]:
    # 已排除的关联也保留理由，不得直接删除
    return _require(payload, "reject_reason", "排除理由")


def _check_statement_amended(payload: dict) -> list[str]:
    return _require(payload, "supersedes_event_id", "被更正的原始口述事件（原件保留，仅追加更正）")


def _check_statement_accessed(payload: dict) -> list[str]:
    errors = _require(payload, "reader", "调阅人")
    errors.extend(_require(payload, "purpose", "调阅事由"))
    return errors


def _check_evidence_sealed(payload: dict) -> list[str]:
    errors: list[str] = []
    for field, label in (
        ("obtained_by_method", "证据取得方式"),
        ("custodian", "证据保管人"),
        ("scope_of_use", "证据使用范围"),
    ):
        errors.extend(_require(payload, field, label))
    return errors


def _check_evidence_accessed(payload: dict) -> list[str]:
    errors = _require(payload, "reader", "调阅人")
    errors.extend(_require(payload, "purpose", "调阅事由"))
    if not payload.get("scope_of_use"):
        errors.append("缺少使用范围说明：scope_of_use")
    return errors


def _check_emergency(payload: dict) -> list[str]:
    errors = _require(payload, "duty_officer", "值班员")
    errors.extend(_require(payload, "legal_authority", "启动紧急联络的法定权限依据"))
    return errors


def _check_fund_requested(payload: dict) -> list[str]:
    errors: list[str] = []
    if payload.get("action") == "freeze" and payload.get("reason_code") == "SIMILAR_TRANSACTION_ONLY":
        errors.append("普通相似交易不得作为无依据冻结的理由")
    return errors


def _check_fund_decided(payload: dict) -> list[str]:
    errors: list[str] = []
    if payload.get("action") == "freeze":
        errors.extend(_require(payload, "authorized_by", "冻结批准人"))
        errors.extend(_require(payload, "legal_basis", "冻结法律依据"))
        if payload.get("reason_code") == "SIMILAR_TRANSACTION_ONLY":
            errors.append("仅凭交易相似不得冻结资金")
        if payload.get("suggested_by") == "risk_model" and not payload.get("authorized_by"):
            errors.append("风险模型提示不得自动触发冻结")
    return errors


def _check_case_merge(payload: dict) -> list[str]:
    errors: list[str] = []
    refs = payload.get("merged_district_case_refs")
    if not isinstance(refs, list) or len(refs) < 2:
        errors.append("跨区合并须在 merged_district_case_refs 中列出至少两个区级案件编号")
    if not payload.get("evidence_refs"):
        errors.append("跨区合并须列明随案证据清单 evidence_refs")
    return errors


def _check_access_granted(payload: dict) -> list[str]:
    errors = _require(payload, "access_role", "授权角色")
    errors.extend(_require(payload, "reader", "被授权人"))
    errors.extend(_require(payload, "purpose", "授权用途"))
    fields = payload.get("fields_granted")
    if not isinstance(fields, list) or not fields:
        errors.append("fields_granted 须明确列出授权字段（最小必要）")
        return errors

    role = payload.get("access_role")
    if role == "social_worker":
        overreach = [f for f in fields if f not in SOCIAL_WORKER_ALLOWED_FIELDS]
        if overreach:
            errors.append(f"社工仅获取保护老人所需信息，越权字段：{', '.join(overreach)}")
    elif role == "family":
        overreach = [f for f in fields if f not in FAMILY_ALLOWED_FIELDS]
        if overreach:
            errors.append(f"家属仅可查询受理与财物追缴进度，越权字段：{', '.join(overreach)}")
    return errors


def _check_risk_notice(payload: dict) -> list[str]:
    errors: list[str] = []
    if payload.get("disclosure_level") != "public":
        errors.append("社区风险公告必须是公开级信息：disclosure_level=public")
    # 未公开案情、嫌疑人指向、受害人口述与封存证据不得进入公告
    forbidden_flags = ("nonpublic_case_detail", "subject_real_name", "statement_text", "sealed_evidence")
    for flag in forbidden_flags:
        if payload.get(flag):
            errors.append(f"社区风险公告不得包含未公开案情或隐私内容：{flag}")
    return errors


_PAYLOAD_RULES = {
    "REPORT_DEDUPED": _check_report_deduped,
    "SUBJECT_ROLE_NOTED": _check_subject_role,
    "LINK_SUGGESTED": _check_link_suggested,
    "LINK_CONFIRMED": _check_link_confirmed,
    "LINK_REJECTED": _check_link_rejected,
    "STATEMENT_AMENDED": _check_statement_amended,
    "STATEMENT_ACCESSED": _check_statement_accessed,
    "EVIDENCE_SEALED": _check_evidence_sealed,
    "EVIDENCE_ACCESSED": _check_evidence_accessed,
    "EMERGENCY_CONTACT_STARTED": _check_emergency,
    "FUND_CONTROL_REQUESTED": _check_fund_requested,
    "FUND_CONTROL_DECIDED": _check_fund_decided,
    "CASE_MERGED": _check_case_merge,
    "ACCESS_GRANTED": _check_access_granted,
    "RISK_NOTICE_PUBLISHED": _check_risk_notice,
}
