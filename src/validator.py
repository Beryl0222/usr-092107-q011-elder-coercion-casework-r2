"""校验涉老强迫交易线索网的领域事件。

两层校验：
- validate_event：单条信封与内容规则；
- validate_stream：跨记录规则（事件唯一、版本递增、去重留源、更正留痕、
  关联提示不得自动定罪、冻结须有法定依据、保管链衔接、公告脱敏、角色最小授权）。

记录一经接收只追加，不原地改写；校验器只报告违规，不修改任何记录。
"""

from datetime import datetime

REQUIRED = ("event_id", "event_type", "aggregate_type", "aggregate_id", "occurred_at", "version", "summary")

# 事件类型与所属聚合的对应
EVENT_AGGREGATE = {
    "REPORT_RECEIVED": "incident_report",
    "REPORT_LINKED_TO_INCIDENT": "incident_report",
    "STATEMENT_AMENDED": "incident_report",
    "ACCEPTANCE_GIVEN": "incident_report",
    "PAYMENT_DISPUTE_FILED": "payment_dispute",
    "PAYMENT_HOLD_DECIDED": "payment_dispute",
    "LINK_SUGGESTED": "subject_link",
    "LINK_CONFIRMED": "subject_link",
    "LINK_EXCLUDED": "subject_link",
    "PROTECTION_PROFILE_PUBLISHED": "protection_profile",
    "EVIDENCE_SEALED": "evidence_item",
    "EVIDENCE_ASSESSED": "evidence_item",
    "EVIDENCE_CUSTODY_TRANSFERRED": "evidence_item",
    "PROTECTIVE_ACTIONED": "protective_action",
    "CASE_TRANSFERRED": "case_transfer",
    "ASSET_RECOVERY_UPDATED": "asset_recovery",
    "PUBLIC_NOTICE_PUBLISHED": "public_notice",
    "ACCESS_GRANTED": "access_grant",
}

SOURCE_CHANNELS = {"police", "community", "family", "bank", "merchant"}

LINK_BASES = {
    "vehicle_track",
    "speech_pattern",
    "shared_location",
    "shared_time",
    "payment_flow",
    "merchant_entity",
}

NETWORK_ROLES = {"driver", "talker", "collector", "enforcer", "merchant", "lookout"}

EVIDENCE_KINDS = {
    "video_sealed",
    "product_sample",
    "document",
    "payment_record",
    "vehicle_record",
    "statement_recording",
}

EMERGENCY_ACTIONS = {
    "EMERGENCY_CONTACT",
    "ACCOMPANIED_WITHDRAWAL_INTERCEPTION",
    "SHELTER_PLACEMENT",
}

ACCESS_ROLES = {"investigator", "social_worker", "family", "public"}
ACCESS_LABELS = {"casework_full", "protection_minimum", "family_status", "public_notice"}

# 角色可访问的信息层级：社工只取保护所需，家属只见受理与追缴进度，公众只见公告
ROLE_ALLOWED_LABELS = {
    "investigator": {"casework_full", "protection_minimum", "family_status", "public_notice"},
    "social_worker": {"protection_minimum", "public_notice"},
    "family": {"family_status", "public_notice"},
    "public": {"public_notice"},
}

# 公告正文中禁止出现的字段键名（未公开案情不得进入社区风险公告）
NOTICE_FORBIDDEN_KEYS = {
    "person_ref",
    "suspect_ref",
    "victim_ref",
    "vehicle_plate",
    "address",
    "id_number",
    "phone",
    "case_detail",
    "seal_ref",
}


def _payload(record: dict) -> dict:
    p = record.get("payload")
    return p if isinstance(p, dict) else {}


def validate_event(record: dict) -> list[str]:
    """校验单条事件，返回中文错误信息列表；空列表表示通过。"""
    errors: list[str] = [f"缺少字段：{name}" for name in REQUIRED if name not in record]
    if errors:
        return errors

    etype = record["event_type"]
    if etype not in EVENT_AGGREGATE:
        errors.append(f"未知事件类型：{etype}")
    expected_agg = EVENT_AGGREGATE.get(etype)
    if expected_agg and record.get("aggregate_type") != expected_agg:
        errors.append(f"{etype} 的 aggregate_type 必须是 {expected_agg}")

    if not isinstance(record.get("version"), int) or record["version"] < 1:
        errors.append("version 必须是正整数")
    if not isinstance(record.get("summary"), str) or not record["summary"].strip():
        errors.append("summary 不能为空")
    try:
        datetime.fromisoformat(record["occurred_at"])
    except (ValueError, TypeError):
        errors.append("occurred_at 必须是合法的 date-time")

    errors.extend(_validate_payload(etype, _payload(record)))
    return errors


def _require(payload: dict, keys: set[str]) -> list[str]:
    return [f"payload 缺少字段：{k}" for k in keys if k not in payload]


def _validate_payload(etype: str, p: dict) -> list[str]:
    if not p:
        return []  # 信封最小契约允许无 payload；带 payload 时才做内容校验

    if etype == "REPORT_RECEIVED":
        errs = _require(p, {"source_channel", "source_record_id"})
        if p.get("source_channel") not in SOURCE_CHANNELS:
            errs.append("source_channel 必须来自 police/community/family/bank/merchant")
        if not isinstance(p.get("source_record_id"), str) or not p.get("source_record_id", "").strip():
            errs.append("source_record_id 不能为空（原始来源标识必须保留）")
        if "access_label" in p and p["access_label"] not in ACCESS_LABELS:
            errs.append("access_label 取值不合法")
        return errs

    if etype == "REPORT_LINKED_TO_INCIDENT":
        errs = _require(p, {"source_event_id", "incident_id", "retain_original"})
        if p.get("retain_original") is not True:
            errs.append("去重合并必须 retain_original=true，保留原始来源")
        return errs

    if etype == "STATEMENT_AMENDED":
        errs = _require(p, {"supersedes_event_id", "amendment_kind", "original_preserved"})
        if p.get("amendment_kind") not in {"supplement", "correction"}:
            errs.append("amendment_kind 必须是 supplement 或 correction")
        if p.get("original_preserved") is not True:
            errs.append("口述补正必须 original_preserved=true，原始版本与访问记录仍需保存")
        return errs

    if etype == "LINK_SUGGESTED":
        errs = _require(p, {"link_id", "adjudication"})
        if p.get("adjudication") != "hint_only":
            errs.append("模型关联只能 adjudication=hint_only，不得自动给个人定罪")
        basis = p.get("basis", [])
        if not isinstance(basis, list) or not basis:
            errs.append("关联提示必须给出至少一条 basis（车辆轨迹/话术/场所/时间/资金/主体）")
        elif any(b not in LINK_BASES for b in basis):
            errs.append("basis 含未登记的关联依据")
        conf = p.get("confidence")
        if conf is not None and not (isinstance(conf, (int, float)) and 0 <= conf <= 1):
            errs.append("confidence 必须落在 [0,1]")
        return errs

    if etype == "LINK_CONFIRMED":
        errs = _require(p, {"link_id", "confirmed_by", "network_id", "members"})
        if isinstance(p.get("confirmed_by"), str) and p["confirmed_by"].lower() in {"model", "risk_model", "auto"}:
            errs.append("关联确认必须由人工作出，confirmed_by 不得是模型")
        members = p.get("members")
        if not isinstance(members, list) or not members:
            errs.append("共同作案网络必须列出 members")
        else:
            for m in members:
                if not isinstance(m, dict) or not m.get("person_ref") or m.get("role") not in NETWORK_ROLES:
                    errs.append("每个 member 需要 person_ref 与合法 role（driver/talker/collector/enforcer/merchant/lookout）")
                    break
        return errs

    if etype == "LINK_EXCLUDED":
        errs = _require(p, {"link_id", "reason"})
        if not isinstance(p.get("reason"), str) or not p.get("reason", "").strip():
            errs.append("排除关联必须写明 reason，排除理由需保留")
        return errs

    if etype == "EVIDENCE_SEALED":
        errs = _require(p, {"evidence_kind", "obtained_how", "custodian", "usage_scope"})
        if p.get("evidence_kind") not in EVIDENCE_KINDS:
            errs.append("evidence_kind 不合法")
        for k in ("obtained_how", "custodian", "usage_scope"):
            if not isinstance(p.get(k), str) or not p.get(k, "").strip():
                errs.append(f"{k} 不能为空：证据须明确取得方式、保管人、使用范围")
        return errs

    if etype == "EVIDENCE_CUSTODY_TRANSFERRED":
        errs = _require(p, {"to_custodian", "legal_basis", "usage_scope", "cross_district"})
        for k in ("to_custodian", "legal_basis", "usage_scope"):
            if not isinstance(p.get(k), str) or not p.get(k, "").strip():
                errs.append(f"{k} 不能为空：跨区合并须明确保管人与使用范围")
        if "cross_district" in p and not isinstance(p["cross_district"], bool):
            errs.append("cross_district 必须是布尔值")
        return errs

    if etype == "PROTECTIVE_ACTIONED":
        errs = _require(p, {"action_type", "legal_authority", "duty_officer"})
        if p.get("action_type") not in EMERGENCY_ACTIONS:
            errs.append("action_type 不合法")
        for k in ("legal_authority", "duty_officer"):
            if not isinstance(p.get(k), str) or not p.get(k, "").strip():
                errs.append(f"{k} 不能为空：紧急措施须有法定权限与值班员")
        return errs

    if etype == "PAYMENT_HOLD_DECIDED":
        errs = _require(p, {"hold"})
        if not isinstance(p.get("hold"), bool):
            errs.append("hold 必须是布尔值")
        elif p["hold"] and not (isinstance(p.get("legal_basis"), str) and p["legal_basis"].strip()):
            errs.append("冻结必须有 legal_basis；普通相似交易不能被无依据冻结")
        return errs

    if etype == "CASE_TRANSFERRED":
        errs = _require(p, {"target_authority", "usage_scope", "transferred_evidence"})
        if not isinstance(p.get("transferred_evidence"), list) or not p["transferred_evidence"]:
            errs.append("司法移送须随附 transferred_evidence 清单")
        return errs

    if etype == "PUBLIC_NOTICE_PUBLISHED":
        errs = _require(p, {"warning_text"})
        leaked = NOTICE_FORBIDDEN_KEYS & set(p.keys())
        if leaked:
            errs.append(f"社区公告不得携带未公开案情字段：{sorted(leaked)}")
        return errs

    if etype == "ACCESS_GRANTED":
        errs = _require(p, {"role", "grantee_id", "purpose", "targets"})
        role = p.get("role")
        if role not in ACCESS_ROLES:
            errs.append("role 不合法")
        labels = p.get("targets")
        if not isinstance(labels, list) or not labels:
            errs.append("targets 必须为非空列表，且限于角色所需范围")
        elif role in ROLE_ALLOWED_LABELS and any(t not in ROLE_ALLOWED_LABELS[role] for t in labels):
            errs.append(f"{role} 仅可访问 {sorted(ROLE_ALLOWED_LABELS[role])}")
        return errs

    return []


def validate_stream(records: list[dict]) -> list[str]:
    """校验按 occurred_at 排序后的事件流，返回跨记录违规说明。"""
    errors: list[str] = []

    seen_event_ids: set[str] = set()
    versions: dict[str, int] = {}
    sealed_evidence: set[str] = set()

    def link_key(p: dict) -> str | None:
        return p.get("link_id")

    suggested: set[str] = set()
    adjudicated: set[str] = set()  # 已确认或已排除
    amended_events: set[str] = set()
    linked_source_events: set[str] = set()

    ordered = sorted(records, key=lambda r: r.get("occurred_at", ""))

    for rec in ordered:
        eid = rec.get("event_id", "?")
        if eid in seen_event_ids:
            errors.append(f"事件标识重复：{eid}（应以仓库事件标识去重，不得复用）")
        seen_event_ids.add(eid)

        agg = rec.get("aggregate_id", "?")
        ver = rec.get("version")
        if isinstance(ver, int):
            prev = versions.get(agg, 0)
            if ver != prev + 1:
                errors.append(f"{agg} 版本断裂：收到 v{ver}，期望 v{prev + 1}（记录不得原地改写）")
            versions[agg] = ver

        etype = rec.get("event_type")
        p = _payload(rec)

        if etype == "REPORT_LINKED_TO_INCIDENT":
            src = p.get("source_event_id")
            if src and src not in seen_event_ids:
                errors.append(f"{eid} 并入的原始记录 {src} 不存在")
            if src:
                linked_source_events.add(src)

        if etype == "STATEMENT_AMENDED":
            old = p.get("supersedes_event_id")
            if old and old not in seen_event_ids:
                errors.append(f"{eid} 更正的原始口述 {old} 不存在；原始版本必须仍在流中保存")
            if old:
                amended_events.add(old)

        if etype == "LINK_SUGGESTED":
            key = link_key(p)
            if key:
                suggested.add(key)

        if etype in {"LINK_CONFIRMED", "LINK_EXCLUDED"}:
            key = link_key(p)
            if key and key not in suggested:
                errors.append(f"{eid} 未经模型提示与人工研判流程，直接对 {key} 下结论")
            if key in adjudicated:
                errors.append(f"{eid} 关联 {key} 已有结论，禁止重复定性；如需翻案应走补正流程")
            if key:
                adjudicated.add(key)

        if etype == "EVIDENCE_SEALED":
            sealed_evidence.add(agg)

        if etype in {"EVIDENCE_ASSESSED", "EVIDENCE_CUSTODY_TRANSFERRED"}:
            if agg not in sealed_evidence:
                errors.append(f"{eid} 证据 {agg} 未先封存即流转，保管链断裂")

        if etype == "CASE_TRANSFERRED":
            for ev in p.get("transferred_evidence", []) or []:
                if ev not in sealed_evidence:
                    errors.append(f"{eid} 移送了未封存的证据 {ev}")

    # 被并入/被更正的原始事件必须真实保留在流中（上面只验证了存在性，这里强调不得删除标记）
    for src in linked_source_events:
        original = next((r for r in records if r.get("event_id") == src), None)
        if original and original.get("event_type") != "REPORT_RECEIVED":
            errors.append(f"{src} 被并入但不是原始接收记录，来源链不可信")

    return errors
