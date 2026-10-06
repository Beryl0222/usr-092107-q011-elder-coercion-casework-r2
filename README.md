# 涉老强迫交易线索网

区级涉老权益中心的线索协同与案件证据后端契约：接收报警、社区走访、家属报失、支付争议、商户主体、车辆、商品鉴定、视频封存与司法移送信息，按仓库事件标识去重并保留原始来源。

## 资料范围

- `contracts/domain.schema.json`：领域事件信封、聚合类型、事件名称与 payload 约定。
- `data/sample.json`：一条用于本地联调的中文样例。
- `data/scenario.json`：覆盖完整办案链路的 25 条串联样例。
- `src/`：事件信封与事件流的校验代码（无第三方依赖）。
- `tests/`：验证样例合规与各类违规被拒绝。

## 事件目录

| 事件 | 聚合 | 含义 |
|---|---|---|
| `REPORT_RECEIVED` | incident_report | 接收报警/社区走访/家属报失/银行/商户线索（含原始来源标识与渠道） |
| `REPORT_LINKED_TO_INCIDENT` | incident_report | 按事件标识将零散来源并入同一事件，`retain_original` 必须为 true |
| `STATEMENT_AMENDED` | incident_report | 受害人口述的补充（supplement）或更正（correction），原版保留 |
| `ACCEPTANCE_GIVEN` | incident_report | 中心受理，家属可凭编号查询 |
| `PAYMENT_DISPUTE_FILED` | payment_dispute | 银行提交的支付争议 |
| `PAYMENT_HOLD_DECIDED` | payment_dispute | 是否冻结；冻结必须填写 `legal_basis` |
| `LINK_SUGGESTED` | subject_link | 风险模型关联提示，`adjudication` 恒为 `hint_only` |
| `LINK_CONFIRMED` / `LINK_EXCLUDED` | subject_link | 人工确认共同作案网络（含角色）/ 排除关联并写明理由 |
| `PROTECTION_PROFILE_PUBLISHED` | protection_profile | 发布给社工的保护方案 |
| `EVIDENCE_SEALED` / `EVIDENCE_ASSESSED` / `EVIDENCE_CUSTODY_TRANSFERRED` | evidence_item | 证据封存（取得方式/保管人/使用范围）→ 鉴定 → 跨区移交 |
| `PROTECTIVE_ACTIONED` | protective_action | 值班员按法定权限启动紧急联络/拦截陪同取款 |
| `CASE_TRANSFERRED` | case_transfer | 司法移送，随附已封存证据清单并限定使用范围 |
| `ASSET_RECOVERY_UPDATED` | asset_recovery | 财物追缴进度（家属可见） |
| `PUBLIC_NOTICE_PUBLISHED` | public_notice | 社区风险公告，仅泛化提示 |
| `ACCESS_GRANTED` | access_grant | 按角色授权查阅范围 |

## 固化原则

记录一经接收**只追加**：`event_id` 全局唯一，同一聚合 `version` 从 1 严格递增，标识、发生时间与版本不得原地改写；更正以 `STATEMENT_AMENDED` 后继记录表达，原始口述与访问记录仍保存。被并入主事件的原始接收记录必须仍在流中（`retain_original=true`）。

**风险模型只提示、不定罪**：模型产出只能是 `LINK_SUGGESTED` 且 `adjudication="hint_only"` 并附依据（车辆轨迹、相似话术、同场所/时间、资金流、商户主体）；定罪性结论只能由人工 `LINK_CONFIRMED`，`confirmed_by` 不允许是模型。已排除的关联用 `LINK_EXCLUDED` 并保留排除理由，确认与排除互斥不可重复定性。

**措施法定**：疑似正在发生限制联络或陪同取款时，值班员以 `PROTECTIVE_ACTIONED` 在法定权限内启动紧急联络；普通相似交易不得无依据冻结（`hold=true` 必须有 `legal_basis`）。

**证据链**：每份证据在 `EVIDENCE_SEALED` 写明取得方式、保管人、使用范围；鉴定与跨区移交只能发生在封存之后，司法移送只允许随附已封存证据。

**分级可见**：

| 角色 | 可见 |
|---|---|
| investigator（办案人员） | 全量案情，可从任一嫌疑人角色回看共同作案网络 |
| social_worker（社工） | 仅 `protection_minimum` 保护所需信息 |
| family（老人及家属） | 受理进度与 `asset_recovery` 追缴进度 |
| public（社区公告） | 泛化防范提示；人名、车牌、地址、未公开案情禁止入公告 |

## 本地检查

```bash
python3 -m unittest discover -s tests
```

32 项测试同时验证 `scenario.json` 的每条记录与整条事件流，并逐一确认上述拒绝规则生效。校验器只读不写，不修改传入记录。
