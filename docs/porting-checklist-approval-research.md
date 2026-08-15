# 移植清单：从 clawnify/agent-permissions + verkflode/remit 抄什么

> 日期：2026-08-15
> 基准代码：openclaw-human-gate v0.4.2（src/ 已含 scope.ts 语义指纹、window.ts 作用域窗口、state.ts 租约）
> 参考源码：`workspace/tmp/approval-research/`（clawnify package/ + remit/ 完整 clone）

## 结论先行

**不用从零推。** 三块里有两块的核心能力我们已经有了（v0.4.2 已实现），真正值得抄的是 remit 的三样：

| 抄什么 | 来源 | 价值 | 成本 |
|---|---|---|---|
| deny cooldown（拒绝冷却） | remit | 高（反弹窗疲劳） | 低 |
| 决策日志（cooldown/flood 的底座） | remit vaom.decision | 高（也是审计） | 低 |
| 自保护（escalation-only 分类升级） | remit sensitive block | 高（安全） | 低 |
| NEVER_GRANTABLE + blanket 二次确认 | remit grants.ts | 中（grant 加固） | 中 |
| flood detector（洪泛检测→建议 grant） | remit | 中 | 中 |
| agent 作用域 + grant 管理命令 | remit | 中 | 中 |
| glob 规则语法糖 | clawnify | 低（UX 而已） | 低 |

**明确不抄的**：clawnify 的默认 allow（我们是 fail-closed，别退化）；clawnify 的 allow-always 持久化 pattern（我们的 fingerprint 更细）；remit 的类别桶替代（我们按工具+参数规则粒度更细，类别可作为可选 rule 字段以后加）；remit 的 caps（场景不同，我们是审批流不是配额）。

---

## 现状盘点（v0.4.2 已实现的，别再重复做）

- **语义作用域指纹**（`src/scope.ts`）：destructive/same-tool/effect/category/path 五档，`createAuthorizationFingerprint` 生成 windowKey + grantKey（grant 永远 path-bound）；路径归一化支持 Windows drive/UNC/POSIX，绝对路径限定、`..` 拒绝、64 目录/128 目标上限；`createPolicyIdentity` 对完整策略规则做 canonical JSON digest；fail-closed（分析不完整 → undefined）。
- **作用域窗口**（`src/window.ts`）：turn/time 两模式，scopeKey 匹配、时钟回拨防护、128 条上限 + 确定性驱逐。
- **规则匹配**（`src/policy.ts` + `src/types.ts`）：toolName / toolNamePattern(regex) / toolKind / paramMatcher（equals/in/missing/**matches 正则**，字符串匹配大小写不敏感）。→ **clawnify 的 glob/exact/prefix 能力已被正则完全覆盖（regex ⊃ glob）**。
- **租约**（`src/state.ts` AllowAlwaysStore）：allow-always 是 bounded lease（默认 TTL 4h），per-session，grantKey path-bound，`revoke()` 已存在。
- **adaptiveAutoPass**：off/shadow/suggest/enforce 四态，maxUses 预算，TTL 1min-1h clamp。
- **unattended 自动放行**（autoPassSessionKeys）：`:` 段精确匹配，只豁免 require-approval，block 照拦。
- **previews 脱敏 + human_gate_ask 工具**。

**关于 remit 的"诚实 path fence"**：我们已隐式满足——exec/process 没有 verifiedTargets → path 指纹走 pathFallback（默认 none → grantKey undefined），所以 shell 命令的 grant 永远不会假装被路径围住。建议补一个显式单测锁住这个语义（见 P2-4）。

---

## P0（低成本、高价值，建议下一版就做）

> ✅ **全部完成于 v0.5.0（2026-08-15）**：`src/decision-log.ts`（新建）、`src/deny-cooldown.ts`（新建）、`src/self-protection.ts`（新建）+ types/config/index/manifest 接线 + 3 个新测试文件 + runtime-load 集成测试，180 测试全绿。

### P0-1 决策日志（anti-flood 底座 + 审计） ✅

remit 的做法：每个决策写一条 `vaom.decision/0.1` 记录（agent 想要什么、tier、outcome、resolution、latency），参数只存 **digest/名字，不存原始值**，文件 0600。

**改哪里**：
- 新文件 `src/decision-log.ts`：内存 ring buffer（如 512 条）+ 可选落盘 `~/.openclaw/human-gate/decisions.jsonl`（append，digest 参数值）。I/O 失败绝不改变审批结果（best-effort）。
- `src/index.ts`：在 hook 决策点（require-approval 发出、allow-once/allow-always/deny/timeout 结算处）写入记录。字段：`{ts, sessionKey(digest), toolName, decision, ruleId, scopeKey, severity, outcome, latencyMs}`。
- 读路径不阻塞主流程（fire-and-forget 或同步但纯内存）。

**为什么先做它**：P0-2/P0-3 都靠它；它本身也是审计证据，小夭之后想查"谁批了什么"有据可依。

### P0-2 deny cooldown（拒绝冷却） ✅

remit：被 deny 的工具调用，2 分钟（可配）内同类请求自动 block，不再重复弹窗。

**改哪里**：
- `src/config.ts` + `src/types.ts`：`denyCooldownMs`（默认 120_000，0=关）。
- `src/decision-log.ts`（或 state.ts）：记录最近 deny 的 `{toolName, scopeKey, at}`。
- `src/policy.ts` 或 `src/index.ts`：require-approval 分支前查 cooldown——命中 → 直接 `{block: true}`（带 reason "recently denied"），**绝不降级为 auto**，只把 ask 变成 block。
- `test/`：新增 `deny-cooldown.test.mjs`（deny 后重复调用被 block、冷却过期后恢复 ask、只对同 scopeKey 生效）。

### P0-3 自保护（escalation-only 分类升级） ✅

remit：任何 write/edit/apply_patch/exec 的参数引用 `openclaw.json` / 自身状态文件（`.remit/`、grants 文件）→ 分类升级为 **change-settings（默认 Never）**，无论哪个工具携带。**只升不降**。

**改哪里**：
- `src/types.ts`：`SENSITIVE_MARKERS = ["openclaw.json", "human-gate/", ".openclaw/", "grants.json"]`（我们自己的状态路径）+ `EXEC_PARAMS = ["command","cmd","code","script"]` + `FILE_PARAMS = ["path","file","target","to","dest","destination"]`。
- `src/policy.ts`：新增 `classifySensitiveTarget(toolName, params)`，在 user rules **之后**、builtin **之前**（或作为 builtin 最高优先级）插入——命中 → `{mode:"block", severity:"critical"}`。escalation-only：只能把 auto/ask 变 block，不能反向。
- 关键区别：这是**结构性的**（代码放置保证），不是规则配置——grant/allow-always 绕不过它。
- `test/`：`self-protection.test.mjs`（write openclaw.json 被 block；exec 里 `-File openclaw.json` 被 block；读 openclaw.json 不误伤；普通文件写不受影响）。

---

## P1（中成本，第二批）

### P1-1 NEVER_GRANTABLE + blanket 二次确认

remit grants.ts：`NEVER_GRANTABLE = ["spend-money","change-settings"]`——即使手写 grants.json 也拒绝；`blanket`（无 pathScope / for:never）要显式二次确认，默认时长 1h。

**改哪里**：
- `src/state.ts`：`AllowAlwaysGrant` 加 `blanket?: boolean`；grant() 前检查 NEVER_GRANTABLE 映射（对我们：`gateway`、`skill_workshop`、命中自保护的调用 → 拒绝生成 grantKey）。
- `src/index.ts`：allow-always 结算时，若 grant 是宽泛形（无 path 的 category/effect 级）→ 弹二次确认（复用 approval 流）或直接拒绝并提示。
- 顺带：`src/scope.ts` 已保证 grantKey 必须 path-bound 才存在——NEVER_GRANTABLE 是第二道闸，防御"手写配置/未来改动引入宽泛 grant"。

### P1-2 flood detector（审批洪泛检测） ✅（v0.5.1）

remit：Review Queue Flood detector——高频 ask = 你在橡皮图章 → **主动建议** grant，而不是默默继续弹。

**改哪里**：
- `src/decision-log.ts`：加计数窗口（如 60s 内 ask > 8 次）。
- `src/index.ts`：触发时在审批弹窗的 description 里加一行提示（"检测到高频审批，考虑给这条规则开 allow-always 或收窄规则"），**不自动放行、不改变决策**。
- 可选：`suggest` 模式复用 adaptiveAutoPass 的提示通道。

### P1-3 grant 管理面（用户可见的 revoke/查看）

**改哪里**：
- 新工具 `human_gate_grants`（list + revoke）：读 AllowAlwaysStore 的 grants，展示剩余 TTL，支持 revoke。
- 或者最小版：`session_status` 旁路——在审批结算日志里输出当前 grants 快照，用户看日志管理。推荐前者（工具更直接）。
- 注意：工具本身要过 gate（self-gating，类似 clawnify 的 permissions_set 保护——revoke 是安全操作，list 是只读）。

---

## P2（可选 / 远期）

- **P2-1 agent 作用域**：AllowAlwaysGrant 加 `agentId` 字段，grant 只对指定 agent 生效（现在是 per-session，session key 隐含 agent，但显式字段更稳，且为跨会话共享做准备）。
- **P2-2 glob 语法糖**：给规则加字符串 DSL `ToolName(foo:*)`（移植 clawnify rule-parser.ts + matchWildcard 的 null-byte sentinel 转义）编译成现有正则。**纯 UX，能力已被 regex 覆盖，建议先只写文档教正则写法，等用户真的觉得难写再上。**
- **P2-3 规则 category 字段**：GateRule 加可选 `category`，让规则能按 remit 式人类类别聚合展示/授权（改文件/发消息/花钱）。不改变匹配语义，只加聚合维度。
- **P2-4 显式单测锁"诚实 path fence"**：`exec` 的 allow-always 永不产生 path-bound grantKey（防未来重构破坏隐式语义）。
- **P2-5 可执行安全测试**（抄 remit 的 security.test.ts 理念）：test 里静态扫描 src/，若引入出网调用/`process.env` 读取/子进程 spawn 则测试失败。我们插件现在应该也符合（纯本地），锁住它。

---

## 文件改动地图（汇总）

| 文件 | 改动 |
|---|---|
| `src/types.ts` | denyCooldownMs、SENSITIVE_MARKERS、NEVER_GRANTABLE、Grant.blanket/agentId、（可选）rule.category |
| `src/config.ts` | 新配置项解析 + schema |
| `src/policy.ts` | classifySensitiveTarget（P0-3）、cooldown 检查接入（P0-2）、（可选）glob 分支 |
| `src/decision-log.ts` | **新建**：ring buffer + 可选 JSONL + 计数窗口（P0-1 / P1-2） |
| `src/state.ts` | grant 结构扩展、NEVER_GRANTABLE 闸（P1-1）、agentId（P2-1） |
| `src/index.ts` | 决策点埋日志、cooldown 拦截、flood 提示、二次确认、grants 工具注册 |
| `src/scope.ts` | 基本不动（已够强）；如做 P2-2 加 glob→正则编译辅助 |
| `test/*.test.mjs` | deny-cooldown / self-protection / decision-log / flood / grants 新测试 |
| `openclaw.plugin.json` | 新配置项 JSON Schema + 新工具声明 |

## 建议实施顺序

1. **v0.5.0**：P0 三件套（决策日志 → deny cooldown → 自保护）。全是低风险收紧，不改变现有放行面，直接提升安全性。
2. **v0.5.1**：P1（NEVER_GRANTABLE + 二次确认 → flood detector → grants 管理面）。
3. P2 按需。

> 原则不变：语义作用域是收紧，autoAllow 是放开——收紧的先进，放开的单独评审。
