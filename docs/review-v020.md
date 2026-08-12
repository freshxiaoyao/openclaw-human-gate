# v0.2.0 评估报告（2026-08-13）

评估人：大龙虾（主会话，deepseek-v4-flash）
范围：代码审核（全模块）+ 59/59 测试 + tarball 冒烟 + 生产升级验证 + 语义分析抽查/基准
时间：2026-08-13 03:37-03:45

## 结论

**v0.2.0 质量达标，可正式使用。** 发现 1 个真实逻辑缺陷（sudo 穿透不一致）、2 个覆盖缺口（npx 类、PS 大小写），均不阻断上线，建议下一补丁修复。误报率为 0。

## 验证链

| 项目 | 结果 |
|---|---|
| npm run check（typecheck + build + 59 tests） | ✅ |
| tarball（61KB / 73 文件 / dist+docs+manifest） | ✅ |
| tarball 安装→import→register→critical 语义端到端 | ✅ |
| 生产升级 0.1.3→0.2.0（npm update）+ 重启 | ✅ |
| 生产真实审批（web 通道，allow-always + 窗口 + grant 持久化） | ✅ |
| 兼容性：现有 config 字段 + approvals.plugin 微信转发配置 | ✅ 全兼容 |

## 语义分析抽查（21 危险 + 8 安全）

- 命中：rm -rf（含转义/long flags）、curl\|bash、wget\|sh、git push -f/--force-with-lease、git reset --hard、git clean -f、terraform destroy、kubectl delete、生产部署、PS iex、嵌套 sh -c、凭据外传、base64\|bash、cmd /c del
- 安全命令 0 误报：引号内 rm、PS 字符串、git status/log、curl GET、npm run build、PS 只读列举 ✅
- 混淆绕过：变量拼接/命令替换 → warning（文档声明不展开变量，符合预期）；引号插入 r''m → 意外命中；PS -enc → 命中

### 缺陷清单

| # | 严重度 | 问题 | 说明 |
|---|---|---|---|
| 1 | **中** | `sudo rm -rf /` 只报 warning（privilege-elevation），不升 critical | `hasDestructiveRecursiveDelete` 用 `executable()` 未穿透 sudo，而 `hasRemoteInterpreterPipeline` 用 `effectiveExecutable()` 已穿透——**不一致**。`echo x \| sudo rm -rf /` 实测漏 critical |
| 2 | 低 | npx/pnpm dlx/yarn dlx 无规则覆盖 | 供应链攻击常见向量（typosquatting），`npx --yes pkg` 实测只走普通审批 |
| 3 | 低 | isFlag 对 PowerShell 方言大小写敏感 | PS 参数名大小写不敏感，`-RF`/`-Rf` 未命中；实际 `-Rf` 在 PS 是无效参数，风险低 |

### 性能基准（hook 同步路径）

- 常规命令（≤28 字符）：**0.03ms/次**，可忽略
- 16KB 极限命令：**27ms/次**，仅审批场景出现，可接受
- 结论：无性能风险

## 生产运行（03:32:38 重启后）

- 插件注册 6 次、审批解决 5 次、window/grant 各 1（process 审批，用户 web 秒批）——全链路正常
- **已知 UX 问题**：process/sessions_*/subagents 等日常只读工具不在 READONLY 词表，全部弹审批（本次 process 即被拦）。建议加只读白名单规则（已提供配置示例，待用户确认）

## 遗留事项（下一阶段，用户已确认有意推迟）

- 自适应自动放行（需语料误报率测量后才做）
- 语义作用域审批窗口（path root/remote/env/git ref 级 window）
- 微信审批链路端到端验证（sessionFilter 放行 + 微信侧 /approve 解析未闭环）

## 建议

- P0（下一补丁）：sudo 穿透统一用 effectiveExecutable（1 行级改动 + 测试）
- P1：npx/pnpm dlx/yarn dlx → code-execution 规则
- P1：isFlag 方言化（PS 大小写不敏感）
- P0（运维）：加 process 等只读工具白名单规则，消除日常误拦
