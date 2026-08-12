import { scanShell } from "./shell-scan.js";
const EXECUTION_NAMES = /(?:^|[_-])(exec|execute|shell|command|run|terminal)(?:$|[_-])/i;
const COMMAND_KEYS = ["command", "cmd", "shellCommand", "shell_command", "script"];
const MAX_SCANNED_COMMANDS = 32;
const REMOTE_PRODUCERS = new Set([
    "curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod",
]);
const INTERPRETER_SINKS = new Set([
    "sh", "bash", "zsh", "ksh", "csh", "dash", "python", "python3", "node",
    "powershell", "pwsh", "iex", "invoke-expression",
]);
function normalizeExecutable(raw) {
    const leaf = raw.replace(/\\/g, "/").split("/").pop() ?? raw;
    return leaf.replace(/\.exe$/i, "").toLowerCase();
}
function executable(scan, invocationIndex) {
    if (invocationIndex === undefined)
        return "";
    return normalizeExecutable(scan.invocations[invocationIndex]?.tokens[0]?.value ?? "");
}
function effectiveExecutable(scan, invocationIndex) {
    const command = executable(scan, invocationIndex);
    if (command !== "sudo" && command !== "doas")
        return command;
    const args = invocationIndex === undefined
        ? []
        : scan.invocations[invocationIndex]?.tokens.slice(1).map((token) => token.value) ?? [];
    const delegated = args.find((arg) => !arg.startsWith("-"));
    return normalizeExecutable(delegated ?? command);
}
function hasRemoteInterpreterPipeline(scan) {
    return scan.operators.some((operator) => operator.operator === "|" &&
        REMOTE_PRODUCERS.has(effectiveExecutable(scan, operator.leftInvocationIndex)) &&
        INTERPRETER_SINKS.has(effectiveExecutable(scan, operator.rightInvocationIndex)));
}
function isFlag(token, short, long) {
    return token === long || new RegExp(`^-[A-Za-z]*${short}[A-Za-z]*$`).test(token);
}
function hasDestructiveRecursiveDelete(scan) {
    return scan.invocations.some((invocation) => {
        const command = executable(scan, invocation.index);
        const args = invocation.tokens.slice(1).map((token) => token.value);
        if (command === "rm") {
            return args.some((arg) => isFlag(arg, "r", "--recursive")) &&
                args.some((arg) => isFlag(arg, "f", "--force"));
        }
        if (["remove-item", "ri"].includes(command)) {
            return args.some((arg) => /^-(?:recurse|r)$/i.test(arg)) &&
                args.some((arg) => /^-(?:force|fo)$/i.test(arg));
        }
        if (["rmdir", "rd", "del", "erase"].includes(command)) {
            return args.some((arg) => /^\/s$/i.test(arg)) &&
                args.some((arg) => /^\/q$/i.test(arg));
        }
        return false;
    });
}
function invocationParts(scan, invocationIndex) {
    const invocation = scan.invocations[invocationIndex];
    return {
        command: executable(scan, invocationIndex),
        args: invocation?.tokens.slice(1).map((token) => token.value) ?? [],
    };
}
function anyInvocation(scans, predicate) {
    return scans.some((scan) => scan.invocations.some((invocation) => {
        const parts = invocationParts(scan, invocation.index);
        return predicate(parts.command, parts.args);
    }));
}
function hasGitForcePush(scans) {
    return anyInvocation(scans, (command, args) => {
        if (command !== "git")
            return false;
        const pushIndex = args.findIndex((arg) => arg.toLowerCase() === "push");
        if (pushIndex < 0)
            return false;
        return args.slice(pushIndex + 1).some((arg) => arg === "-f" || /^--force(?:-with-lease)?(?:=|$)/i.test(arg) || arg === "--mirror");
    });
}
function hasGitDestructiveHistory(scans) {
    return anyInvocation(scans, (command, args) => {
        if (command !== "git")
            return false;
        const lower = args.map((arg) => arg.toLowerCase());
        const reset = lower.indexOf("reset");
        const clean = lower.indexOf("clean");
        const branch = lower.indexOf("branch");
        return reset >= 0 && lower.slice(reset + 1).includes("--hard") ||
            clean >= 0 && lower.slice(clean + 1).some((arg) => /^-[a-z]*f[a-z]*$/i.test(arg)) ||
            branch >= 0 && args.slice(branch + 1).includes("-D");
    });
}
function hasInfrastructureDestruction(scans) {
    return anyInvocation(scans, (command, args) => {
        const lower = args.map((arg) => arg.toLowerCase());
        return command === "terraform" && (lower.includes("destroy") ||
            lower.includes("apply") && lower.includes("-auto-approve")) || command === "kubectl" && lower.includes("delete") ||
            command === "helm" && lower.includes("uninstall");
    });
}
function hasProductionDeployment(scans) {
    return anyInvocation(scans, (command, args) => {
        const words = [command, ...args].map((word) => word.toLowerCase());
        return words.some((word) => /^(?:deploy|release|publish)$/.test(word)) &&
            words.some((word) => /^(?:prod|production)$/.test(word));
    });
}
function hasEncodedOrDynamicExecution(scans) {
    return anyInvocation(scans, (command, args) => {
        const words = [command, ...args];
        return ["iex", "invoke-expression", "eval"].includes(command) ||
            words.some((word) => /^-(?:encodedcommand|enc)$/i.test(word)) ||
            words.some((word) => /frombase64string/i.test(word));
    }) || scans.some((scan) => scan.operators.some((operator) => {
        if (operator.operator !== "|")
            return false;
        return executable(scan, operator.leftInvocationIndex) === "base64" &&
            INTERPRETER_SINKS.has(executable(scan, operator.rightInvocationIndex));
    }));
}
function hasCredentialExfiltration(scans) {
    const sensitive = /(?:\.env\b|id_(?:rsa|ed25519)\b|credentials\b|api[_-]?key|access[_-]?token|secret[_-]?key)/i;
    const network = new Set([
        "curl", "wget", "scp", "sftp", "nc", "invoke-webrequest", "invoke-restmethod", "iwr", "irm",
    ]);
    return scans.some((scan) => {
        const hasSensitiveSource = scan.invocations.some((invocation) => invocation.tokens.some((token) => sensitive.test(token.value)));
        const hasNetworkSink = scan.invocations.some((invocation) => network.has(executable(scan, invocation.index)));
        return hasSensitiveSource && hasNetworkSink;
    });
}
function hasPrivilegeElevation(scans) {
    return anyInvocation(scans, (command, args) => command === "sudo" || command === "doas" || command === "runas" ||
        command === "start-process" && args.some((arg, index) => /^-verb$/i.test(arg) && /^runas$/i.test(args[index + 1] ?? "")));
}
function hasOutputWrite(scans) {
    const writers = new Set(["set-content", "add-content", "out-file", "tee"]);
    return scans.some((scan) => scan.redirections.length > 0) ||
        anyInvocation(scans, (command) => writers.has(command));
}
function wrappedCommand(scan, invocationIndex) {
    let { command, args } = invocationParts(scan, invocationIndex);
    if (command === "sudo" || command === "doas") {
        const commandIndex = args.findIndex((arg) => !arg.startsWith("-"));
        if (commandIndex < 0)
            return undefined;
        command = normalizeExecutable(args[commandIndex] ?? "");
        args = args.slice(commandIndex + 1);
    }
    let marker;
    if (["sh", "bash", "zsh", "ksh", "csh", "dash"].includes(command)) {
        marker = args.findIndex((arg) => arg === "-c");
    }
    else if (command === "cmd") {
        marker = args.findIndex((arg) => /^\/c$/i.test(arg));
    }
    else if (command === "powershell" || command === "pwsh") {
        marker = args.findIndex((arg) => /^-(?:command|c)$/i.test(arg));
    }
    else {
        return undefined;
    }
    if (marker < 0 || marker + 1 >= args.length)
        return undefined;
    return args.slice(marker + 1).join(" ");
}
function scanDialects(command, maxWrapperDepth) {
    const dialects = ["posix", "powershell", "cmd"];
    const scans = [];
    const seen = new Set();
    let wrapperLimitReached = false;
    const visit = (value, depth) => {
        if (seen.has(value))
            return;
        if (seen.size >= MAX_SCANNED_COMMANDS) {
            wrapperLimitReached = true;
            return;
        }
        seen.add(value);
        const current = dialects.map((dialect) => scanShell(value, dialect));
        scans.push(...current);
        for (const scan of current) {
            for (const invocation of scan.invocations) {
                const inner = wrappedCommand(scan, invocation.index);
                if (!inner)
                    continue;
                if (depth >= maxWrapperDepth) {
                    wrapperLimitReached = true;
                    continue;
                }
                visit(inner, depth + 1);
            }
        }
    };
    visit(command, 0);
    return { scans, wrapperLimitReached };
}
const RULES = [
    {
        id: "command.remote-pipe-to-shell",
        category: "execution",
        severity: "critical",
        confidence: "high",
        title: "Remote content is piped into an interpreter",
        explanation: "Downloaded content may execute without being reviewed locally.",
        effect: "code-execution",
        disablesWindow: true,
        matches: (_value, scans) => scans.some(hasRemoteInterpreterPipeline),
    },
    {
        id: "command.destructive-recursive-delete",
        category: "filesystem",
        severity: "critical",
        confidence: "high",
        title: "Recursive forced deletion",
        explanation: "The command can remove a directory tree without interactive confirmation.",
        effect: "destructive",
        disablesWindow: true,
        matches: (_value, scans) => scans.some(hasDestructiveRecursiveDelete),
    },
    {
        id: "command.git-force-push",
        category: "source-control",
        severity: "critical",
        confidence: "high",
        title: "Force push rewrites remote history",
        explanation: "Existing remote commits may become unreachable for collaborators.",
        effect: "destructive",
        disablesWindow: true,
        matches: (_value, scans) => hasGitForcePush(scans),
    },
    {
        id: "command.git-destructive-history",
        category: "source-control",
        severity: "critical",
        confidence: "high",
        title: "Destructive Git history or worktree operation",
        explanation: "The command can discard uncommitted work or repository history.",
        effect: "destructive",
        disablesWindow: true,
        matches: (_value, scans) => hasGitDestructiveHistory(scans),
    },
    {
        id: "command.infrastructure-destructive",
        category: "deployment",
        severity: "critical",
        confidence: "high",
        title: "Infrastructure-destructive command",
        explanation: "The command can delete or irreversibly change managed infrastructure.",
        effect: "destructive",
        disablesWindow: true,
        matches: (_value, scans) => hasInfrastructureDestruction(scans),
    },
    {
        id: "command.production-deployment",
        category: "deployment",
        severity: "critical",
        confidence: "medium",
        title: "Production deployment target",
        explanation: "The command appears to deploy, publish, or release to a production environment.",
        effect: "network-write",
        disablesWindow: true,
        matches: (_value, scans) => hasProductionDeployment(scans),
    },
    {
        id: "command.encoded-or-dynamic-execution",
        category: "obfuscation",
        severity: "critical",
        confidence: "medium",
        title: "Encoded or dynamic execution",
        explanation: "The executable payload is obscured or assembled dynamically, reducing reviewability.",
        effect: "code-execution",
        disablesWindow: true,
        matches: (_value, scans) => hasEncodedOrDynamicExecution(scans),
    },
    {
        id: "command.possible-credential-exfiltration",
        category: "credentials",
        severity: "critical",
        confidence: "medium",
        title: "Sensitive material may be sent over the network",
        explanation: "The command references a likely credential source and a network transfer command.",
        effect: "network-write",
        disablesWindow: true,
        matches: (_value, scans) => hasCredentialExfiltration(scans),
    },
    {
        id: "command.privilege-elevation",
        category: "privilege",
        severity: "warning",
        confidence: "high",
        title: "Privilege elevation",
        explanation: "The command requests elevated operating-system privileges.",
        effect: "privilege-change",
        matches: (_value, scans) => hasPrivilegeElevation(scans),
    },
    {
        id: "command.output-redirection",
        category: "filesystem",
        severity: "warning",
        confidence: "medium",
        title: "Shell output redirection writes data",
        explanation: "The command redirects output into a file or content-writing shell command.",
        effect: "local-write",
        matches: (_value, scans) => hasOutputWrite(scans),
    },
    {
        id: "command.dynamic-expansion",
        category: "execution",
        severity: "warning",
        confidence: "medium",
        title: "Command contains dynamic expansion",
        explanation: "Variables or substitutions can change the effective command at runtime.",
        effect: "unknown",
        disablesWindow: true,
        matches: (_value, scans) => scans.some((scan) => scan.tokens.some((token) => token.dynamic)),
    },
];
export function extractCommand(context) {
    if (context.toolKind === "code_mode_exec")
        return undefined;
    for (const key of COMMAND_KEYS) {
        const value = context.params[key];
        if (typeof value === "string" && value.trim())
            return { key, value };
    }
    return undefined;
}
function supportsExecution(context) {
    if (!extractCommand(context))
        return false;
    return EXECUTION_NAMES.test(context.toolName) ||
        context.toolName.toLowerCase() === "exec";
}
function findingFor(rule, excerpt) {
    return {
        id: rule.id,
        category: rule.category,
        severity: rule.severity,
        confidence: rule.confidence,
        title: rule.title,
        explanation: rule.explanation,
        evidence: { source: "command", excerpt },
    };
}
export class CommandAnalyzer {
    config;
    id = "builtin.command-semantics";
    priority = 100;
    constructor(config) {
        this.config = config;
    }
    supports(context) {
        return supportsExecution(context);
    }
    analyze(context) {
        const extracted = extractCommand(context);
        if (!extracted) {
            return {
                analyzerId: this.id,
                findings: [],
                effects: [],
                windowEligible: true,
            };
        }
        const wasTruncated = extracted.value.length > this.config.maxCommandLength;
        const command = extracted.value.slice(0, this.config.maxCommandLength);
        const excerpt = command.slice(0, 320);
        const bundle = scanDialects(command, this.config.maxWrapperDepth);
        const scans = bundle.scans;
        const parseIncomplete = scans.slice(0, 3).filter((scan) => !scan.complete).length >= 2;
        const matchedRules = RULES.filter((rule) => rule.matches(command, scans));
        const findings = matchedRules
            .map((rule) => findingFor(rule, excerpt));
        if (wasTruncated) {
            findings.unshift({
                id: "command.input-truncated",
                category: "unknown",
                severity: "warning",
                confidence: "low",
                title: "Command exceeds analysis limit",
                explanation: "Only the configured prefix was analyzed; approval-window reuse is disabled.",
                evidence: { source: "command", excerpt },
            });
        }
        if (bundle.wrapperLimitReached) {
            findings.unshift({
                id: "command.wrapper-depth-exceeded",
                category: "unknown",
                severity: "warning",
                confidence: "low",
                title: "Nested command exceeds wrapper analysis limit",
                explanation: "A nested shell payload could not be fully inspected; window reuse is disabled.",
                evidence: { source: "command", excerpt },
            });
        }
        if (parseIncomplete) {
            findings.unshift({
                id: "command.parse-incomplete",
                category: "unknown",
                severity: "warning",
                confidence: "low",
                title: "Command syntax could not be fully scanned",
                explanation: "The input is malformed or incomplete; window reuse is disabled.",
                evidence: { source: "command", excerpt },
            });
        }
        const critical = findings.some((finding) => finding.severity === "critical");
        const windowEligible = !wasTruncated &&
            !bundle.wrapperLimitReached &&
            !parseIncomplete &&
            !matchedRules.some((rule) => rule.disablesWindow);
        const effects = [...new Set(matchedRules.map((rule) => rule.effect))];
        return {
            analyzerId: this.id,
            findings,
            effects,
            minimumMode: findings.length > 0 ? "require-approval" : undefined,
            minimumSeverity: critical ? "critical" : findings.length > 0 ? "warning" : undefined,
            windowEligible,
        };
    }
}
//# sourceMappingURL=command.js.map