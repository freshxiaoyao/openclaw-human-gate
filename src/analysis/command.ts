import type { SemanticAnalysisConfig } from "../types.js";
import type {
  AnalysisResult,
  RiskCategory,
  RiskFinding,
  ToolCallAnalyzer,
  ToolCallContext,
  ToolEffect,
} from "./types.js";
import { scanShell, type ShellDialect, type ShellScanResult } from "./shell-scan.js";

interface CommandRule {
  id: string;
  category: RiskCategory;
  severity: "warning" | "critical";
  confidence: "high" | "medium";
  title: string;
  explanation: string;
  effect: ToolEffect;
  disablesWindow?: boolean;
  matches(command: string, scans: readonly ShellScanResult[]): boolean;
}

interface CommandScanBundle {
  scans: ShellScanResult[];
  wrapperLimitReached: boolean;
}

const EXECUTION_NAMES = /(?:^|[_-])(exec|execute|shell|command|run|terminal)(?:$|[_-])/i;
const COMMAND_KEYS = ["command", "cmd", "shellCommand", "shell_command", "script"] as const;
const MAX_SCANNED_COMMANDS = 32;

const REMOTE_PRODUCERS = new Set([
  "curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod",
]);
const INTERPRETER_SINKS = new Set([
  "sh", "bash", "zsh", "ksh", "csh", "dash", "python", "python3", "node",
  "powershell", "pwsh", "iex", "invoke-expression",
]);

function normalizeExecutable(raw: string): string {
  const leaf = raw.replace(/\\/g, "/").split("/").pop() ?? raw;
  return leaf.replace(/\.exe$/i, "").toLowerCase();
}

function executable(scan: ShellScanResult, invocationIndex: number | undefined): string {
  if (invocationIndex === undefined) return "";
  return normalizeExecutable(scan.invocations[invocationIndex]?.tokens[0]?.value ?? "");
}

const SUDO_SHORT_OPTIONS_WITH_VALUE = new Set([
  "a", "C", "D", "g", "h", "p", "R", "r", "T", "t", "U", "u",
]);
const SUDO_LONG_OPTIONS_WITH_VALUE = new Set([
  "auth-type", "chdir", "chroot", "close-from", "command-timeout", "group",
  "host", "other-user", "prompt", "role", "type", "user",
]);
const DOAS_SHORT_OPTIONS_WITH_VALUE = new Set(["a", "C", "u"]);

/** Find the delegated executable without mistaking an option value (for
 * example `root` in `sudo -u root rm`) for the command. */
function delegatedCommandIndex(command: string, args: readonly string[]): number | undefined {
  const shortWithValue = command === "sudo"
    ? SUDO_SHORT_OPTIONS_WITH_VALUE
    : DOAS_SHORT_OPTIONS_WITH_VALUE;
  let index = 0;
  while (index < args.length) {
    const arg = args[index] ?? "";
    if (arg === "--") return index + 1 < args.length ? index + 1 : undefined;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(arg)) {
      index += 1;
      continue;
    }
    if (arg.startsWith("--")) {
      const equals = arg.indexOf("=");
      const name = arg.slice(2, equals < 0 ? undefined : equals);
      if (command === "sudo" && SUDO_LONG_OPTIONS_WITH_VALUE.has(name) && equals < 0) {
        index += 2;
      } else {
        index += 1;
      }
      continue;
    }
    if (arg.startsWith("-") && arg !== "-") {
      let consumesNext = false;
      for (let offset = 1; offset < arg.length; offset += 1) {
        if (!shortWithValue.has(arg[offset] ?? "")) continue;
        consumesNext = offset === arg.length - 1;
        break;
      }
      index += consumesNext ? 2 : 1;
      continue;
    }
    return index;
  }
  return undefined;
}

const ENV_OPTIONS_WITH_VALUE = new Set([
  "-u", "--unset", "-C", "--chdir", "-S", "--split-string",
]);
const ENV_TERMINAL_OPTIONS = new Set(["--help", "--version"]);

function envCommandIndex(args: readonly string[]): number | undefined {
  let index = 0;
  while (index < args.length) {
    const arg = args[index] ?? "";
    if (arg === "--") return index + 1 < args.length ? index + 1 : undefined;
    if (ENV_TERMINAL_OPTIONS.has(arg)) return undefined;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(arg)) {
      index += 1;
      continue;
    }
    if (/^-(?:u|C).+/.test(arg)) {
      index += 1;
      continue;
    }
    if (arg.startsWith("-S") && arg !== "-S") return undefined;
    const optionName = arg.split("=", 1)[0] ?? arg;
    if (ENV_OPTIONS_WITH_VALUE.has(optionName)) {
      if (optionName === "-S" || optionName === "--split-string") {
        // The value is itself re-tokenized by env. Treat it as opaque rather
        // than incorrectly authorizing or classifying its first word.
        return undefined;
      }
      index += arg.includes("=") ? 1 : 2;
      continue;
    }
    if (arg.startsWith("-") && arg !== "-") {
      // Known flag-only forms include -i/-0/--ignore-environment/--null and
      // --debug. Unknown options are skipped conservatively for risk finding;
      // shell reuse remains disabled unless the complete intent is Git.
      index += 1;
      continue;
    }
    return index;
  }
  return undefined;
}

function commandBuiltinCommandIndex(args: readonly string[]): number | undefined {
  let index = 0;
  while (index < args.length) {
    const arg = args[index] ?? "";
    if (arg === "--") return index + 1 < args.length ? index + 1 : undefined;
    // `command -v/-V` queries metadata and does not execute the argument.
    if (arg === "-v" || arg === "-V") return undefined;
    if (arg === "-p") {
      index += 1;
      continue;
    }
    if (arg.startsWith("-") && arg !== "-") return undefined;
    return index;
  }
  return undefined;
}

function nohupCommandIndex(args: readonly string[]): number | undefined {
  if (args.length === 0 || args[0] === "--help" || args[0] === "--version") return undefined;
  return args[0] === "--" ? (args.length > 1 ? 1 : undefined) : 0;
}

function busyBoxAppletIndex(args: readonly string[]): number | undefined {
  if (args.length === 0) return undefined;
  const first = args[0] ?? "";
  // BusyBox has meta-options, but no generic `--` command delimiter. Only a
  // non-option first argument is an applet name.
  return first.startsWith("-") ? undefined : 0;
}

function effectiveInvocationParts(scan: ShellScanResult, invocationIndex: number | undefined): {
  command: string;
  args: string[];
} {
  if (invocationIndex === undefined) return { command: "", args: [] };
  const invocation = scan.invocations[invocationIndex];
  let command = executable(scan, invocationIndex);
  let args = invocation?.tokens.slice(1).map((token) => token.value) ?? [];

  // Static wrapper peeling is deliberately bounded. It is used only to find
  // high-risk executables; dynamic tokens separately make analysis incomplete.
  for (let depth = 0; depth < 16; depth += 1) {
    let delegatedIndex: number | undefined;
    if (command === "sudo" || command === "doas") {
      delegatedIndex = delegatedCommandIndex(command, args);
    } else if (command === "env") {
      delegatedIndex = envCommandIndex(args);
    } else if (command === "command") {
      delegatedIndex = commandBuiltinCommandIndex(args);
    } else if (command === "nohup") {
      delegatedIndex = nohupCommandIndex(args);
    } else if (command === "busybox" || command.startsWith("busybox.")) {
      delegatedIndex = busyBoxAppletIndex(args);
    } else {
      return { command, args };
    }

    if (delegatedIndex === undefined) return { command: "", args: [] };
    command = normalizeExecutable(args[delegatedIndex] ?? "");
    args = args.slice(delegatedIndex + 1);
  }
  return { command: "", args: [] };
}

function effectiveExecutable(scan: ShellScanResult, invocationIndex: number | undefined): string {
  return effectiveInvocationParts(scan, invocationIndex).command;
}

function hasRemoteInterpreterPipeline(scan: ShellScanResult): boolean {
  return scan.operators.some((operator) =>
    operator.operator === "|" &&
    REMOTE_PRODUCERS.has(effectiveExecutable(scan, operator.leftInvocationIndex)) &&
    INTERPRETER_SINKS.has(effectiveExecutable(scan, operator.rightInvocationIndex)));
}

function isFlag(token: string, short: string, long: string): boolean {
  return token === long || new RegExp(`^-[A-Za-z]*${short}[A-Za-z]*$`).test(token);
}

function hasDestructiveRecursiveDelete(scan: ShellScanResult): boolean {
  return scan.invocations.some((invocation) => {
    const { command, args } = effectiveInvocationParts(scan, invocation.index);
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

function invocationParts(scan: ShellScanResult, invocationIndex: number): {
  command: string;
  args: string[];
} {
  const invocation = scan.invocations[invocationIndex];
  return {
    command: executable(scan, invocationIndex),
    args: invocation?.tokens.slice(1).map((token) => token.value) ?? [],
  };
}

function anyInvocation(
  scans: readonly ShellScanResult[],
  predicate: (command: string, args: readonly string[]) => boolean,
): boolean {
  return scans.some((scan) => scan.invocations.some((invocation) => {
    const parts = invocationParts(scan, invocation.index);
    return predicate(parts.command, parts.args);
  }));
}

function anyEffectiveInvocation(
  scans: readonly ShellScanResult[],
  predicate: (command: string, args: readonly string[]) => boolean,
): boolean {
  return scans.some((scan) => scan.invocations.some((invocation) => {
    const parts = effectiveInvocationParts(scan, invocation.index);
    return predicate(parts.command, parts.args);
  }));
}

const GIT_GLOBAL_OPTIONS_WITH_VALUE = new Set([
  "-C", "-c", "--config-env", "--exec-path", "--git-dir", "--namespace",
  "--super-prefix", "--work-tree",
]);

function gitSubcommand(args: readonly string[]): { name: string; index: number } | undefined {
  let index = 0;
  while (index < args.length) {
    const arg = args[index] ?? "";
    if (arg === "--") {
      index += 1;
      break;
    }
    if (!arg.startsWith("-")) break;
    const optionName = arg.split("=", 1)[0] ?? arg;
    if (GIT_GLOBAL_OPTIONS_WITH_VALUE.has(optionName) && !arg.includes("=")) {
      // -Cpath and -cname=value carry their value in the same token.
      if ((arg.startsWith("-C") || arg.startsWith("-c")) && arg.length > 2) {
        index += 1;
      } else {
        index += 2;
      }
    } else {
      index += 1;
    }
  }
  const name = args[index]?.toLowerCase();
  return name ? { name, index } : undefined;
}

function hasGitIntent(scans: readonly ShellScanResult[], intent: "commit" | "push"): boolean {
  return anyEffectiveInvocation(scans, (command, args) =>
    command === "git" && gitSubcommand(args)?.name === intent);
}

function hasGitForcePush(scans: readonly ShellScanResult[]): boolean {
  return anyEffectiveInvocation(scans, (command, args) => {
    if (command !== "git") return false;
    const subcommand = gitSubcommand(args);
    if (subcommand?.name !== "push") return false;
    const pushIndex = subcommand.index;
    return args.slice(pushIndex + 1).some((arg) =>
      arg === "-f" || /^--force(?:-with-lease)?(?:=|$)/i.test(arg) || arg === "--mirror");
  });
}

function hasGitDestructiveHistory(scans: readonly ShellScanResult[]): boolean {
  return anyInvocation(scans, (command, args) => {
    if (command !== "git") return false;
    const lower = args.map((arg) => arg.toLowerCase());
    const reset = lower.indexOf("reset");
    const clean = lower.indexOf("clean");
    const branch = lower.indexOf("branch");
    return reset >= 0 && lower.slice(reset + 1).includes("--hard") ||
      clean >= 0 && lower.slice(clean + 1).some((arg) => /^-[a-z]*f[a-z]*$/i.test(arg)) ||
      branch >= 0 && args.slice(branch + 1).includes("-D");
  });
}

function hasInfrastructureDestruction(scans: readonly ShellScanResult[]): boolean {
  return anyInvocation(scans, (command, args) => {
    const lower = args.map((arg) => arg.toLowerCase());
    return command === "terraform" && (
      lower.includes("destroy") ||
      lower.includes("apply") && lower.includes("-auto-approve")
    ) || command === "kubectl" && lower.includes("delete") ||
      command === "helm" && lower.includes("uninstall");
  });
}

function hasProductionDeployment(scans: readonly ShellScanResult[]): boolean {
  return anyInvocation(scans, (command, args) => {
    const words = [command, ...args].map((word) => word.toLowerCase());
    return words.some((word) => /^(?:deploy|release|publish)$/.test(word)) &&
      words.some((word) => /^(?:prod|production)$/.test(word));
  });
}

function hasEncodedOrDynamicExecution(scans: readonly ShellScanResult[]): boolean {
  return anyInvocation(scans, (command, args) => {
    const words = [command, ...args];
    return ["iex", "invoke-expression", "eval"].includes(command) ||
      words.some((word) => /^-(?:encodedcommand|enc)$/i.test(word)) ||
      words.some((word) => /frombase64string/i.test(word));
  }) || scans.some((scan) => scan.operators.some((operator) => {
    if (operator.operator !== "|") return false;
    return executable(scan, operator.leftInvocationIndex) === "base64" &&
      INTERPRETER_SINKS.has(executable(scan, operator.rightInvocationIndex));
  }));
}

function hasCredentialExfiltration(scans: readonly ShellScanResult[]): boolean {
  const sensitive = /(?:\.env\b|id_(?:rsa|ed25519)\b|credentials\b|api[_-]?key|access[_-]?token|secret[_-]?key)/i;
  const network = new Set([
    "curl", "wget", "scp", "sftp", "nc", "invoke-webrequest", "invoke-restmethod", "iwr", "irm",
  ]);
  return scans.some((scan) => {
    const hasSensitiveSource = scan.invocations.some((invocation) =>
      invocation.tokens.some((token) => sensitive.test(token.value)));
    const hasNetworkSink = scan.invocations.some((invocation) =>
      network.has(executable(scan, invocation.index)));
    return hasSensitiveSource && hasNetworkSink;
  });
}

function hasPrivilegeElevation(scans: readonly ShellScanResult[]): boolean {
  return anyInvocation(scans, (command, args) =>
    command === "sudo" || command === "doas" || command === "runas" ||
    command === "start-process" && args.some((arg, index) =>
      /^-verb$/i.test(arg) && /^runas$/i.test(args[index + 1] ?? "")));
}

function hasOutputWrite(scans: readonly ShellScanResult[]): boolean {
  const writers = new Set(["set-content", "add-content", "out-file", "tee"]);
  return scans.some((scan) => scan.redirections.length > 0) ||
    anyInvocation(scans, (command) => writers.has(command));
}

function wrappedCommand(scan: ShellScanResult, invocationIndex: number): string | undefined {
  const { command, args } = effectiveInvocationParts(scan, invocationIndex);

  let marker: number;
  if (["sh", "bash", "zsh", "ksh", "csh", "dash"].includes(command)) {
    marker = args.findIndex((arg) => arg === "-c");
  } else if (command === "cmd") {
    marker = args.findIndex((arg) => /^\/c$/i.test(arg));
  } else if (command === "powershell" || command === "pwsh") {
    marker = args.findIndex((arg) => /^-(?:command|c)$/i.test(arg));
  } else {
    return undefined;
  }
  if (marker < 0 || marker + 1 >= args.length) return undefined;
  return args.slice(marker + 1).join(" ");
}

function scanDialects(command: string, maxWrapperDepth: number): CommandScanBundle {
  const dialects: ShellDialect[] = ["posix", "powershell", "cmd"];
  const scans: ShellScanResult[] = [];
  const seen = new Set<string>();
  let wrapperLimitReached = false;

  const visit = (value: string, depth: number): void => {
    if (seen.has(value)) return;
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
        if (!inner) continue;
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

const RULES: readonly CommandRule[] = [
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
    id: "command.git-push",
    category: "source-control",
    severity: "warning",
    confidence: "high",
    title: "Git push writes to a remote repository",
    explanation: "The command publishes local refs to a configured remote.",
    effect: "network-write",
    matches: (_value, scans) => hasGitIntent(scans, "push"),
  },
  {
    id: "command.git-commit",
    category: "source-control",
    severity: "warning",
    confidence: "high",
    title: "Git commit writes local repository history",
    explanation: "The command creates a commit in the local repository.",
    effect: "local-write",
    matches: (_value, scans) => hasGitIntent(scans, "commit"),
  },
  {
    id: "command.dev-build",
    category: "dev-build",
    severity: "warning",
    confidence: "high",
    title: "Build command",
    explanation: "Compiles or bundles the project. Reusable within an approval window.",
    effect: "code-execution",
    matches: (_value, scans) => anyDevIntent(scans, "build"),
  },
  {
    id: "command.dev-test",
    category: "dev-test",
    severity: "warning",
    confidence: "high",
    title: "Test command",
    explanation: "Runs the project test suite. Reusable within an approval window.",
    effect: "code-execution",
    matches: (_value, scans) => anyDevIntent(scans, "test"),
  },
  {
    id: "command.dev-format",
    category: "dev-format",
    severity: "warning",
    confidence: "high",
    title: "Code formatting command",
    explanation: "Rewrites source files to match a formatting convention. Reusable within an approval window.",
    effect: "local-write",
    matches: (_value, scans) => anyDevIntent(scans, "format"),
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
    matches: (_value, scans) => scans.some((scan) =>
      scan.tokens.some((token) => token.dynamic)),
  },
];

export interface ExtractedCommand {
  key: string;
  value: string;
}

export function extractCommand(context: ToolCallContext): ExtractedCommand | undefined {
  if (context.toolKind === "code_mode_exec") return undefined;
  for (const key of COMMAND_KEYS) {
    const value = context.params[key];
    if (typeof value === "string" && value.trim()) return { key, value };
  }
  return undefined;
}

function supportsExecution(context: ToolCallContext): boolean {
  if (context.toolKind !== undefined || context.toolInputKind !== undefined) return false;
  if (!extractCommand(context)) return false;
  return EXECUTION_NAMES.test(context.toolName) ||
    context.toolName.toLowerCase() === "exec";
}

function findingFor(rule: CommandRule, excerpt: string): RiskFinding {
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

/** Recognized, reusable development-loop intents. Each maps to a distinct
 * semantic category so approving one does not silently authorize another. */
type DevIntent = "git-commit" | "git-push" | "build" | "test" | "format";

/** Extract the script name from `npm|yarn|pnpm|bun [run|run-script|exec] <name>`. */
function packageManagerScript(args: readonly string[]): string | undefined {
  let index = 0;
  const first = args[0]?.toLowerCase();
  if (first === "run" || first === "run-script" || first === "exec") index = 1;
  const script = args[index];
  if (!script || script.startsWith("-")) return undefined;
  return script.toLowerCase();
}

/** Conservative classifier over a single, already wrapper-peeled invocation.
 * Anything ambiguous returns undefined and remains fail-closed (per-approval).
 * Only the write forms of formatters are reusable; their check-only forms
 * (`prettier --check`, `eslint` without `--fix`, `gofmt -l`) stay fail-closed. */
function classifyIntent(command: string, args: readonly string[]): DevIntent | undefined {
  if (command === "git") {
    const sub = gitSubcommand(args)?.name;
    if (sub === "commit") return "git-commit";
    if (sub === "push") return "git-push";
    return undefined;
  }
  const lower = args.map((arg) => arg.toLowerCase());

  if (command === "npm" || command === "yarn" || command === "pnpm" || command === "bun") {
    const script = packageManagerScript(args);
    if (script === "build") return "build";
    if (script === "test") return "test";
    if (script === "format" || script === "fmt") return "format";
    return undefined;
  }

  if (command === "make" || command === "ninja" || command === "tsc" ||
      command === "babel" || command === "webpack" || command === "esbuild" ||
      command === "rollup") {
    return "build";
  }
  if (command === "vite") return lower.includes("build") ? "build" : undefined;
  if (command === "cargo") {
    if (lower[0] === "build") return "build";
    if (lower[0] === "test") return "test";
    if (lower[0] === "fmt") return "format";
    return undefined;
  }
  if (command === "go") {
    if (lower[0] === "build") return "build";
    if (lower[0] === "test") return "test";
    return undefined;
  }
  if (command === "dotnet") {
    if (lower[0] === "build") return "build";
    if (lower[0] === "test") return "test";
    return undefined;
  }
  if (command === "gradle" || command === "mvn" || command === "maven" || command === "sbt") {
    if (lower[0] === "build") return "build";
    if (lower[0] === "test") return "test";
    if (lower[0] === "compile" || lower[0] === "package" || lower[0] === "install") return "build";
    return undefined;
  }

  if (command === "pytest" || command === "py.test" || command === "jest" ||
      command === "vitest" || command === "mocha" || command === "ava") {
    return "test";
  }

  if (command === "rustfmt" || command === "black" || command === "isort") return "format";
  if (command === "prettier") return lower.includes("--write") || lower.includes("-w") ? "format" : undefined;
  if (command === "eslint") return lower.includes("--fix") ? "format" : undefined;
  if (command === "gofmt" || command === "gofumpt") return lower.includes("-w") ? "format" : undefined;
  if (command === "clang-format") return lower.includes("-i") ? "format" : undefined;

  return undefined;
}

/** Loose intent detection across any (wrapper-peeled) invocation, used only
 * for risk findings — never to mint a reusable authorization. */
function anyDevIntent(scans: readonly ShellScanResult[], intent: DevIntent): boolean {
  return anyEffectiveInvocation(scans, (command, args) => classifyIntent(command, args) === intent);
}

/** A reusable semantic authorization must not be minted from a partially
 * understood shell program. Completeness requires a single, non-dynamic,
 * operator/redirection-free invocation across all three dialects that all
 * agree on one recognized intent. Other commands are still risk-scanned but
 * remain fail-closed. */
function completeIntent(scans: readonly ShellScanResult[]): DevIntent | undefined {
  const rootScans = scans.slice(0, 3);
  if (rootScans.length !== 3) return undefined;
  const intents = new Set<DevIntent>();
  for (const scan of rootScans) {
    if (!scan.complete || scan.invocations.length !== 1 || scan.operators.length > 0 ||
      scan.redirections.length > 0 || scan.tokens.some((token) => token.dynamic)) {
      return undefined;
    }
    const invocation = scan.invocations[0];
    const { command, args } = effectiveInvocationParts(scan, invocation?.index);
    const intent = classifyIntent(command, args);
    if (!intent) return undefined;
    intents.add(intent);
  }
  return intents.size === 1 ? [...intents][0] : undefined;
}

const READONLY_GIT_SUBCOMMANDS = new Set([
  "status", "diff", "log", "show", "grep", "blame", "ls-files", "rev-parse",
]);

/** Conservative read-only executables. Commands with write flags are excluded
 * (`sort -o`, `tee`, `sed -i`, `find -delete`/`-exec`) so an auto rule can
 * never silently authorize a filesystem write. */
const READONLY_EXECUTABLES = new Set([
  // POSIX
  "cat", "head", "tail", "less", "more", "wc", "uniq", "comm", "grep", "egrep",
  "rg", "ls", "locate", "echo", "printf", "pwd", "whoami", "hostname", "date",
  "uname", "id", "df", "du", "true", "false", "test", "which", "where",
  "whereis", "type", "file", "stat", "cmp", "diff", "cut", "tr", "dirname",
  "basename", "realpath", "readlink",
  // PowerShell read-only cmdlets
  "get-childitem", "get-content", "get-location", "get-date", "get-process",
  "get-service", "get-item", "get-itemproperty", "select-string", "test-path",
  "measure-object", "where-object", "resolve-path", "split-path", "join-path",
  "format-list", "format-table", "out-string", "compare-object", "select-object",
  "group-object", "sort-object", "convertto-json", "convertfrom-json",
]);

function isReadOnlyOpenclaw(args: readonly string[]): boolean {
  const sub = args[0]?.toLowerCase();
  if (sub === "status" || sub === "doctor") return true;
  if (sub === "config") return args[1] === "get" || args[1] === "schema.lookup";
  if (sub === "plugins") {
    const cmd = args[1];
    return cmd === "list" || cmd === "info" || cmd === "inspect" ||
      cmd === "doctor" || cmd === "search";
  }
  if (sub === "session") return args[1] === "list" || args[1] === "status";
  return false;
}

function isReadOnlyNpm(args: readonly string[]): boolean {
  const sub = args[0]?.toLowerCase();
  if (sub === "view" || sub === "info" || sub === "ls" || sub === "list" || sub === "outdated") {
    return true;
  }
  if (sub === "config") return args[1] === "get";
  return false;
}

function isReadOnlyInvocation(command: string, args: readonly string[]): boolean {
  if (command === "git") {
    return READONLY_GIT_SUBCOMMANDS.has(gitSubcommand(args)?.name ?? "");
  }
  if (command === "openclaw") return isReadOnlyOpenclaw(args);
  if (command === "npm") return isReadOnlyNpm(args);
  return READONLY_EXECUTABLES.has(command);
}

/** A read-only shell command is a single, simple, operator/redirection-free
 * invocation of a known read-only executable (or read-only subcommand) across
 * all three dialects. Wrappers (`sudo`/`env`/…) still carry their own risk
 * findings independently, so a privileged read-only command stays gated. */
function isReadOnlyCommand(scans: readonly ShellScanResult[]): boolean {
  const rootScans = scans.slice(0, 3);
  if (rootScans.length !== 3) return false;
  const results = new Set<boolean>();
  for (const scan of rootScans) {
    if (!scan.complete || scan.invocations.length !== 1 || scan.operators.length > 0 ||
      scan.redirections.length > 0 || scan.tokens.some((token) => token.dynamic)) {
      return false;
    }
    const invocation = scan.invocations[0];
    const { command, args } = effectiveInvocationParts(scan, invocation?.index);
    results.add(isReadOnlyInvocation(command, args));
  }
  return results.size === 1 && results.has(true);
}

export class CommandAnalyzer implements ToolCallAnalyzer {
  readonly id = "builtin.command-semantics";
  readonly priority = 100;

  constructor(private readonly config: SemanticAnalysisConfig) {}

  supports(context: ToolCallContext): boolean {
    return supportsExecution(context);
  }

  analyze(context: ToolCallContext): AnalysisResult {
    const extracted = extractCommand(context);
    if (!extracted) {
      return {
        analyzerId: this.id,
        findings: [],
        effects: ["unknown"],
        categories: ["unknown"],
        verifiedTargets: [],
        complete: false,
        windowEligible: false,
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

    const readOnly = !wasTruncated &&
      !bundle.wrapperLimitReached &&
      !parseIncomplete &&
      isReadOnlyCommand(scans);
    const intentComplete = (!wasTruncated &&
      !bundle.wrapperLimitReached &&
      !parseIncomplete) &&
      (completeIntent(scans) !== undefined || readOnly);
    if (!intentComplete && !wasTruncated && !bundle.wrapperLimitReached && !parseIncomplete) {
      findings.push({
        id: "command.intent-incomplete",
        category: "unknown",
        severity: "warning",
        confidence: "low",
        title: "Command intent is not completely classified",
        explanation: "Risk patterns were checked, but this command is outside the reusable semantic scope.",
        evidence: { source: "command", excerpt },
      });
    }

    const critical = findings.some((finding) => finding.severity === "critical");
    const windowEligible = !readOnly &&
      !wasTruncated &&
      !bundle.wrapperLimitReached &&
      !parseIncomplete &&
      intentComplete &&
      !matchedRules.some((rule) => rule.disablesWindow);
    const effects = [...new Set([
      ...matchedRules.map((rule) => rule.effect),
      ...(readOnly ? ["read-only" as const] : []),
      ...(!intentComplete ? ["unknown" as const] : []),
    ])];
    const categories = [...new Set([
      ...matchedRules.map((rule) => rule.category),
      ...(readOnly ? ["read-only" as const] : []),
      ...(!intentComplete ? ["unknown" as const] : []),
    ])];

    return {
      analyzerId: this.id,
      findings,
      effects,
      categories,
      verifiedTargets: [],
      complete: intentComplete,
      minimumMode: findings.length > 0 ? "require-approval" : undefined,
      minimumSeverity: critical ? "critical" : findings.length > 0 ? "warning" : undefined,
      windowEligible,
    };
  }
}
