/**
 * A small, deterministic shell scanner for approval-time inspection.
 *
 * This is deliberately a scanner rather than a shell parser. It never
 * expands variables, resolves aliases, reads files, or executes input. Its
 * only job is to expose quote-aware words, command boundaries, and output
 * redirections so semantic rules do not mistake text inside a string literal
 * for another command.
 */

export type ShellDialect = "posix" | "powershell" | "cmd";

export type ShellControlOperator = "|" | "&&" | "||" | ";" | "&" | "\n";
export type ShellRedirectionOperator = ">" | ">>";
export type ShellQuoteKind = "none" | "single" | "double" | "mixed";
export type ShellTokenRole = "command" | "argument" | "redirection-target";

export interface ShellToken {
  /** Value with quote delimiters and escaping syntax removed. */
  value: string;
  /** Exact source slice for display and evidence. */
  raw: string;
  start: number;
  end: number;
  quote: ShellQuoteKind;
  /** True when the token contains shell expansion syntax outside a literal. */
  dynamic: boolean;
  role: ShellTokenRole;
  invocationIndex: number;
}

export interface ShellRedirection {
  operator: ShellRedirectionOperator;
  start: number;
  end: number;
  /** Explicit descriptor in forms such as `2>errors.log`. */
  fd?: number;
  target?: ShellToken;
  invocationIndex: number;
}

export interface ShellInvocation {
  index: number;
  start: number;
  end: number;
  /** Command and argument words. Redirection targets are kept separately. */
  tokens: readonly ShellToken[];
  redirections: readonly ShellRedirection[];
}

export interface ShellOperator {
  operator: ShellControlOperator;
  start: number;
  end: number;
  leftInvocationIndex?: number;
  rightInvocationIndex?: number;
}

export type ShellScanIssueCode =
  | "unterminated-single-quote"
  | "unterminated-double-quote"
  | "trailing-escape"
  | "missing-redirection-target"
  | "missing-command-before-operator"
  | "missing-command-after-operator";

export interface ShellScanIssue {
  code: ShellScanIssueCode;
  offset: number;
}

export interface ShellScanResult {
  dialect: ShellDialect;
  source: string;
  invocations: readonly ShellInvocation[];
  /** All words, including redirection targets, in source order. */
  tokens: readonly ShellToken[];
  operators: readonly ShellOperator[];
  redirections: readonly ShellRedirection[];
  complete: boolean;
  issues: readonly ShellScanIssue[];
}

type ActiveQuote = "single" | "double";

interface MutableInvocation {
  index: number;
  start: number;
  end: number;
  tokens: ShellToken[];
  redirections: ShellRedirection[];
}

function isLineBreak(ch: string): boolean {
  return ch === "\r" || ch === "\n";
}

function isHorizontalWhitespace(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "\v" || ch === "\f";
}

function quoteKind(kinds: ReadonlySet<"none" | ActiveQuote>): ShellQuoteKind {
  if (kinds.size !== 1) return "mixed";
  if (kinds.has("single")) return "single";
  if (kinds.has("double")) return "double";
  return "none";
}

function isDynamicCharacter(
  dialect: ShellDialect,
  quote: ActiveQuote | undefined,
  ch: string,
): boolean {
  if (quote === "single") return false;
  if (dialect === "cmd") return ch === "%" || ch === "!";
  if (dialect === "powershell") return ch === "$";
  return ch === "$" || ch === "`";
}

function controlOperatorAt(
  source: string,
  index: number,
  dialect: ShellDialect,
): { operator: ShellControlOperator; width: number } | undefined {
  const pair = source.slice(index, index + 2);
  if (pair === "&&" || pair === "||") {
    return { operator: pair, width: 2 };
  }
  const ch = source[index];
  if (ch === "|") return { operator: "|", width: 1 };
  // Semicolon is not a command separator in cmd.exe.
  if (ch === ";" && dialect !== "cmd") return { operator: ";", width: 1 };
  // A single ampersand is a command separator/background operator in POSIX
  // and cmd. In PowerShell it is normally a call operator when it starts an
  // invocation, so only treat it as a boundary after a command word.
  if (ch === "&" && dialect !== "powershell") return { operator: "&", width: 1 };
  return undefined;
}

/**
 * Scan one shell command without performing expansion or execution.
 *
 * The result is conservative metadata only. It must not be used by itself to
 * auto-authorize a command: aliases, functions, variables, and nested shell
 * wrappers can change runtime meaning after this scan.
 */
export function scanShell(source: string, dialect: ShellDialect): ShellScanResult {
  const invocations: ShellInvocation[] = [];
  const tokens: ShellToken[] = [];
  const operators: ShellOperator[] = [];
  const redirections: ShellRedirection[] = [];
  const issues: ShellScanIssue[] = [];

  let current: MutableInvocation | undefined;
  let pendingRedirection: ShellRedirection | undefined;
  let activeQuote: ActiveQuote | undefined;

  let tokenStart = -1;
  let tokenValue = "";
  let tokenDynamic = false;
  let tokenStarted = false;
  let tokenKinds = new Set<"none" | ActiveQuote>();

  const ensureInvocation = (start: number): MutableInvocation => {
    if (!current) {
      current = {
        index: invocations.length,
        start,
        end: start,
        tokens: [],
        redirections: [],
      };
    } else {
      current.start = Math.min(current.start, start);
    }
    return current;
  };

  const beginToken = (start: number): void => {
    if (tokenStarted) return;
    tokenStarted = true;
    tokenStart = start;
    tokenValue = "";
    tokenDynamic = false;
    tokenKinds = new Set<"none" | ActiveQuote>();
  };

  const addCharacter = (
    ch: string,
    sourceKind: "none" | ActiveQuote,
    dynamic = false,
  ): void => {
    tokenKinds.add(sourceKind);
    tokenValue += ch;
    tokenDynamic = tokenDynamic || dynamic;
  };

  const clearToken = (): void => {
    tokenStart = -1;
    tokenValue = "";
    tokenDynamic = false;
    tokenStarted = false;
    tokenKinds = new Set<"none" | ActiveQuote>();
  };

  const flushToken = (end: number): ShellToken | undefined => {
    if (!tokenStarted) return undefined;
    const invocation = ensureInvocation(tokenStart);
    const role: ShellTokenRole = pendingRedirection
      ? "redirection-target"
      : invocation.tokens.length === 0
        ? "command"
        : "argument";
    const token: ShellToken = {
      value: tokenValue,
      raw: source.slice(tokenStart, end),
      start: tokenStart,
      end,
      quote: quoteKind(tokenKinds),
      dynamic: tokenDynamic,
      role,
      invocationIndex: invocation.index,
    };
    tokens.push(token);
    if (pendingRedirection) {
      pendingRedirection.target = token;
      pendingRedirection = undefined;
    } else {
      invocation.tokens.push(token);
    }
    invocation.end = Math.max(invocation.end, end);
    clearToken();
    return token;
  };

  const noteMissingRedirectionTarget = (offset: number): void => {
    if (!pendingRedirection) return;
    issues.push({ code: "missing-redirection-target", offset });
    pendingRedirection = undefined;
  };

  const finishInvocation = (end: number): number | undefined => {
    flushToken(end);
    noteMissingRedirectionTarget(end);
    if (!current) return undefined;
    current.end = Math.max(current.end, end);
    const finished: ShellInvocation = {
      index: current.index,
      start: current.start,
      end: current.end,
      tokens: current.tokens,
      redirections: current.redirections,
    };
    invocations.push(finished);
    current = undefined;
    return finished.index;
  };

  const recordOperator = (
    operator: ShellControlOperator,
    start: number,
    end: number,
  ): void => {
    const leftInvocationIndex = finishInvocation(start);
    operators.push({
      operator,
      start,
      end,
      ...(leftInvocationIndex === undefined ? {} : { leftInvocationIndex }),
    });
  };

  const recordRedirection = (
    operator: ShellRedirectionOperator,
    start: number,
    end: number,
    fd?: number,
  ): void => {
    noteMissingRedirectionTarget(start);
    const invocation = ensureInvocation(start);
    const redirection: ShellRedirection = {
      operator,
      start,
      end,
      invocationIndex: invocation.index,
      ...(fd === undefined ? {} : { fd }),
    };
    invocation.redirections.push(redirection);
    redirections.push(redirection);
    invocation.end = Math.max(invocation.end, end);
    pendingRedirection = redirection;
  };

  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i] ?? "";

    if (activeQuote === "single") {
      beginToken(tokenStart >= 0 ? tokenStart : i);
      if (ch === "'") {
        // PowerShell represents a literal apostrophe inside a single-quoted
        // string with two consecutive apostrophes.
        if (dialect === "powershell" && source[i + 1] === "'") {
          addCharacter("'", "single");
          i += 1;
        } else {
          tokenKinds.add("single");
          activeQuote = undefined;
        }
      } else {
        addCharacter(ch, "single");
      }
      continue;
    }

    if (activeQuote === "double") {
      beginToken(tokenStart >= 0 ? tokenStart : i);
      if (ch === "\"") {
        // Consecutive double quotes are the common literal-quote form in
        // PowerShell. In the other dialects the first quote terminates.
        if (dialect === "powershell" && source[i + 1] === "\"") {
          addCharacter("\"", "double");
          i += 1;
        } else {
          tokenKinds.add("double");
          activeQuote = undefined;
        }
        continue;
      }
      if (dialect === "powershell" && ch === "`") {
        tokenKinds.add("double");
        const next = source[i + 1];
        if (next === undefined) {
          issues.push({ code: "trailing-escape", offset: i });
        } else {
          addCharacter(next, "double");
          i += 1;
        }
        continue;
      }
      if (dialect === "posix" && ch === "\\") {
        tokenKinds.add("double");
        const next = source[i + 1];
        if (next === undefined) {
          issues.push({ code: "trailing-escape", offset: i });
        } else {
          addCharacter(next, "double");
          i += 1;
        }
        continue;
      }
      addCharacter(ch, "double", isDynamicCharacter(dialect, "double", ch));
      continue;
    }

    if (isLineBreak(ch)) {
      const width = ch === "\r" && source[i + 1] === "\n" ? 2 : 1;
      recordOperator("\n", i, i + width);
      i += width - 1;
      continue;
    }

    if (isHorizontalWhitespace(ch)) {
      flushToken(i);
      continue;
    }

    if (ch === "'" && dialect !== "cmd") {
      beginToken(i);
      tokenKinds.add("single");
      activeQuote = "single";
      continue;
    }

    if (ch === "\"") {
      beginToken(i);
      tokenKinds.add("double");
      activeQuote = "double";
      continue;
    }

    const escape = dialect === "posix" ? "\\" : dialect === "powershell" ? "`" : "^";
    if (ch === escape) {
      beginToken(i);
      tokenKinds.add("none");
      const next = source[i + 1];
      if (next === undefined) {
        issues.push({ code: "trailing-escape", offset: i });
      } else {
        addCharacter(next, "none");
        i += 1;
      }
      continue;
    }

    // Output redirection is recognized before generic control operators.
    if (ch === ">") {
      let fd: number | undefined;
      let redirectionStart = i;
      if (
        tokenStarted &&
        tokenKinds.size === 1 &&
        tokenKinds.has("none") &&
        /^\d+$/.test(tokenValue)
      ) {
        fd = Number(tokenValue);
        redirectionStart = tokenStart;
        clearToken();
      } else {
        flushToken(i);
      }
      const operator: ShellRedirectionOperator = source[i + 1] === ">" ? ">>" : ">";
      const width = operator.length;
      recordRedirection(operator, redirectionStart, i + width, fd);
      i += width - 1;
      continue;
    }

    const control = controlOperatorAt(source, i, dialect);
    if (control) {
      // PowerShell's leading `&` is a call operator and therefore part of the
      // command rather than a separator. `controlOperatorAt` excludes it.
      recordOperator(control.operator, i, i + control.width);
      i += control.width - 1;
      continue;
    }

    beginToken(i);
    addCharacter(ch, "none", isDynamicCharacter(dialect, undefined, ch));
  }

  if (activeQuote) {
    issues.push({
      code: activeQuote === "single"
        ? "unterminated-single-quote"
        : "unterminated-double-quote",
      offset: tokenStart >= 0 ? tokenStart : source.length,
    });
  }
  finishInvocation(source.length);

  // Bind operators to neighboring invocations by source position. Keeping
  // indices rather than object references makes the result serialization-safe.
  for (const operator of operators) {
    if (operator.leftInvocationIndex === undefined) {
      for (let i = invocations.length - 1; i >= 0; i -= 1) {
        const invocation = invocations[i];
        if (invocation && invocation.end <= operator.start) {
          operator.leftInvocationIndex = invocation.index;
          break;
        }
      }
    }
    for (const invocation of invocations) {
      if (invocation.start >= operator.end) {
        operator.rightInvocationIndex = invocation.index;
        break;
      }
    }

    if (
      (operator.operator === "|" || operator.operator === "&&" || operator.operator === "||") &&
      operator.leftInvocationIndex === undefined
    ) {
      issues.push({ code: "missing-command-before-operator", offset: operator.start });
    }
    if (
      (operator.operator === "|" || operator.operator === "&&" || operator.operator === "||") &&
      operator.rightInvocationIndex === undefined
    ) {
      issues.push({ code: "missing-command-after-operator", offset: operator.end });
    }
  }

  return {
    dialect,
    source,
    invocations,
    tokens,
    operators,
    redirections,
    complete: issues.length === 0,
    issues,
  };
}
