/**
 * A small, deterministic shell scanner for approval-time inspection.
 *
 * This is deliberately a scanner rather than a shell parser. It never
 * expands variables, resolves aliases, reads files, or executes input. Its
 * only job is to expose quote-aware words, command boundaries, and output
 * redirections so semantic rules do not mistake text inside a string literal
 * for another command.
 */
function isLineBreak(ch) {
    return ch === "\r" || ch === "\n";
}
function isHorizontalWhitespace(ch) {
    return ch === " " || ch === "\t" || ch === "\v" || ch === "\f";
}
function quoteKind(kinds) {
    if (kinds.size !== 1)
        return "mixed";
    if (kinds.has("single"))
        return "single";
    if (kinds.has("double"))
        return "double";
    return "none";
}
function isDynamicCharacter(dialect, quote, ch) {
    if (quote === "single")
        return false;
    if (dialect === "cmd")
        return ch === "%" || ch === "!";
    if (dialect === "powershell")
        return ch === "$";
    return ch === "$" || ch === "`";
}
function controlOperatorAt(source, index, dialect) {
    const pair = source.slice(index, index + 2);
    if (pair === "&&" || pair === "||") {
        return { operator: pair, width: 2 };
    }
    const ch = source[index];
    if (ch === "|")
        return { operator: "|", width: 1 };
    // Semicolon is not a command separator in cmd.exe.
    if (ch === ";" && dialect !== "cmd")
        return { operator: ";", width: 1 };
    // A single ampersand is a command separator/background operator in POSIX
    // and cmd. In PowerShell it is normally a call operator when it starts an
    // invocation, so only treat it as a boundary after a command word.
    if (ch === "&" && dialect !== "powershell")
        return { operator: "&", width: 1 };
    return undefined;
}
/**
 * Scan one shell command without performing expansion or execution.
 *
 * The result is conservative metadata only. It must not be used by itself to
 * auto-authorize a command: aliases, functions, variables, and nested shell
 * wrappers can change runtime meaning after this scan.
 */
export function scanShell(source, dialect) {
    const invocations = [];
    const tokens = [];
    const operators = [];
    const redirections = [];
    const issues = [];
    let current;
    let pendingRedirection;
    let activeQuote;
    let tokenStart = -1;
    let tokenValue = "";
    let tokenDynamic = false;
    let tokenStarted = false;
    let tokenKinds = new Set();
    const ensureInvocation = (start) => {
        if (!current) {
            current = {
                index: invocations.length,
                start,
                end: start,
                tokens: [],
                redirections: [],
            };
        }
        else {
            current.start = Math.min(current.start, start);
        }
        return current;
    };
    const beginToken = (start) => {
        if (tokenStarted)
            return;
        tokenStarted = true;
        tokenStart = start;
        tokenValue = "";
        tokenDynamic = false;
        tokenKinds = new Set();
    };
    const addCharacter = (ch, sourceKind, dynamic = false) => {
        tokenKinds.add(sourceKind);
        tokenValue += ch;
        tokenDynamic = tokenDynamic || dynamic;
    };
    const clearToken = () => {
        tokenStart = -1;
        tokenValue = "";
        tokenDynamic = false;
        tokenStarted = false;
        tokenKinds = new Set();
    };
    const flushToken = (end) => {
        if (!tokenStarted)
            return undefined;
        const invocation = ensureInvocation(tokenStart);
        const role = pendingRedirection
            ? "redirection-target"
            : invocation.tokens.length === 0
                ? "command"
                : "argument";
        const token = {
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
        }
        else {
            invocation.tokens.push(token);
        }
        invocation.end = Math.max(invocation.end, end);
        clearToken();
        return token;
    };
    const noteMissingRedirectionTarget = (offset) => {
        if (!pendingRedirection)
            return;
        issues.push({ code: "missing-redirection-target", offset });
        pendingRedirection = undefined;
    };
    const finishInvocation = (end) => {
        flushToken(end);
        noteMissingRedirectionTarget(end);
        if (!current)
            return undefined;
        current.end = Math.max(current.end, end);
        const finished = {
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
    const recordOperator = (operator, start, end) => {
        const leftInvocationIndex = finishInvocation(start);
        operators.push({
            operator,
            start,
            end,
            ...(leftInvocationIndex === undefined ? {} : { leftInvocationIndex }),
        });
    };
    const recordRedirection = (operator, start, end, fd) => {
        noteMissingRedirectionTarget(start);
        const invocation = ensureInvocation(start);
        const redirection = {
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
                }
                else {
                    tokenKinds.add("single");
                    activeQuote = undefined;
                }
            }
            else {
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
                }
                else {
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
                }
                else {
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
                }
                else {
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
            }
            else {
                addCharacter(next, "none");
                i += 1;
            }
            continue;
        }
        // Output redirection is recognized before generic control operators.
        if (ch === ">") {
            let fd;
            let redirectionStart = i;
            if (tokenStarted &&
                tokenKinds.size === 1 &&
                tokenKinds.has("none") &&
                /^\d+$/.test(tokenValue)) {
                fd = Number(tokenValue);
                redirectionStart = tokenStart;
                clearToken();
            }
            else {
                flushToken(i);
            }
            const operator = source[i + 1] === ">" ? ">>" : ">";
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
        if ((operator.operator === "|" || operator.operator === "&&" || operator.operator === "||") &&
            operator.leftInvocationIndex === undefined) {
            issues.push({ code: "missing-command-before-operator", offset: operator.start });
        }
        if ((operator.operator === "|" || operator.operator === "&&" || operator.operator === "||") &&
            operator.rightInvocationIndex === undefined) {
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
//# sourceMappingURL=shell-scan.js.map