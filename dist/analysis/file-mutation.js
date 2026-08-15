const WRITE_NAMES = new Set(["write", "write_file", "writefile"]);
const EDIT_NAMES = new Set(["edit", "edit_file", "editfile"]);
const APPLY_PATCH_NAME = "apply_patch";
const PATH_KEYS = ["path", "filePath", "file_path"];
const PATCH_KEYS = ["input", "patch", "patchText", "patch_text"];
const WRITE_PAYLOAD_KEYS = ["content", "text", "newContent", "new_content", "data"];
const EDIT_PAYLOAD_KEYS = [
    "edits",
    "oldText", "old_text", "oldString", "old_string", "search",
    "newText", "new_text", "newString", "new_string", "replace",
];
/** Canonical mutation-tool vocabulary, exported so policy layers (e.g.
 * self-protection) share the analyzer's single source of truth and never
 * drift from the envelope shapes the analyzer actually recognizes. */
export const MUTATION_TOOL_NAMES = {
    write: WRITE_NAMES,
    edit: EDIT_NAMES,
    applyPatch: APPLY_PATCH_NAME,
};
export const MUTATION_PATH_KEYS = PATH_KEYS;
export const MUTATION_PATCH_KEYS = PATCH_KEYS;
function allowedEnvelopeKeys(toolName) {
    if (WRITE_NAMES.has(toolName)) {
        return new Set([...PATH_KEYS, ...WRITE_PAYLOAD_KEYS]);
    }
    if (EDIT_NAMES.has(toolName)) {
        return new Set([...PATH_KEYS, ...EDIT_PAYLOAD_KEYS]);
    }
    return new Set(PATCH_KEYS);
}
/** A name match is only enough to select this analyzer, not to trust an
 * arbitrary tool envelope. Unknown fields may change the behavior of a
 * third-party tool that happens to reuse a built-in name, so reusable
 * authorization is limited to the canonical/legacy fields we understand. */
function hasTrustedEnvelope(params, allowedKeys) {
    const prototype = Object.getPrototypeOf(params);
    if (prototype !== Object.prototype && prototype !== null)
        return false;
    for (const key of Reflect.ownKeys(params)) {
        if (typeof key !== "string" || !allowedKeys.has(key))
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(params, key);
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
            return false;
    }
    return true;
}
function ownDataValue(params, key) {
    const descriptor = Object.getOwnPropertyDescriptor(params, key);
    if (!descriptor)
        return { present: false };
    if (!("value" in descriptor))
        return { present: true };
    return { present: true, value: descriptor.value };
}
function validPath(value) {
    return typeof value === "string" && value.trim().length > 0 &&
        !/[\0\r\n]/.test(value) && value !== "/dev/null";
}
function normalizedForComparison(path) {
    return path.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
}
function uniqueTargets(targets) {
    const seen = new Set();
    const result = [];
    for (const target of targets) {
        const key = normalizedForComparison(target.path);
        if (seen.has(key))
            continue;
        seen.add(key);
        result.push(target);
    }
    return result;
}
function extractDirectPath(params) {
    const candidates = [];
    let invalid = false;
    for (const key of PATH_KEYS) {
        const own = ownDataValue(params, key);
        if (!own.present)
            continue;
        if (!validPath(own.value)) {
            invalid = true;
            continue;
        }
        candidates.push({ path: own.value, targetKind: "file", source: "params", parameter: key });
    }
    const unique = uniqueTargets(candidates);
    if (invalid || unique.length !== 1) {
        return {
            targets: [],
            complete: false,
            problem: invalid
                ? "A target path parameter is not a plain, valid string."
                : unique.length === 0
                    ? "No authoritative target path parameter was provided."
                    : "Conflicting target path parameters were provided.",
        };
    }
    return { targets: unique, complete: true };
}
function extractPatchText(params) {
    const values = [];
    let invalid = false;
    for (const key of PATCH_KEYS) {
        const own = ownDataValue(params, key);
        if (!own.present)
            continue;
        if (typeof own.value !== "string" || own.value.length === 0) {
            invalid = true;
            continue;
        }
        values.push({ key, value: own.value });
    }
    const distinct = new Map(values.map((item) => [item.value, item]));
    if (invalid || distinct.size !== 1)
        return { complete: false };
    const selected = [...distinct.values()][0];
    return { key: selected?.key, value: selected?.value, complete: selected !== undefined };
}
function extractPatchTargets(params, maxLength) {
    const patch = extractPatchText(params);
    if (!patch.complete || patch.value === undefined || patch.key === undefined) {
        return { targets: [], complete: false, problem: "No single authoritative patch payload was provided." };
    }
    if (patch.value.length > maxLength) {
        return { targets: [], complete: false, problem: "The patch exceeds the configured analysis limit." };
    }
    const lines = patch.value.split(/\r?\n/);
    while (lines[0] === "")
        lines.shift();
    while (lines.at(-1) === "")
        lines.pop();
    if (lines[0] !== "*** Begin Patch" || lines.at(-1) !== "*** End Patch") {
        return { targets: [], complete: false, problem: "The patch envelope is missing or malformed." };
    }
    const targets = [];
    let currentOperation;
    let destructive = false;
    let malformed = false;
    for (let index = 1; index < lines.length - 1; index += 1) {
        const line = lines[index] ?? "";
        const file = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(line);
        if (file) {
            currentOperation = file[1];
            if (currentOperation === "Delete")
                destructive = true;
            const path = file[2];
            if (!validPath(path)) {
                malformed = true;
            }
            else {
                targets.push({ path, targetKind: "file", source: "patch", parameter: patch.key });
            }
            continue;
        }
        const move = /^\*\*\* Move to: (.+)$/.exec(line);
        if (move) {
            const path = move[1];
            if (currentOperation !== "Update" || !validPath(path)) {
                malformed = true;
            }
            else {
                destructive = true;
                targets.push({ path, targetKind: "file", source: "patch", parameter: patch.key });
            }
            continue;
        }
        if (/^\*\*\* (?:Add|Update|Delete) File:/.test(line) ||
            /^\*\*\* Move to:/.test(line) ||
            line === "*** Begin Patch" || line === "*** End Patch") {
            malformed = true;
        }
    }
    const unique = uniqueTargets(targets);
    if (malformed || unique.length === 0) {
        return { targets: [], complete: false, problem: "Patch target declarations are missing or malformed." };
    }
    return { targets: unique, complete: true, destructive };
}
function finding(id, category, title, explanation, path) {
    return {
        id,
        category,
        severity: "warning",
        confidence: category === "filesystem" ? "high" : "low",
        title,
        explanation,
        evidence: path ? { source: "path", excerpt: path.slice(0, 320) } : undefined,
    };
}
/** Semantic classifier for the plugin's strictly known filesystem mutation
 * tools. It never promotes host-derived paths into verified targets. */
export class FileMutationAnalyzer {
    config;
    id = "builtin.file-mutation-semantics";
    priority = 105;
    constructor(config) {
        this.config = config;
    }
    supports(context) {
        // `toolKind` is host-authoritative. Today its only value is
        // `code_mode_exec`; future kinds must remain unclassified until an
        // analyzer explicitly understands their envelope.
        if (context.toolKind !== undefined || context.toolInputKind !== undefined)
            return false;
        const name = context.toolName.toLowerCase();
        return WRITE_NAMES.has(name) || EDIT_NAMES.has(name) || name === APPLY_PATCH_NAME;
    }
    analyze(context) {
        const name = context.toolName.toLowerCase();
        const extracted = name === APPLY_PATCH_NAME
            ? extractPatchTargets(context.params, this.config.maxCommandLength)
            : extractDirectPath(context.params);
        const envelopeTrusted = hasTrustedEnvelope(context.params, allowedEnvelopeKeys(name));
        const extraction = envelopeTrusted
            ? extracted
            : {
                targets: extracted.targets,
                complete: false,
                destructive: extracted.destructive,
                problem: "The tool envelope contains fields this analyzer does not understand.",
            };
        const primary = finding("file-mutation.local-write", "filesystem", "Filesystem content will be modified", "This tool writes, edits, or removes local file content.", extraction.targets[0]?.path);
        const findings = [primary];
        if (extraction.destructive) {
            findings.push(finding("file-mutation.delete-or-move", "filesystem", "Patch deletes or moves filesystem content", "Delete and move operations use a separate destructive semantic scope.", extraction.targets[0]?.path));
        }
        if (!extraction.complete) {
            findings.unshift(finding("file-mutation.target-unverified", "unknown", "Filesystem target is not completely verified", extraction.problem ?? "The authoritative input did not yield a complete target set."));
        }
        return {
            analyzerId: this.id,
            findings,
            effects: extraction.complete
                ? ["local-write", ...(extraction.destructive ? ["destructive"] : [])]
                : ["local-write", "unknown"],
            categories: extraction.complete ? ["filesystem"] : ["filesystem", "unknown"],
            verifiedTargets: extraction.targets,
            complete: extraction.complete,
            minimumMode: "require-approval",
            minimumSeverity: "warning",
            windowEligible: extraction.complete,
        };
    }
}
//# sourceMappingURL=file-mutation.js.map