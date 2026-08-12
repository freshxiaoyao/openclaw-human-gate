import { extractCommand } from "../analysis/command.js";
import { extractCode } from "../analysis/code.js";
import { boundedLines, headTailText, sanitizeText } from "./sanitize.js";
function firstString(params, keys) {
    for (const key of keys) {
        const value = params[key];
        if (typeof value === "string" && value.length > 0)
            return { key, value };
    }
    return undefined;
}
function firstEdit(params) {
    let rawEdits = params.edits;
    if (typeof rawEdits === "string" && rawEdits.length <= 65_536) {
        try {
            rawEdits = JSON.parse(rawEdits);
        }
        catch {
            rawEdits = undefined;
        }
    }
    if (Array.isArray(rawEdits)) {
        const edits = rawEdits.filter((item) => typeof item === "object" && item !== null && !Array.isArray(item));
        for (const edit of edits) {
            const oldValue = firstString(edit, OLD_KEYS);
            const newValue = firstString(edit, NEW_KEYS);
            if (oldValue && newValue) {
                return { oldValue: oldValue.value, newValue: newValue.value, count: edits.length };
            }
        }
    }
    const oldValue = firstString(params, OLD_KEYS);
    const newValue = firstString(params, NEW_KEYS);
    return oldValue && newValue
        ? { oldValue: oldValue.value, newValue: newValue.value, count: 1 }
        : undefined;
}
function targetPath(context) {
    return firstString(context.params, ["path", "filePath", "file_path"])?.value ??
        context.derivedPaths[0];
}
function bounded(value, config) {
    // Preview processing is on the hook hot path. Bound work before applying
    // redaction regexes; the rendered excerpt remains redacted before display.
    const scanLimit = Math.max(config.maxSectionChars * 8, 4_096);
    const sampled = value.slice(0, scanLimit);
    return boundedLines(sanitizeText(sampled, config.redactSecrets), config.maxLines, config.maxSectionChars);
}
function boundedHeadTail(value, config) {
    const scanLimit = Math.max(config.maxSectionChars * 8, 4_096);
    const rawSample = value.length <= scanLimit
        ? value
        : `${value.slice(0, Math.ceil(scanLimit / 2))}\n…\n${value.slice(-Math.floor(scanLimit / 2))}`;
    const clean = sanitizeText(rawSample, config.redactSecrets);
    const lines = clean.split("\n");
    const lineBudget = Math.max(1, config.maxLines);
    const selected = lines.length <= lineBudget
        ? clean
        : [
            ...lines.slice(0, Math.ceil(lineBudget / 2)),
            "…",
            ...lines.slice(-Math.floor(lineBudget / 2)),
        ].join("\n");
    return headTailText(selected, config.maxSectionChars);
}
function patchText(context) {
    const candidate = context.params.input ?? context.params.patch ?? context.params.patchText;
    return typeof candidate === "string" ? candidate : undefined;
}
function countPatch(patch) {
    const files = new Set();
    let added = 0;
    let removed = 0;
    for (const line of patch.split(/\r?\n/)) {
        const marker = line.match(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/);
        if (marker?.[1])
            files.add(marker[1]);
        if (line.startsWith("+") && !line.startsWith("+++"))
            added += 1;
        if (line.startsWith("-") && !line.startsWith("---"))
            removed += 1;
    }
    return { files: files.size, added, removed };
}
class ApplyPatchPreviewProvider {
    id = "builtin.preview.apply-patch";
    priority = 100;
    supports(context) {
        return context.toolName === "apply_patch" && patchText(context) !== undefined;
    }
    build(context, config) {
        const patch = patchText(context);
        if (!patch)
            return undefined;
        const scanLimit = 65_536;
        const partial = patch.length > scanLimit;
        const count = countPatch(patch.slice(0, scanLimit));
        return {
            title: `Patch ${count.files || "?"} file(s), +${count.added}/-${count.removed}${partial ? " (partial)" : ""}`,
            body: bounded(patch, config),
        };
    }
}
const OLD_KEYS = ["oldText", "old_text", "oldString", "old_string", "search"];
const NEW_KEYS = ["newText", "new_text", "newString", "new_string", "replace"];
class EditPreviewProvider {
    id = "builtin.preview.edit";
    priority = 90;
    supports(context) {
        return firstEdit(context.params) !== undefined;
    }
    build(context, config) {
        const edit = firstEdit(context.params);
        if (!edit)
            return undefined;
        const path = targetPath(context);
        return {
            title: `Edit${path ? ` ${path}` : ""} (${edit.count} replacement(s))`,
            body: bounded(`- ${edit.oldValue}\n+ ${edit.newValue}`, config),
        };
    }
}
const CONTENT_KEYS = ["content", "text", "newContent", "new_content", "data"];
class WritePreviewProvider {
    id = "builtin.preview.write";
    priority = 80;
    supports(context) {
        return firstString(context.params, CONTENT_KEYS) !== undefined;
    }
    build(context, config) {
        const content = firstString(context.params, CONTENT_KEYS);
        if (!content)
            return undefined;
        const lineSample = content.value.slice(0, 65_536);
        const lines = lineSample.split(/\r?\n/).length;
        const lineLabel = content.value.length > lineSample.length ? `at least ${lines}` : String(lines);
        const path = targetPath(context);
        return {
            title: `New content${path ? ` for ${path}` : ""} (${lineLabel} line(s), ${content.value.length} chars)`,
            body: bounded(content.value, config),
        };
    }
}
class CommandPreviewProvider {
    id = "builtin.preview.command";
    priority = 70;
    supports(context) {
        return extractCommand(context) !== undefined;
    }
    build(context, config) {
        const command = extractCommand(context);
        if (!command)
            return undefined;
        const metadata = [];
        for (const key of ["workdir", "host", "node"]) {
            const value = context.params[key];
            if (typeof value === "string" && value)
                metadata.push(`${key}: ${value}`);
        }
        for (const key of ["elevated", "background"]) {
            const value = context.params[key];
            if (typeof value === "boolean")
                metadata.push(`${key}: ${String(value)}`);
        }
        const env = context.params.env;
        if (env && typeof env === "object" && !Array.isArray(env)) {
            const keys = Object.keys(env).slice(0, 8);
            if (keys.length > 0)
                metadata.push(`env keys: ${keys.join(", ")}`);
        }
        return {
            title: context.toolKind === "code_mode_exec" ? "Code preview" : "Command preview",
            body: boundedHeadTail([...metadata, command.value].join("\n"), config),
        };
    }
}
class CodeModePreviewProvider {
    id = "builtin.preview.code-mode";
    priority = 110;
    supports(context) {
        return extractCode(context) !== undefined;
    }
    build(context, config) {
        const code = extractCode(context);
        if (!code)
            return undefined;
        return {
            title: `Code preview (${context.toolInputKind ?? "unknown language"})`,
            body: boundedHeadTail(code, config),
        };
    }
}
export function defaultPreviewProviders() {
    return [
        new CodeModePreviewProvider(),
        new ApplyPatchPreviewProvider(),
        new EditPreviewProvider(),
        new WritePreviewProvider(),
        new CommandPreviewProvider(),
    ];
}
//# sourceMappingURL=providers.js.map