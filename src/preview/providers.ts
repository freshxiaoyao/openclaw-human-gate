import { extractCommand } from "../analysis/command.js";
import { extractCode } from "../analysis/code.js";
import type { ToolCallContext } from "../analysis/types.js";
import type { ApprovalPreviewConfig } from "../types.js";
import { boundedLines, headTailText, sanitizeText } from "./sanitize.js";
import type { ApprovalPreviewProvider, PreviewSection } from "./types.js";

function firstString(
  params: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): { key: string; value: string } | undefined {
  for (const key of keys) {
    const value = params[key];
    if (typeof value === "string" && value.length > 0) return { key, value };
  }
  return undefined;
}

function firstEdit(params: Readonly<Record<string, unknown>>): {
  oldValue: string;
  newValue: string;
  count: number;
} | undefined {
  let rawEdits = params.edits;
  if (typeof rawEdits === "string" && rawEdits.length <= 65_536) {
    try {
      rawEdits = JSON.parse(rawEdits) as unknown;
    } catch {
      rawEdits = undefined;
    }
  }
  if (Array.isArray(rawEdits)) {
    const edits = rawEdits.filter(
      (item): item is Record<string, unknown> =>
        typeof item === "object" && item !== null && !Array.isArray(item),
    );
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

function targetPath(context: ToolCallContext): string | undefined {
  return firstString(context.params, ["path", "filePath", "file_path"])?.value ??
    context.derivedPaths[0];
}

function bounded(value: string, config: ApprovalPreviewConfig): string {
  // Preview processing is on the hook hot path. Bound work before applying
  // redaction regexes; the rendered excerpt remains redacted before display.
  const scanLimit = Math.max(config.maxSectionChars * 8, 4_096);
  const sampled = value.slice(0, scanLimit);
  return boundedLines(
    sanitizeText(sampled, config.redactSecrets),
    config.maxLines,
    config.maxSectionChars,
  );
}

function boundedHeadTail(value: string, config: ApprovalPreviewConfig): string {
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

function patchText(context: ToolCallContext): string | undefined {
  const candidate = context.params.input ?? context.params.patch ?? context.params.patchText;
  return typeof candidate === "string" ? candidate : undefined;
}

function countPatch(patch: string): { files: number; added: number; removed: number } {
  const files = new Set<string>();
  let added = 0;
  let removed = 0;
  for (const line of patch.split(/\r?\n/)) {
    const marker = line.match(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/);
    if (marker?.[1]) files.add(marker[1]);
    if (line.startsWith("+") && !line.startsWith("+++")) added += 1;
    if (line.startsWith("-") && !line.startsWith("---")) removed += 1;
  }
  return { files: files.size, added, removed };
}

class ApplyPatchPreviewProvider implements ApprovalPreviewProvider {
  readonly id = "builtin.preview.apply-patch";
  readonly priority = 100;

  supports(context: ToolCallContext): boolean {
    return context.toolName === "apply_patch" && patchText(context) !== undefined;
  }

  build(context: ToolCallContext, config: ApprovalPreviewConfig): PreviewSection | undefined {
    const patch = patchText(context);
    if (!patch) return undefined;
    const scanLimit = 65_536;
    const partial = patch.length > scanLimit;
    const count = countPatch(patch.slice(0, scanLimit));
    return {
      title: `Patch ${count.files || "?"} file(s), +${count.added}/-${count.removed}${partial ? " (partial)" : ""}`,
      body: bounded(patch, config),
    };
  }
}

const OLD_KEYS = ["oldText", "old_text", "oldString", "old_string", "search"] as const;
const NEW_KEYS = ["newText", "new_text", "newString", "new_string", "replace"] as const;

class EditPreviewProvider implements ApprovalPreviewProvider {
  readonly id = "builtin.preview.edit";
  readonly priority = 90;

  supports(context: ToolCallContext): boolean {
    return firstEdit(context.params) !== undefined;
  }

  build(context: ToolCallContext, config: ApprovalPreviewConfig): PreviewSection | undefined {
    const edit = firstEdit(context.params);
    if (!edit) return undefined;
    const path = targetPath(context);
    return {
      title: `Edit${path ? ` ${path}` : ""} (${edit.count} replacement(s))`,
      body: bounded(`- ${edit.oldValue}\n+ ${edit.newValue}`, config),
    };
  }
}

const CONTENT_KEYS = ["content", "text", "newContent", "new_content", "data"] as const;

class WritePreviewProvider implements ApprovalPreviewProvider {
  readonly id = "builtin.preview.write";
  readonly priority = 80;

  supports(context: ToolCallContext): boolean {
    return firstString(context.params, CONTENT_KEYS) !== undefined;
  }

  build(context: ToolCallContext, config: ApprovalPreviewConfig): PreviewSection | undefined {
    const content = firstString(context.params, CONTENT_KEYS);
    if (!content) return undefined;
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

class CommandPreviewProvider implements ApprovalPreviewProvider {
  readonly id = "builtin.preview.command";
  readonly priority = 70;

  supports(context: ToolCallContext): boolean {
    return extractCommand(context) !== undefined;
  }

  build(context: ToolCallContext, config: ApprovalPreviewConfig): PreviewSection | undefined {
    const command = extractCommand(context);
    if (!command) return undefined;
    const metadata: string[] = [];
    for (const key of ["workdir", "host", "node"] as const) {
      const value = context.params[key];
      if (typeof value === "string" && value) metadata.push(`${key}: ${value}`);
    }
    for (const key of ["elevated", "background"] as const) {
      const value = context.params[key];
      if (typeof value === "boolean") metadata.push(`${key}: ${String(value)}`);
    }
    const env = context.params.env;
    if (env && typeof env === "object" && !Array.isArray(env)) {
      const keys = Object.keys(env).slice(0, 8);
      if (keys.length > 0) metadata.push(`env keys: ${keys.join(", ")}`);
    }
    return {
      title: context.toolKind === "code_mode_exec" ? "Code preview" : "Command preview",
      body: boundedHeadTail([...metadata, command.value].join("\n"), config),
    };
  }
}

class CodeModePreviewProvider implements ApprovalPreviewProvider {
  readonly id = "builtin.preview.code-mode";
  readonly priority = 110;

  supports(context: ToolCallContext): boolean {
    return extractCode(context) !== undefined;
  }

  build(context: ToolCallContext, config: ApprovalPreviewConfig): PreviewSection | undefined {
    const code = extractCode(context);
    if (!code) return undefined;
    return {
      title: `Code preview (${context.toolInputKind ?? "unknown language"})`,
      body: boundedHeadTail(code, config),
    };
  }
}

export function defaultPreviewProviders(): ApprovalPreviewProvider[] {
  return [
    new CodeModePreviewProvider(),
    new ApplyPatchPreviewProvider(),
    new EditPreviewProvider(),
    new WritePreviewProvider(),
    new CommandPreviewProvider(),
  ];
}
