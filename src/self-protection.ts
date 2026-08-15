/**
 * Structural self-protection (remit-style sensitive-target classification).
 *
 * Any file-write or shell-command call whose parameters reference the
 * authority surface — `openclaw.json` (the config that carries this plugin's
 * rules) or any path under a `.openclaw` directory (config, keys, plugin
 * state) — escalates to a block. Escalation-only: it can only tighten a
 * decision, never loosen one, and it runs before grants/windows are
 * consulted, so no lease can reach it.
 *
 * Pure reads are deliberately NOT escalated: inspecting the config
 * (`read`, `openclaw doctor`, `status`) stays usable. Only carriers that
 * can mutate are escalated — destructive toolKinds, file tools, and
 * unknown tools (fail-closed).
 *
 * Tool-name and parameter shapes are aligned with the semantic analyzer's
 * canonical vocabulary (see `analysis/file-mutation.ts`), so the scan
 * covers the same envelopes the analyzer trusts: write/write_file/writefile,
 * edit/edit_file/editfile, apply_patch (canonical `input`), and exec-like
 * command parameters.
 */

import {
  DESTRUCTIVE_NAME_TOKENS,
  DESTRUCTIVE_TOOL_KINDS,
  READONLY_NAME_TOKENS,
  READONLY_TOOL_KINDS,
} from "./types.js";
import { tokenizeName } from "./policy.js";
import {
  MUTATION_PATH_KEYS,
  MUTATION_PATCH_KEYS,
  MUTATION_TOOL_NAMES,
} from "./analysis/file-mutation.js";

export const SELF_PROTECTION_VERSION = 1 as const;

/** Exec-like tools: scan their command parameters. */
const EXEC_TOOLS = new Set<string>(["exec", "process", "code_mode_exec"]);
const EXEC_PARAMS = ["command", "cmd", "code", "script", "args"];

/** File-write/edit tools: scan path parameters only. Payload/content fields
 * can legitimately mention `openclaw.json` and must not false-positive. */
const FILE_TOOLS = new Set<string>([
  ...MUTATION_TOOL_NAMES.write,
  ...MUTATION_TOOL_NAMES.edit,
  "file_write",
]);
const FILE_PARAMS = [
  ...MUTATION_PATH_KEYS,
  "file", "target", "to", "dest", "destination", "dir", "directory",
];

/** apply_patch and patch-shaped tools: scan the patch body itself, because
 * the target file is named inside the patch. */
const PATCH_TOOLS = new Set<string>([MUTATION_TOOL_NAMES.applyPatch, "applypatch"]);
const PATCH_PARAMS = [...MUTATION_PATCH_KEYS];

const MAX_SCAN_LENGTH = 16_384;
const MAX_HITS = 8;

/** Path-component match for a `.openclaw` directory (any filesystem style). */
const DIR_MARKER_RE = /(^|[\\/])\.openclaw([\\/]|$)/;
/** Word-boundary filename match for the config file itself. */
const CONFIG_MARKER_RE = /\bopenclaw\.json\b/;

export interface SelfProtectionHit {
  marker: ".openclaw" | "openclaw.json";
  param: string;
}

export interface SelfProtectionResult {
  hits: SelfProtectionHit[];
  escalate: boolean;
}

/** Scan only the parameters that can carry a filesystem/command target. */
function relevantParams(toolName: string, toolKind: string | undefined): string[] | undefined {
  // Case-insensitive, like the analyzer's own name matching.
  const name = toolName.toLowerCase();
  if (EXEC_TOOLS.has(name)) return EXEC_PARAMS;
  if (FILE_TOOLS.has(name)) return FILE_PARAMS;
  if (PATCH_TOOLS.has(name)) return PATCH_PARAMS;
  if (toolKind && DESTRUCTIVE_TOOL_KINDS.has(toolKind)) {
    // e.g. code_mode_exec surfaced under a different name.
    return EXEC_PARAMS;
  }
  return undefined;
}

function matchMarker(value: string): SelfProtectionHit["marker"] | undefined {
  if (DIR_MARKER_RE.test(value)) return ".openclaw";
  if (CONFIG_MARKER_RE.test(value)) return "openclaw.json";
  return undefined;
}

/** Escalation classifier. `escalate` is true only for mutating carriers that
 *  reference the authority surface. Pure reads pass through untouched. */
export function classifySensitiveEscalation(
  toolName: string,
  toolKind: string | undefined,
  params: Record<string, unknown> | undefined,
): SelfProtectionResult {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    return { hits: [], escalate: false };
  }
  const keys = relevantParams(toolName, toolKind);
  if (!keys) return { hits: [], escalate: false };

  const hits: SelfProtectionHit[] = [];
  for (const key of keys) {
    const value = params[key];
    if (typeof value !== "string" || value.length === 0 || value.length > MAX_SCAN_LENGTH) continue;
    const marker = matchMarker(value);
    if (marker) hits.push({ marker, param: key });
    if (hits.length >= MAX_HITS) break;
  }
  if (hits.length === 0) return { hits, escalate: false };
  // The carrier is mutating by construction (exec/file tool), so any hit
  // escalates. This mirrors remit: the classification is structural, not a
  // per-parameter judgement call.
  return { hits, escalate: true };
}

/** True when the tool is a known pure observation carrier (reads of the
 *  authority surface are allowed). Exported for tests. */
export function isReadOnlyCarrier(toolName: string, toolKind: string | undefined): boolean {
  if (toolKind) {
    if (READONLY_TOOL_KINDS.has(toolKind)) return true;
    if (DESTRUCTIVE_TOOL_KINDS.has(toolKind)) return false;
  }
  const segments = tokenizeName(toolName);
  if (segments.some((seg) => DESTRUCTIVE_NAME_TOKENS.includes(seg))) return false;
  if (segments.some((seg) => READONLY_NAME_TOKENS.includes(seg))) return true;
  return false; // unknown → assume it can mutate (fail-closed)
}
