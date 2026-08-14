/** Semantic authorization fingerprints used by approval windows and grants. */
import { createHash } from "node:crypto";
export const AUTHORIZATION_FINGERPRINT_VERSION = 2;
/** Bound path fingerprints so a single approval cannot create unbounded state. */
export const MAX_PATH_SCOPE_DIRECTORIES = 64;
const MAX_PATH_SCOPE_TARGETS = 128;
const IS_WINDOWS = process.platform === "win32";
function strictToken(value) {
    if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
        return undefined;
    }
    return value;
}
function normalizedSet(values) {
    if (!Array.isArray(values) || values.length === 0)
        return undefined;
    const result = new Set();
    for (const value of values) {
        const token = strictToken(value);
        if (!token || token.toLowerCase() === "unknown")
            return undefined;
        result.add(token);
    }
    return [...result].sort((a, b) => a.localeCompare(b, "en"));
}
function parseSegments(raw, windows) {
    const parts = windows ? raw.split(/[\\/]+/) : raw.split("/");
    const result = [];
    for (const part of parts) {
        if (part.length === 0 || part === ".")
            continue;
        // Never resolve parent traversal while constructing an authorization key.
        if (part === "..")
            return undefined;
        if (windows) {
            // Windows aliases trailing dots/spaces and reserves these characters.
            if (/[<>:"|?*]/.test(part) || /[. ]$/.test(part))
                return undefined;
            result.push(part.toLowerCase());
        }
        else {
            result.push(part);
        }
    }
    return result;
}
function parseAbsolutePath(value, allowRoot = false) {
    if (typeof value !== "string" || value.length === 0)
        return undefined;
    if (value.startsWith("~") || /[\0-\x1f\x7f]/.test(value))
        return undefined;
    // Device namespaces have aliasing rules that cannot safely share a key with
    // ordinary DOS/UNC paths, so they deliberately receive no path scope.
    if (/^(?:\\\\|\/\/)[?.](?:\\|\/)/.test(value))
        return undefined;
    const drive = /^([A-Za-z]):[\\/](.*)$/.exec(value);
    if (drive) {
        if (!IS_WINDOWS)
            return undefined;
        const segments = parseSegments(drive[2] ?? "", true);
        if (!segments || (!allowRoot && segments.length === 0))
            return undefined;
        return {
            kind: "windows-drive",
            volume: `drive:${drive[1].toLowerCase()}`,
            segments,
        };
    }
    const unc = /^(?:\\\\|\/\/)([^\\/]+)[\\/]([^\\/]+)(?:[\\/](.*))?$/.exec(value);
    if (unc) {
        if (!IS_WINDOWS)
            return undefined;
        const server = unc[1].toLowerCase();
        const share = unc[2].toLowerCase();
        if (server === "." || server === ".." || share === "." || share === ".." ||
            /[<>:"|?*]/.test(server) || /[<>:"|?*]/.test(share) ||
            /[. ]$/.test(server) || /[. ]$/.test(share)) {
            return undefined;
        }
        const segments = parseSegments(unc[3] ?? "", true);
        if (!segments || (!allowRoot && segments.length === 0))
            return undefined;
        return { kind: "unc", volume: `unc:${server}/${share}`, segments };
    }
    // `//` was considered as UNC above. An invalid UNC must not silently become
    // a POSIX path with a broader interpretation.
    if (IS_WINDOWS)
        return undefined;
    if (!value.startsWith("/") || value.startsWith("//"))
        return undefined;
    const segments = parseSegments(value.slice(1), false);
    if (!segments || (!allowRoot && segments.length === 0))
        return undefined;
    return { kind: "posix", volume: "posix:/", segments };
}
function parseRelativePath(value, base) {
    if (value.length === 0 || value.startsWith("~") || value.startsWith("/") ||
        value.startsWith("\\") || /^[A-Za-z]:/.test(value) || /[\0-\x1f\x7f]/.test(value)) {
        return undefined;
    }
    return parseSegments(value, base.kind !== "posix");
}
function resolveTarget(target, executionCwd) {
    if (!target || (target.targetKind !== "file" && target.targetKind !== "directory")) {
        return undefined;
    }
    if (target.targetKind === "file" &&
        (/[\\/]$/.test(target.path) || /(?:^|[\\/])\.{1,2}$/.test(target.path))) {
        return undefined;
    }
    let parsed = parseAbsolutePath(target.path, true);
    if (!parsed) {
        // An agent workspace is not necessarily the tool's execution cwd. Relative
        // targets are reusable only when the host supplies the authoritative cwd.
        const base = parseAbsolutePath(executionCwd, true);
        if (!base)
            return undefined;
        const relative = parseRelativePath(target.path, base);
        if (!relative)
            return undefined;
        parsed = { ...base, segments: [...base.segments, ...relative] };
    }
    const segments = [...parsed.segments];
    // File authorization is directory-scoped: this permits sibling writes while
    // preventing a single approved file from turning into a volume-wide grant.
    if (target.targetKind === "file")
        segments.pop();
    if (segments.length === 0)
        return undefined;
    return { ...parsed, segments };
}
function renderDirectory(path) {
    const normalized = path.kind === "posix"
        ? `/${path.segments.join("/")}`
        : path.kind === "windows-drive"
            ? `${path.volume.slice("drive:".length)}:\\${path.segments.join("\\")}`
            : `\\\\${path.volume.slice("unc:".length).replace("/", "\\")}\\${path.segments.join("\\")}`;
    return { kind: path.kind, volume: path.volume, path: normalized };
}
function directoryIdentity(directory) {
    return `${directory.kind}\0${directory.volume}\0${directory.path}`;
}
/** Return a bounded exact set of canonical parent directories. */
export function normalizePathScope(targets, executionCwd) {
    if (!Array.isArray(targets) || targets.length === 0 ||
        targets.length > MAX_PATH_SCOPE_TARGETS) {
        return undefined;
    }
    const unique = new Map();
    for (const target of targets) {
        const resolved = resolveTarget(target, executionCwd);
        if (!resolved)
            return undefined;
        const directory = renderDirectory(resolved);
        unique.set(directoryIdentity(directory), directory);
        if (unique.size > MAX_PATH_SCOPE_DIRECTORIES)
            return undefined;
    }
    const directories = [...unique.values()].sort((left, right) => directoryIdentity(left).localeCompare(directoryIdentity(right), "en"));
    return directories.length > 0 ? { directories } : undefined;
}
function digest(prefix, value) {
    const hash = createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
    return `${prefix}${AUTHORIZATION_FINGERPRINT_VERSION}:${hash}`;
}
function canonicalJson(value, seen) {
    if (value === null || typeof value === "string" || typeof value === "boolean") {
        return JSON.stringify(value);
    }
    if (typeof value === "number")
        return Number.isFinite(value) ? JSON.stringify(value) : undefined;
    if (typeof value !== "object")
        return undefined;
    if (seen.has(value))
        return undefined;
    seen.add(value);
    try {
        if (Array.isArray(value)) {
            const keys = Reflect.ownKeys(value);
            if (keys.some((key) => {
                if (key === "length")
                    return false;
                if (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(key))
                    return true;
                const index = Number(key);
                return !Number.isSafeInteger(index) || index < 0 || index >= value.length;
            })) {
                return undefined;
            }
            const items = [];
            for (let index = 0; index < value.length; index += 1) {
                const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
                if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
                    return undefined;
                const item = canonicalJson(descriptor.value, seen);
                if (item === undefined)
                    return undefined;
                items.push(item);
            }
            return `[${items.join(",")}]`;
        }
        const keys = Reflect.ownKeys(value);
        if (keys.some((key) => typeof key !== "string"))
            return undefined;
        const sorted = keys.sort((a, b) => a.localeCompare(b, "en"));
        const fields = [];
        for (const key of sorted) {
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
                return undefined;
            const field = canonicalJson(descriptor.value, seen);
            if (field === undefined)
                return undefined;
            fields.push(`${JSON.stringify(key)}:${field}`);
        }
        return `{${fields.join(",")}}`;
    }
    finally {
        seen.delete(value);
    }
}
/** Stable digest of every authorization-relevant policy field. */
export function createPolicyIdentity(policy) {
    const canonical = canonicalJson(policy, new Set());
    if (canonical === undefined)
        return undefined;
    return `policy2:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}
/**
 * Build stable temporary-window and permanent-grant keys. Returning undefined
 * is the expected fail-closed result for missing/unknown/partial semantics.
 */
export function createAuthorizationFingerprint(context, options) {
    const toolName = strictToken(context.toolName);
    const toolKind = strictToken(context.toolKind);
    const toolInputKind = strictToken(context.toolInputKind);
    const ruleId = strictToken(context.ruleId);
    const policyIdentity = strictToken(context.policyIdentity);
    const rulesetVersion = strictToken(options.rulesetVersion);
    if (context.analysisComplete !== true || !toolName || !toolKind || !toolInputKind ||
        !ruleId || !policyIdentity || !rulesetVersion) {
        return undefined;
    }
    const effects = normalizedSet(context.effects);
    const categories = normalizedSet(context.categories);
    if (!effects || !categories)
        return undefined;
    const identity = {
        toolName,
        toolKind,
        toolInputKind,
        ruleId,
        policyIdentity,
    };
    const pathScope = normalizePathScope(context.verifiedTargets, context.executionCwd);
    const requestedScope = options.scope;
    let resolvedScope = requestedScope;
    if (requestedScope === "path" && !pathScope) {
        // A supplied target that cannot be normalized is materially different from
        // a tool with no path semantics. Never broaden an unresolved relative or
        // malformed target through pathFallback.
        if (context.verifiedTargets.length > 0)
            return undefined;
        const fallback = options.pathFallback ?? "none";
        if (fallback === "none")
            return undefined;
        resolvedScope = fallback;
    }
    // Legacy `destructive` remains an explicit compatibility scope. Every new
    // semantic/default scope is narrower, while permanent grants never use it.
    const projection = resolvedScope === "destructive"
        ? { destructive: true }
        : resolvedScope === "same-tool"
            ? { identity }
            : resolvedScope === "effect"
                ? { identity, effects }
                : resolvedScope === "category"
                    ? { identity, effects, categories }
                    : { identity, effects, categories, path: pathScope };
    const windowCanonical = {
        fingerprintVersion: AUTHORIZATION_FINGERPRINT_VERSION,
        rulesetVersion,
        requestedScope,
        resolvedScope,
        projection,
    };
    const windowKey = digest("win", windowCanonical);
    const grantKey = pathScope
        ? digest("grant", {
            fingerprintVersion: AUTHORIZATION_FINGERPRINT_VERSION,
            rulesetVersion,
            identity,
            effects,
            categories,
            path: pathScope,
        })
        : undefined;
    return {
        windowKey,
        grantKey,
        scopeKey: windowKey,
        requestedScope,
        resolvedScope,
        fingerprintVersion: AUTHORIZATION_FINGERPRINT_VERSION,
        rulesetVersion,
        identity,
    };
}
export function isAuthorizationFingerprint(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return false;
    const candidate = value;
    const validScope = (scope) => scope === "destructive" || scope === "same-tool" || scope === "effect" ||
        scope === "category" || scope === "path";
    const identity = candidate.identity;
    return (typeof candidate.windowKey === "string" && /^win2:[0-9a-f]{64}$/.test(candidate.windowKey) &&
        candidate.scopeKey === candidate.windowKey &&
        (candidate.grantKey === undefined || /^grant2:[0-9a-f]{64}$/.test(candidate.grantKey)) &&
        validScope(candidate.requestedScope) && validScope(candidate.resolvedScope) &&
        candidate.fingerprintVersion === AUTHORIZATION_FINGERPRINT_VERSION &&
        strictToken(candidate.rulesetVersion) !== undefined &&
        Boolean(identity && strictToken(identity.toolName) && strictToken(identity.toolKind) &&
            strictToken(identity.toolInputKind) && strictToken(identity.ruleId) &&
            strictToken(identity.policyIdentity)));
}
//# sourceMappingURL=scope.js.map