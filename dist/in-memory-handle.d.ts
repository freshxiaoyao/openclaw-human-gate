/**
 * In-memory fallback for `SessionExtensionHandle` when the host runtime does
 * not support session extensions (e.g. some embedded runtimes). State is
 * per-process and does not survive restarts, but keeps the plugin functional.
 */
import type { SessionExtensionHandle } from "openclaw/plugin-sdk/plugin-entry";
export declare function createInMemoryHandle<T>(defaultValue?: T): SessionExtensionHandle<T>;
//# sourceMappingURL=in-memory-handle.d.ts.map