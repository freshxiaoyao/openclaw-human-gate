/**
 * In-memory fallback for `SessionExtensionHandle` when the host runtime does
 * not support session extensions (e.g. some embedded runtimes). State is
 * per-process and does not survive restarts, but keeps the plugin functional.
 */

import type { SessionExtensionHandle } from "openclaw/plugin-sdk/plugin-entry";

export function createInMemoryHandle<T>(
  defaultValue?: T,
): SessionExtensionHandle<T> {
  let value: T | undefined = defaultValue;
  return {
    get(): T | undefined {
      return value;
    },
    set(next: T): void {
      value = next;
    },
    update(fn: (current: T | undefined) => T): void {
      value = fn(value);
    },
  };
}
