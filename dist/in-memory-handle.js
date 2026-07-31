/**
 * In-memory fallback for `SessionExtensionHandle` when the host runtime does
 * not support session extensions (e.g. some embedded runtimes). State is
 * per-process and does not survive restarts, but keeps the plugin functional.
 */
export function createInMemoryHandle(defaultValue) {
    let value = defaultValue;
    return {
        get() {
            return value;
        },
        set(next) {
            value = next;
        },
        update(fn) {
            value = fn(value);
        },
    };
}
//# sourceMappingURL=in-memory-handle.js.map