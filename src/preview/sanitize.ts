const ANSI_ESCAPE = /\x1B(?:\][^\u0007]*(?:\u0007|\x1B\\)|\[[0-?]*[ -/]*[@-~]|[@-_])/g;
const BIDI_CONTROL = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
const PRIVATE_KEY = /-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-\r\n]*PRIVATE KEY-----|$)/gi;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const BASIC = /\bBasic\s+[A-Za-z0-9+/=]{8,}/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const PROVIDER_TOKEN = /\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,})\b/g;
const SECRET_ASSIGNMENT = /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|password|passwd|secret(?:[_-]?key)?|client[_-]?secret)\b(\s*[=:]\s*)(["'`]?[A-Za-z0-9_./+~=-]{6,}["'`]?)/gi;
const SECRET_FLAG = /(^|[\s;&|])(--?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|authorization|cookie))(\s+)([^\s"'`]{4,}|["'`][^"'`]{4,}["'`])/gim;
const COOKIE_HEADER = /\bCookie\s*:\s*[^\r\n]+/gi;
const URL_CREDENTIALS = /(https?:\/\/)([^\s/@:]+):([^\s/@]+)@/gi;

export function truncateText(value: string, max: number): string {
  if (value.length <= max) return value;
  let prefix = value.slice(0, Math.max(0, max - 1));
  if (/[\uD800-\uDBFF]$/.test(prefix)) prefix = prefix.slice(0, -1);
  return `${prefix}…`;
}

export function headTailText(value: string, max: number): string {
  if (value.length <= max) return value;
  const separator = "\n…\n";
  const available = Math.max(0, max - separator.length);
  const headLength = Math.ceil(available / 2);
  const tailLength = Math.floor(available / 2);
  let head = value.slice(0, headLength);
  let tail = value.slice(value.length - tailLength);
  if (/[\uD800-\uDBFF]$/.test(head)) head = head.slice(0, -1);
  if (/^[\uDC00-\uDFFF]/.test(tail)) tail = tail.slice(1);
  return `${head}${separator}${tail}`;
}

export function sanitizeText(value: string, redactSecrets: boolean): string {
  let clean = value
    .replace(ANSI_ESCAPE, "")
    .replace(BIDI_CONTROL, "[BIDI]")
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "�");

  if (redactSecrets) {
    clean = clean
      .replace(PRIVATE_KEY, "[REDACTED PRIVATE KEY]")
      .replace(BEARER, "Bearer [REDACTED]")
      .replace(BASIC, "Basic [REDACTED]")
      .replace(JWT, "[REDACTED JWT]")
      .replace(PROVIDER_TOKEN, "[REDACTED TOKEN]")
      .replace(SECRET_ASSIGNMENT, (_match, name: string, separator: string) =>
        `${name}${separator}[REDACTED]`)
      .replace(SECRET_FLAG, (_match, prefix: string, name: string, separator: string) =>
        `${prefix}${name}${separator}[REDACTED]`)
      .replace(COOKIE_HEADER, "Cookie: [REDACTED]")
      .replace(URL_CREDENTIALS, "$1[REDACTED]@[HOST]");
  }
  return clean;
}

export function boundedLines(value: string, maxLines: number, maxChars: number): string {
  const lines = value.split("\n");
  const selected = lines.slice(0, maxLines).join("\n");
  const suffix = lines.length > maxLines ? "\n…" : "";
  return truncateText(`${selected}${suffix}`, maxChars);
}
