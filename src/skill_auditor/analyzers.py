"""Small, bounded cross-line analyzers for language-specific risk patterns."""

from __future__ import annotations

import ast
import re
from pathlib import Path


def run_named_check(rule: dict, relative_path: str, text: str) -> list[tuple[int, str]]:
    check = rule.get("check")
    suffix = Path(relative_path).suffix.lower()
    if check == "python-exfiltration" and suffix == ".py":
        return _python_exfiltration(text)
    if check == "python-decoded-exec" and suffix == ".py":
        return _python_decoded_exec(text)
    if check == "node-exfiltration" and suffix in {".js", ".mjs", ".cjs", ".ts"}:
        return _node_exfiltration(text)
    if check == "powershell-download-exec" and suffix == ".ps1":
        return _powershell_download_exec(text)
    if check == "mcp-config-write":
        return _mcp_config_write(text)
    if check == "unicode-homoglyph":
        return _unicode_homoglyph(text)
    if check == "vscode-remote-vsix-install":
        return _vscode_remote_vsix_install(text)
    return []


def _python_exfiltration(text: str) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    tainted: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is not None and _is_sensitive_python_expression(value):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    tainted.update(_assigned_names(target))
    output = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_python_network_sink(node):
            continue
        payload_nodes = [*node.args, *(keyword.value for keyword in node.keywords)]
        if any(_is_sensitive_python_expression(item) or _references_names(item, tainted)
               for item in payload_nodes):
            output.append((getattr(node, "lineno", 1), _source_line(text, node)))
    return output


def _python_decoded_exec(text: str) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    output = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name not in {"eval", "exec"} or not node.args:
            continue
        expression = ast.unparse(node.args[0]) if hasattr(ast, "unparse") else ""
        if re.search(r"(base64|b64decode|urlopen|requests\.|socket\.)", expression, re.I):
            output.append((getattr(node, "lineno", 1), expression))
    return output


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _node_exfiltration(text: str) -> list[tuple[int, str]]:
    assignment = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[^\n]*"
        r"(?:readFileSync|readFile|process\.env|\.ssh|\.aws|\.env|TOKEN|SECRET|PASSWORD)",
        re.IGNORECASE,
    )
    sink = re.compile(
        r"(?:fetch\s*\(|https?\.request\s*\(|axios\.(?:post|put|patch)"
        r"|child_process\.(?:exec|spawn)[^\n]*(?:curl|wget))",
        re.IGNORECASE,
    )
    tainted = {match.group(1) for match in assignment.finditer(text)}
    if not tainted:
        return []
    output = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if sink.search(line) and any(re.search(rf"\b{re.escape(name)}\b", line) for name in tainted):
            output.append((line_number, line.strip()))
    return output


def _powershell_download_exec(text: str) -> list[tuple[int, str]]:
    download = re.compile(r"(?:Invoke-WebRequest|iwr\b|Net\.WebClient|DownloadString)", re.I)
    execute = re.compile(r"(?:Invoke-Expression|\biex\b|Start-Process|&\s*\$)", re.I)
    if not download.search(text) or not execute.search(text):
        return []
    return _matching_lines(text, execute)


def _mcp_config_write(text: str) -> list[tuple[int, str]]:
    target = re.compile(
        r"(?:claude_desktop_config\.json|\.cursor[\\/].*(?:mcp|config)"
        r"|\.codex[\\/].*(?:config|mcp)|mcpServers)",
        re.I,
    )
    mutation = re.compile(
        r"(?:write_text|writeFile|Set-Content|Add-Content|Out-File|>>|json\.dump)",
        re.I,
    )
    if not target.search(text) or not mutation.search(text):
        return []
    return _matching_lines(text, mutation)


_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Χ": "X", "Υ": "Y",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "χ": "x", "υ": "y",
})
_SENSITIVE_SKELETON = re.compile(
    r"(?i)(?:https?://|curl|wget|powershell|invoke|ignore|instruction|"
    r"token|secret|upload|execute|eval|github)"
)


def _unicode_homoglyph(text: str) -> list[tuple[int, str]]:
    output = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        skeleton = line.translate(_CONFUSABLES)
        if skeleton != line and _SENSITIVE_SKELETON.search(skeleton):
            output.append((line_number, line.strip()))
    return output


def _vscode_remote_vsix_install(text: str) -> list[tuple[int, str]]:
    remote_vsix = re.compile(
        r"(?i)(?:https?://[^\s\"']+\.vsix\b|"
        r"(?:curl|wget|Invoke-WebRequest)[^\n]{0,200}\.vsix\b)"
    )
    installer = re.compile(
        r"(?i)(?:\bcode(?:\.cmd)?\b|\bcodium\b)"
        r"[^\n]{0,120}--install-extension[^\n]{0,120}\.vsix\b"
    )
    if not remote_vsix.search(text) or not installer.search(text):
        return []
    return _matching_lines(text, installer)


def _matching_lines(text: str, pattern: re.Pattern) -> list[tuple[int, str]]:
    output = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            output.append((line_number, line.strip()))
    return output


def _assigned_names(node: ast.AST) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def _references_names(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(item, ast.Name) and item.id in names for item in ast.walk(node))


def _is_sensitive_python_expression(node: ast.AST) -> bool:
    rendered = ast.dump(node, include_attributes=False)
    return bool(re.search(
        r"(?:\bopen\b|read_text|read_bytes|os.*(?:environ|getenv)|"
        r"\.ssh|\.aws|\.env|TOKEN|SECRET|PASSWORD|CREDENTIAL)",
        rendered,
        re.IGNORECASE,
    ))


def _is_python_network_sink(node: ast.Call) -> bool:
    name = _call_name(node.func)
    if name in {
        "requests.post", "requests.put", "requests.patch",
        "urllib.request.urlopen", "urllib.request.Request",
    }:
        return True
    if name.endswith((".send", ".sendall", ".sendto")):
        return True
    if name in {"subprocess.run", "subprocess.Popen", "subprocess.call"}:
        rendered = ast.dump(node, include_attributes=False)
        return bool(re.search(r"(?:curl|wget)", rendered, re.IGNORECASE))
    return False


def _source_line(text: str, node: ast.AST) -> str:
    lines = text.splitlines()
    number = max(1, getattr(node, "lineno", 1))
    return lines[number - 1].strip() if number <= len(lines) else ""
