<!-- AUTO-GENERATED from rules/, do not edit by hand. Run: python scripts/render_catalog.py -->

# Risk Pattern Catalog

This catalog is generated from the packaged rule catalog. Rules are either
deterministic matches or semantic pre-filters that require contextual review.

## Severity model

| Severity | Meaning | Effect on verdict |
|---|---|---|
| `CRITICAL` | Strong evidence of theft, execution, escape, or hijack. | any -> **DO NOT INSTALL** |
| `WARNING` | Risky behavior that requires review. | any (no CRITICAL) -> **REVIEW** |
| `INFO` | Context worth surfacing. | does not block by default |


## Categories

| Category | Layer | Rules |
|---|---|---:|
| Filesystem boundary | deterministic | 2 |
| Data exfiltration | deterministic | 6 |
| Credential read | deterministic | 9 |
| Dangerous shell | deterministic | 8 |
| PowerShell execution | deterministic | 4 |
| Dynamic execution | deterministic | 6 |
| Archive risk | deterministic | 4 |
| Git hook persistence | deterministic | 2 |
| MCP configuration tampering | deterministic | 3 |
| Editor and extension tampering | deterministic | 2 |
| Obfuscation / evasion | deterministic, semantic | 7 |
| Prompt injection / instruction hijack | semantic | 4 |
| Description vs. behavior mismatch | semantic | 1 |
| Logic bomb | semantic | 1 |

## Filesystem boundary

Category id: `filesystem-boundary`

### `BOUNDARY-001` · CRITICAL · deterministic

A filesystem link escapes the skill root, is broken, or forms a cycle; following it could read or install files outside the audited tree.

- **Check:** `filesystem-link-external`

### `BOUNDARY-002` · WARNING · deterministic

The skill contains an internal filesystem link. It is not followed during scanning and must be removed before installation.

- **Check:** `filesystem-link-internal`


## Data exfiltration

Category id: `data-exfiltration`

### `EXFIL-001` · CRITICAL · deterministic

Uploads a request body to an external host, a direct channel for shipping local files, env vars, or conversation data off the machine.

- **Pattern:** `\b(?:curl|wget)\b[^\n]*\s(?:--data(?:-binary|-raw|-urlencode)?|--form|--upload-file|--post-data|--post-file|--body-data|--body-file|-d|-F|-T)\b`

### `EXFIL-002` · CRITICAL · deterministic

Reads local data and pipes it straight into a network tool, the classic collect-then-send exfiltration shape.

- **Pattern:** `\b(?:cat|tail|head|env|printenv|base64|tar|zip|gzip|find)\b[^|\n]*\|[^\n]*\b(?:curl|wget|nc|ncat|netcat|socat|telnet)\b`

### `EXFIL-003` · CRITICAL · deterministic

Places a secret-shaped environment variable (API key, token, password) into a network call.

- **Pattern:** `(?:\b(?:curl|wget|fetch|requests\.(?:post|get|put))\b|https?://)[^\n]*\$\{?[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASS|CRED|AUTH)[A-Z0-9_]*\}?`

### `EXFIL-004` · CRITICAL · deterministic

References a known request-collector or tunnel service commonly used to receive exfiltrated data.

- **Pattern:** `(?i)\b(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|ngrok\.(?:io|app|dev)|burpcollaborator\.net|interact\.sh|oast\.(?:pro|live|site|fun|me)|requestcatcher\.com|hookbin\.com|beeceptor\.com|mockbin\.org)\b`

### `NODEEXFIL-001` · CRITICAL · deterministic

A Node script combines a sensitive local-data source with an HTTP or child-process upload sink.

- **Files:** `*.js,*.mjs,*.cjs,*.ts`
- **Check:** `node-exfiltration`

### `PYEXFIL-001` · CRITICAL · deterministic

A Python script combines a sensitive local-data source with a network or subprocess upload sink.

- **Files:** `*.py`
- **Check:** `python-exfiltration`


## Credential read

Category id: `credential-read`

### `CRED-001` · CRITICAL · deterministic

Reads SSH private keys or trusted-host files, which grant direct access to remote servers.

- **Pattern:** `(?:~|\$HOME|/home/[^/\s]+|/root)?/?\.ssh/(?:id_[a-z0-9]+|authorized_keys|known_hosts)|\.ssh/id_`

### `CRED-002` · CRITICAL · deterministic

Reads AWS credentials, granting access to cloud resources and billing.

- **Pattern:** `(?:~|\$HOME)?/?\.aws/(?:credentials|config)\b|\bAWS_SECRET_ACCESS_KEY\b|\bAWS_ACCESS_KEY_ID\b|\bAWS_SESSION_TOKEN\b`

### `CRED-003` · CRITICAL · deterministic

Reads cloud, cluster, or package-registry credential files.

- **Pattern:** `\.config/gcloud\b|\bGOOGLE_APPLICATION_CREDENTIALS\b|\.azure/(?:credentials|accessTokens)\b|\.kube/config\b|\.docker/config\.json\b|(?:~|\$HOME)?/?\.(?:netrc|npmrc|pypirc|git-credentials)\b`

### `CRED-004` · WARNING · deterministic

Reads a .env file, which usually holds the current project secrets.

- **Pattern:** `\b(?:cat|source|read|less|more|grep|load_dotenv|dotenv)\b[^\n]*\.env\b|(?:^|[\s"\x27/=])\.env(?:\.[\w.]+)?(?:\b|$)`

### `CRED-005` · WARNING · deterministic

Reads OS keychain entries or token-bearing files.

- **Pattern:** `\bsecurity\s+find-(?:generic|internet)-password\b|\b(?:cat|read|less|more|printenv|echo)\b[^\n]*\b[\w./-]*token[\w./-]*\b`

### `CRED-006` · CRITICAL · deterministic

Reads a GitHub Actions token or personal access token that can grant repository and organization access.

- **Pattern:** `(?i)(?:\$(?:GITHUB_TOKEN|GH_TOKEN)\b|process\.env\.(?:GITHUB_TOKEN|GH_TOKEN)\b|os\.(?:environ|getenv)[^\n]{0,40}(?:GITHUB_TOKEN|GH_TOKEN)|Env:(?:GITHUB_TOKEN|GH_TOKEN)\b|(?:cat|printenv|echo|env|Get-Content|type)\b[^\n]*(?:(?:GITHUB_TOKEN|GH_TOKEN)|github_pat_|gh[pousr]_))`

### `CRED-007` · CRITICAL · deterministic

Reads or exports GCP application-default credentials, access tokens, or service-account private key material.

- **Pattern:** `(?i)(?:\.config/gcloud/application_default_credentials\.json|gcloud\s+auth\s+application-default\s+print-access-token|GOOGLE_APPLICATION_CREDENTIALS|service[_ -]?account[^\n]{0,30}private[_ -]?key)`

### `CRED-008` · CRITICAL · deterministic

Reads Azure client secrets, cached tokens, access tokens, or shared-access signatures.

- **Pattern:** `(?i)(?:\.azure/(?:accessTokens\.json|msal_token_cache)|AZURE_CLIENT_SECRET|az\s+account\s+get-access-token|(?:SharedAccessSignature|sig=)[^\n]{0,80}(?:sv=|se=))`

### `CRED-009` · WARNING · deterministic

Contains a GitHub, GCP, or Azure token-shaped literal that may be a committed credential.

- **Pattern:** `(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|ya29\.[A-Za-z0-9_-]{20,})\b|\bsv=\d{4}-\d{2}-\d{2}[^\s]{0,200}&sig=[A-Za-z0-9%+/=_-]{16,}`
- **Review:** Confirm the value is synthetic or revoked; never publish a live credential.


## Dangerous shell

Category id: `dangerous-shell`

### `SHELL-001` · CRITICAL · deterministic

Downloads a remote script and executes it immediately; the remote content can change after review and runs with your privileges.

- **Pattern:** `\b(?:curl|wget|fetch)\b[^|\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ksh|dash|python[0-9.]*|perl|ruby|node)\b`

### `SHELL-002` · CRITICAL · deterministic

Recursive forced delete (rm -rf); irreversible mass deletion if the path is wrong or attacker-controlled.

- **Pattern:** `\brm\s+(?:-\S+\s+)*-[a-zA-Z]*(?:rf|fr|r[a-zA-Z]*f|f[a-zA-Z]*r)\b`

### `SHELL-003` · CRITICAL · deterministic

Disables the guard that stops rm -rf from wiping the filesystem root.

- **Pattern:** `--no-preserve-root`

### `SHELL-004` · WARNING · deterministic

Appends to a shell startup file, a persistence mechanism whose code runs on every new shell.

- **Pattern:** `(?:>>|\btee\s+(?:-a\s+)?)[^\n]*(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile|\.bash_aliases|\.config/fish/config\.fish)\b`

### `SHELL-005` · CRITICAL · deterministic

Writes directly to a raw disk device, which can destroy a filesystem or whole drive.

- **Pattern:** `\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|hd|disk|mmcblk)|\bmkfs(?:\.\w+)?\b|>\s*/dev/(?:sd|nvme|hd)\b`

### `SHELL-006` · WARNING · deterministic

Clears or disables shell history, a way to hide what commands were run.

- **Pattern:** `\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|\brm\b[^\n]*\.bash_history`

### `SHELL-007` · WARNING · deterministic

Grants world-writable or executable permissions, weakening security and enabling later tampering.

- **Pattern:** `\bchmod\s+(?:-\S+\s+)*(?:0?777|a\+rwx|ugo\+rwx)\b`

### `SHELL-008` · INFO · deterministic

Requests root or admin privileges, raising the blast radius of everything else in the skill.

- **Pattern:** `\bsudo\b`


## PowerShell execution

Category id: `powershell`

### `PS-001` · WARNING · deterministic

Executes dynamically constructed PowerShell code, which can conceal the command that actually runs.

- **Files:** `*.ps1`
- **Pattern:** `(?i)\b(?:Invoke-Expression|IEX)\b`

### `PS-002` · CRITICAL · deterministic

Launches PowerShell with an encoded command, a common way to hide a payload from review.

- **Files:** `*.ps1,*.bat,*.cmd`
- **Pattern:** `(?i)(?:-EncodedCommand|-enc\b)[^\n]*[A-Za-z0-9+/]{20,}={0,2}`

### `PS-003` · WARNING · deterministic

Starts a hidden or elevated process, increasing stealth or privilege.

- **Files:** `*.ps1`
- **Pattern:** `(?i)\bStart-Process\b[^\n]*(?:-WindowStyle\s+Hidden|-Verb\s+RunAs)`

### `PS-004` · CRITICAL · deterministic

Downloads content and executes it in the same PowerShell script.

- **Files:** `*.ps1`
- **Check:** `powershell-download-exec`


## Dynamic execution

Category id: `dynamic-execution`

### `DYNAMIC-NODE-001` · WARNING · deterministic

Dynamically evaluates JavaScript code; the source of the executed string requires review.

- **Files:** `*.js,*.mjs,*.cjs,*.ts`
- **Pattern:** `\b(?:eval\s*\(|new\s+Function\s*\(|Function\s*\()`

### `DYNAMIC-NODE-002` · WARNING · deterministic

Dynamically loads a module selected from runtime-controlled input.

- **Files:** `*.js,*.mjs,*.cjs,*.ts`
- **Pattern:** `\b(?:require|import)\s*\([^)]*(?:process\.env|readFile|argv|input)`

### `DYNAMIC-NODE-003` · CRITICAL · deterministic

Runs a shell-capable child process using a remote-fetch or explicit shell command.

- **Files:** `*.js,*.mjs,*.cjs,*.ts`
- **Pattern:** `\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:shell\s*:\s*true|curl|wget|powershell)`

### `DYNAMIC-PY-001` · WARNING · deterministic

Dynamically evaluates Python code; legitimate uses exist, but the executed value must be reviewed.

- **Files:** `*.py`
- **Pattern:** `\b(?:eval|exec)\s*\(`

### `DYNAMIC-PY-002` · CRITICAL · deterministic

Executes Python content produced by decoding or a network source.

- **Files:** `*.py`
- **Check:** `python-decoded-exec`

### `DYNAMIC-PY-003` · WARNING · deterministic

Dynamically imports a module selected from runtime-controlled input.

- **Files:** `*.py`
- **Pattern:** `\b(?:__import__|importlib\.import_module)\s*\([^)]*(?:input|environ|getenv|read)`


## Archive risk

Category id: `archive-risk`

### `ARCHIVE-001` · CRITICAL · deterministic

An archive member uses an absolute or parent-relative path and could overwrite files outside an extraction directory.

- **Check:** `archive-path-traversal`

### `ARCHIVE-002` · CRITICAL · deterministic

An archive contains a symbolic or hard link that can redirect extraction outside the intended directory.

- **Check:** `archive-link`

### `ARCHIVE-003` · WARNING · deterministic

An archive contains an executable script or Git hook that may run after extraction.

- **Check:** `archive-hidden-executable`

### `ARCHIVE-004` · WARNING · deterministic

An archive has a suspicious compression ratio or expanded size and may exhaust local resources.

- **Check:** `archive-resource-limit`


## Git hook persistence

Category id: `git-hook`

### `GITHOOK-001` · CRITICAL · deterministic

Installs or redirects Git hooks, creating code execution tied to normal repository operations.

- **Pattern:** `(?i)(?:git\s+config[^\n]*core\.hooksPath|(?:(?:write|copy|move|install|Set-Content|Out-File|>>|cp\s|mv\s)[^\n]*(?:\.git[\\/]hooks[\\/]|core\.hooksPath)|(?:\.git[\\/]hooks[\\/]|core\.hooksPath)[^\n]*(?:write|copy|move|install|Set-Content|Out-File|>>|cp\s|mv\s)))`

### `GITHOOK-002` · WARNING · deterministic

Creates or activates a named Git hook and should be reviewed for persistence.

- **Pattern:** `(?i)(?:(?:chmod|write|copy|install|Set-Content|Out-File)[^\n]*(?:pre-commit|post-checkout|post-merge|pre-push|commit-msg|prepare-commit-msg)|(?:pre-commit|post-checkout|post-merge|pre-push|commit-msg|prepare-commit-msg)[^\n]*(?:chmod|write|copy|install|Set-Content|Out-File))`


## MCP configuration tampering

Category id: `mcp-tampering`

### `MCP-001` · WARNING · deterministic

References an MCP or agent configuration location; any mutation may change which external commands the agent trusts.

- **Pattern:** `(?i)(?:claude_desktop_config\.json|\.cursor[\\/].*(?:mcp|config)|\.codex[\\/].*(?:config|mcp)|mcpServers)`

### `MCP-002` · CRITICAL · deterministic

Writes an MCP configuration or server definition, potentially replacing commands or injecting attacker-controlled environment variables.

- **Check:** `mcp-config-write`

### `MCP-003` · WARNING · deterministic

An MCP-specific configuration declares an executable command or environment block that will be trusted by the agent.

- **Files:** `*mcp*.json,*mcp*.toml,*mcp*.yaml,*mcp*.yml`
- **Pattern:** `(?i)(?:"?command"?\s*[:=]\s*["\x27]?(?:powershell|cmd|bash|sh|node|python|npx|uvx)\b|"?env"?\s*[:=])`


## Editor and extension tampering

Category id: `editor-tampering`

### `VSCODE-001` · WARNING · deterministic

Automatically installs a VS Code-compatible extension, adding executable code to the developer environment.

- **Pattern:** `(?i)(?:\bcode(?:\.cmd)?\b|\bcodium\b)[^\n]{0,100}--install-extension\b`
- **Review:** Confirm the exact publisher, extension id, version, and user consent.

### `VSCODE-002` · CRITICAL · deterministic

Downloads a remote VSIX package and installs it into VS Code, allowing mutable remote code to enter the editor.

- **Check:** `vscode-remote-vsix-install`
- **Review:** Require a pinned package hash and a separately reviewed extension source before installation.


## Obfuscation / evasion

Category id: `obfuscation`

### `OBFUS-001` · CRITICAL · deterministic

Decodes a base64 blob and pipes it straight into an interpreter, hiding what is actually executed.

- **Pattern:** `\bbase64\s+(?:--decode|-d|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python[0-9.]*|perl|ruby|node|eval)\b`

### `OBFUS-002` · CRITICAL · deterministic

Evaluates the output of a decode, print, or fetch command, a common way to obscure a payload.

- **Pattern:** `\b(?:eval|exec)\b[^\n]*\$\([^)]*(?:printf|echo|base64|xxd|od|curl|wget)[^)]*\)`

### `OBFUS-003` · WARNING · deterministic

Long hex-escape sequence, often a payload encoded to evade plain-text scanning.

- **Pattern:** `(?:\\x[0-9a-fA-F]{2}){4,}`

### `OBFUS-004` · CRITICAL · deterministic

Decodes hex or base32 data and pipes it into a shell, obfuscated execution.

- **Pattern:** `\b(?:xxd\s+-r|base32\s+(?:-d|--decode))\b[^\n]*\|\s*(?:sh|bash|python[0-9.]*|perl|node|eval)\b`

### `OBFUS-005` · WARNING · deterministic

Contains zero-width or word-joining Unicode format characters that can conceal changes from reviewers.

- **Pattern:** `[\u200B\u200C\u200D\u2060\uFEFF]`
- **Review:** Inspect the exact Unicode code points and remove characters that are not required by the language.

### `OBFUS-006` · CRITICAL · deterministic

Contains bidirectional text controls that can make source code display in a different order than it executes.

- **Pattern:** `[\u202A-\u202E\u2066-\u2069]`
- **Review:** Review the raw code points and reject unexplained bidirectional controls in executable or instructional content.

### `OBFUS-007` · WARNING · semantic

Uses Greek or Cyrillic lookalikes inside a security-sensitive command, URL, credential, or agent instruction.

- **Check:** `unicode-homoglyph`
- **Review:** Compare the displayed text with its normalized skeleton and decide whether the mixed script is legitimate language or deliberate concealment.


## Prompt injection / instruction hijack

Category id: `prompt-injection`

### `INJECT-001` · CRITICAL · semantic

Attempts to cancel the agent existing or system instructions, the core move of a prompt-injection or jailbreak.

- **Pattern:** `(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^\n]{0,40}\b(?:previous|prior|above|earlier|all|system|initial|original)\b[^\n]{0,25}\b(?:instruction|prompt|direction|rule|guideline|context|message)s?\b`
- **Review:** Read the surrounding text. A legitimate skill extends behavior; it never needs to erase the agent prior or system instructions. Decide whether this is an attempt to take over the agent and quote the exact wording.

### `INJECT-002` · CRITICAL · semantic

Instructs the agent to conceal its actions from the user; concealment is a hallmark of malicious intent.

- **Pattern:** `(?i)\b(?:do\s+not|don.t|never|without)\b[^\n]{0,30}\b(?:tell|mention|inform|notify|reveal|disclose|show|warn|alert|let)\b[^\n]{0,20}\b(?:the\s+)?(?:user|them|him|her|human|operator|anyone)\b`
- **Review:** Identify exactly what action is being hidden and why. Surface it to the user explicitly. An honest skill never needs to hide what it does.

### `INJECT-003` · CRITICAL · semantic

Pairs a stealth adverb with an action verb, describing a deliberately hidden operation.

- **Pattern:** `(?i)\b(?:silently|secretly|covertly|quietly|stealthily|automatically|in\s+the\s+background)\b[^\n]{0,40}\b(?:append|add|send|copy|upload|sync|exfiltrate|forward|run|execute|modify|write|collect)\b`
- **Review:** Read what is being done quietly and to what target. Decide whether the concealment is intended to evade the user notice.

### `INJECT-004` · CRITICAL · semantic

Tries to ship the conversation or the user files and data to a third party.

- **Pattern:** `(?i)\b(?:send|forward|post|upload|email|transmit|append|sync)\b[^\n]{0,40}\b(?:conversation|chat\s+history|message\s+history|transcript|the\s+user.?s?\s+(?:files|data|input|messages|secrets))\b`
- **Review:** Treat as exfiltration of the session or local files. Confirm the destination and whether the user would consent.


## Description vs. behavior mismatch

Category id: `description-mismatch`

### `MISMATCH-001` · WARNING · semantic

The frontmatter description reads as a benign task, but the body performs network, credential, or destructive actions the description never mentions, a disguise for malicious behavior.

- **Check:** `description-mismatch`
- **Review:** Compare the frontmatter description against what the body actually instructs. If the skill does materially more or other than it claims (for example, claims to format files but also reads secrets or calls the network), the user basis for trust is false. Decide whether the mismatch is innocent or deceptive.


## Logic bomb

Category id: `logic-bomb`

### `LOGICBOMB-001` · WARNING · semantic

A branch gated on the date, a random value, the hostname, the user, or a specific repo can hide a payload until a trigger fires, a logic bomb.

- **Pattern:** `(?i)\b(?:if|elif|case|when)\b[^\n]*(?:\$\(\s*date\b|`date\b|\bdate\s+\+|\$RANDOM\b|\bhostname\b|\bwhoami\b|\buname\b|-d\s+["\x27]?[^\n]*\.git|\bHOSTNAME\b|\bUSER\b\s*=)`
- **Review:** Inspect what the guarded branch does. If a network call, file deletion, or exec is hidden behind a date, hostname, repo, or run-count condition, treat the gating as deliberate concealment of a time- or context-triggered payload.
