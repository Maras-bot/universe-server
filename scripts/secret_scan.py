#!/usr/bin/env python3
"""Scansione anti-segreti per Universe (solo stdlib).

Usato dai hook pre-commit / pre-push e dalla GitHub Action.
Esce con codice 1 se trova segreti. I valori vengono solo mascherati.
I token in /workspace/progetti/universe-secrets/*.json (o UNIVERSE_SECRETS_DIR)
vengono caricati a runtime se la cartella esiste: non vanno committati.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ALLOW_MARKER = "secret-scan: allow"
DEFAULT_LOCAL_SECRETS = Path("/workspace/progetti/universe-secrets")
ZERO_SHA = "0" * 40
MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "logs",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "universe-secrets",
}
SKIP_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".so",
    ".o",
    ".a",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".zip",
    ".gz",
    ".whl",
    ".egg",
}
METADATA_JSON_KEYS = {"generated_at", "updated_at", "note", "used_for", "comment", "description"}
KEY_SUFFIX_SKIP = ("_FILE", "_PATH", "_DIR", "_URL", "_URI", "_HOME")

PLACEHOLDER_RE = re.compile(
    r"""(?ix)
    ^(
        <|
        \$\{ |
        %\w+% |
        \.\.\. |
        x+ |
        your[_-]?.* |
        insert[_-]?.* |
        replace[_-]?.* |
        put[_-]?.* |
        metti[_-]?.* |
        changeme |
        change[_-]?me |
        placeholder |
        example |
        sample |
        dummy |
        fake |
        todo |
        tbd |
        redacted |
        redact |
        none |
        null |
        nil |
        n/?a |
        password |
        secret |
        token |
        bearer |
        api[_-]?key |
        <[^>]+> |
        xxx+
    )
    """,
)

# Token noti (prefissi / blocchi). I gruppi catturano il valore intero.
KNOWN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "github_token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "github_token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    ),
    (
        "slack_token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ),
    (
        "stripe_live_key",
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    (
        "render_api_key",
        re.compile(r"\brnd_[A-Za-z0-9]{20,}\b"),
    ),
]

# Chiavi che somigliano a un segreto (api_key, phone_token, UNIVERSE_PHONE_TOKEN, ...).
_SECRET_KEY = (
    r"(?:[A-Za-z][A-Za-z0-9_]*_)?(?:token|api[_-]?key|apikey|secret|password|passwd|bearer)"
    r"(?:_[A-Za-z0-9]+)*"
)
ASSIGN_QUOTED_RE = re.compile(
    rf"""(?ix)
    \b(?P<key>{_SECRET_KEY})\b
    \s*[:=]\s*
    (?P<q>["'])
    (?P<quoted>(?:(?!(?P=q)).){{8,}})
    (?P=q)
    """
)
# Solo KEY=value stile env (chiave maiuscola), così non prende phone_token=settings.foo.
ASSIGN_UNQUOTED_RE = re.compile(
    r"""(?x)
    (?:^|[\s;])(?:export\s+)?
    (?P<key>[A-Z][A-Z0-9_]*(?:TOKEN|API[_-]?KEY|APIKEY|SECRET|PASSWORD|PASSWD|BEARER)[A-Z0-9_]*)
    =
    (?P<unquoted>[^\s"'\\#]{8,})
    """
)

# Stringhe candidate per l'entropia. Lo `=` è escluso, altrimenti KEY=value
# viene preso come un unico token.
ENTROPY_RE = re.compile(
    r"""(?x)
    (?:['"])
    (?P<quoted>[A-Za-z0-9/+_\-.]{32,})
    (?:['"])
    |
    \b(?P<bare>[A-Za-z0-9/+_\-.]{32,})\b
    """
)

UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
HEX_HASH_RE = re.compile(r"(?i)^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$")
HYPHEN_PHRASE_RE = re.compile(r"^[a-z]+(?:-[a-z0-9]+){2,}$")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    pattern: str
    masked: str

    def format(self) -> str:
        return f"{self.path}:{self.line}  [{self.pattern}]  {self.masked}"


def mask_value(value: str, *, reveal_edges: bool = True) -> str:
    """Maschera un valore. Per i token locali non mostra nessun carattere."""
    if not reveal_edges:
        return f"*** (len {len(value)})"
    if len(value) <= 8:
        return "*" * min(len(value), 8)
    hidden = min(len(value) - 4, 12)
    return f"{value[:2]}{'*' * hidden}{value[-2:]}"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in Counter(value).values())


def charset_classes(value: str) -> int:
    groups = 0
    if re.search(r"[a-z]", value):
        groups += 1
    if re.search(r"[A-Z]", value):
        groups += 1
    if re.search(r"[0-9]", value):
        groups += 1
    if re.search(r"[^A-Za-z0-9]", value):
        groups += 1
    return groups


def is_placeholder(value: str) -> bool:
    text = value.strip().strip("'\"")
    if not text:
        return True
    if text.startswith("${") or (text.startswith("$") and text[1:].replace("_", "").isalnum()):
        return True
    if PLACEHOLDER_RE.match(text):
        return True
    if len(set(text)) == 1:
        return True
    if HYPHEN_PHRASE_RE.match(text) and charset_classes(text) <= 2 and shannon_entropy(text) < 4.0:
        return True
    return False


def is_pathish(value: str) -> bool:
    if "/" in value and not value.startswith("eyJ"):
        if value.startswith(("/", "./", "../", "~/")) or value.endswith(
            (".json", ".pem", ".key", ".txt", ".yml", ".yaml")
        ):
            return True
    return False


def is_identifier_or_code(value: str) -> bool:
    """Nomi di variabile, attributi e chiamate: non sono literal secret.

    Una stringa lunga con maiuscole, minuscole e cifre mescolate è più
    simile a un token che a un identificatore, quindi non si esclude.
    """
    text = value.strip().rstrip(",;")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", text):
        return True
    if re.match(r"[A-Za-z_][A-Za-z0-9_\.]*\(", text):
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
        if len(text) >= 24 and charset_classes(text) >= 3:
            return False
        return True
    return False


def assignment_key_skipped(key: str) -> bool:
    return key.upper().endswith(KEY_SUFFIX_SKIP)


def load_known_secret_values(extra_dirs: list[Path] | None = None) -> set[str]:
    """Carica i valori esatti dai JSON locali. Non stampa nulla."""
    dirs: list[Path] = []
    env_dir = os.environ.get("UNIVERSE_SECRETS_DIR")
    if env_dir:
        dirs.append(Path(env_dir))
    if extra_dirs:
        dirs.extend(extra_dirs)
    if DEFAULT_LOCAL_SECRETS.is_dir():
        dirs.append(DEFAULT_LOCAL_SECRETS)
    # cartella sorella rispetto alla root del repo, se presente
    here = Path.cwd()
    sibling = here.parent / "universe-secrets"
    if sibling.is_dir():
        dirs.append(sibling)

    values: set[str] = set()

    def walk(obj: object, key: str | None = None) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, str(k))
            return
        if isinstance(obj, list):
            for item in obj:
                walk(item, key)
            return
        if not isinstance(obj, str):
            return
        text = obj.strip()
        if len(text) < 16:
            return
        if key and key in METADATA_JSON_KEYS:
            return
        if " " in text:  # frasi, note
            return
        if re.match(r"\d{4}-\d{2}-\d{2}", text):
            return
        values.add(text)

    seen: set[Path] = set()
    for folder in dirs:
        try:
            folder = folder.resolve()
        except OSError:
            continue
        if not folder.is_dir() or folder in seen:
            continue
        seen.add(folder)
        for path in sorted(folder.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            walk(data)
    return values


def scan_text(
    path: str,
    text: str,
    *,
    known_values: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    known_values = known_values if known_values is not None else set()
    example_file = Path(path).name.endswith((".example", ".sample", ".template")) or Path(path).name in {
        ".env.example",
        "env.example",
    }

    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if ALLOW_MARKER in line:
            continue
        occupied: list[tuple[int, int]] = []

        def overlaps(start: int, end: int) -> bool:
            return any(start < b and end > a for a, b in occupied)

        def add(pattern: str, value: str, start: int, end: int, *, reveal: bool = True) -> None:
            if overlaps(start, end):
                return
            occupied.append((start, end))
            findings.append(
                Finding(
                    path=path,
                    line=lineno,
                    pattern=pattern,
                    masked=mask_value(value, reveal_edges=reveal),
                )
            )

        # 1. Valori esatti dei token locali (prima, e senza rivelare i caratteri).
        if known_values:
            for secret in known_values:
                start = 0
                while True:
                    idx = line.find(secret, start)
                    if idx < 0:
                        break
                    add("known_local_token", secret, idx, idx + len(secret), reveal=False)
                    start = idx + len(secret)

        # 2. Pattern noti (GitHub, AWS, Slack, Stripe, JWT, Render, chiavi private).
        for name, regex in KNOWN_PATTERNS:
            for match in regex.finditer(line):
                add(name, match.group(0), match.start(), match.end())

        # 3. Assegnazioni generiche con valore non-placeholder.
        assign_matches: list[re.Match[str]] = []
        assign_matches.extend(ASSIGN_QUOTED_RE.finditer(line))
        assign_matches.extend(ASSIGN_UNQUOTED_RE.finditer(line))
        for match in assign_matches:
            groups = match.groupdict()
            quoted = groups.get("quoted")
            unquoted = groups.get("unquoted")
            value = (quoted or unquoted or "").rstrip(",;")
            key = groups.get("key") or ""
            if not value or is_placeholder(value) or is_pathish(value):
                continue
            if unquoted and is_identifier_or_code(value):
                continue
            if assignment_key_skipped(key):
                continue
            if example_file and not any(rx.search(value) for _, rx in KNOWN_PATTERNS):
                if charset_classes(value) < 3 and shannon_entropy(value) < 4.5:
                    continue
            if len(value) < 16 and not any(rx.search(value) for _, rx in KNOWN_PATTERNS):
                continue
            add(
                "generic_secret_assignment",
                value,
                match.start(),
                match.end(),
            )

        # 4. Stringhe ad alta entropia (>= 32 caratteri).
        for match in ENTROPY_RE.finditer(line):
            value = match.group("quoted") or match.group("bare") or ""
            if len(value) < 32:
                continue
            if is_placeholder(value) or is_pathish(value) or is_identifier_or_code(value):
                continue
            if UUID_RE.match(value) or HEX_HASH_RE.match(value):
                continue
            if HYPHEN_PHRASE_RE.match(value):
                continue
            entropy = shannon_entropy(value)
            classes = charset_classes(value)
            if classes >= 3 and entropy >= 4.0:
                pass
            elif classes >= 2 and entropy >= 4.5:
                pass
            else:
                continue
            add("high_entropy", value, match.start(), match.end())

    return findings


def is_probably_binary(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return True
    if not data:
        return False
    # troppi byte non-testo
    sample = data[:8192]
    if sample.decode("utf-8", errors="ignore").count("\ufffd"):
        return True
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        # latin-1 / utf-8 misto: se troppi control bytes, salta
        control = sum(1 for b in sample if b < 9 or (13 < b < 32))
        return control > len(sample) * 0.05
    return False


def read_text_bytes(data: bytes) -> str | None:
    if len(data) > MAX_FILE_BYTES or is_probably_binary(data):
        return None
    return data.decode("utf-8", errors="replace")


def should_skip_path(path: Path) -> bool:
    if any(part in SKIP_DIR_NAMES for part in path.parts):
        return True
    if path.suffix.lower() in SKIP_SUFFIXES:
        return True
    name = path.name
    if name in {"tokens.json", "railway-tokens.json", "render-tokens.json", "deploy-tokens.json"}:
        return True
    return False


def git(*args: str, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        input=input_text,
    )


def repo_root() -> Path:
    try:
        proc = git("rev-parse", "--show-toplevel", check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return Path.cwd()


def list_tracked_files(root: Path) -> list[Path]:
    proc = git("ls-files", "-z", check=False)
    if proc.returncode == 0 and proc.stdout:
        files = [root / p for p in proc.stdout.split("\0") if p]
        return [p for p in files if p.is_file() and not should_skip_path(p.relative_to(root))]
    collected: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                rel = path.relative_to(root)
            except ValueError:
                continue
            if should_skip_path(rel):
                continue
            if path.is_file():
                collected.append(path)
    return collected


def scan_path(path: Path, display: str, known: set[str]) -> list[Finding]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [Finding(display, 0, "read_error", str(exc))]
    text = read_text_bytes(data)
    if text is None:
        return []
    return scan_text(display, text, known_values=known)


def scan_staged(root: Path, known: set[str]) -> list[Finding]:
    proc = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", check=False)
    if proc.returncode != 0:
        print("secret-scan: impossibile leggere l'indice git (pre-commit).", file=sys.stderr)
        return [Finding(".git", 0, "git_error", "diff --cached failed")]
    names = [n for n in proc.stdout.split("\0") if n]
    findings: list[Finding] = []
    for name in names:
        rel = Path(name)
        if should_skip_path(rel):
            continue
        show = git("show", f":{name}", check=False)
        if show.returncode != 0:
            # file nuovo? prova il working tree
            path = root / name
            if path.is_file():
                findings.extend(scan_path(path, name, known))
            continue
        data = show.stdout.encode("utf-8", errors="replace") if isinstance(show.stdout, str) else b""
        # git show può corrompere i binari in text mode: per i file testuali va bene
        text = read_text_bytes(data)
        if text is None:
            continue
        findings.extend(scan_text(name, text, known_values=known))
    return findings


def _commit_parents(sha: str) -> list[str]:
    proc = git("rev-list", "--parents", "-n", "1", sha, check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    parts = proc.stdout.strip().split()
    return parts[1:]


def _files_changed_in_commit(sha: str) -> list[str]:
    parents = _commit_parents(sha)
    if not parents:
        proc = git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "--diff-filter=ACMR", sha, check=False)
    else:
        proc = git("diff-tree", "--no-commit-id", "--name-only", "-r", "--diff-filter=ACMR", f"{parents[0]}..{sha}", check=False)
    if proc.returncode != 0:
        return []
    return [n for n in proc.stdout.splitlines() if n]


def _blob_at(sha: str, path: str) -> str | None:
    proc = git("show", f"{sha}:{path}", check=False)
    if proc.returncode != 0:
        return None
    return read_text_bytes(proc.stdout.encode("utf-8", errors="replace"))


def scan_pre_push(known: set[str], stdin_text: str | None = None) -> list[Finding]:
    raw = sys.stdin.read() if stdin_text is None else stdin_text
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    findings: list[Finding] = []
    if not lines:
        # invocazione manuale: confronta con origin/HEAD se esiste, altrimenti l'albero corrente
        proc = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{push}", check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            remote_ref = proc.stdout.strip()
            range_spec = f"{remote_ref}..HEAD"
            commits_proc = git("rev-list", range_spec, check=False)
            shas = [s for s in commits_proc.stdout.splitlines() if s] if commits_proc.returncode == 0 else []
        else:
            shas = []
        if not shas:
            return findings
        for sha in shas:
            findings.extend(_scan_commit(sha, known))
        return findings

    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        _local_ref, local_sha, _remote_ref, remote_sha = parts[:4]
        if local_sha == ZERO_SHA:
            continue
        if remote_sha == ZERO_SHA:
            proc = git("rev-list", local_sha, "--not", "--remotes", check=False)
            shas = [s for s in proc.stdout.splitlines() if s] if proc.returncode == 0 else [local_sha]
            if not shas:
                shas = [local_sha]
        else:
            proc = git("rev-list", f"{remote_sha}..{local_sha}", check=False)
            shas = [s for s in proc.stdout.splitlines() if s] if proc.returncode == 0 else []
        for sha in shas:
            findings.extend(_scan_commit(sha, known))
    return findings


def _scan_commit(sha: str, known: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for name in _files_changed_in_commit(sha):
        if should_skip_path(Path(name)):
            continue
        text = _blob_at(sha, name)
        if text is None:
            continue
        display = f"{name}@{sha[:12]}"
        findings.extend(scan_text(display, text, known_values=known))
    return findings


def scan_tree(root: Path, known: set[str], paths: list[Path] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if paths:
        for path in paths:
            if path.is_dir():
                for found in path.rglob("*"):
                    if found.is_file():
                        try:
                            rel = found.relative_to(root)
                        except ValueError:
                            rel = found
                        if should_skip_path(Path(rel)):
                            continue
                        findings.extend(scan_path(found, str(rel), known))
                continue
            if not path.exists():
                continue
            try:
                rel = path.resolve().relative_to(root.resolve())
            except ValueError:
                rel = path
            if should_skip_path(Path(rel)):
                continue
            findings.extend(scan_path(path, str(rel), known))
        return findings
    for path in list_tracked_files(root):
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        findings.extend(scan_path(path, rel, known))
    return findings


def print_findings(findings: list[Finding]) -> None:
    print("secret-scan: trovati possibili segreti (valori mascherati):", file=sys.stderr)
    for item in findings:
        print(f"  {item.format()}", file=sys.stderr)
    print(f"secret-scan: {len(findings)} segnalazion{'e' if len(findings) == 1 else 'i'}. Push/commit bloccato.", file=sys.stderr)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Blocca commit/push se i file contengono token o segreti."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="Scansiona i file in stage (pre-commit).")
    mode.add_argument("--pre-push", action="store_true", help="Scansiona i commit in push (pre-push).")
    mode.add_argument("--ci", action="store_true", help="Scansiona i file tracciati del checkout (CI).")
    parser.add_argument("paths", nargs="*", help="Percorsi da scansionare (se non usi --staged/--pre-push).")
    parser.add_argument(
        "--secrets-dir",
        action="append",
        default=[],
        help="Cartella extra di JSON locali da cui caricare valori esatti (non committare).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = repo_root()
    extras = [Path(p) for p in args.secrets_dir]
    known = load_known_secret_values(extras)
    if args.staged:
        findings = scan_staged(root, known)
    elif args.pre_push:
        findings = scan_pre_push(known)
    else:
        paths = [Path(p) for p in args.paths] if args.paths else None
        findings = scan_tree(root, known, paths)
    if findings:
        print_findings(findings)
        return 1
    print("secret-scan: pulito.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
