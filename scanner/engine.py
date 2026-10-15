"""Directory-walk engine: detectors + entropy + allowlist.

scan_path(path) -> list of finding dicts. The allowlist is checked
against the raw source line (before redaction); severity overrides come
from the active config (see scanner.config and configure()).
"""
import os

from . import config as config_module
from .detectors import scan_text
from .entropy import find_high_entropy

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv",
             "node_modules", ".tox"}
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll",
    ".so", ".dylib", ".bin", ".dat", ".pyc",
}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MiB

_active_config = None


def configure(cfg=None):
    """Install a config dict from config.default_config()/load_config()."""
    global _active_config
    _active_config = cfg or config_module.default_config()


def _config():
    if _active_config is None:
        configure()
    return _active_config


def _is_binary(path):
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(4096)
    except OSError:
        return True


def _iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in SKIP_EXTENSIONS:
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_FILE_SIZE or _is_binary(full):
                    continue
            except OSError:
                continue
            yield full


def _allowed(cfg, raw_line):
    return any(p.search(raw_line) for p in cfg["allowlist"])


def scan_path(path):
    """Walk ``path`` and return a list of finding dicts."""
    cfg = _config()
    findings = []
    for filename in _iter_files(path):
        try:
            with open(filename, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        raw_lines = text.splitlines()
        candidates = scan_text(filename, text) + find_high_entropy(filename, text)
        for f in candidates:
            lineno = f["line"]
            raw = raw_lines[lineno - 1] if 0 < lineno <= len(raw_lines) else ""
            if _allowed(cfg, raw):
                continue
            f["severity"] = cfg["severity"].get(f["type"], f["severity"])
            findings.append(f)
    return findings
