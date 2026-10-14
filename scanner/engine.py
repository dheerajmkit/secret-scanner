"""Directory-walk engine: find candidate files and run detectors."""
import os

from .detectors import scan_text

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv",
             "node_modules", ".tox"}
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll",
    ".so", ".dylib", ".bin", ".dat", ".pyc",
}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MiB


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


def scan_path(path):
    """Walk ``path`` and return a list of finding dicts."""
    findings = []
    for filename in _iter_files(path):
        try:
            with open(filename, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        findings.extend(scan_text(filename, text))
    return findings
