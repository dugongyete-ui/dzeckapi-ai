#!/usr/bin/env python3
"""
push.py — Push file proyek ke GitHub via GitHub REST API.
Tidak menggunakan git command, sehingga tidak terblokir oleh sandbox.

Usage:
    python3 push.py
    bash push.sh

Env yang dibutuhkan:
    GITHUB_TOKEN — Personal Access Token dengan scope repo
"""

import os
import sys
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

# ── Konfigurasi ────────────────────────────────────────────────
REPO       = "dugongyete-ui/dzeckapi-ai"
BRANCH     = "main"
COMMIT_MSG = "Update project files via push.py"

# File yang akan di-push ke GitHub (tambah/hapus sesuai kebutuhan)
FILES = [
    "main.py",
    "requirements.txt",
    "install.sh",
    "push.sh",
    "push.py",
    ".gitignore",
    "env.example",
    "scripts/post-merge.sh",
    ".replit",
]

# ── Setup ──────────────────────────────────────────────────────
token = os.environ.get("GITHUB_TOKEN")
if not token:
    print("ERROR: GITHUB_TOKEN belum diset.")
    print("Simpan sebagai env var bernama GITHUB_TOKEN di file .env atau shell.")
    sys.exit(1)

BASE    = f"https://api.github.com/repos/{REPO}"
HEADERS = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
}

def api(method, path, **kwargs):
    url = BASE + path if not path.startswith("http") else path
    r = getattr(requests, method)(url, headers=HEADERS, **kwargs)
    return r

def ok(msg):  print(f"\033[0;32m✓ {msg}\033[0m")
def err(msg): print(f"\033[0;31m✗ {msg}\033[0m")
def info(msg):print(f"\033[1;33m→ {msg}\033[0m")

# ─────────────────────────────────────────────────────────────
print()
print("╔═══════════════════════════════════╗")
print("║  GitHub Push via API              ║")
print(f"║  Repo: {REPO:<27}║")
print(f"║  Branch: {BRANCH:<25}║")
print("╚═══════════════════════════════════╝")
print()

# 1. Ambil remote HEAD
info("Mengambil remote HEAD...")
r = api("get", f"/git/ref/heads/{BRANCH}")
if r.status_code != 200:
    err(f"Gagal ambil ref: {r.text[:200]}")
    sys.exit(1)
remote_sha = r.json()["object"]["sha"]
ok(f"Remote HEAD: {remote_sha[:8]}")

# 2. Ambil tree SHA dari commit HEAD
r = api("get", f"/git/commits/{remote_sha}")
tree_sha = r.json()["tree"]["sha"]
ok(f"Remote tree: {tree_sha[:8]}")

# 3. Buat blobs untuk setiap file
print()
info("Membuat blobs...")
tree_items = []
skipped    = []

for fpath in FILES:
    if not os.path.exists(fpath):
        skipped.append(fpath)
        print(f"  SKIP (tidak ada): {fpath}")
        continue

    with open(fpath, "rb") as f:
        content = f.read()

    encoded = base64.b64encode(content).decode("utf-8")
    r = api("post", "/git/blobs", json={"content": encoded, "encoding": "base64"})
    if r.status_code not in (200, 201):
        err(f"  Blob error {fpath}: {r.text[:100]}")
        sys.exit(1)

    blob_sha = r.json()["sha"]
    mode = "100755" if fpath.endswith(".sh") or fpath.endswith(".py") else "100644"
    tree_items.append({"path": fpath, "mode": mode, "type": "blob", "sha": blob_sha})
    print(f"  \033[0;32m✓\033[0m {fpath}")

print()

# 4. Buat tree baru
info("Membuat tree baru...")
r = api("post", "/git/trees", json={"base_tree": tree_sha, "tree": tree_items})
if r.status_code not in (200, 201):
    err(f"Tree error: {r.text[:200]}")
    sys.exit(1)
new_tree_sha = r.json()["sha"]
ok(f"Tree: {new_tree_sha[:8]}")

# 5. Buat commit
info("Membuat commit...")
r = api("post", "/git/commits", json={
    "message": COMMIT_MSG,
    "tree": new_tree_sha,
    "parents": [remote_sha],
})
if r.status_code not in (200, 201):
    err(f"Commit error: {r.text[:200]}")
    sys.exit(1)
new_commit_sha = r.json()["sha"]
ok(f"Commit: {new_commit_sha[:8]}")

# 6. Update ref
info("Memperbarui ref...")
r = api("patch", f"/git/refs/heads/{BRANCH}", json={"sha": new_commit_sha, "force": True})
if r.status_code in (200, 201):
    ok(f"Ref heads/{BRANCH} -> {new_commit_sha[:8]}")
else:
    err(f"Ref error: {r.status_code} {r.text[:300]}")
    sys.exit(1)

# ── Selesai ───────────────────────────────────────────────────
print()
print("╔═══════════════════════════════════╗")
print("║  ✓  PUSH BERHASIL!                ║")
print(f"║  Commit: {new_commit_sha[:8]:<25}  ║")
print(f"║  Files: {len(tree_items):<4} file di-push          ║")
if skipped:
    print(f"║  Skip:  {len(skipped):<4} file tidak ditemukan    ║")
print("╚═══════════════════════════════════╝")
print(f"\n  https://github.com/{REPO}/tree/{BRANCH}\n")
