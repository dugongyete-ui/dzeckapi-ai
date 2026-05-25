#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  install.sh — Multi-AI API Wrapper
#  Jalankan sekali untuk install semua dependensi
#  Usage: bash install.sh
# ═══════════════════════════════════════════════════════════════
set -e

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
step() { echo -e "\n${YELLOW}► $1${NC}"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       Multi-AI API Wrapper Installer     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 1. Cek Python ─────────────────────────────────────────────
step "Mengecek versi Python..."
PYTHON=$(command -v python3 || command -v python || fail "Python tidak ditemukan!")
PY_VER=$($PYTHON --version 2>&1)
ok "Ditemukan: $PY_VER"

# ── 2. Upgrade pip ────────────────────────────────────────────
step "Upgrade pip..."
$PYTHON -m pip install --upgrade pip -q && ok "pip sudah terbaru"

# ── 3. Install semua packages dari requirements.txt ───────────
step "Menginstall Python packages dari requirements.txt..."
if [ ! -f "requirements.txt" ]; then
    fail "requirements.txt tidak ditemukan!"
fi

$PYTHON -m pip install -r requirements.txt -q
ok "Semua packages terinstall"

# ── 4. Verifikasi import packages kritis ──────────────────────
step "Verifikasi import packages..."

check_pkg() {
    local pkg=$1
    local import_name=${2:-$1}
    if $PYTHON -c "import $import_name" 2>/dev/null; then
        ok "  $pkg"
    else
        warn "  $pkg GAGAL diimport — coba install ulang..."
        $PYTHON -m pip install "$pkg" -q
    fi
}

check_pkg "flask"
check_pkg "gunicorn"
check_pkg "requests"
check_pkg "werkzeug"
check_pkg "g4f"
check_pkg "meta-ai-api" "meta_ai_api"
check_pkg "ddgs"
check_pkg "pymongo"
check_pkg "redis"
check_pkg "psycopg2-binary" "psycopg2"
check_pkg "dnspython" "dns"
check_pkg "python-dotenv" "dotenv"

# ── 5. Cek file .env ──────────────────────────────────────────
step "Mengecek file .env..."
if [ -f ".env" ]; then
    ok ".env ditemukan — variabel akan dimuat otomatis saat app start"
else
    warn ".env tidak ditemukan — buat file .env dari contoh berikut:"
    echo ""
    echo "  MONGODB_URI=mongodb+srv://..."
    echo "  MONGODB_DATABASE=manus"
    echo "  REDIS_HOST=..."
    echo "  REDIS_PORT=..."
    echo "  REDIS_PASSWORD=..."
    echo "  POSTGRES_URL=postgresql://..."
    echo "  HF_TOKEN=hf_..."
    echo "  HF_TOKEN_2=hf_..."
    echo ""
fi

# ── 6. Cek environment variables (dari .env atau shell) ───────
step "Mengecek environment variables..."

# Load .env jika ada
if [ -f ".env" ]; then
    set -a
    source .env 2>/dev/null || true
    set +a
fi

check_env() {
    local key=$1
    local required=$2
    if [ -n "${!key}" ]; then
        ok "  $key tersedia"
    elif [ "$required" = "true" ]; then
        fail "  $key TIDAK DITEMUKAN (wajib!)"
    else
        warn "  $key tidak diset (opsional)"
    fi
}

check_env "MONGODB_URI"      false
check_env "MONGODB_DATABASE" false
check_env "REDIS_HOST"       false
check_env "REDIS_PORT"       false
check_env "REDIS_PASSWORD"   false
check_env "POSTGRES_URL"     false
check_env "HF_TOKEN"         false
check_env "HF_TOKEN_2"       false

# ── 7. Test koneksi database (opsional) ───────────────────────
step "Test koneksi database (opsional)..."

if [ -n "$MONGODB_URI" ]; then
    $PYTHON -c "
from pymongo import MongoClient
try:
    c = MongoClient('$MONGODB_URI', serverSelectionTimeoutMS=3000)
    c.admin.command('ping')
    print('\033[0;32m✓   MongoDB: terhubung\033[0m')
except Exception as e:
    print(f'\033[1;33m⚠   MongoDB: {e}\033[0m')
" 2>/dev/null || true
fi

if [ -n "$REDIS_HOST" ]; then
    $PYTHON -c "
import redis, os
try:
    r = redis.Redis(host='$REDIS_HOST', port=int('${REDIS_PORT:-6379}'), password='$REDIS_PASSWORD', socket_connect_timeout=3)
    r.ping()
    print('\033[0;32m✓   Redis: terhubung\033[0m')
except Exception as e:
    print(f'\033[1;33m⚠   Redis: {e}\033[0m')
" 2>/dev/null || true
fi

if [ -n "$POSTGRES_URL" ]; then
    $PYTHON -c "
import psycopg2
try:
    conn = psycopg2.connect('$POSTGRES_URL')
    conn.close()
    print('\033[0;32m✓   PostgreSQL: terhubung\033[0m')
except Exception as e:
    print(f'\033[1;33m⚠   PostgreSQL: {e}\033[0m')
" 2>/dev/null || true
fi

# ── Selesai ───────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   ✓ Instalasi selesai! Jalankan:         ║"
echo "║     python main.py                       ║"
echo "╚══════════════════════════════════════════╝"
echo ""
