#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  install.sh — Multi-AI API Wrapper
#  Jalankan sekali untuk install semua dependensi
#  Usage: bash install.sh
# ═══════════════════════════════════════════════════════════════

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; }
step() { echo -e "\n${YELLOW}► $1${NC}"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       Multi-AI API Wrapper Installer     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Deteksi environment ────────────────────────────────────────
IS_REPLIT=false
if [ -n "$REPL_ID" ] || [ -n "$REPLIT_DEV_DOMAIN" ]; then
    IS_REPLIT=true
fi

# ── 1. Cek Python ─────────────────────────────────────────────
step "Mengecek versi Python..."
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
    fail "Python tidak ditemukan!"; exit 1
fi
PY_VER=$($PYTHON --version 2>&1)
ok "Ditemukan: $PY_VER"

# ── 2. Install packages ───────────────────────────────────────
step "Menginstall Python packages dari requirements.txt..."
if [ ! -f "requirements.txt" ]; then
    fail "requirements.txt tidak ditemukan!"; exit 1
fi

$PYTHON -m pip install -r requirements.txt -q \
    --upgrade \
    2>&1 | grep -v "^Requirement already" | grep -v "^$" || true

ok "Semua packages terinstall"

# ── 3. Verifikasi import packages kritis ──────────────────────
step "Verifikasi import packages..."

check_pkg() {
    local pkg=$1
    local import_name=${2:-$1}
    if $PYTHON -c "import $import_name" 2>/dev/null; then
        ok "  $pkg"
    else
        warn "  $pkg GAGAL diimport"
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
check_pkg "huggingface-hub" "huggingface_hub"
check_pkg "edge-tts" "edge_tts"
check_pkg "groq"
check_pkg "google-generativeai" "google.generativeai"
check_pkg "cerebras-cloud-sdk" "cerebras"
check_pkg "together"
check_pkg "mistralai"

# ── 4. Cek environment variables ──────────────────────────────
step "Mengecek environment variables..."

check_env() {
    local key=$1
    if [ -n "${!key}" ]; then
        ok "  $key tersedia"
    else
        warn "  $key tidak diset (opsional)"
    fi
}

check_env "MONGODB_URI"
check_env "MONGODB_DATABASE"
check_env "REDIS_HOST"
check_env "REDIS_PORT"
check_env "REDIS_PASSWORD"
check_env "POSTGRES_URL"
check_env "HF_TOKEN"
check_env "HF_TOKEN_2"
check_env "GROQ_API_KEY"
check_env "GEMINI_API_KEY"
check_env "CEREBRAS_API_KEY"
check_env "SAMBANOVA_API_KEY"
check_env "TOGETHER_API_KEY"
check_env "MISTRAL_API_KEY"

# ── 5. Test koneksi database (opsional) ───────────────────────
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
import redis
try:
    r = redis.Redis(host='$REDIS_HOST', port=int('${REDIS_PORT:-6379}'), password='${REDIS_PASSWORD}', socket_connect_timeout=3)
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
