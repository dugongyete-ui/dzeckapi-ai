import os
from dotenv import load_dotenv
load_dotenv(override=True)
import json
import uuid
import time
import re
import base64
import secrets
import hashlib
import functools
import urllib.parse
import requests
from huggingface_hub import InferenceClient as HFClient
import redis
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, make_response, Response, stream_with_context, g
from pymongo import MongoClient, ASCENDING
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

# ── g4f — isolasi ketat, last resort ──────────────────────────────────────────
try:
    import g4f
    from g4f import Provider
    from g4f.client import Client as G4FClient
    g4f_client = G4FClient()
    G4F_AVAILABLE = True
except Exception as _g4f_err:
    print(f"[g4f] Tidak tersedia: {_g4f_err}")
    g4f_client = None
    G4F_AVAILABLE = False

# ── Qwen cookie generator (dari g4f, opsional) ────────────────────────────────
try:
    from g4f.Provider.qwen.cookie_generator import generate_cookies as _qwen_gen_cookies
    _QWEN_COOKIES_AVAILABLE = True
except Exception:
    _QWEN_COOKIES_AVAILABLE = False

app = Flask(__name__)

# ── MongoDB ────────────────────────────────────────────────────────────────────
_mongo_client = None
_mongo_db = None

def get_db():
    global _mongo_client, _mongo_db
    if _mongo_db is None:
        uri = os.environ.get("MONGODB_URI")
        dbname = os.environ.get("MONGODB_DATABASE", "manus")
        if uri:
            try:
                _mongo_client = MongoClient(uri, serverSelectionTimeoutMS=3000)
                _mongo_db = _mongo_client[dbname]
                _mongo_db.list_collection_names()  # test connection
            except Exception as e:
                print(f"[MongoDB] Gagal koneksi: {e}")
                _mongo_db = None
    return _mongo_db


# ── Auth helpers ───────────────────────────────────────────────────────────────

def generate_api_key() -> str:
    """Generate API key format: sk-dzcx<44 random chars>"""
    return "sk-dzcx" + secrets.token_urlsafe(33)

def _ensure_user_indexes():
    db = get_db()
    if db is not None:
        db["users"].create_index([("email",    ASCENDING)], unique=True)
        db["users"].create_index([("username", ASCENDING)], unique=True)
        db["users"].create_index([("api_key",  ASCENDING)], unique=True)

def get_user_by_api_key(api_key: str):
    db = get_db()
    if db is None:
        return None
    return db["users"].find_one({"api_key": api_key, "is_active": True})

def get_user_by_email(email: str):
    db = get_db()
    if db is None:
        return None
    return db["users"].find_one({"email": email.lower().strip()})

def get_user_by_username(username: str):
    db = get_db()
    if db is None:
        return None
    return db["users"].find_one({"username": username.lower().strip()})

# Jalankan index saat startup
try:
    _ensure_user_indexes()
except Exception:
    pass


# ── API Key middleware ─────────────────────────────────────────────────────────

# Path yang TIDAK perlu auth
_PUBLIC_PATHS = {
    "/", "/dashboard", "/providers", "/v1/providers", "/v1/models",
    "/auth/register", "/auth/login",
}
_PUBLIC_PREFIXES = ("/static/",)

def _extract_bearer(req) -> str | None:
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None

AUTHOR = "dzeck"

@app.after_request
def inject_author(response):
    """Inject 'author' field hanya untuk non-/v1/ endpoints."""
    if response.direct_passthrough:
        return response
    if request.path.startswith("/v1/"):
        return response
    ct = response.content_type or ""
    if "text/event-stream" in ct:
        return response
    if "application/json" in ct:
        try:
            data = response.get_json(force=True, silent=True)
            if isinstance(data, dict) and "author" not in data:
                data["author"] = AUTHOR
                response.set_data(json.dumps(data, ensure_ascii=False))
        except Exception:
            pass
    return response


@app.before_request
def require_api_key_middleware():
    path = request.path
    # Public endpoints
    if path in _PUBLIC_PATHS:
        return None
    for prefix in _PUBLIC_PREFIXES:
        if path.startswith(prefix):
            return None
    # Semua endpoint lain butuh API key
    api_key = _extract_bearer(request)
    if not api_key:
        return jsonify({"error": "API key diperlukan. Gunakan header: Authorization: Bearer <api_key>"}), 401
    if not api_key.startswith("sk-dzcx"):
        return jsonify({"error": "Format API key tidak valid (harus dimulai sk-dzcx...)"}), 401
    user = get_user_by_api_key(api_key)
    if not user:
        return jsonify({"error": "API key tidak valid atau akun dinonaktifkan"}), 401
    # Simpan user ke request context
    g.current_user = user
    g.api_key = api_key


# ── PostgreSQL (Neon) ─────────────────────────────────────────────────────────
import psycopg2.pool as _pg_pool

# ── PostgreSQL — Thread-safe connection pool ───────────────────────────────────
_pg_pool_instance = None

def _get_pg_pool():
    """Buat atau kembalikan ThreadedConnectionPool (lazy init)."""
    global _pg_pool_instance
    if _pg_pool_instance is None:
        url = os.environ.get("POSTGRES_URL")
        if not url:
            return None
        try:
            _pg_pool_instance = _pg_pool.ThreadedConnectionPool(
                minconn=1, maxconn=10, dsn=url
            )
            # Inisialisasi tabel pada koneksi pertama
            conn = _pg_pool_instance.getconn()
            try:
                conn.autocommit = True
                _init_pg_tables(conn)
            finally:
                _pg_pool_instance.putconn(conn)
            print("[PostgreSQL] Connection pool siap")
        except Exception as e:
            print(f"[PostgreSQL] Gagal buat pool: {e}")
            _pg_pool_instance = None
    return _pg_pool_instance

def get_pg_conn():
    """Ambil koneksi dari pool. Kembalikan None jika pool tidak tersedia."""
    pool = _get_pg_pool()
    if pool is None:
        return None
    try:
        conn = pool.getconn()
        conn.autocommit = True
        return conn
    except Exception as e:
        print(f"[PostgreSQL] Gagal ambil koneksi dari pool: {e}")
        return None

def release_pg_conn(conn):
    """Kembalikan koneksi ke pool."""
    pool = _get_pg_pool()
    if pool and conn:
        try:
            pool.putconn(conn)
        except Exception as e:
            print(f"[PostgreSQL] Gagal kembalikan koneksi: {e}")

# Alias lama — dipertahankan agar kode yang pakai get_pg() tetap jalan
def get_pg():
    return get_pg_conn()

def _init_pg_tables(conn):
    """Buat tabel dan index jika belum ada."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS api_logs (
                id          SERIAL PRIMARY KEY,
                endpoint    VARCHAR(100),
                provider    VARCHAR(100),
                success     BOOLEAN,
                error_msg   TEXT,
                ip          VARCHAR(50),
                created_at  TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS conversation_stats (
                id              SERIAL PRIMARY KEY,
                conversation_id VARCHAR(100),
                message_count   INT DEFAULT 0,
                last_provider   VARCHAR(100),
                updated_at      TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        # Hapus duplikat conversation_id sebelum buat unique index (idempotent)
        cur.execute("""
            DELETE FROM conversation_stats
            WHERE id NOT IN (
                SELECT MAX(id) FROM conversation_stats GROUP BY conversation_id
            );
        """)
        # UNIQUE index untuk UPSERT yang benar di update_conv_stats
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_conv_stats_conv_id
            ON conversation_stats(conversation_id);
        """)

def log_api_request(endpoint: str, provider: str = None, success: bool = True, error: str = None):
    """Catat setiap request ke tabel api_logs di PostgreSQL (non-blocking)."""
    conn = get_pg_conn()
    if not conn:
        return
    try:
        ip = request.remote_addr if request else None
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO api_logs (endpoint, provider, success, error_msg, ip) VALUES (%s, %s, %s, %s, %s)",
                (endpoint, provider, success, error, ip),
            )
    except Exception as e:
        print(f"[PostgreSQL] log_api_request gagal: {e}")
    finally:
        release_pg_conn(conn)

def update_conv_stats(conv_id: str, msg_count: int, provider: str):
    """Update statistik percakapan di PostgreSQL (single UPSERT, race-condition safe)."""
    conn = get_pg_conn()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO conversation_stats (conversation_id, message_count, last_provider, updated_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (conversation_id) DO UPDATE
                SET message_count = EXCLUDED.message_count,
                    last_provider = EXCLUDED.last_provider,
                    updated_at    = NOW()
            """, (conv_id, msg_count, provider))
    except Exception as e:
        print(f"[PostgreSQL] update_conv_stats gagal: {e}")
    finally:
        release_pg_conn(conn)


# ── Redis ──────────────────────────────────────────────────────────────────────
_redis_client = None

def get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.Redis(
                host=os.environ.get("REDIS_HOST", "localhost"),
                port=int(os.environ.get("REDIS_PORT", 6379)),
                password=os.environ.get("REDIS_PASSWORD"),
                decode_responses=True,
                socket_connect_timeout=3,
            )
            _redis_client.ping()
        except Exception as e:
            print(f"[Redis] Gagal koneksi: {e}")
            _redis_client = None
    return _redis_client


# ── Conversation store (MongoDB + Redis) ──────────────────────────────────────

REDIS_TTL = 3600  # 1 jam cache di Redis

def load_conversation(conv_id: str) -> list:
    """Ambil riwayat pesan dari Redis (cache) atau MongoDB."""
    r = get_redis()
    if r:
        try:
            raw = r.get(f"conv:{conv_id}")
            if raw:
                return json.loads(raw)
        except Exception:
            pass
    db = get_db()
    if db is not None:
        try:
            doc = db.conversations.find_one({"_id": conv_id})
            if doc:
                msgs = doc.get("messages", [])
                # simpan kembali ke Redis
                if r:
                    try:
                        r.setex(f"conv:{conv_id}", REDIS_TTL, json.dumps(msgs))
                    except Exception:
                        pass
                return msgs
        except Exception:
            pass
    return []


def save_conversation(conv_id: str, messages: list):
    """Simpan riwayat pesan ke Redis + MongoDB."""
    r = get_redis()
    if r:
        try:
            r.setex(f"conv:{conv_id}", REDIS_TTL, json.dumps(messages))
        except Exception:
            pass
    db = get_db()
    if db is not None:
        try:
            db.conversations.update_one(
                {"_id": conv_id},
                {"$set": {"messages": messages, "updated_at": datetime.now(timezone.utc)}},
                upsert=True,
            )
        except Exception:
            pass


def delete_conversation(conv_id: str):
    """Hapus riwayat percakapan."""
    r = get_redis()
    if r:
        try:
            r.delete(f"conv:{conv_id}")
        except Exception:
            pass
    db = get_db()
    if db is not None:
        try:
            db.conversations.delete_one({"_id": conv_id})
        except Exception:
            pass


# ── Provider registries ───────────────────────────────────────────────────────
# Hanya HF Token providers — paling efisien, tidak butuh API key tambahan.

CHAT_PROVIDERS = {}
CHAT_ORDER     = []
TOOL_CAPABLE_ORDER = []

# ── Circuit Breaker ────────────────────────────────────────────────────────────
# Provider yang gagal 402 (Payment Required) di-skip selama CIRCUIT_TTL detik.
# Setelah TTL habis, provider dicoba lagi (quota mungkin sudah reset).
import time as _time_module

_PROVIDER_CIRCUIT: dict[str, float] = {}  # pid → timestamp saat di-trip
_CIRCUIT_TTL = 1800  # 30 menit
_CIRCUIT_FILE = os.path.join(os.path.dirname(__file__), ".circuit_state.json")

def _load_circuit_state() -> None:
    """Muat state circuit breaker dari file (survive restart)."""
    try:
        if os.path.exists(_CIRCUIT_FILE):
            with open(_CIRCUIT_FILE, "r") as f:
                data = json.load(f)
            now = _time_module.time()
            # Hanya load yang belum expired
            _PROVIDER_CIRCUIT.update({
                pid: ts for pid, ts in data.items()
                if now - ts < _CIRCUIT_TTL
            })
            if _PROVIDER_CIRCUIT:
                print(f"[Circuit] Loaded {len(_PROVIDER_CIRCUIT)} tripped provider dari disk: {list(_PROVIDER_CIRCUIT.keys())}")
    except Exception:
        pass

def _save_circuit_state() -> None:
    """Simpan state circuit breaker ke file."""
    try:
        with open(_CIRCUIT_FILE, "w") as f:
            json.dump(_PROVIDER_CIRCUIT, f)
    except Exception:
        pass

def _is_tripped(pid: str) -> bool:
    ts = _PROVIDER_CIRCUIT.get(pid)
    if ts is None:
        return False
    if _time_module.time() - ts > _CIRCUIT_TTL:
        del _PROVIDER_CIRCUIT[pid]
        _save_circuit_state()
        return False
    return True

def _trip_circuit(pid: str, reason: str = "402"):
    _PROVIDER_CIRCUIT[pid] = _time_module.time()
    _save_circuit_state()
    print(f"[Circuit] {pid} di-trip ({reason}) — skip selama {_CIRCUIT_TTL//60} menit")

_load_circuit_state()

# ── Qwen AI keyless provider (chat.qwen.ai) ───────────────────────────────────
# Tiga model tersedia: flash (cepat), plus (balanced), max (paling kuat).
# Tidak butuh login/API key — menggunakan bx-umidtoken + generated cookies.
_QWEN_MIDTOKEN: str = ""
_QWEN_MIDTOKEN_TS: float = 0.0
_QWEN_TOKEN_TTL: int = 3600  # cache 1 jam

def _get_qwen_midtoken() -> str:
    """Ambil bx-umidtoken dari Alibaba CDN, di-cache 1 jam."""
    global _QWEN_MIDTOKEN, _QWEN_MIDTOKEN_TS
    if _QWEN_MIDTOKEN and (_time_module.time() - _QWEN_MIDTOKEN_TS) < _QWEN_TOKEN_TTL:
        return _QWEN_MIDTOKEN
    try:
        r = requests.get("https://sg-wum.alibaba.com/w/wu.json", timeout=8,
            headers={"User-Agent": "Mozilla/5.0 Chrome/138.0.0.0 Safari/537.36"})
        import re as _re2
        m = _re2.search(r"(?:umx\.wu|__fycb)\('([^']+)'\)", r.text)
        if m:
            _QWEN_MIDTOKEN = m.group(1)
            _QWEN_MIDTOKEN_TS = _time_module.time()
            return _QWEN_MIDTOKEN
    except Exception:
        pass
    return ""

def _qwen_headers() -> dict:
    """Build headers untuk request ke chat.qwen.ai."""
    cookie_str = ""
    if _QWEN_COOKIES_AVAILABLE:
        try:
            cd = _qwen_gen_cookies()
            cookie_str = f'ssxmod_itna={cd["ssxmod_itna"]};ssxmod_itna2={cd["ssxmod_itna2"]}'
        except Exception:
            pass
    midtoken = _get_qwen_midtoken()
    h = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/138.0.0.0 Safari/537.36",
        "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5",
        "Origin": "https://chat.qwen.ai", "Referer": "https://chat.qwen.ai/",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest", "X-Source": "web",
        "bx-v": "2.5.31",
    }
    if midtoken:
        h["bx-umidtoken"] = midtoken
    if cookie_str:
        h["Cookie"] = cookie_str
    return h

def _qwen_chat(messages: list, model: str = "qwen3.6-plus") -> str:
    """
    Kirim pesan ke chat.qwen.ai tanpa login.
    Flow: POST /api/v2/chats/new → POST /api/v2/chat/completions (SSE).
    """
    h = _qwen_headers()
    # Step 1: buat sesi chat baru
    r1 = requests.post("https://chat.qwen.ai/api/v2/chats/new", headers=h, timeout=12,
        json={"title": "New Chat", "models": [model],
              "chat_mode": "normal", "chat_type": "t2t",
              "timestamp": int(_time_module.time() * 1000)})
    r1.raise_for_status()
    d1 = r1.json()
    if not d1.get("success"):
        raise RuntimeError(f"[Qwen] new chat failed: {d1}")
    chat_id = d1["data"]["id"]

    # Step 2: kirim semua messages, ambil hanya konten user terakhir sebagai prompt
    # tapi sertakan history sebagai context (convert format)
    prompt = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            prompt = m.get("content", "")
            break
    msg_id = str(uuid.uuid4())
    payload = {
        "stream": True, "incremental_output": True,
        "chat_id": chat_id, "chat_mode": "normal", "model": model,
        "parent_id": None,
        "messages": [{
            "fid": msg_id, "parentId": None, "childrenIds": [],
            "role": "user", "content": prompt, "user_action": "chat",
            "files": [], "models": [model], "chat_type": "t2t",
            "feature_config": {
                "thinking_enabled": False, "output_schema": "phase", "thinking_budget": 81920
            },
            "sub_chat_type": "t2t",
        }],
    }
    r2 = requests.post(
        f"https://chat.qwen.ai/api/v2/chat/completions?chat_id={chat_id}",
        headers=h, json=payload, timeout=30,
    )
    r2.raise_for_status()

    # Parse SSE stream — kumpulkan delta content dari phase=answer
    result = []
    for line in r2.text.split("\n"):
        line = line.strip()
        if not line.startswith("data:"):
            continue
        try:
            chunk = json.loads(line[5:].strip())
            choices = chunk.get("choices", [])
            if not choices:
                continue
            delta = choices[0].get("delta", {})
            if delta.get("phase") == "answer" and delta.get("content"):
                result.append(delta["content"])
        except Exception:
            continue
    text = "".join(result).strip()
    if not text:
        raise RuntimeError("[Qwen] respons kosong dari SSE stream")
    return text

# ── HF provider definitions (ordered powerful → lightweight) ─────────────────
_HF_PROVIDERS = [
    {
        "id":       "hf-cerebras-qwen",
        "url":      "https://router.huggingface.co/cerebras/v1/chat/completions",
        "model":    "qwen-3-235b-a22b-instruct-2507",
        "desc":     "Qwen3 235B via HF Cerebras — most powerful, best for coding & math",
        "tool_cap": True,
    },
    {
        "id":       "hf-hyperbolic",
        "url":      "https://router.huggingface.co/hyperbolic/v1/chat/completions",
        "model":    "meta-llama/Llama-3.3-70B-Instruct",
        "desc":     "Llama 3.3 70B via HF Hyperbolic — most Claude-like, best instruction following",
        "tool_cap": True,
    },
    {
        "id":       "hf-cerebras",
        "url":      "https://router.huggingface.co/cerebras/v1/chat/completions",
        "model":    "gpt-oss-120b",
        "desc":     "GPT-OSS 120B (MoE) via HF Cerebras — fast, native tool calls",
        "tool_cap": True,
    },
    {
        "id":       "hf-cerebras-fast",
        "url":      "https://router.huggingface.co/cerebras/v1/chat/completions",
        "model":    "llama3.1-8b",
        "desc":     "Llama 3.1 8B via HF Cerebras — speed-only, last-resort fallback",
        "tool_cap": False,
    },
]

# Register HF_TOKEN then HF_TOKEN_2 — each token gets its own set of provider IDs
for _slot, _key_env in [("", "HF_TOKEN"), ("2", "HF_TOKEN_2")]:
    _hf_key = os.environ.get(_key_env, "").strip()
    if not _hf_key:
        continue
    _is_t2 = (_slot == "2")
    _label = " [token2]" if _is_t2 else ""
    for _p in _HF_PROVIDERS:
        _pid = _p["id"] + ("-t2" if _is_t2 else "")
        CHAT_PROVIDERS[_pid] = {
            "type":        "openai_compatible",
            "url":         _p["url"],
            "model":       _p["model"],
            "api_key":     _hf_key,
            "desc":        _p["desc"] + _label,
            "hf_provider": True,
            "is_t2":       _is_t2,
        }
        CHAT_ORDER.append(_pid)
        if _p["tool_cap"]:
            TOOL_CAPABLE_ORDER.append(_pid)

# ── Pollinations — permanent free provider (no API key required) ─────────────
CHAT_PROVIDERS["pollinations-gptoss"] = {
    "type":        "openai_compatible",
    "url":         "https://text.pollinations.ai/openai",
    "model":       "openai",
    "api_key":     "",          # keyless — no auth header needed
    "desc":        "GPT-OSS 20B Reasoning via Pollinations — free, no key, tool calls supported",
    "hf_provider": False,
    "is_t2":       False,
    "pollinations": True,
}
CHAT_ORDER.append("pollinations-gptoss")
TOOL_CAPABLE_ORDER.append("pollinations-gptoss")

# ── G4F keyless providers — gratis, no API key, via g4f library ──────────────
# Diregistrasi hanya jika g4f tersedia
if G4F_AVAILABLE:
    _G4F_CHAT_PROVIDERS = [
        {
            "id":       "g4f-deepinfra",
            "provider": Provider.DeepInfra,
            "model":    "",
            "desc":     "Llama via DeepInfra (G4F) — free, fast, multi-turn",
            "tool_cap": False,
        },
        {
            "id":       "g4f-yqcloud",
            "provider": Provider.Yqcloud,
            "model":    "",
            "desc":     "GPT via Yqcloud (G4F) — free, fastest ~1s",
            "tool_cap": False,
        },
        {
            "id":       "g4f-cohere",
            "provider": Provider.CohereForAI_C4AI_Command,
            "model":    "",
            "desc":     "Cohere Command R via HF Space (G4F) — free, no key",
            "tool_cap": False,
        },
        {
            "id":       "g4f-perplexity",
            "provider": Provider.Perplexity,
            "model":    "",
            "desc":     "Perplexity AI (G4F) — free, no key",
            "tool_cap": False,
        },
        {
            "id":       "g4f-opera",
            "provider": Provider.OperaAria,
            "model":    "aria",
            "desc":     "Opera Aria (G4F) — free, anonymous OAuth, no key",
            "tool_cap": False,
        },
    ]
    for _gp in _G4F_CHAT_PROVIDERS:
        CHAT_PROVIDERS[_gp["id"]] = {
            "type":     "g4f",
            "provider": _gp["provider"],
            "model":    _gp["model"],
            "desc":     _gp["desc"],
            "hf_provider": False,
            "is_t2":       False,
            "g4f":         True,
        }
        CHAT_ORDER.append(_gp["id"])
        if _gp["tool_cap"]:
            TOOL_CAPABLE_ORDER.append(_gp["id"])

# ── Qwen AI keyless providers (chat.qwen.ai) — 3 tier model ──────────────────
if _QWEN_COOKIES_AVAILABLE:
    _QWEN_CHAT_PROVIDERS = [
        {
            "id":    "qwen-flash",
            "model": "qwen3.5-flash",
            "desc":  "Qwen3.5-Flash via chat.qwen.ai — free, cepat, tanpa login",
        },
        {
            "id":    "qwen-plus",
            "model": "qwen3.6-plus",
            "desc":  "Qwen3.6-Plus via chat.qwen.ai — free, balanced, tanpa login",
        },
        {
            "id":    "qwen-max",
            "model": "qwen3.7-max",
            "desc":  "Qwen3.7-Max via chat.qwen.ai — free, paling kuat, tanpa login",
        },
    ]
    for _qp in _QWEN_CHAT_PROVIDERS:
        CHAT_PROVIDERS[_qp["id"]] = {
            "type":        "qwen",
            "model":       _qp["model"],
            "desc":        _qp["desc"],
            "hf_provider": False,
            "is_t2":       False,
            "g4f":         False,
            "qwen":        True,
        }
        CHAT_ORDER.append(_qp["id"])

# ── _OPT_PROVIDERS: HF providers yang belum aktif (HF_TOKEN tidak di-set) ────
_OPT_PROVIDERS = []
for _p in _HF_PROVIDERS:
    if _p["id"] not in CHAT_PROVIDERS:
        _OPT_PROVIDERS.append({
            "id":      _p["id"],
            "desc":    _p["desc"],
            "model":   _p["model"],
            "key_env": "HF_TOKEN",
        })
    if (_p["id"] + "-t2") not in CHAT_PROVIDERS:
        _OPT_PROVIDERS.append({
            "id":      _p["id"] + "-t2",
            "desc":    _p["desc"] + " [token2]",
            "model":   _p["model"],
            "key_env": "HF_TOKEN_2",
        })

# ── Public display names (clean, user-facing) ────────────────────────────────
# Pemetaan internal ID → nama publik yang tampil di UI dan /v1/models.
# t2 variants disembunyikan dari tampilan — hanya dipakai secara internal.
_PUBLIC_LABEL: dict[str, str] = {
    # HF models
    "hf-cerebras-qwen":   "Qwen3-235B",
    "hf-hyperbolic":      "Llama-3.3-70B",
    "hf-cerebras":        "GPT-OSS-120B",
    "hf-cerebras-fast":   "Llama-3.1-8B",
    # Pollinations
    "pollinations-gptoss": "GPT-OSS-20B",
    # Qwen AI keyless
    "qwen-flash": "Qwen3.5-Flash",
    "qwen-plus":  "Qwen3.6-Plus",
    "qwen-max":   "Qwen3.7-Max",
    # G4F keyless
    "g4f-deepinfra":   "Llama-3-8B",
    "g4f-yqcloud":     "Yqcloud-GPT",
    "g4f-cohere":      "Cohere-Command-R",
    "g4f-perplexity":  "Perplexity-AI",
    "g4f-opera":       "Opera-Aria",
    # Audio
    "edge-id-female":        "Indonesia · Wanita",
    "edge-id-male":          "Indonesia · Pria",
    "edge-ms-female":        "Malaysia · Wanita",
    "edge-ms-male":          "Malaysia · Pria",
    "edge-en-female":        "English · Female",
    "edge-en-male":          "English · Male",
    "edge-en-multilingual":  "English · Multilingual",
    "edge-en-gb-female":     "English UK · Female",
    # Image
    "hf-flux-schnell":      "FLUX.1-schnell",
    "hf-flux-dev":          "FLUX.1-dev",
    "hf-sdxl":              "Stable Diffusion XL",
    "pollinations-image":   "Pollinations",
}

def _public_label(pid: str) -> str:
    """Kembalikan nama publik untuk provider ID. Fallback ke pid jika tidak ada mapping."""
    return _PUBLIC_LABEL.get(pid, pid)

def _is_t2(pid: str) -> bool:
    """Cek apakah ini provider t2 (internal only, tidak ditampilkan ke user)."""
    return CHAT_PROVIDERS.get(pid, {}).get("is_t2", False)


# ── Smart Routing ──────────────────────────────────────────────────────────────
# Preferred provider order per intent. Only providers actually in CHAT_PROVIDERS
# (i.e. their API key is set) will be used; others are skipped transparently.

_INTENT_PREFERRED = {
    "coding": [
        "hf-cerebras-qwen",    # Qwen3 235B — best coding & math
        "hf-cerebras",         # GPT-OSS 120B — fast, native tool calls
        "hf-hyperbolic",       # Llama 3.3 70B — strong instruction following
        "hf-cerebras-fast",    # Llama 3.1 8B
        "pollinations-gptoss", # GPT-OSS 20B — free, tool calls
        "qwen-max",            # Qwen3.7-Max — free, strong coding
        "qwen-plus",           # Qwen3.6-Plus — free, balanced
        "qwen-flash",          # Qwen3.5-Flash — free, cepat
        "g4f-deepinfra",       # Llama 3 8B — free fallback
        "g4f-cohere",          # Cohere Command R
        "g4f-yqcloud",         # GPT wrapper — fastest
        "g4f-opera",           # Opera Aria — free, anonymous OAuth
        "g4f-perplexity",      # Perplexity — last resort
    ],
    "analysis": [
        "hf-hyperbolic",       # Llama 3.3 70B — most Claude-like
        "hf-cerebras-qwen",    # Qwen3 235B — wide knowledge
        "hf-cerebras",         # GPT-OSS 120B
        "hf-cerebras-fast",
        "pollinations-gptoss",
        "qwen-max",            # Qwen3.7-Max — free, analysis
        "qwen-plus",
        "qwen-flash",
        "g4f-deepinfra",
        "g4f-cohere",
        "g4f-yqcloud",
        "g4f-opera",
        "g4f-perplexity",
    ],
    "math": [
        "hf-cerebras-qwen",    # Qwen3 235B — best math
        "hf-cerebras",         # GPT-OSS 120B
        "hf-hyperbolic",
        "hf-cerebras-fast",
        "pollinations-gptoss",
        "qwen-max",            # Qwen3.7-Max — Qwen sangat kuat di math
        "qwen-plus",
        "qwen-flash",
        "g4f-deepinfra",
        "g4f-cohere",
        "g4f-yqcloud",
        "g4f-opera",
        "g4f-perplexity",
    ],
    "search": [
        "hf-hyperbolic",       # Llama 3.3 70B — best instruction following
        "hf-cerebras-qwen",    # Qwen3 235B — wide factual knowledge
        "hf-cerebras",         # GPT-OSS 120B — fast
        "hf-cerebras-fast",
        "pollinations-gptoss",
        "g4f-perplexity",      # Perplexity baik untuk search-like queries
        "qwen-plus",
        "qwen-max",
        "qwen-flash",
        "g4f-deepinfra",
        "g4f-cohere",
        "g4f-yqcloud",
        "g4f-opera",
    ],
}

# Keyword patterns per intent (checked against last user message, lowercase)
import re as _re

_INTENT_PATTERNS = {
    "coding": _re.compile(
        r'\b(code|kode|coding|program|script|function|fungsi|class|method|debug|error|bug|'
        r'implement|buat fungsi|bikin fungsi|buatkan fungsi|buatkan script|buatkan program|'
        r'bikin script|bikin program|bikin kode|buat kode|buat script|buat program|'
        r'algoritma|algorithm|python|javascript|typescript|java|kotlin|golang|rust|'
        r'react|nodejs|html|css|sql|bash|shell|api|endpoint|deploy|git|npm|pip|library|'
        r'module|package|refactor|syntax|compile|runtime|exception|stacktrace|snippet|'
        r'loop|recursion|array|object|json|xml|regex|database|query|orm|framework|'
        r'otomasi|automate|bot|scraper|crawler|webhook|cron|scheduler)\b',
        _re.IGNORECASE
    ),
    "math": _re.compile(
        r'\b(hitung|hitungan|kalkulator|calculator|calculate|matematika|math|rumus|formula|'
        r'equation|persamaan|statistik|statistic|probabilitas|probability|integral|'
        r'turunan|derivative|matriks|matrix|vektor|vector|aljabar|algebra|'
        r'kalkulus|calculus|buktikan|prove|optimasi|optimization|regresi|regression|'
        r'distribusi|distribution|konversi|convert|persen|percent|rata.?rata|average|'
        r'median|modus|standar deviasi|standard deviation)\b',
        _re.IGNORECASE
    ),
    "analysis": _re.compile(
        r'\b(analisis|analisa|analyze|analysis|bandingkan|compare|evaluasi|evaluate|'
        r'strategi|strategy|riset|research|jelaskan mendalam|explain in depth|'
        r'pros dan cons|pros and cons|kelebihan|kekurangan|advantages|disadvantages|'
        r'review|assessment|laporan|report|kesimpulan|conclusion|rekomendasi|recommendation|'
        r'mendalam|in-depth|detailed|komprehensif|comprehensive|elaborasi|elaborate|'
        r'breakdown|rangkum|summarize|apa pendapat|what do you think|opini|opinion|'
        r'jelaskan kenapa|explain why|penyebab|cause|dampak|impact|efek|effect)\b',
        _re.IGNORECASE
    ),
    "search": _re.compile(
        r'\b(cari|carikan|cek|search|berita|news|terkini|terbaru|latest|update terbaru|'
        r'hari ini|today|sekarang|current|real.?time|live data|'
        r'harga saham|stock price|cuaca|weather|informasi tentang|info tentang|'
        r'siapa itu|who is|apa itu|what is|dimana|where is|kapan|when did)\b',
        _re.IGNORECASE
    ),
}


def detect_intent(messages: list) -> str:
    """
    Deteksi intent dari pesan user terakhir.
    Returns: 'coding' | 'math' | 'analysis' | 'search' | 'general'
    """
    # Ambil teks user dari beberapa pesan terakhir (maks 3)
    user_texts = [
        m.get("content", "") for m in messages[-3:]
        if m.get("role") == "user" and isinstance(m.get("content"), str)
    ]
    combined = " ".join(user_texts)
    if not combined.strip():
        return "general"

    scores = {intent: 0 for intent in _INTENT_PATTERNS}
    for intent, pattern in _INTENT_PATTERNS.items():
        scores[intent] = len(pattern.findall(combined))

    best_intent = max(scores, key=lambda k: scores[k])
    return best_intent if scores[best_intent] > 0 else "general"


def get_order_for_intent(intent: str, pinned: str = None) -> list:
    """
    Urutan provider optimal untuk intent.
    Semua provider adalah HF Token — t1 didahulukan, lalu t2 pasangannya.

    Jika `pinned` diisi dengan provider ID yang valid, provider tersebut
    diletakkan di posisi pertama (kemudian diikuti fallback urutan normal).

    Contoh untuk coding:
      hf-cerebras-qwen → hf-cerebras-qwen-t2
      → hf-cerebras → hf-cerebras-t2
      → hf-hyperbolic → hf-hyperbolic-t2
      → hf-cerebras-fast → hf-cerebras-fast-t2
    """
    preferred = _INTENT_PREFERRED.get(intent, [
        "hf-cerebras-qwen", "hf-cerebras", "hf-hyperbolic", "hf-cerebras-fast",
    ])

    # Bangun ordered: t1 → t2 pasangannya langsung
    ordered = []
    seen = set()
    for pid in preferred:
        if pid not in CHAT_PROVIDERS or pid in seen:
            continue
        ordered.append(pid)
        seen.add(pid)
        t2_pid = pid + "-t2"
        if t2_pid in CHAT_PROVIDERS and t2_pid not in seen:
            ordered.append(t2_pid)
            seen.add(t2_pid)

    # Sisa CHAT_ORDER yang belum masuk (fallback)
    for p in CHAT_ORDER:
        if p not in seen:
            ordered.append(p)
            seen.add(p)

    # Jika ada pinned provider, letakkan di depan
    if pinned and pinned in CHAT_PROVIDERS:
        ordered = [pinned] + [p for p in ordered if p != pinned]

    return ordered


IMAGE_PROVIDERS = {
    "hf-flux-schnell": {
        "model":   "black-forest-labs/FLUX.1-schnell",
        "type":    "huggingface",
        "desc":    "FLUX.1-schnell — fast, high-quality (HuggingFace free tier)",
    },
    "hf-flux-dev": {
        "model":   "black-forest-labs/FLUX.1-dev",
        "type":    "huggingface",
        "desc":    "FLUX.1-dev — detailed, high-quality (HuggingFace free tier)",
    },
    "hf-sdxl": {
        "model":   "stabilityai/stable-diffusion-xl-base-1.0",
        "type":    "huggingface",
        "desc":    "Stable Diffusion XL — photorealistic (HuggingFace free tier)",
    },
    "pollinations": {
        "model":   "sana",
        "type":    "pollinations",
        "desc":    "Pollinations Image (Sana model, no key required)",
    },
}
IMAGE_ORDER = ["hf-flux-schnell", "hf-flux-dev", "hf-sdxl", "pollinations"]

AUDIO_PROVIDERS = {
    # ── Bahasa Indonesia ───────────────────────────────────────────────────────
    "edge-id-female": {
        "model":        "edge-id-female",
        "voice":        "id-ID-GadisNeural",
        "lang":         "id-ID",
        "gender":       "female",
        "desc":         "Suara wanita Indonesia (Microsoft Edge TTS — Gadis)",
        "content_type": "audio/mpeg",
    },
    "edge-id-male": {
        "model":        "edge-id-male",
        "voice":        "id-ID-ArdiNeural",
        "lang":         "id-ID",
        "gender":       "male",
        "desc":         "Suara pria Indonesia (Microsoft Edge TTS — Ardi)",
        "content_type": "audio/mpeg",
    },
    # ── Bahasa Melayu ──────────────────────────────────────────────────────────
    "edge-ms-female": {
        "model":        "edge-ms-female",
        "voice":        "ms-MY-YasminNeural",
        "lang":         "ms-MY",
        "gender":       "female",
        "desc":         "Suara wanita Melayu (Microsoft Edge TTS — Yasmin)",
        "content_type": "audio/mpeg",
    },
    "edge-ms-male": {
        "model":        "edge-ms-male",
        "voice":        "ms-MY-OsmanNeural",
        "lang":         "ms-MY",
        "gender":       "male",
        "desc":         "Suara pria Melayu (Microsoft Edge TTS — Osman)",
        "content_type": "audio/mpeg",
    },
    # ── English ────────────────────────────────────────────────────────────────
    "edge-en-female": {
        "model":        "edge-en-female",
        "voice":        "en-US-AvaNeural",
        "lang":         "en-US",
        "gender":       "female",
        "desc":         "English female voice (Microsoft Edge TTS — Ava)",
        "content_type": "audio/mpeg",
    },
    "edge-en-male": {
        "model":        "edge-en-male",
        "voice":        "en-US-AndrewNeural",
        "lang":         "en-US",
        "gender":       "male",
        "desc":         "English male voice (Microsoft Edge TTS — Andrew)",
        "content_type": "audio/mpeg",
    },
    "edge-en-multilingual": {
        "model":        "edge-en-multilingual",
        "voice":        "en-US-AndrewMultilingualNeural",
        "lang":         "en-US",
        "gender":       "male",
        "desc":         "Multilingual voice — bisa campur Inggris & bahasa lain",
        "content_type": "audio/mpeg",
    },
    "edge-en-gb-female": {
        "model":        "edge-en-gb-female",
        "voice":        "en-GB-LibbyNeural",
        "lang":         "en-GB",
        "gender":       "female",
        "desc":         "British English female (Microsoft Edge TTS — Libby)",
        "content_type": "audio/mpeg",
    },
}

# Urutan default: Indonesia dulu → Melayu → Inggris
AUDIO_ORDER = [
    "edge-id-female", "edge-id-male",
    "edge-ms-female", "edge-ms-male",
    "edge-en-female", "edge-en-male",
    "edge-en-multilingual", "edge-en-gb-female",
]

# Pattern deteksi bahasa teks input
_ID_PATTERN = re.compile(
    r'\b(aku|kamu|saya|kita|kami|dia|mereka|adalah|yang|dan|atau|juga|dengan|untuk|'
    r'tidak|bisa|mau|akan|sudah|ada|ini|itu|dari|ke|di|pada|lagi|jangan|boleh|'
    r'bagaimana|dimana|kapan|siapa|kenapa|karena|tapi|kalau|setelah|sebelum|'
    r'halo|hai|sayang|cantik|indah|senang|suka|cinta|rindu|maaf|terima kasih)\b',
    re.IGNORECASE,
)


def _detect_best_voice(text: str, gender: str = None) -> str:
    """
    Pilih voice edge-tts terbaik berdasarkan bahasa teks.
    gender: 'male' | 'female' | None (default female untuk Indonesia)
    """
    is_indonesian = bool(_ID_PATTERN.search(text))
    if is_indonesian:
        return "id-ID-GadisNeural" if gender != "male" else "id-ID-ArdiNeural"
    return "en-US-AvaNeural" if gender != "male" else "en-US-AndrewNeural"


import asyncio as _asyncio
import io as _io


def _edge_tts_generate(text: str, voice: str) -> bytes:
    """
    Hasilkan audio MP3 dari teks menggunakan Microsoft Edge TTS (edge-tts).
    Tidak memerlukan API key — gratis dan selalu tersedia.
    """
    try:
        import edge_tts
    except ImportError:
        raise RuntimeError("edge-tts tidak terinstal. Jalankan: pip install edge-tts")

    async def _generate():
        communicate = edge_tts.Communicate(text, voice)
        buf = _io.BytesIO()
        async for chunk in communicate.stream():
            if chunk["type"] == "audio":
                buf.write(chunk["data"])
        return buf.getvalue()

    # Jalankan coroutine — handle event loop yang sudah ada (Flask sync context)
    try:
        loop = _asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(_asyncio.run, _generate())
                return future.result(timeout=30)
        else:
            return loop.run_until_complete(_generate())
    except RuntimeError:
        return _asyncio.run(_generate())


# ── Tool calling helpers ───────────────────────────────────────────────────────

# ── Default system prompt (fallback jika user tidak kirim system message) ──────
DEFAULT_SYSTEM_PROMPT = """You are a helpful, accurate, and concise AI assistant.
You respond in the same language the user uses.
You are honest about what you know and don't know.
When using tools, follow the tool-calling format exactly as instructed."""


# ── Tool calling system prompt (diinjeksi untuk g4f providers) ─────────────────
TOOL_SYSTEM_INJECT = """\
You have access to the following tools/functions:

<tools>
{tools_json}
</tools>

## Tool Calling Rules

When you need to call a tool, respond with ONLY a raw JSON object — no explanation, \
no markdown, no code block, no text before or after:

{{"tool_calls": [
  {{
    "id": "call_{rand_id}",
    "type": "function",
    "function": {{
      "name": "<tool_name>",
      "arguments": "<json_string_of_args>"
    }}
  }}
]}}

### Parallel calls (when multiple tools are needed at once):
{{"tool_calls": [
  {{"id": "call_{rand_id}a", "type": "function", "function": {{"name": "<tool1>", "arguments": "<args1>"}}}},
  {{"id": "call_{rand_id}b", "type": "function", "function": {{"name": "<tool2>", "arguments": "<args2>"}}}}
]}}

### Rules:
1. If a tool is needed → output ONLY the JSON above, nothing else.
2. If no tool is needed → reply normally in plain text.
3. NEVER mix tool call JSON with plain text in the same response.
4. NEVER wrap the JSON in markdown (no ```json blocks).
5. The "arguments" field MUST be a JSON-encoded string, not a raw object.
6. Only call tools that are listed above. Never invent tool names.
"""

def build_tool_system_prompt(tools: list, forced_tool_name: str = None) -> str:
    tools_json = json.dumps(tools, ensure_ascii=False, indent=2)
    rand_id = uuid.uuid4().hex[:8]
    prompt = TOOL_SYSTEM_INJECT.format(tools_json=tools_json, rand_id=rand_id)
    if forced_tool_name:
        prompt += (
            f"\n\n## MANDATORY\n"
            f"You MUST call the tool '{forced_tool_name}' right now. "
            f"Do NOT reply with plain text. Output only the tool_calls JSON."
        )
    return prompt


def parse_tool_calls(text: str):
    """
    Cek apakah respons model adalah tool call JSON.
    Kembalikan (tool_calls_list, is_tool_call).
    """
    if not text:
        return None, False
    text_stripped = text.strip()
    # Cari JSON tool_calls di dalam respons
    start = text_stripped.find('{"tool_calls"')
    if start == -1:
        start = text_stripped.find('{ "tool_calls"')
    if start == -1:
        return None, False
    try:
        # Ambil dari posisi { sampai akhir, coba parse
        candidate = text_stripped[start:]
        # Temukan closing brace yang matching
        depth = 0
        end = -1
        for i, c in enumerate(candidate):
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end == -1:
            return None, False
        data = json.loads(candidate[:end])
        calls = data.get("tool_calls", [])
        if calls:
            return calls, True
    except Exception:
        pass
    return None, False


def format_tool_calls_openai(raw_calls: list) -> list:
    """Normalisasi tool_calls ke format OpenAI."""
    result = []
    for i, c in enumerate(raw_calls):
        call_id = c.get("id") or f"call_{uuid.uuid4().hex[:8]}"
        fn = c.get("function", {})
        args = fn.get("arguments", "{}")
        if isinstance(args, dict):
            args = json.dumps(args, ensure_ascii=False)
        result.append({
            "id": call_id,
            "type": "function",
            "function": {
                "name": fn.get("name", ""),
                "arguments": args,
            },
        })
    return result


# ── Core chat helpers ──────────────────────────────────────────────────────────

def parse_body(*required):
    data = request.get_json(silent=True)
    if not data:
        return None, jsonify({"error": "Body harus JSON"}), 400
    for f in required:
        if not data.get(f):
            return None, jsonify({"error": f"Field '{f}' wajib diisi"}), 400
    return data, None, None


def run_chat(cfg, messages: list, model_override=None, tools=None):
    """
    Jalankan chat dengan daftar messages (multi-turn).
    - tools : list OpenAI tool definitions (opsional).
      Untuk openai_compatible → dikirim native ke API.
      Untuk g4f providers → diinjeksi ke system message (JSON injection).
    """
    model = model_override or cfg["model"]
    if cfg["type"] == "qwen":
        return _qwen_chat(messages, model=model or cfg["model"])
    if cfg["type"] == "pollinations_http":
        r = requests.post(
            "https://text.pollinations.ai/",
            json={"messages": messages, "model": model, "stream": False},
            timeout=30,
        )
        r.raise_for_status()
        return r.text
    if cfg["type"] == "openai_compatible":
        payload = {"model": model, "messages": messages, "stream": False}
        # Kirim tools natively jika tersedia (openai_compatible providers mendukung ini)
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        api_key = cfg.get("api_key", "")
        hdrs = {"Content-Type": "application/json"}
        if api_key:
            hdrs["Authorization"] = f"Bearer {api_key}"
        r = requests.post(cfg["url"], headers=hdrs, json=payload, timeout=35)
        # Pollinations 429 (queue full) → retry sekali dengan backoff
        if r.status_code == 429 and cfg.get("pollinations"):
            import time as _time
            _time.sleep(3)
            r = requests.post(cfg["url"], headers=hdrs, json=payload, timeout=40)
        # Fast-path: jika HF t1 rate-limited (429) → langsung retry dengan HF_TOKEN_2
        # Hanya berlaku untuk t1 provider, dan hanya jika token-nya memang berbeda
        if r.status_code == 429 and cfg.get("hf_provider") and not cfg.get("is_t2"):
            hf_token_2 = os.environ.get("HF_TOKEN_2", "").strip()
            if hf_token_2 and hf_token_2 != cfg.get("api_key"):
                print(f"[HF] {cfg.get('model')} token-1 rate-limited → fast-retry token-2")
                r = requests.post(
                    cfg["url"],
                    headers={
                        "Authorization": f"Bearer {hf_token_2}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=30,
                )
        r.raise_for_status()
        data = r.json()
        msg = data["choices"][0]["message"]
        # Handle native tool_calls dari API → konversi ke format JSON kita
        if msg.get("tool_calls"):
            return json.dumps({"tool_calls": [
                {
                    "id": tc.get("id", f"call_{i}"),
                    "type": "function",
                    "function": {
                        "name": tc["function"]["name"],
                        "arguments": tc["function"]["arguments"],
                    },
                }
                for i, tc in enumerate(msg["tool_calls"])
            ]})
        return msg.get("content") or ""
    # ── g4f path ──────────────────────────────────────────────────────────────
    if not G4F_AVAILABLE:
        raise RuntimeError("g4f tidak tersedia di environment ini")
    # Untuk g4f providers, tools diinjeksi sebagai system message JSON
    msgs_for_g4f = messages
    if tools:
        tool_inject = build_tool_system_prompt(tools)
        msgs_for_g4f = list(messages)
        if msgs_for_g4f and msgs_for_g4f[0].get("role") == "system":
            msgs_for_g4f[0] = {
                "role": "system",
                "content": msgs_for_g4f[0]["content"] + "\n\n" + tool_inject,
            }
        else:
            msgs_for_g4f.insert(0, {"role": "system", "content": tool_inject})
    kwargs = {"provider": cfg["provider"], "messages": msgs_for_g4f}
    if model:
        kwargs["model"] = model
    resp = g4f_client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content


def _provider_tier(pid: str) -> str:
    """Label tier provider untuk logging."""
    cfg = CHAT_PROVIDERS.get(pid, {})
    if cfg.get("qwen"):
        return "Qwen"
    if cfg.get("pollinations"):
        return "Pollinations"
    if cfg.get("g4f"):
        return "G4F"
    if cfg.get("hf_provider"):
        return "HF-t2" if cfg.get("is_t2") else "HF-t1"
    if cfg.get("type") == "openai_compatible":
        return "non-HF"
    return "static"


def run_chat_fallback(messages: list, model_override=None, require_tool_call: bool = False,
                      intent: str = "general", tools: list = None, pinned: str = None):
    """
    Coba setiap provider secara berurutan (semua HF Token).

    - intent            : hasil detect_intent(), menentukan urutan provider optimal
    - pinned            : provider ID yang diminta user secara eksplisit — diletakkan pertama
    - require_tool_call : provider tanpa tool_calls JSON dianggap gagal
    - tools             : list OpenAI tool definitions
    """
    errors = {}
    # Pilih urutan berdasarkan intent; pinned provider diletakkan paling depan
    base_order = get_order_for_intent(intent, pinned=pinned)

    # Saat require_tool_call, dahulukan provider yang tool-capable dalam urutan intent
    if require_tool_call:
        tc_set = set(TOOL_CAPABLE_ORDER)
        order = [p for p in base_order if p in tc_set] + \
                [p for p in base_order if p not in tc_set]
    else:
        order = base_order

    # Hitung berapa provider yang aktif (belum di-trip circuit breaker)
    active_order = [p for p in order if not _is_tripped(p)]
    skipped = [p for p in order if _is_tripped(p)]
    if skipped:
        print(f"[Circuit] Skip {len(skipped)} provider (tripped): {skipped}")
    print(f"[Routing] intent={intent} tool_call={require_tool_call} tools={bool(tools)} → {len(active_order)}/{len(order)} provider aktif")

    for pk in active_order:
        tier = _provider_tier(pk)
        try:
            print(f"[{tier}] mencoba {pk} ...")
            text = run_chat(CHAT_PROVIDERS[pk], messages, model_override, tools=tools)
            if not text or not text.strip():
                errors[pk] = "Respons kosong"
                print(f"[{tier}] {pk} → respons kosong, skip")
                continue
            # Jika tools diperlukan, cek apakah model menghasilkan tool call
            if require_tool_call:
                _, is_tc = parse_tool_calls(text)
                if not is_tc:
                    errors[pk] = "Model tidak menghasilkan tool_calls"
                    print(f"[{tier}] {pk} → tidak menghasilkan tool_calls, skip")
                    continue
            print(f"[{tier}] {pk} → sukses ✓")
            return text, pk, errors
        except Exception as e:
            err_str = str(e)
            errors[pk] = err_str
            # Trip circuit breaker untuk 402 (quota habis) dan 401 (token invalid)
            if "402" in err_str or "Payment Required" in err_str:
                _trip_circuit(pk, "402 quota habis")
            elif "401" in err_str and CHAT_PROVIDERS[pk].get("hf_provider"):
                _trip_circuit(pk, "401 token invalid")
            print(f"[{tier}] {pk} → error: {e}")

    # Semua provider tool-capable gagal → fallback teks biasa (tetap gunakan tools)
    if require_tool_call:
        print("[Routing] Semua provider tool-capable gagal → fallback plain text")
        for pk in active_order:
            tier = _provider_tier(pk)
            try:
                text = run_chat(CHAT_PROVIDERS[pk], messages, model_override, tools=tools)
                if text and text.strip():
                    print(f"[{tier}] {pk} → sukses (plain text fallback) ✓")
                    return text, pk, errors
            except Exception:
                pass

    print("[Routing] Semua provider gagal")
    return None, None, errors


def run_audio_fallback(text: str, model: str = None, voice_override: str = None, gender: str = None):
    """
    Generate audio menggunakan edge-tts dengan auto-select suara terbaik.
    - model          : provider key (misal 'edge-id-female'), prioritas tertinggi
    - voice_override : nama voice edge-tts (misal 'id-ID-GadisNeural'), override auto-detect
    - gender         : 'male' | 'female' | None
    - Kembalikan (audio_bytes, provider_key, content_type, errors)
    """
    errors = {}

    # Pilih voice: model key → voice override → auto-detect dari teks → default
    if model and model in AUDIO_PROVIDERS:
        pk_used = model
        target_voice = AUDIO_PROVIDERS[model]["voice"]
    elif voice_override:
        # Cari provider_key yang matching voice, atau pakai edge-id-female sebagai fallback
        target_voice = voice_override
        pk_used = next(
            (k for k, v in AUDIO_PROVIDERS.items() if v["voice"] == voice_override),
            "edge-id-female"
        )
    else:
        target_voice = _detect_best_voice(text, gender)
        pk_used = next(
            (k for k, v in AUDIO_PROVIDERS.items() if v["voice"] == target_voice),
            "edge-id-female"
        )

    print(f"[Audio] voice={target_voice} provider={pk_used}")

    # Coba voice utama, lalu fallback ke provider lain jika gagal
    order = [pk_used] + [pk for pk in AUDIO_ORDER if pk != pk_used]
    for pk in order:
        cfg = AUDIO_PROVIDERS[pk]
        voice = target_voice if pk == pk_used else cfg["voice"]
        try:
            print(f"[Audio] mencoba {pk} voice={voice} ...")
            audio_bytes = _edge_tts_generate(text, voice)
            if audio_bytes and len(audio_bytes) > 100:
                print(f"[Audio] {pk} → sukses ({len(audio_bytes)} bytes) ✓")
                return audio_bytes, pk, cfg["content_type"], errors
            errors[pk] = "Output kosong"
        except Exception as e:
            errors[pk] = str(e)
            print(f"[Audio] {pk} → error: {e}")

    print("[Audio] Semua provider gagal")
    return None, None, None, errors


def make_image_url(prompt, model="sana", width=1024, height=1024):
    enc = urllib.parse.quote(prompt)
    return f"https://image.pollinations.ai/prompt/{enc}?model={model}&width={width}&height={height}&nologo=true"


def _hf_image_generate(prompt: str, model_id: str, width: int = 1024, height: int = 1024) -> bytes:
    """Generate gambar dari HuggingFace Inference API, return PNG bytes."""
    token = os.environ.get("HF_TOKEN") or os.environ.get("HF_TOKEN_2")
    if not token:
        raise RuntimeError("HF_TOKEN tidak tersedia di environment")
    client = HFClient(token=token)
    img = client.text_to_image(prompt, model=model_id, width=width, height=height)
    import io as _io_mod
    buf = _io_mod.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def run_image_fallback(prompt: str, model: str = None, width: int = 1024, height: int = 1024):
    """
    Generate gambar dengan auto-fallback antar provider.
    - model  : provider key (misal 'hf-flux-schnell'), None = coba urutan default
    - Return : (image_data, provider_key, content_type, errors)
      image_data bisa berupa URL string (pollinations) atau bytes (hf)
    """
    errors = {}
    order = ([model] + [k for k in IMAGE_ORDER if k != model]) if (model and model in IMAGE_PROVIDERS) else IMAGE_ORDER

    for pk in order:
        cfg = IMAGE_PROVIDERS.get(pk)
        if not cfg:
            continue
        try:
            if cfg["type"] == "huggingface":
                img_bytes = _hf_image_generate(prompt, cfg["model"], width, height)
                print(f"[Image] {pk} → sukses ({len(img_bytes)//1024}KB) ✓")
                return img_bytes, pk, "image/png", errors
            else:  # pollinations
                url = make_image_url(prompt, cfg["model"], width, height)
                print(f"[Image] {pk} → URL generated ✓")
                return url, pk, "image/url", errors
        except Exception as e:
            errors[pk] = str(e)
            print(f"[Image] {pk} → error: {e}")

    return None, None, None, errors


# ── OpenAI-compatible response builders ───────────────────────────────────────

def _estimate_tokens(text: str) -> int:
    """Estimasi kasar jumlah token (1 token ≈ 4 karakter)."""
    return max(1, len(text) // 4)


def _count_prompt_tokens(messages: list) -> int:
    """Estimasi prompt tokens dari daftar messages (overhead per-message sesuai tiktoken)."""
    total = 0
    for msg in (messages or []):
        content = msg.get("content") or ""
        if isinstance(content, list):
            content = " ".join(p.get("text", "") for p in content if isinstance(p, dict))
        total += _estimate_tokens(str(content)) + 4
    return total + 2


def build_completion_response(content, provider_used, tool_calls=None,
                              finish_reason="stop", messages=None):
    """Buat response dalam format OpenAI Chat Completions (standar resmi)."""
    msg = {"role": "assistant"}
    if tool_calls:
        msg["tool_calls"] = tool_calls
        msg["content"] = None
        finish_reason = "tool_calls"
    else:
        msg["content"] = content
    completion_tokens = _estimate_tokens(content) if content else 0
    prompt_tokens     = _count_prompt_tokens(messages)
    return {
        "id":                 f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object":             "chat.completion",
        "created":            int(time.time()),
        "model":              provider_used,
        "system_fingerprint": f"fp_dzeck_{provider_used}",
        "choices": [
            {
                "index":         0,
                "message":       msg,
                "logprobs":      None,
                "finish_reason": finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens":              prompt_tokens,
            "completion_tokens":          completion_tokens,
            "total_tokens":               prompt_tokens + completion_tokens,
            "prompt_tokens_details":      None,
            "completion_tokens_details":  None,
        },
    }


def _sse_chunk(resp_id, created, provider, delta, finish_reason=None):
    return "data: " + json.dumps({
        "id": resp_id, "object": "chat.completion.chunk",
        "created": created, "model": provider,
        "system_fingerprint": f"fp_dzeck_{provider}",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    }) + "\n\n"


def stream_text_response(content, provider_used, conv_id=None, chunk_size=6):
    """Generator SSE: kirim teks sebagai delta chunks."""
    resp_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    created = int(time.time())
    yield _sse_chunk(resp_id, created, provider_used, {"role": "assistant", "content": ""})
    for i in range(0, len(content), chunk_size):
        yield _sse_chunk(resp_id, created, provider_used, {"content": content[i:i+chunk_size]})
    meta = {"finish_reason": "stop"}
    if conv_id:
        meta["conversation_id"] = conv_id
    yield _sse_chunk(resp_id, created, provider_used, {}, finish_reason="stop")
    yield "data: [DONE]\n\n"


def stream_tool_calls_response(tool_calls, provider_used, conv_id=None):
    """Generator SSE: kirim tool_calls sesuai format OpenAI streaming."""
    resp_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    created = int(time.time())
    for i, tc in enumerate(tool_calls):
        delta = {
            "tool_calls": [{
                "index": i, "id": tc["id"], "type": "function",
                "function": {"name": tc["function"]["name"], "arguments": tc["function"]["arguments"]},
            }],
        }
        if i == 0:
            delta["role"] = "assistant"
            delta["content"] = None
        yield _sse_chunk(resp_id, created, provider_used, delta)
    yield _sse_chunk(resp_id, created, provider_used, {}, finish_reason="tool_calls")
    yield "data: [DONE]\n\n"


# ── Landing Page ──────────────────────────────────────────────────────────────

def build_landing_html():
    providers = [
        "HuggingFace", "Groq", "Cerebras", "SambaNova", "Together AI",
        "Google Gemini", "Mistral", "OpenAI", "DeepSeek", "Cohere",
        "Pollinations", "Meta AI"
    ]
    ticker_items = "".join(
        f'<div class="ticker-item"><span class="ticker-dot"></span>{p}</div>'
        for p in providers * 4
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DzeckAPI — One API. Every AI Model.</title>
<meta name="description" content="DzeckAPI is a unified AI gateway. One API key, access to every major AI model — HuggingFace, Groq, Cerebras, Gemini, Mistral, and more. OpenAI SDK compatible."/>
<meta name="keywords" content="AI API, AI gateway, unified AI, multi-provider AI, OpenAI compatible, LLM API, DzeckAPI"/>
<meta property="og:title" content="DzeckAPI — One API. Every AI Model."/>
<meta property="og:description" content="One endpoint for every major AI provider. Switch models instantly, no lock-in."/>
<meta property="og:type" content="website"/>
<meta name="twitter:card" content="summary_large_image"/>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#080808;--surface:#111111;--surface2:#181818;--surface3:#202020;
  --border:#2a2a2a;--border-hi:#383838;
  --text:#f0f0f0;--sub:#a0a0a0;--muted:#666;
  --accent:#d97757;--accent-dim:rgba(217,119,87,.12);--accent-border:rgba(217,119,87,.35);
  --green:#4ade80;--mono:'JetBrains Mono','Fira Code','Menlo',monospace;
  --r:10px;--r-sm:8px;
}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased;overflow-x:hidden}}
a{{color:inherit;text-decoration:none}}
::-webkit-scrollbar{{width:4px}}
::-webkit-scrollbar-thumb{{background:var(--border-hi);border-radius:4px}}

/* ── Nav ── */
nav{{position:fixed;top:0;left:0;right:0;z-index:200;border-bottom:1px solid var(--border);background:rgba(8,8,8,.85);backdrop-filter:blur(20px);height:58px;display:flex;align-items:center;padding:0 32px}}
.nav-inner{{max-width:1100px;margin:0 auto;width:100%;display:flex;align-items:center;justify-content:space-between}}
.nav-logo{{display:flex;align-items:center;gap:10px;font-weight:700;font-size:15px;letter-spacing:-.3px}}
.nav-logo-svg{{flex-shrink:0;display:flex;align-items:center}}
.nav-links{{display:flex;align-items:center;gap:6px}}
.nav-link{{color:var(--sub);font-size:13.5px;padding:6px 12px;border-radius:7px;transition:color .15s,background .15s;font-weight:500}}
.nav-link:hover{{color:var(--text);background:var(--surface2)}}
.nav-cta{{display:flex;align-items:center;gap:8px}}
.btn-ghost{{background:none;border:1px solid var(--border-hi);color:var(--text);padding:7px 16px;border-radius:99px;font-size:13px;font-weight:500;cursor:pointer;font-family:inherit;transition:all .15s}}
.btn-ghost:hover{{background:var(--surface2);border-color:var(--sub)}}
.btn-primary{{background:var(--text);color:#000;padding:7px 18px;border-radius:99px;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;border:none;transition:opacity .15s}}
.btn-primary:hover{{opacity:.85}}

/* ── Hero ── */
.hero{{padding:140px 24px 80px;text-align:center;position:relative;overflow:hidden}}
.hero::before{{content:'';position:absolute;inset:0;background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(217,119,87,.08) 0%,transparent 70%);pointer-events:none}}
.hero-badge{{display:inline-flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border-hi);border-radius:99px;padding:5px 14px 5px 10px;font-size:12.5px;color:var(--sub);margin-bottom:28px}}
.hero-badge-dot{{width:7px;height:7px;border-radius:50%;background:var(--border-hi);flex-shrink:0}}
.hero h1{{font-size:clamp(42px,6vw,72px);font-weight:800;letter-spacing:-2.5px;line-height:1.05;max-width:700px;margin:0 auto 22px}}
.hero h1 em{{font-style:normal;color:var(--accent)}}
.hero-sub{{font-size:17px;color:var(--sub);max-width:480px;margin:0 auto 40px;line-height:1.65;font-weight:400}}
.hero-cta{{display:flex;align-items:center;justify-content:center;gap:12px;flex-wrap:wrap;margin-bottom:56px}}
.btn-hero-primary{{background:var(--text);color:#000;padding:12px 28px;border-radius:99px;font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;border:none;transition:opacity .15s;display:inline-flex;align-items:center;gap:8px}}
.btn-hero-primary:hover{{opacity:.85}}
.btn-hero-secondary{{background:none;border:1px solid var(--border-hi);color:var(--text);padding:12px 28px;border-radius:99px;font-size:14px;font-weight:500;cursor:pointer;font-family:inherit;transition:all .15s;display:inline-flex;align-items:center;gap:8px}}
.btn-hero-secondary:hover{{background:var(--surface2);border-color:var(--sub)}}
.hero-chips{{display:flex;align-items:center;justify-content:center;gap:16px;flex-wrap:wrap}}
.chip{{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--muted)}}
.chip-dot{{width:5px;height:5px;border-radius:50%;background:var(--border-hi);flex-shrink:0}}

/* ── Code widget ── */
.code-widget{{max-width:700px;margin:0 auto 80px;background:var(--surface);border:1px solid var(--border-hi);border-radius:14px;overflow:hidden;text-align:left;box-shadow:0 32px 80px rgba(0,0,0,.5)}}
.code-tabs{{display:flex;align-items:center;gap:0;border-bottom:1px solid var(--border);background:var(--surface2);padding:0 16px}}
.code-tab{{padding:11px 14px;font-size:12.5px;font-weight:500;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;font-family:inherit;background:none;border-top:none;border-left:none;border-right:none}}
.code-tab.active{{color:var(--text);border-bottom-color:var(--accent)}}
.code-win-dots{{display:flex;gap:6px;margin-right:auto;order:-1}}
.code-dot{{width:11px;height:11px;border-radius:50%;background:var(--border-hi)}}
.code-body{{padding:22px 24px;font-family:var(--mono);font-size:13px;line-height:1.8;color:#c9d1d9;overflow-x:auto}}
.code-body .c{{color:#6e7681}}.code-body .k{{color:#ff7b72}}.code-body .s{{color:#a5d6ff}}
.code-body .f{{color:#d2a8ff}}.code-body .n{{color:#ffa657}}.code-body .p{{color:#c9d1d9}}
pre{{white-space:pre}}

/* ── Ticker ── */
.ticker-wrap{{overflow:hidden;border-top:1px solid var(--border);border-bottom:1px solid var(--border);background:var(--surface);padding:14px 0;margin-bottom:80px}}
.ticker-track{{display:flex;gap:0;animation:ticker 32s linear infinite;width:max-content}}
.ticker-track:hover{{animation-play-state:paused}}
.ticker-item{{display:flex;align-items:center;gap:9px;padding:0 28px;font-size:13px;color:var(--sub);font-weight:500;white-space:nowrap}}
.ticker-dot{{width:4px;height:4px;border-radius:50%;background:var(--border-hi);flex-shrink:0}}
@keyframes ticker{{0%{{transform:translateX(0)}}100%{{transform:translateX(-50%)}}}}

/* ── Section ── */
.section{{max-width:1100px;margin:0 auto;padding:0 24px 100px}}
.sec-label{{font-size:11px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--accent);margin-bottom:12px}}
.sec-title{{font-size:clamp(28px,3.5vw,40px);font-weight:800;letter-spacing:-1.2px;line-height:1.15;margin-bottom:14px}}
.sec-sub{{font-size:16px;color:var(--sub);max-width:500px;line-height:1.65}}

/* ── Features grid ── */
.features-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;margin-top:52px}}
.feat{{background:var(--surface);padding:28px 26px;transition:background .15s}}
.feat:hover{{background:var(--surface2)}}
.feat-icon{{width:36px;height:36px;border-radius:9px;background:var(--surface2);border:1px solid var(--border-hi);display:flex;align-items:center;justify-content:center;margin-bottom:16px}}
.feat-icon svg{{width:18px;height:18px;stroke:var(--sub);fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}}
.feat h3{{font-size:15px;font-weight:700;letter-spacing:-.3px;margin-bottom:7px}}
.feat p{{font-size:13.5px;color:var(--sub);line-height:1.6}}

/* ── Steps ── */
.steps{{display:grid;grid-template-columns:repeat(3,1fr);gap:24px;margin-top:52px}}
.step{{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:28px 24px}}
.step-num{{font-size:11px;font-weight:700;letter-spacing:1.2px;color:var(--accent);margin-bottom:14px;text-transform:uppercase}}
.step h3{{font-size:15px;font-weight:700;letter-spacing:-.3px;margin-bottom:10px}}
.step-code{{background:var(--surface2);border:1px solid var(--border-hi);border-radius:7px;padding:12px 14px;font-family:var(--mono);font-size:12px;color:var(--sub);margin-top:14px;overflow-x:auto;line-height:1.7}}

/* ── CTA ── */
.cta-section{{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:64px 48px;text-align:center;margin-bottom:80px;position:relative;overflow:hidden}}
.cta-section::before{{content:'';position:absolute;inset:0;background:radial-gradient(ellipse 60% 80% at 50% 50%,rgba(217,119,87,.05) 0%,transparent 70%);pointer-events:none}}
.cta-section h2{{font-size:clamp(26px,3.5vw,40px);font-weight:800;letter-spacing:-1.2px;margin-bottom:14px}}
.cta-section p{{font-size:16px;color:var(--sub);margin-bottom:36px;max-width:440px;margin-left:auto;margin-right:auto}}
.cta-meta{{font-size:12.5px;color:var(--muted);margin-top:18px}}

/* ── Footer ── */
footer{{border-top:1px solid var(--border);padding:32px;text-align:center;font-size:13px;color:var(--muted)}}
footer a{{color:var(--sub);transition:color .15s}}
footer a:hover{{color:var(--text)}}

/* ── Auth Modal ── */
.overlay{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(8px);z-index:300;align-items:center;justify-content:center}}
.overlay.open{{display:flex}}
.modal{{background:var(--surface);border:1px solid var(--border-hi);border-radius:16px;width:100%;max-width:380px;margin:16px;padding:28px 26px 24px;position:relative;box-shadow:0 32px 80px rgba(0,0,0,.6)}}
.modal-close{{position:absolute;top:14px;right:16px;background:none;border:none;color:var(--muted);font-size:16px;cursor:pointer;font-family:inherit;width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;transition:all .15s}}
.modal-close:hover{{background:var(--surface2);color:var(--text)}}
.modal h2{{font-size:18px;font-weight:700;margin-bottom:4px;letter-spacing:-.4px}}
.modal .sub{{color:var(--muted);font-size:13px;margin-bottom:22px}}
.tab-row{{display:flex;gap:3px;margin-bottom:20px;background:var(--surface2);border-radius:8px;padding:3px;border:1px solid var(--border)}}
.tab{{flex:1;padding:7px;border-radius:6px;border:none;background:none;color:var(--muted);font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;font-family:inherit}}
.tab.active{{background:var(--surface3);color:var(--text);box-shadow:0 1px 4px rgba(0,0,0,.4)}}
.field{{margin-bottom:14px}}
label{{display:block;font-size:12px;color:var(--sub);margin-bottom:5px;font-weight:500}}
input{{width:100%;background:var(--surface2);border:1px solid var(--border-hi);border-radius:8px;padding:10px 13px;color:var(--text);font-family:inherit;font-size:14px;outline:none;transition:border-color .15s,box-shadow .15s}}
input:focus{{border-color:var(--accent-border);box-shadow:0 0 0 3px var(--accent-dim)}}
input::placeholder{{color:var(--muted)}}
.modal-btn{{width:100%;background:var(--accent);color:#fff;border:none;padding:11px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;transition:opacity .15s;margin-top:6px}}
.modal-btn:hover{{opacity:.88}}
.modal-btn:disabled{{opacity:.4;cursor:not-allowed}}
.modal-err{{color:#f87171;font-size:12.5px;margin-top:10px;display:none;padding:9px 13px;background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.2);border-radius:7px}}

@media(max-width:900px){{
  .features-grid{{grid-template-columns:repeat(2,1fr)}}
  .steps{{grid-template-columns:1fr}}
  nav .nav-links{{display:none}}
}}
@media(max-width:600px){{
  nav{{padding:0 16px}}
  .hero{{padding:110px 16px 60px}}
  .hero h1{{letter-spacing:-1.5px}}
  .features-grid{{grid-template-columns:1fr}}
  .cta-section{{padding:40px 24px}}
  .section{{padding:0 16px 70px}}
}}
</style>
</head>
<body>

<!-- Nav -->
<nav>
  <div class="nav-inner">
    <a href="/" class="nav-logo">
      <div class="nav-logo-svg">
        <svg width="38" height="34" viewBox="-2 0 32 30" fill="none" xmlns="http://www.w3.org/2000/svg" overflow="visible">
          <defs>
            <linearGradient id="nlg" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#e8956d"/>
              <stop offset="100%" stop-color="#c0604a"/>
            </linearGradient>
          </defs>
          <path d="M3 23 a6 6 0 0 1 0-12 a3.8 3.8 0 0 1 7-1 a5 5 0 1 1 1 13Z"
            stroke="url(#nlg)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
          <circle cx="20" cy="12" r="3" stroke="#d97757" stroke-width="2"/>
          <circle cx="20" cy="12" r="1.1" fill="#d97757"/>
          <line x1="20" y1="12" x2="20" y2="6" stroke="#e8956d" stroke-width="1.8" stroke-linecap="round"/>
          <line x1="17.8" y1="9.8" x2="13" y2="6" stroke="#d97757" stroke-width="1.6" stroke-linecap="round"/>
          <circle cx="13" cy="6" r="1.9" stroke="#d97757" stroke-width="1.6"/>
          <line x1="22.5" y1="9.8" x2="27" y2="6" stroke="#e8956d" stroke-width="1.6" stroke-linecap="round"/>
          <circle cx="27" cy="6" r="1.9" stroke="#e8956d" stroke-width="1.6"/>
          <line x1="22.8" y1="13.5" x2="27" y2="16.5" stroke="#d97757" stroke-width="1.6" stroke-linecap="round"/>
          <circle cx="27" cy="16.5" r="1.9" stroke="#d97757" stroke-width="1.6"/>
        </svg>
      </div>
      DzeckAPI
    </a>
    <div class="nav-links">
      <a href="#features" class="nav-link">Features</a>
      <a href="#get-started" class="nav-link">Get Started</a>
      <a href="/dashboard" class="nav-link">Docs</a>
    </div>
    <div class="nav-cta">
      <button class="btn-ghost" onclick="openModal('login')">Log in</button>
      <button class="btn-primary" onclick="openModal('register')">Sign up free</button>
    </div>
  </div>
</nav>

<!-- Auth Modal -->
<div class="overlay" id="auth-overlay" onclick="overlayClick(event)">
  <div class="modal">
    <button class="modal-close" onclick="closeModal()">✕</button>
    <h2 id="modal-title">Sign in</h2>
    <p class="sub" id="modal-sub">Access all AI models with your API key</p>
    <div class="tab-row">
      <button class="tab active" id="tab-login" onclick="switchTab('login')">Login</button>
      <button class="tab" id="tab-register" onclick="switchTab('register')">Register</button>
    </div>
    <div id="form-login">
      <div class="field"><label>Email</label><input id="l-email" type="email" placeholder="you@example.com" autocomplete="email"/></div>
      <div class="field"><label>Password</label><input id="l-pass" type="password" placeholder="••••••••" autocomplete="current-password"/></div>
      <button class="modal-btn" onclick="doLogin()">Sign in</button>
      <div class="modal-err" id="l-err"></div>
    </div>
    <div id="form-register" style="display:none">
      <div class="field"><label>Username</label><input id="r-user" type="text" placeholder="yourname" autocomplete="username"/></div>
      <div class="field"><label>Email</label><input id="r-email" type="email" placeholder="you@example.com" autocomplete="email"/></div>
      <div class="field"><label>Password</label><input id="r-pass" type="password" placeholder="Min. 8 characters" autocomplete="new-password"/></div>
      <button class="modal-btn" onclick="doRegister()">Create account</button>
      <div class="modal-err" id="r-err"></div>
    </div>
  </div>
</div>

<!-- Hero -->
<section class="hero">
  <div class="hero-badge">
    <span class="hero-badge-dot"></span>
    Now supporting {len(providers)} AI providers
  </div>
  <h1>One API.<br/><em>Every AI Model.</em></h1>
  <p class="hero-sub">One endpoint, every major AI provider. Switch models instantly — no lock-in, no vendor complexity.</p>
  <div class="hero-cta">
    <button class="btn-hero-primary" onclick="openModal('register')">Get Started Free →</button>
    <a href="/dashboard" class="btn-hero-secondary">Documentation</a>
  </div>
  <div class="hero-chips">
    <span class="chip"><span class="chip-dot"></span>One API key</span>
    <span class="chip"><span class="chip-dot"></span>Usage analytics</span>
    <span class="chip"><span class="chip-dot"></span>OpenAI SDK compatible</span>
  </div>
</section>

<!-- Code widget -->
<div style="padding:0 24px">
<div class="code-widget">
  <div class="code-tabs">
    <div class="code-win-dots">
      <div class="code-dot r"></div>
      <div class="code-dot y"></div>
      <div class="code-dot g"></div>
    </div>
    <button class="code-tab active" onclick="showCode('python',this)">Python</button>
    <button class="code-tab" onclick="showCode('node',this)">Node.js</button>
    <button class="code-tab" onclick="showCode('curl',this)">cURL</button>
  </div>
  <div class="code-body" id="code-python"><pre><span class="c"># Install: pip install openai</span>
<span class="k">from</span> <span class="n">openai</span> <span class="k">import</span> <span class="n">OpenAI</span>

<span class="n">client</span> <span class="p">=</span> <span class="f">OpenAI</span><span class="p">(</span>
  <span class="n">base_url</span><span class="p">=</span><span class="s">"<span class='landing-base-url'></span>/v1"</span><span class="p">,</span>
  <span class="n">api_key</span><span class="p">=</span><span class="s">"sk-dzcx-your-api-key"</span>
<span class="p">)</span>

<span class="n">response</span> <span class="p">=</span> <span class="n">client</span><span class="p">.</span><span class="n">chat</span><span class="p">.</span><span class="n">completions</span><span class="p">.</span><span class="f">create</span><span class="p">(</span>
  <span class="n">model</span><span class="p">=</span><span class="s">"gemini-2.0-flash"</span><span class="p">,</span>
  <span class="n">messages</span><span class="p">=[{{"</span><span class="n">role</span><span class="p">":</span> <span class="s">"user"</span><span class="p">, "</span><span class="n">content</span><span class="p">":</span> <span class="s">"Hello!"</span><span class="p">}}]</span>
<span class="p">)</span>
<span class="f">print</span><span class="p">(</span><span class="n">response</span><span class="p">.</span><span class="n">choices</span><span class="p">[</span><span class="s">0</span><span class="p">].</span><span class="n">message</span><span class="p">.</span><span class="n">content</span><span class="p">)</span></pre></div>
  <div class="code-body" id="code-node" style="display:none"><pre><span class="c">// Install: npm install openai</span>
<span class="k">import</span> <span class="n">OpenAI</span> <span class="k">from</span> <span class="s">'openai'</span><span class="p">;</span>

<span class="k">const</span> <span class="n">client</span> <span class="p">=</span> <span class="k">new</span> <span class="f">OpenAI</span><span class="p">({{</span>
  <span class="n">baseURL</span><span class="p">:</span> <span class="s">'<span class='landing-base-url'></span>/v1'</span><span class="p">,</span>
  <span class="n">apiKey</span><span class="p">:</span>  <span class="s">'sk-dzcx-your-api-key'</span><span class="p">,</span>
<span class="p">}});</span>

<span class="k">const</span> <span class="n">res</span> <span class="p">=</span> <span class="k">await</span> <span class="n">client</span><span class="p">.</span><span class="n">chat</span><span class="p">.</span><span class="n">completions</span><span class="p">.</span><span class="f">create</span><span class="p">({{</span>
  <span class="n">model</span><span class="p">:</span> <span class="s">'gemini-2.0-flash'</span><span class="p">,</span>
  <span class="n">messages</span><span class="p">: [{{</span> <span class="n">role</span><span class="p">:</span> <span class="s">'user'</span><span class="p">,</span> <span class="n">content</span><span class="p">:</span> <span class="s">'Hello!'</span> <span class="p">}}],</span>
<span class="p">}});</span>
<span class="n">console</span><span class="p">.</span><span class="f">log</span><span class="p">(</span><span class="n">res</span><span class="p">.</span><span class="n">choices</span><span class="p">[</span><span class="s">0</span><span class="p">].</span><span class="n">message</span><span class="p">.</span><span class="n">content</span><span class="p">);</span></pre></div>
  <div class="code-body" id="code-curl" style="display:none"><pre><span class="n">curl</span> <span class="n"><span class='landing-base-url'></span>/v1/chat/completions</span> <span class="p">\\</span>
  <span class="n">-H</span> <span class="s">"Authorization: Bearer sk-dzcx-your-api-key"</span> <span class="p">\\</span>
  <span class="n">-H</span> <span class="s">"Content-Type: application/json"</span> <span class="p">\\</span>
  <span class="n">-d</span> <span class="s">'{{"model":"gemini-2.0-flash","messages":[{{"role":"user","content":"Hello!"}}]}}'</span></pre></div>
</div>
</div>

<!-- Provider ticker -->
<div class="ticker-wrap">
  <div class="ticker-track">{ticker_items}</div>
</div>

<!-- Features -->
<section class="section" id="features">
  <div style="text-align:center;margin-bottom:0">
    <div class="sec-label">Features</div>
    <h2 class="sec-title">Everything you need to ship with AI</h2>
    <p class="sec-sub" style="margin:0 auto">One API, built-in redundancy, usage tracking, and full multi-modal support.</p>
  </div>
  <div class="features-grid">
    <div class="feat">
      <div class="feat-icon"><svg viewBox="0 0 24 24"><polyline points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div>
      <h3>Unified API</h3>
      <p>One endpoint for models from HuggingFace, Groq, Cerebras, Gemini, Mistral, and more. Switch models with a single parameter.</p>
    </div>
    <div class="feat">
      <div class="feat-icon"><svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg></div>
      <h3>Smart Routing</h3>
      <p>Automatic provider selection based on request intent. Coding, reasoning, chat — each routed to the best available model.</p>
    </div>
    <div class="feat">
      <div class="feat-icon"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
      <h3>Built-in Redundancy</h3>
      <p>Automatic retries on upstream failures. Reduces failed requests without any extra code on your side.</p>
    </div>
    <div class="feat">
      <div class="feat-icon"><svg viewBox="0 0 24 24"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg></div>
      <h3>Usage Analytics</h3>
      <p>Track requests, response times, and provider stats. Per-key analytics so you know exactly what's running.</p>
    </div>
    <div class="feat">
      <div class="feat-icon"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg></div>
      <h3>Multi-Modal</h3>
      <p>Not just chat — image generation and text-to-speech built in. All through the same unified key.</p>
    </div>
    <div class="feat">
      <div class="feat-icon"><svg viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg></div>
      <h3>OpenAI Compatible</h3>
      <p>Drop-in replacement for the OpenAI SDK. Change your base URL and start building — no code rewrites.</p>
    </div>
  </div>
</section>

<!-- Get started steps -->
<section class="section" id="get-started">
  <div style="text-align:center;margin-bottom:0">
    <div class="sec-label">Quickstart</div>
    <h2 class="sec-title">Get started in minutes</h2>
    <p class="sec-sub" style="margin:0 auto">Drop-in OpenAI SDK compatibility. Change your base URL and start building.</p>
  </div>
  <div class="steps">
    <div class="step">
      <div class="step-num">Step 01</div>
      <h3>Create your account</h3>
      <p style="color:var(--sub);font-size:13.5px;line-height:1.6">Sign up and your API key is generated instantly. No credit card required.</p>
      <div class="step-code">DZECKAPI_KEY=<span style="color:#ffa657">"sk-dzcx-..."</span></div>
    </div>
    <div class="step">
      <div class="step-num">Step 02</div>
      <h3>Point your SDK at DzeckAPI</h3>
      <p style="color:var(--sub);font-size:13.5px;line-height:1.6">Use your existing OpenAI client. Just change the base URL.</p>
      <div class="step-code"><span style="color:#d2a8ff">client</span> = <span style="color:#d2a8ff">OpenAI</span>(<br/>  base_url=<span style="color:#a5d6ff">"…/v1"</span>,<br/>  api_key=DZECKAPI_KEY<br/>)</div>
    </div>
    <div class="step">
      <div class="step-num">Step 03</div>
      <h3>Access any model</h3>
      <p style="color:var(--sub);font-size:13.5px;line-height:1.6">Switch between providers with a single parameter. No separate SDKs.</p>
      <div class="step-code"><span style="color:#6e7681"># Qwen · coding &amp; math</span><br/>model=<span style="color:#a5d6ff">"qwen-3-235b-a22b-instruct-2507"</span><br/><span style="color:#6e7681"># Llama · instruction</span><br/>model=<span style="color:#a5d6ff">"meta-llama/Llama-3.3-70B-Instruct"</span><br/><span style="color:#6e7681"># GPT-OSS · general</span><br/>model=<span style="color:#a5d6ff">"gpt-oss-120b"</span></div>
    </div>
  </div>
</section>

<!-- CTA -->
<section class="section">
  <div class="cta-section">
    <h2>Ready to build with AI?</h2>
    <p>One API key. Every major model. Start building in under 2 minutes.</p>
    <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
      <button id="cta-bottom-btn" class="btn-hero-primary" onclick="openModal('register')">Start Building Free →</button>
      <a href="/dashboard" class="btn-hero-secondary">View Documentation</a>
    </div>
    <p id="cta-meta-text" class="cta-meta">Free to use · No credit card required · OpenAI SDK compatible</p>
  </div>
</section>

<!-- Footer -->
<footer>
  <p>© 2025 DzeckAPI — AI Gateway &nbsp;·&nbsp; <a href="/dashboard">Documentation</a> &nbsp;·&nbsp; <a id="footer-auth-link" href="#" onclick="openModal('login');return false">Login</a></p>
</footer>

<script>
function showCode(lang, btn) {{
  document.querySelectorAll('.code-body').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.code-tab').forEach(el => el.classList.remove('active'));
  document.getElementById('code-' + lang).style.display = 'block';
  btn.classList.add('active');
}}

function openModal(tab) {{
  document.getElementById('auth-overlay').classList.add('open');
  switchTab(tab);
  document.body.style.overflow = 'hidden';
}}
function closeModal() {{
  document.getElementById('auth-overlay').classList.remove('open');
  document.body.style.overflow = '';
}}
function overlayClick(e) {{
  if (e.target === document.getElementById('auth-overlay')) closeModal();
}}
function switchTab(t) {{
  document.getElementById('form-login').style.display = t === 'login' ? '' : 'none';
  document.getElementById('form-register').style.display = t === 'register' ? '' : 'none';
  document.getElementById('tab-login').classList.toggle('active', t === 'login');
  document.getElementById('tab-register').classList.toggle('active', t === 'register');
  document.getElementById('modal-title').textContent = t === 'login' ? 'Sign in' : 'Create account';
  document.getElementById('modal-sub').textContent = t === 'login' ? 'Access all AI models with your API key' : 'Get your free API key instantly';
}}

async function doLogin() {{
  const email = document.getElementById('l-email').value.trim();
  const pass  = document.getElementById('l-pass').value;
  const errEl = document.getElementById('l-err');
  errEl.style.display = 'none';
  if (!email || !pass) {{ errEl.textContent = 'Please fill in all fields.'; errEl.style.display = 'block'; return; }}
  try {{
    const r = await fetch('/auth/login', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{email, password:pass}}) }});
    const d = await r.json();
    if (!r.ok) {{ errEl.textContent = d.error || 'Login failed.'; errEl.style.display = 'block'; return; }}
    localStorage.setItem('dzeck_api_key', d.api_key);
    localStorage.setItem('dzeck_username', d.username);
    closeModal();
    window.location.href = '/dashboard';
  }} catch(e) {{ errEl.textContent = 'Network error.'; errEl.style.display = 'block'; }}
}}

async function doRegister() {{
  const user  = document.getElementById('r-user').value.trim();
  const email = document.getElementById('r-email').value.trim();
  const pass  = document.getElementById('r-pass').value;
  const errEl = document.getElementById('r-err');
  errEl.style.display = 'none';
  if (!user || !email || !pass) {{ errEl.textContent = 'Please fill in all fields.'; errEl.style.display = 'block'; return; }}
  if (pass.length < 8) {{ errEl.textContent = 'Password must be at least 8 characters.'; errEl.style.display = 'block'; return; }}
  try {{
    const r = await fetch('/auth/register', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{username:user, email, password:pass}}) }});
    const d = await r.json();
    if (!r.ok) {{ errEl.textContent = d.error || 'Registration failed.'; errEl.style.display = 'block'; return; }}
    localStorage.setItem('dzeck_api_key', d.api_key);
    localStorage.setItem('dzeck_username', d.username);
    closeModal();
    window.location.href = '/dashboard';
  }} catch(e) {{ errEl.textContent = 'Network error.'; errEl.style.display = 'block'; }}
}}

document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeModal(); }});

// ── Auto-detect base URL ──
(function fillBaseUrl() {{
  const origin = window.location.origin;
  document.querySelectorAll('.landing-base-url').forEach(el => {{ el.textContent = origin; }});
}})();

// ── Cek sesi yang sudah ada saat halaman load ──
(function checkExistingSession() {{
  const savedKey  = localStorage.getItem('dzeck_api_key');
  const savedUser = localStorage.getItem('dzeck_username');
  if (!savedKey) return;
  // Ganti tombol nav
  const navCta = document.querySelector('.nav-cta');
  if (navCta) {{
    navCta.innerHTML = '<a href="/dashboard" class="btn-primary" style="text-decoration:none;display:inline-flex;align-items:center;gap:6px">'
      + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>'
      + 'Dashboard</a>';
  }}
  // Ganti hero CTA utama (hero section)
  const heroBtn = document.querySelector('.btn-hero-primary');
  if (heroBtn) {{
    heroBtn.textContent = 'Go to Dashboard';
    heroBtn.onclick = function() {{ window.location.href = '/dashboard'; }};
  }}
  // Ganti tombol CTA bawah
  const ctaBtn = document.getElementById('cta-bottom-btn');
  if (ctaBtn) {{
    ctaBtn.textContent = 'Go to Dashboard →';
    ctaBtn.onclick = function() {{ window.location.href = '/dashboard'; }};
  }}
  const ctaMeta = document.getElementById('cta-meta-text');
  if (ctaMeta) ctaMeta.style.display = 'none';
  // Ganti link Login di footer
  const footerLink = document.getElementById('footer-auth-link');
  if (footerLink) {{
    footerLink.textContent = 'Dashboard';
    footerLink.href = '/dashboard';
    footerLink.onclick = null;
  }}
}})();
</script>
</body>
</html>"""


# ── Documentation UI ──────────────────────────────────────────────────────────

def build_docs_html():
    # Provider rows — hanya tampilkan t1 (sembunyikan t2 sebagai detail internal)
    _chat_public = [(k, v) for k, v in CHAT_PROVIDERS.items() if not v.get("is_t2")]
    chat_provider_rows = "".join(
        f'<div class="prov-row"><span class="prov-dot"></span>'
        f'<span class="prov-name">{_public_label(k)}</span>'
        f'<span class="prov-desc">{v.get("desc","").split(" —")[0]}</span></div>'
        for k, v in _chat_public
    )
    image_provider_rows = "".join(
        f'<div class="prov-row"><span class="prov-dot"></span>'
        f'<span class="prov-name">{_public_label(k)}</span>'
        f'<span class="prov-desc">{v.get("desc","").split(" —")[0]}</span></div>'
        for k, v in IMAGE_PROVIDERS.items()
    )
    audio_provider_rows = "".join(
        f'<div class="prov-row"><span class="prov-dot"></span>'
        f'<span class="prov-name">{_public_label(k)}</span>'
        f'<span class="prov-desc">{v.get("desc","").split(" —")[0]}</span></div>'
        for k, v in AUDIO_PROVIDERS.items()
    )
    _n_chat_public = len(_chat_public)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="description" content="DzeckAPI dashboard — manage your API key, explore endpoints, and access every major AI model through one unified gateway."/>
<title>DzeckAPI — AI Gateway</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#1a1917;--surface:#242220;--surface2:#2c2a28;--surface3:#343230;
  --border:#3a3734;--border-hi:#4e4a46;
  --text:#f5f5f5;--sub:#b8b0a8;--muted:#7a7570;--muted2:#55514e;
  --accent:#d97757;--accent-dim:rgba(217,119,87,.12);--accent-border:rgba(217,119,87,.3);
  --danger:#c0604a;--danger-dim:rgba(192,96,74,.1);--danger-border:rgba(192,96,74,.25);
  --mono:'JetBrains Mono','Fira Code','Menlo',monospace;
  --r:10px;--r-sm:8px;--r-xs:6px;
}}
body{{background:var(--bg);color:var(--text);font-family:'Inter','Anthropic Sans','Helvetica Neue',system-ui,sans-serif;font-size:14px;line-height:1.6;min-height:100vh;-webkit-font-smoothing:antialiased}}
::-webkit-scrollbar{{width:4px;height:4px}}
::-webkit-scrollbar-track{{background:transparent}}
::-webkit-scrollbar-thumb{{background:var(--border-hi);border-radius:4px}}

/* ── Header ── */
header{{border-bottom:1px solid var(--border);padding:0 32px;height:54px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:rgba(26,25,23,.92);backdrop-filter:blur(18px);z-index:100}}
.logo{{font-size:14px;font-weight:600;letter-spacing:-.3px;color:var(--text);display:flex;align-items:center;gap:9px}}
.logo-icon{{width:32px;height:32px;display:flex;align-items:center;justify-content:center;flex-shrink:0}}
.header-right{{display:flex;align-items:center;gap:8px}}

/* ── Auth buttons ── */
.auth-btn{{background:var(--surface);border:1px solid var(--border-hi);color:var(--text);padding:6px 16px;border-radius:var(--r-sm);font-size:12.5px;font-weight:500;cursor:pointer;transition:all .15s;font-family:inherit}}
.auth-btn:hover{{background:var(--surface2);border-color:var(--muted)}}
.auth-user{{display:flex;align-items:center;gap:9px}}
.auth-avatar{{width:26px;height:26px;border-radius:99px;background:var(--surface3);border:1px solid var(--border-hi);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--text);flex-shrink:0}}
.auth-uname{{font-size:13px;font-weight:500;color:var(--sub)}}
.auth-logout{{background:none;border:1px solid var(--border);color:var(--muted);padding:5px 12px;border-radius:var(--r-sm);font-size:12px;cursor:pointer;font-family:inherit;transition:all .15s}}
.auth-logout:hover{{color:var(--text);border-color:var(--border-hi)}}

/* ── Auth Modal ── */
.overlay{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(6px);z-index:200;align-items:center;justify-content:center}}
.overlay.open{{display:flex}}
.modal{{background:var(--surface);border:1px solid var(--border-hi);border-radius:16px;width:100%;max-width:380px;margin:16px;padding:28px 26px 24px;position:relative;box-shadow:0 32px 80px rgba(0,0,0,.5)}}
.modal-close{{position:absolute;top:14px;right:16px;background:none;border:none;color:var(--muted);font-size:16px;cursor:pointer;font-family:inherit;width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;transition:all .15s}}
.modal-close:hover{{background:var(--surface2);color:var(--text)}}
.modal h2{{font-size:17px;font-weight:700;margin-bottom:3px;letter-spacing:-.4px;color:var(--text)}}
.modal .sub{{color:var(--muted);font-size:12.5px;margin-bottom:22px}}
.tab-row{{display:flex;gap:3px;margin-bottom:20px;background:var(--surface2);border-radius:var(--r-sm);padding:3px;border:1px solid var(--border)}}
.tab{{flex:1;padding:6px;border-radius:6px;border:none;background:none;color:var(--muted);font-size:12.5px;font-weight:500;cursor:pointer;transition:all .15s;font-family:inherit}}
.tab.active{{background:var(--surface3);color:var(--text);box-shadow:0 1px 4px rgba(0,0,0,.35)}}
.modal .btn{{width:100%;justify-content:center;margin-top:6px}}
.modal-err{{color:var(--danger);font-size:12px;margin-top:10px;display:none;padding:9px 12px;background:var(--danger-dim);border:1px solid var(--danger-border);border-radius:var(--r-xs)}}

/* ── Layout ── */
.wrap{{max-width:780px;margin:0 auto;padding:48px 24px 100px}}

/* ── Hero ── */
.hero{{margin-bottom:36px;padding-bottom:32px;border-bottom:1px solid var(--border)}}
.hero h1{{font-size:26px;font-weight:700;letter-spacing:-.7px;line-height:1.2;color:var(--text)}}
.hero-sub{{color:var(--sub);font-size:13.5px;margin-top:7px;max-width:440px;line-height:1.65}}
.stats{{display:flex;margin-top:24px;border:1px solid var(--border);border-radius:var(--r);overflow:hidden;background:var(--surface)}}
.stat{{flex:1;padding:16px 20px;border-right:1px solid var(--border)}}
.stat:last-child{{border-right:none}}
.stat-n{{font-size:22px;font-weight:700;color:var(--text);letter-spacing:-.6px;line-height:1}}
.stat-l{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.9px;margin-top:5px}}

/* ── Credential boxes ── */
.cred-grid{{display:flex;flex-direction:column;gap:8px;margin-bottom:28px}}
.cred-box{{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:13px 16px;display:flex;align-items:center;gap:10px}}
.cred-box.key-box{{background:var(--surface2)}}
.cred-label{{font-size:10px;font-weight:600;letter-spacing:1.1px;text-transform:uppercase;color:var(--muted);white-space:nowrap;min-width:62px}}
.cred-val{{font-family:var(--mono);font-size:12px;color:var(--sub);background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:5px 10px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.cred-actions{{display:flex;gap:5px;flex-shrink:0}}
.cred-actions button,.copy-btn{{background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--sub);font-size:11px;padding:4px 10px;cursor:pointer;white-space:nowrap;transition:all .15s;font-family:inherit;font-weight:500}}
.cred-actions button:hover,.copy-btn:hover{{color:var(--text);border-color:var(--border-hi);background:var(--surface2)}}

/* ── Lock notice ── */
.lock-notice{{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:12px 16px;font-size:12.5px;color:var(--sub);display:none;align-items:center;gap:12px;flex-wrap:wrap}}
.lock-notice span{{flex:1}}

/* ── Section heading ── */
.sec-head{{display:flex;align-items:center;gap:10px;margin:32px 0 12px}}
.sec-title{{font-size:10.5px;font-weight:600;letter-spacing:1.1px;text-transform:uppercase;color:var(--muted)}}
.sec-line{{flex:1;height:1px;background:var(--border)}}

/* ── Endpoint cards ── */
.card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;margin-bottom:6px;transition:border-color .2s,box-shadow .2s}}
.card:has(.card-body.open){{border-color:var(--border-hi);box-shadow:0 2px 12px rgba(0,0,0,.06)}}
.card-head{{display:flex;align-items:center;gap:10px;padding:13px 16px;cursor:pointer;user-select:none;transition:background .12s}}
.card-head:hover{{background:var(--surface2)}}
.chevron{{margin-left:auto;color:var(--muted);font-size:11px;transition:transform .2s;flex-shrink:0;line-height:1}}
.card:has(.card-body.open) .chevron{{transform:rotate(180deg);color:var(--sub)}}
.card-body{{border-top:1px solid var(--border);padding:20px 18px;display:none;background:var(--bg)}}
.card-body.open{{display:block}}

.mth{{font-size:9.5px;font-weight:700;letter-spacing:.5px;padding:3px 8px;border-radius:4px;min-width:40px;text-align:center;flex-shrink:0;border:1px solid var(--border);background:var(--surface2);color:var(--sub)}}
.ep{{font-family:var(--mono);font-size:12.5px;color:var(--text);font-weight:500}}
.badge{{margin-left:7px;font-size:10px;font-weight:500;padding:2px 8px;border-radius:99px;vertical-align:middle;border:1px solid var(--border);color:var(--muted);background:var(--surface2)}}
.ep-meta{{color:var(--muted);font-size:11.5px;margin-left:auto;flex-shrink:0}}
.curl-btn{{margin-left:8px;padding:3px 10px;font-size:11px;font-weight:500;background:var(--surface2);border:1px solid var(--border);color:var(--sub);border-radius:var(--r-xs);cursor:pointer;font-family:var(--mono);letter-spacing:.3px;transition:all .15s;flex-shrink:0;line-height:1.6}}
.curl-btn:hover{{background:var(--surface3);border-color:var(--border-hi);color:var(--text)}}
.curl-btn.copied{{border-color:var(--accent);color:var(--accent)}}

/* ── Form ── */
.url-bar{{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:9px 13px;font-family:var(--mono);font-size:11.5px;color:var(--muted);margin-bottom:18px;display:flex;align-items:center;gap:9px;overflow:hidden}}
.url-bar .mth{{font-size:9px;padding:2px 6px}}
.url-bar .url-text{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.field{{margin-bottom:13px}}
label{{display:block;font-size:11.5px;color:var(--sub);margin-bottom:5px;font-weight:500}}
label .req{{color:var(--muted);margin-left:2px}}
label .opt{{color:var(--muted2);font-weight:400;font-size:11px}}
input,select,textarea{{width:100%;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-sm);padding:9px 12px;color:var(--text);font-family:inherit;font-size:13px;outline:none;transition:border-color .15s,box-shadow .15s}}
input:focus,select:focus,textarea:focus{{border-color:var(--accent-border);box-shadow:0 0 0 3px var(--accent-dim)}}
input::placeholder,textarea::placeholder{{color:var(--muted2)}}
textarea{{resize:vertical;min-height:72px;line-height:1.55}}
select option{{background:var(--surface)}}
.row{{display:flex;gap:10px}}.row .field{{flex:1}}
.form-actions{{margin-top:6px}}
.btn{{background:var(--accent);color:#fff;border:none;padding:9px 20px;border-radius:var(--r-sm);font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s,transform .08s;display:inline-flex;align-items:center;gap:8px;font-family:inherit}}
.btn:hover{{opacity:.88}}.btn:active{{transform:scale(.98)}}.btn:disabled{{opacity:.35;cursor:not-allowed}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.spin{{width:12px;height:12px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .55s linear infinite;display:none;flex-shrink:0}}

/* ── Response ── */
.res-wrap{{margin-top:16px}}
.res-header{{display:flex;align-items:center;gap:8px;margin-bottom:8px}}
.res-label{{font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--muted)}}
.status-pill{{font-size:11px;padding:2px 9px;border-radius:99px;font-weight:600;border:1px solid var(--border);color:var(--sub);background:var(--surface2)}}
.ok{{border-color:var(--border-hi);color:var(--text)}}
.err{{border-color:var(--danger-border);color:var(--danger);background:var(--danger-dim)}}
.res-meta{{font-size:11px;color:var(--muted);display:flex;flex-direction:column;gap:2px;margin-bottom:8px}}
.res-meta span{{font-family:var(--mono)}}
.res-box{{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-sm);padding:13px;font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto;color:var(--sub);display:none;line-height:1.6}}
.res-box.v{{display:block}}
.img-out{{margin-top:13px;max-width:100%;border-radius:var(--r-sm);border:1px solid var(--border);display:none}}

/* ── Providers ── */
.prov-table{{display:flex;flex-direction:column;border-radius:var(--r);overflow:hidden;border:1px solid var(--border)}}
.prov-row{{display:flex;align-items:center;gap:12px;padding:10px 16px;background:var(--surface);border-bottom:1px solid var(--border);transition:background .1s}}
.prov-row:last-child{{border-bottom:none}}
.prov-row:hover{{background:var(--surface2)}}
.prov-dot{{width:5px;height:5px;border-radius:50%;background:var(--border-hi);flex-shrink:0}}
.prov-name{{font-family:var(--mono);font-size:11.5px;color:var(--sub);min-width:150px;flex-shrink:0}}
.prov-desc{{font-size:12px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.prov-sub-head{{font-size:10px;font-weight:600;letter-spacing:.9px;text-transform:uppercase;color:var(--muted);padding:10px 16px 7px;background:var(--surface2);border-bottom:1px solid var(--border)}}

code{{background:var(--surface2);padding:1px 6px;border-radius:4px;font-family:var(--mono);font-size:12px;color:var(--sub);border:1px solid var(--border)}}

@media(max-width:600px){{
  header{{padding:0 14px}}
  .header-center{{gap:4px}}
  .hpill{{font-size:10px;padding:2px 8px}}
  .wrap{{padding:28px 14px 72px}}
  .hero h1{{font-size:21px}}
  .ep-meta,.prov-desc{{display:none}}
  .prov-name{{min-width:unset}}
  .stats{{flex-direction:row}}
  .stat{{padding:12px 14px}}
  .stat-n{{font-size:18px}}
  .cred-box{{flex-wrap:wrap}}
  .cred-val{{min-width:0;width:100%;order:3}}
  .cred-label{{order:1}}.cred-actions{{order:2}}
}}
</style>
</head>
<body>

<!-- Auth Modal -->
<div class="overlay" id="auth-overlay" onclick="overlayClick(event)">
  <div class="modal">
    <button class="modal-close" onclick="closeModal()">✕</button>
    <h2 id="modal-title">Sign in</h2>
    <p class="sub" id="modal-sub">Access all endpoints with your API key</p>
    <div class="tab-row">
      <button class="tab active" id="tab-login" onclick="switchTab('login')">Login</button>
      <button class="tab" id="tab-register" onclick="switchTab('register')">Register</button>
    </div>
    <div id="form-login">
      <div class="field"><label>Email or username</label><input id="m-email" placeholder="you@example.com" autocomplete="email"/></div>
      <div class="field"><label>Password</label><input id="m-pass" type="password" placeholder="••••••••" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()"/></div>
      <button class="btn" onclick="doLogin()"><span>Sign in</span><div class="spin" id="sp-login"></div></button>
    </div>
    <div id="form-register" style="display:none">
      <div class="field"><label>Username</label><input id="m-uname" placeholder="username" autocomplete="username"/></div>
      <div class="field"><label>Email</label><input id="m-remail" placeholder="you@example.com" autocomplete="email"/></div>
      <div class="field"><label>Password <span style="color:var(--muted2);font-size:11px">— min. 6 chars</span></label><input id="m-rpass" type="password" placeholder="••••••••" autocomplete="new-password" onkeydown="if(event.key==='Enter')doRegister()"/></div>
      <button class="btn" onclick="doRegister()"><span>Create account</span><div class="spin" id="sp-reg"></div></button>
    </div>
    <div class="modal-err" id="modal-err"></div>
  </div>
</div>

<header>
  <div class="logo">
    <div class="logo-icon">
      <svg width="34" height="30" viewBox="-2 0 32 30" fill="none" xmlns="http://www.w3.org/2000/svg" overflow="visible">
        <defs>
          <linearGradient id="lg" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#e8956d"/>
            <stop offset="100%" stop-color="#c0604a"/>
          </linearGradient>
        </defs>
        <!-- Cloud -->
        <path d="M3 23 a6 6 0 0 1 0-12 a3.8 3.8 0 0 1 7-1 a5 5 0 1 1 1 13Z"
          stroke="url(#lg)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
        <!-- Hub circle -->
        <circle cx="20" cy="12" r="3" stroke="#d97757" stroke-width="2"/>
        <circle cx="20" cy="12" r="1.1" fill="#d97757"/>
        <!-- Sweep line up -->
        <line x1="20" y1="12" x2="20" y2="6" stroke="#e8956d" stroke-width="1.8" stroke-linecap="round"/>
        <!-- Top-left node -->
        <line x1="17.8" y1="9.8" x2="13" y2="6" stroke="#d97757" stroke-width="1.6" stroke-linecap="round"/>
        <circle cx="13" cy="6" r="1.9" stroke="#d97757" stroke-width="1.6"/>
        <!-- Top-right node -->
        <line x1="22.5" y1="9.8" x2="27" y2="6" stroke="#e8956d" stroke-width="1.6" stroke-linecap="round"/>
        <circle cx="27" cy="6" r="1.9" stroke="#e8956d" stroke-width="1.6"/>
        <!-- Right-mid node -->
        <line x1="22.8" y1="13.5" x2="27" y2="16.5" stroke="#d97757" stroke-width="1.6" stroke-linecap="round"/>
        <circle cx="27" cy="16.5" r="1.9" stroke="#d97757" stroke-width="1.6"/>
      </svg>
    </div>
    <span class="logo-name">DzeckAPI</span>
  </div>
  <div class="header-right">
    <div id="auth-header-guest">
      <button class="auth-btn" onclick="openModal()">Sign in</button>
    </div>
    <div class="auth-user" id="auth-header-user" style="display:none">
      <div class="auth-avatar" id="auth-avatar-letter">U</div>
      <span class="auth-uname" id="auth-uname-label"></span>
      <button class="auth-logout" onclick="doLogout()">Sign out</button>
    </div>
  </div>
</header>

<div class="wrap">

  <div class="hero">
    <div class="hero-top">
      <div>
        <h1>AI Gateway</h1>
        <p class="hero-sub">Production-grade AI infrastructure with intelligent multi-provider orchestration, automatic failover, and full OpenAI API compatibility.</p>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-n">{_n_chat_public}</div><div class="stat-l">Chat Models</div></div>
      <div class="stat"><div class="stat-n">{len(IMAGE_PROVIDERS)}</div><div class="stat-l">Image Models</div></div>
      <div class="stat"><div class="stat-n">{len(AUDIO_PROVIDERS)}</div><div class="stat-l">Audio Models</div></div>
    </div>
  </div>

  <div class="cred-grid">
    <div class="cred-box">
      <span class="cred-label">Base URL</span>
      <span class="cred-val" id="base-url-val">—</span>
      <div class="cred-actions"><button id="copy-base-btn" onclick="copyBase()">Copy</button></div>
    </div>
    <div class="lock-notice" id="lock-notice">
      <span>Authentication required — sign in to get your API key.</span>
      <button class="auth-btn" style="font-size:12px;padding:4px 12px" onclick="openModal()">Sign in</button>
    </div>
    <div class="cred-box key-box" id="apikey-bar" style="display:none">
      <span class="cred-label purple">API Key</span>
      <span class="cred-val" id="apikey-display"></span>
      <div class="cred-actions">
        <button id="copy-key-btn" onclick="copyApiKey()">Copy</button>
        <button onclick="doRegenKey()">Regenerate</button>
      </div>
    </div>
  </div>

  <div class="sec-head"><span class="sec-title">Endpoints</span><span class="sec-line"></span></div>

  <!-- POST /v1/chat/completions -->
  <div class="card">
    <div class="card-head" onclick="toggle(this)">
      <span class="mth post">POST</span>
      <span class="ep">/v1/chat/completions<span class="badge">OpenAI Compatible</span></span>
      <span class="ep-meta">Chat · Tools · Memory</span>
      <button class="curl-btn" onclick="event.stopPropagation();copyCurlV1(this)">curl</button>
      <span class="chevron">▾</span>
    </div>
    <div class="card-body">
      <div class="url-bar"><span class="mth post">POST</span><span class="url-text base-url-span"></span><span style="color:var(--muted)">/v1/chat/completions</span></div>
      <div class="field">
        <label>Message<span class="req">*</span></label>
        <textarea id="v1-prompt" placeholder="Enter your message..."></textarea>
      </div>
      <div class="field">
        <label>System prompt <span class="opt">optional</span></label>
        <input id="v1-system" placeholder="You are a helpful assistant."/>
      </div>
      <div class="row">
        <div class="field">
          <label>Conversation ID <span class="opt">optional — for multi-turn</span></label>
          <input id="v1-conv-id" placeholder="Leave blank to start new"/>
        </div>
      </div>
      <div class="field">
        <label>Model <span class="opt">optional — leave blank for auto routing</span></label>
        <select id="v1-model" style="background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:var(--r-xs);padding:8px 10px;width:100%;font-size:13px;font-family:inherit">
          <option value="">Auto (smart routing by intent)</option>
          {''.join(f'<option value="{k}">{_public_label(k)} — {v["desc"].split(" — ")[0] if " — " in v["desc"] else v["desc"]}</option>' for k, v in CHAT_PROVIDERS.items() if not v.get("is_t2"))}
        </select>
      </div>
      <div class="field">
        <label>Tools <span class="opt">optional — JSON array</span></label>
        <textarea id="v1-tools" style="min-height:76px;font-family:var(--mono);font-size:12px" placeholder='[{{"type":"function","function":{{"name":"get_weather","description":"Get weather","parameters":{{"type":"object","properties":{{"location":{{"type":"string"}}}},"required":["location"]}}}}}}]'></textarea>
      </div>
      <div class="form-actions">
        <button class="btn" onclick="execV1()"><span>Send Request</span><div class="spin" id="sp-v1"></div></button>
      </div>
      <div class="res-wrap" id="wr-v1"></div>
    </div>
  </div>

  <!-- POST /image -->
  <div class="card">
    <div class="card-head" onclick="toggle(this)">
      <span class="mth post">POST</span>
      <span class="ep">/image</span>
      <span class="ep-meta">Image Generation</span>
      <button class="curl-btn" onclick="event.stopPropagation();copyCurlImage(this)">curl</button>
      <span class="chevron">▾</span>
    </div>
    <div class="card-body">
      <div class="url-bar"><span class="mth post">POST</span><span class="url-text base-url-span"></span><span style="color:var(--muted)">/image</span></div>
      <div class="field">
        <label>Prompt<span class="req">*</span></label>
        <textarea id="au-img-p" placeholder="Describe the image you want to generate..."></textarea>
      </div>
      <div class="field">
        <label>Model <span class="opt">optional — leave blank for auto fallback</span></label>
        <select id="au-img-model" style="background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:var(--r-xs);padding:8px 10px;width:100%;font-size:13px;font-family:inherit">
          <option value="">Auto (hf-flux-schnell → hf-flux-dev → hf-sdxl → pollinations)</option>
          {''.join(f'<option value="{k}">{_public_label(k)} — {v["desc"].split(" (")[0]}</option>' for k, v in IMAGE_PROVIDERS.items())}
        </select>
      </div>
      <div class="row">
        <div class="field"><label>Width</label><input id="au-img-w" type="number" value="1024"/></div>
        <div class="field"><label>Height</label><input id="au-img-h" type="number" value="1024"/></div>
      </div>
      <div class="form-actions">
        <button class="btn" onclick="execAutoImage()"><span>Generate</span><div class="spin" id="sp-au-img"></div></button>
      </div>
      <div class="res-wrap" id="wr-au-img"></div>
      <img id="img-au-out" class="img-out" style="display:none;max-width:100%;border-radius:var(--r);margin-top:12px"/>
    </div>
  </div>

  <!-- POST /audio -->
  <div class="card">
    <div class="card-head" onclick="toggle(this)">
      <span class="mth post">POST</span>
      <span class="ep">/audio</span>
      <span class="ep-meta">Text to Speech</span>
      <button class="curl-btn" onclick="event.stopPropagation();copyCurlAudio(this)">curl</button>
      <span class="chevron">▾</span>
    </div>
    <div class="card-body">
      <div class="url-bar"><span class="mth post">POST</span><span class="url-text base-url-span"></span><span style="color:var(--muted)">/audio</span></div>
      <div class="field">
        <label>Text<span class="req">*</span></label>
        <textarea id="au-aud-text" placeholder="Enter text to convert to speech..."></textarea>
      </div>
      <div class="field">
        <label>Model <span class="opt">optional — leave blank for auto-detect</span></label>
        <select id="au-aud-model" style="background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:var(--r-xs);padding:8px 10px;width:100%;font-size:13px;font-family:inherit">
          <option value="">Auto-detect (bahasa dari teks)</option>
          {''.join(f'<option value="{k}">{_public_label(k)} — {v["desc"].split(" (")[0]}</option>' for k, v in AUDIO_PROVIDERS.items())}
        </select>
      </div>
      <div class="form-actions">
        <button class="btn" onclick="execAutoAudio()"><span>Generate Audio</span><div class="spin" id="sp-au-aud"></div></button>
      </div>
      <div class="res-wrap" id="wr-au-aud"></div>
      <audio id="audio-au-out" controls style="display:none;width:100%;margin-top:12px;border-radius:var(--r-xs)"></audio>
    </div>
  </div>

  <div class="sec-head" style="margin-top:36px"><span class="sec-title">Providers</span><span class="sec-line"></span></div>

  <div class="prov-table">
    <div class="prov-sub-head">Chat — {len(CHAT_PROVIDERS)} active</div>
    {chat_provider_rows}
    <div class="prov-sub-head">Image</div>
    {image_provider_rows}
    <div class="prov-sub-head">Audio</div>
    {audio_provider_rows}
  </div>

</div>

<script>
const BASE = window.location.origin;
document.getElementById('base-url-val').textContent = BASE;
document.querySelectorAll('.base-url-span').forEach(el => el.textContent = BASE);

// ── Auth state ──
let _apiKey = localStorage.getItem('dzeck_api_key') || '';
let _username = localStorage.getItem('dzeck_username') || '';

function authHeaders() {{
  const h = {{'Content-Type': 'application/json'}};
  if (_apiKey) h['Authorization'] = 'Bearer ' + _apiKey;
  return h;
}}
function setSession(k, u) {{
  _apiKey = k; _username = u;
  localStorage.setItem('dzeck_api_key', k);
  localStorage.setItem('dzeck_username', u);
  renderAuthState();
}}
function clearSession() {{
  _apiKey = ''; _username = '';
  localStorage.removeItem('dzeck_api_key');
  localStorage.removeItem('dzeck_username');
  renderAuthState();
}}
function renderAuthState() {{
  const in_ = !!_apiKey;
  document.getElementById('auth-header-guest').style.display = in_ ? 'none' : 'block';
  document.getElementById('auth-header-user').style.display  = in_ ? 'flex' : 'none';
  if (in_) {{
    document.getElementById('auth-uname-label').textContent = _username;
    const av = document.getElementById('auth-avatar-letter');
    if (av) av.textContent = _username.charAt(0).toUpperCase();
  }}
  const bar = document.getElementById('apikey-bar');
  const notice = document.getElementById('lock-notice');
  if (in_) {{
    bar.style.display = 'flex'; notice.style.display = 'none';
    document.getElementById('apikey-display').textContent = _apiKey;
  }} else {{
    bar.style.display = 'none'; notice.style.display = 'flex';
  }}
}}
renderAuthState();

// ── Modal ──
function openModal() {{
  document.getElementById('auth-overlay').classList.add('open');
  document.getElementById('modal-err').style.display = 'none';
}}
function closeModal() {{ document.getElementById('auth-overlay').classList.remove('open'); }}
function overlayClick(e) {{ if (e.target === document.getElementById('auth-overlay')) closeModal(); }}
function switchTab(t) {{
  const isL = t === 'login';
  document.getElementById('form-login').style.display    = isL ? 'block' : 'none';
  document.getElementById('form-register').style.display = isL ? 'none' : 'block';
  document.getElementById('tab-login').classList.toggle('active', isL);
  document.getElementById('tab-register').classList.toggle('active', !isL);
  document.getElementById('modal-title').textContent = isL ? 'Masuk' : 'Buat Akun';
  document.getElementById('modal-err').style.display = 'none';
}}
function showModalErr(msg) {{
  const el = document.getElementById('modal-err');
  el.textContent = msg; el.style.display = 'block';
}}
async function doLogin() {{
  const email = document.getElementById('m-email').value.trim();
  const pass  = document.getElementById('m-pass').value;
  if (!email || !pass) {{ showModalErr('Email dan password wajib diisi'); return; }}
  document.getElementById('sp-login').style.display = 'inline-block';
  try {{
    const r = await fetch('/auth/login', {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email,password:pass}})}});
    const d = await r.json();
    document.getElementById('sp-login').style.display = 'none';
    if (!r.ok) {{ showModalErr(d.error || 'Login gagal'); return; }}
    setSession(d.api_key, d.username); closeModal();
  }} catch(e) {{ document.getElementById('sp-login').style.display='none'; showModalErr('Gagal terhubung'); }}
}}
async function doRegister() {{
  const uname = document.getElementById('m-uname').value.trim();
  const email = document.getElementById('m-remail').value.trim();
  const pass  = document.getElementById('m-rpass').value;
  if (!uname||!email||!pass) {{ showModalErr('Semua field wajib diisi'); return; }}
  document.getElementById('sp-reg').style.display = 'inline-block';
  try {{
    const r = await fetch('/auth/register', {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:uname,email,password:pass}})}});
    const d = await r.json();
    document.getElementById('sp-reg').style.display = 'none';
    if (!r.ok) {{ showModalErr(d.error || 'Registrasi gagal'); return; }}
    setSession(d.api_key, d.username); closeModal();
  }} catch(e) {{ document.getElementById('sp-reg').style.display='none'; showModalErr('Gagal terhubung'); }}
}}
function doLogout() {{ clearSession(); }}

// ── API Key actions ──
function copyApiKey() {{
  navigator.clipboard.writeText(_apiKey).then(() => {{
    const b = document.getElementById('copy-key-btn');
    b.textContent = 'Copied!'; setTimeout(()=>b.textContent='Copy', 1800);
  }});
}}
async function doRegenKey() {{
  if (!confirm('Regenerate API key? Key lama akan langsung tidak berlaku.')) return;
  try {{
    const r = await fetch('/auth/regenerate-key', {{method:'POST',headers:authHeaders()}});
    const d = await r.json();
    if (r.ok) {{
      _apiKey = d.api_key;
      localStorage.setItem('api_key', _apiKey);
      document.getElementById('apikey-display').textContent = _apiKey;
    }}
  }} catch(e) {{ alert('Gagal regenerate key'); }}
}}
function copyBase() {{
  navigator.clipboard.writeText(BASE).then(() => {{
    const b = document.getElementById('copy-base-btn');
    b.textContent = 'Copied!'; setTimeout(()=>b.textContent='Copy', 1800);
  }});
}}

// ── Copy cURL helpers ──
function _flashCurl(btn) {{
  btn.textContent = 'copied!'; btn.classList.add('copied');
  setTimeout(() => {{ btn.textContent = 'curl'; btn.classList.remove('copied'); }}, 1800);
}}
function _curlCopy(text, btn) {{
  navigator.clipboard.writeText(text).then(() => _flashCurl(btn));
}}

function copyCurlV1(btn) {{
  const msg    = (document.getElementById('v1-prompt').value   || 'Hello!').replace(/'/g, "'\\''");
  const sys    = (document.getElementById('v1-system').value   || '').replace(/'/g, "'\\''");
  const convId = (document.getElementById('v1-conv-id').value  || '').replace(/'/g, "'\\''");
  const key    = _apiKey || 'YOUR_API_KEY';
  let body = {{}};
  body.messages = [{{"role":"user","content":msg}}];
  if (sys)    body.system = sys;
  if (convId) body.conversation_id = convId;
  body.stream = false;
  const curl = `curl -X POST '${{BASE}}/v1/chat/completions' \\
  -H 'Authorization: Bearer ${{key}}' \\
  -H 'Content-Type: application/json' \\
  -d '${{JSON.stringify(body).replace(/'/g, "'\\''")  }}'`;
  _curlCopy(curl, btn);
}}

function copyCurlImage(btn) {{
  const prompt = (document.getElementById('au-img-p').value || 'a beautiful landscape').replace(/'/g, "'\\''");
  const model  = document.getElementById('au-img-model').value;
  const w      = document.getElementById('au-img-w').value || 1024;
  const h      = document.getElementById('au-img-h').value || 1024;
  const key    = _apiKey || 'YOUR_API_KEY';
  let body = {{prompt, width: Number(w), height: Number(h)}};
  if (model) body.model = model;
  const curl = `curl -X POST '${{BASE}}/image' \\
  -H 'Authorization: Bearer ${{key}}' \\
  -H 'Content-Type: application/json' \\
  -d '${{JSON.stringify(body).replace(/'/g, "'\\''")  }}'`;
  _curlCopy(curl, btn);
}}

function copyCurlAudio(btn) {{
  const text  = (document.getElementById('au-aud-text').value || 'Hello, this is a test.').replace(/'/g, "'\\''");
  const model = document.getElementById('au-aud-model').value;
  const key   = _apiKey || 'YOUR_API_KEY';
  let body = {{text}};
  if (model) body.model = model;
  const curl = `curl -X POST '${{BASE}}/audio' \\
  -H 'Authorization: Bearer ${{key}}' \\
  -H 'Content-Type: application/json' \\
  -d '${{JSON.stringify(body).replace(/'/g, "'\\''")  }}' \\
  --output audio.mp3`;
  _curlCopy(curl, btn);
}}

// ── Toggle card ──
function toggle(head) {{ head.nextElementSibling.classList.toggle('open'); }}

// ── Show result ──
function showResult(wrapId, spinId, status, data, extra) {{
  const wrap = document.getElementById(wrapId);
  const ok = status >= 200 && status < 300;
  let html = '<div class="res-header"><span class="res-label">Response</span>';
  html += `<span class="status-pill ${{ok?'ok':'err'}}">${{ok?'200 OK':status}}</span></div>`;
  if (extra?.provider) html += `<div class="provider-used">provider: ${{extra.provider}}</div>`;
  if (extra?.conv_id)  html += `<div class="provider-used" style="color:#93c5fd">conversation_id: ${{extra.conv_id}}</div>`;
  html += `<div class="res-box v">${{typeof data==='string'?data:JSON.stringify(data,null,2)}}</div>`;
  wrap.innerHTML = html;
  if (spinId) document.getElementById(spinId).style.display = 'none';
}}
function startSpin(id) {{ document.getElementById(id).style.display = 'inline-block'; }}

async function postJSON(path, body, wrapId, spinId, imgId) {{
  startSpin(spinId);
  try {{
    const r = await fetch(path, {{method:'POST',headers:authHeaders(),body:JSON.stringify(body)}});
    const d = await r.json();
    showResult(wrapId, spinId, r.status, d, {{provider:d.provider_used, conv_id:d.conversation_id}});
    if (imgId && d.image_urls?.[0]) {{
      const img = document.getElementById(imgId);
      img.src = d.image_urls[0]; img.style.display = 'block';
    }}
  }} catch(e) {{ showResult(wrapId, spinId, 0, e.message); }}
}}

// ── /v1/chat/completions ──
async function execV1() {{
  startSpin('sp-v1');
  const toolsRaw = document.getElementById('v1-tools').value.trim();
  let tools;
  if (toolsRaw) {{ try {{ tools = JSON.parse(toolsRaw); }} catch(e) {{ showResult('wr-v1','sp-v1',400,'Tools JSON tidak valid: '+e.message); return; }} }}
  const selectedModel = document.getElementById('v1-model').value;
  const body = {{
    messages: [{{role:'user', content: document.getElementById('v1-prompt').value}}],
    conversation_id: document.getElementById('v1-conv-id').value || undefined,
    system: document.getElementById('v1-system').value || undefined,
    tools,
  }};
  if (selectedModel) body.model = selectedModel;
  try {{
    const r = await fetch('/v1/chat/completions', {{method:'POST',headers:authHeaders(),body:JSON.stringify(body)}});
    const d = await r.json();
    const convId = r.headers.get('X-Conversation-Id') || d.conversation_id;
    const provider = d.system_fingerprint ? d.system_fingerprint.replace('fp_dzeck_','') : d.provider_used;
    showResult('wr-v1','sp-v1',r.status,d,{{provider, conv_id: convId}});
  }} catch(e) {{ showResult('wr-v1','sp-v1',0,e.message); }}
}}

// ── /image ──
async function execAutoImage() {{
  const model = document.getElementById('au-img-model').value;
  const body = {{
    prompt: document.getElementById('au-img-p').value,
    width:  +document.getElementById('au-img-w').value || 1024,
    height: +document.getElementById('au-img-h').value || 1024,
  }};
  if (model) body.model = model;
  startSpin('sp-au-img');
  try {{
    const r = await fetch('/image', {{method:'POST',headers:authHeaders(),body:JSON.stringify(body)}});
    const d = await r.json();
    showResult('wr-au-img','sp-au-img',r.status,d,{{provider:d.provider_used}});
    const imgEl = document.getElementById('img-au-out');
    if (r.ok && d.image_base64) {{
      imgEl.src = 'data:' + d.content_type + ';base64,' + d.image_base64;
      imgEl.style.display = 'block';
    }} else if (r.ok && d.image_urls?.[0]) {{
      imgEl.src = d.image_urls[0];
      imgEl.style.display = 'block';
    }} else {{
      imgEl.style.display = 'none';
    }}
  }} catch(e) {{ showResult('wr-au-img','sp-au-img',0,e.message); }}
}}

// ── /audio ──
async function execAutoAudio() {{
  const text = document.getElementById('au-aud-text').value;
  const model = document.getElementById('au-aud-model').value;
  const body = {{ text }};
  if (model) body.model = model;
  startSpin('sp-au-aud');
  try {{
    const r = await fetch('/audio', {{method:'POST',headers:authHeaders(),body:JSON.stringify(body)}});
    const d = await r.json();
    showResult('wr-au-aud','sp-au-aud',r.status,d,{{provider:d.provider_used}});
    if (r.ok && d.audio_base64) {{
      const audio = document.getElementById('audio-au-out');
      audio.src = 'data:' + d.content_type + ';base64,' + d.audio_base64;
      audio.style.display = 'block';
      audio.play();
    }}
  }} catch(e) {{ showResult('wr-au-aud','sp-au-aud',0,e.message); }}
}}
</script>
</body>
</html>"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    resp = make_response(build_landing_html())
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.route("/dashboard", methods=["GET"])
def dashboard():
    resp = make_response(build_docs_html())
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/auth/register", methods=["POST"])
def auth_register():
    """
    Daftar akun baru.
    Body: { "username": "...", "email": "...", "password": "..." }
    Returns: { "api_key": "sk-dzcx...", "username": "...", "email": "..." }
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    email    = (data.get("email")    or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not username or not email or not password:
        return jsonify({"error": "username, email, dan password wajib diisi"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password minimal 6 karakter"}), 400
    if "@" not in email:
        return jsonify({"error": "Format email tidak valid"}), 400

    db = get_db()
    if db is None:
        return jsonify({"error": "Database tidak tersedia"}), 503

    if db["users"].find_one({"$or": [{"email": email}, {"username": username}]}):
        return jsonify({"error": "Username atau email sudah terdaftar"}), 409

    api_key = generate_api_key()
    user_doc = {
        "username":   username,
        "email":      email,
        "password":   generate_password_hash(password),
        "api_key":    api_key,
        "is_active":  True,
        "created_at": datetime.now(timezone.utc),
        "last_login": None,
    }
    db["users"].insert_one(user_doc)

    return jsonify({
        "message":  "Akun berhasil dibuat",
        "username": username,
        "email":    email,
        "api_key":  api_key,
    }), 201


@app.route("/auth/login", methods=["POST"])
def auth_login():
    """
    Login dengan email/username dan password.
    Body: { "email": "..." / "username": "...", "password": "..." }
    Returns: { "api_key": "sk-dzcx...", "username": "...", "email": "..." }
    """
    data     = request.get_json(silent=True) or {}
    login    = (data.get("email") or data.get("username") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not login or not password:
        return jsonify({"error": "email/username dan password wajib diisi"}), 400

    db = get_db()
    if db is None:
        return jsonify({"error": "Database tidak tersedia"}), 503

    user = db["users"].find_one({
        "$or": [{"email": login}, {"username": login}]
    })
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Email/username atau password salah"}), 401
    if not user.get("is_active", True):
        return jsonify({"error": "Akun dinonaktifkan"}), 403

    db["users"].update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": datetime.now(timezone.utc)}}
    )

    return jsonify({
        "message":  "Login berhasil",
        "username": user["username"],
        "email":    user["email"],
        "api_key":  user["api_key"],
    })


@app.route("/auth/me", methods=["GET"])
def auth_me():
    """Info akun saat ini (butuh Authorization: Bearer sk-dzcx...)"""
    user = getattr(g, "current_user", None)
    if not user:
        return jsonify({"error": "Tidak terautentikasi"}), 401
    return jsonify({
        "username":   user["username"],
        "email":      user["email"],
        "api_key":    user["api_key"],
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
        "last_login": user["last_login"].isoformat() if user.get("last_login") else None,
    })


@app.route("/auth/regenerate-key", methods=["POST"])
def auth_regenerate_key():
    """Generate ulang API key (butuh Authorization: Bearer sk-dzcx...)"""
    user = getattr(g, "current_user", None)
    if not user:
        return jsonify({"error": "Tidak terautentikasi"}), 401
    db = get_db()
    if db is None:
        return jsonify({"error": "Database tidak tersedia"}), 503

    new_key = generate_api_key()
    db["users"].update_one(
        {"_id": user["_id"]},
        {"$set": {"api_key": new_key}}
    )
    return jsonify({
        "message":  "API key berhasil di-generate ulang",
        "api_key":  new_key,
    })


@app.route("/v1/models", methods=["GET"])
def list_models():
    """OpenAI-compatible /v1/models endpoint."""
    _MODEL_CREATED = 1706745088  # realistic Unix timestamp (Jan 2024)
    models = []
    for pid, cfg in CHAT_PROVIDERS.items():
        models.append({
            "id":       pid,
            "object":   "model",
            "created":  _MODEL_CREATED,
            "owned_by": AUTHOR,
        })
    return jsonify({
        "object": "list",
        "data":   models,
    })


@app.route("/providers", methods=["GET"])
def list_providers_legacy():
    return jsonify({
        "author": "dzeck",
        "chat":  {k: {"model": v["model"], "desc": v["desc"]} for k, v in CHAT_PROVIDERS.items()},
        "image": {k: {"model": v["model"], "desc": v["desc"]} for k, v in IMAGE_PROVIDERS.items()},
        "audio": {k: {"model": v["model"], "desc": v["desc"]} for k, v in AUDIO_PROVIDERS.items()},
        "fallback_order": {"chat": CHAT_ORDER, "audio": AUDIO_ORDER, "image": IMAGE_ORDER},
    })


# ── /v1/chat/completions (OpenAI-compatible + Tool Calling) ───────────────────

@app.route("/v1/chat/completions", methods=["POST"])
def v1_chat_completions():
    """
    OpenAI-compatible chat completions dengan tool calling.

    Body (JSON):
      messages        list  – array pesan OpenAI format (role: system/user/assistant/tool)
      conversation_id str   – (opsional) ID untuk multi-turn memory
      system          str   – (opsional) system prompt tambahan
      tools           list  – (opsional) tool definitions OpenAI format
      tool_choice     str   – (opsional) "auto" | "none" | {{"type":"function","function":{"name":"..."}}}
      model           str   – (opsional) override model
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Body harus JSON"}), 400

    incoming_messages = data.get("messages", [])
    if not incoming_messages:
        return jsonify({"error": "Field 'messages' wajib diisi dan tidak boleh kosong"}), 400

    conv_id          = data.get("conversation_id")
    system_text      = data.get("system", "")
    tools            = data.get("tools")
    tool_choice_raw  = data.get("tool_choice", "auto")
    requested_model  = data.get("model")   # label dari client, TIDAK diteruskan ke provider
    do_stream        = bool(data.get("stream", False))

    # ── Normalisasi tool_choice ───────────────────────────────────────────────
    # OpenAI mendukung: "auto" | "none" | "required" | {"type":"function","function":{"name":"..."}}
    forced_tool_name = None
    if isinstance(tool_choice_raw, dict):
        # tool_choice = {"type": "function", "function": {"name": "nama_tool"}}
        forced_tool_name = tool_choice_raw.get("function", {}).get("name")
        tool_choice = "function"   # marker internal
    else:
        tool_choice = tool_choice_raw  # "auto" | "none" | "required"

    # ── Susun messages ────────────────────────────────────────────────────────
    history = []
    if conv_id:
        history = load_conversation(conv_id)

    # System message: gunakan dari request, atau fallback ke DEFAULT_SYSTEM_PROMPT
    # Tool definitions dikirim native ke provider (openai_compatible) atau diinjeksi per-call (g4f)
    final_messages = []
    effective_system = system_text.strip() if system_text else DEFAULT_SYSTEM_PROMPT
    final_messages.append({"role": "system", "content": effective_system})

    final_messages += [m for m in history if m.get("role") != "system"]
    final_messages += incoming_messages

    # ── Tentukan require_tool_call ────────────────────────────────────────────
    # "required" / force specific tool → WAJIB panggil tool setiap turn
    # "auto"                           → hanya wajib saat user turn (bukan tool result)
    # "none"                           → tidak boleh panggil tool
    last_role = incoming_messages[-1].get("role", "") if incoming_messages else ""
    force_always = tool_choice in ("required", "function")
    need_tc = (
        bool(tools)
        and tool_choice != "none"
        and (force_always or last_role not in ("tool", "assistant"))
    )

    # Tools yang akan diteruskan ke providers
    # - openai_compatible (HF/API): dikirim sebagai parameter native `tools`
    # - g4f (static): diinjeksi via system message di dalam run_chat
    active_tools = tools if tools and tool_choice != "none" else None

    # Jika tool_choice forced ke nama tertentu, inject instruksi ke system message
    if forced_tool_name and active_tools:
        force_msg = (
            f"\n\n## MANDATORY\n"
            f"You MUST call the tool '{forced_tool_name}' right now. "
            f"Do NOT reply with plain text. Output only the tool_calls JSON."
        )
        if final_messages and final_messages[0].get("role") == "system":
            final_messages[0] = {
                "role": "system",
                "content": final_messages[0]["content"] + force_msg,
            }
        else:
            final_messages.insert(0, {"role": "system", "content": force_msg.strip()})

    # Smart routing: deteksi intent dari pesan user
    intent = detect_intent(incoming_messages)

    # Jika user minta model spesifik yang ada di CHAT_PROVIDERS, pin ke sana
    pinned_provider = requested_model if requested_model in CHAT_PROVIDERS else None

    raw_text, provider_used, errors = run_chat_fallback(
        final_messages, None,
        require_tool_call=need_tc,
        intent=intent,
        tools=active_tools,
        pinned=pinned_provider,
    )

    if not raw_text:
        return jsonify({"error": "Semua provider gagal.", "details": errors}), 503

    # ── Deteksi tool calls ────────────────────────────────────────────────────
    tool_calls_raw, is_tool_call = parse_tool_calls(raw_text)

    if is_tool_call and tools and tool_choice != "none":
        tool_calls = format_tool_calls_openai(tool_calls_raw)
        new_history = [m for m in final_messages if m.get("role") != "system"]
        new_history.append({"role": "assistant", "content": None, "tool_calls": tool_calls})
        if conv_id:
            save_conversation(conv_id, new_history)
        log_api_request("/v1/chat/completions", provider_used, True)

        if do_stream:
            return Response(
                stream_with_context(stream_tool_calls_response(tool_calls, provider_used, conv_id)),
                content_type="text/event-stream",
                headers={"X-Conversation-Id": conv_id or "", "Cache-Control": "no-cache"},
            )
        resp = build_completion_response(None, provider_used, tool_calls=tool_calls,
                                        messages=incoming_messages)
        return jsonify(resp), 200, {"X-Conversation-Id": conv_id or ""}

    # ── Respons teks biasa ────────────────────────────────────────────────────
    new_history = [m for m in final_messages if m.get("role") != "system"]
    new_history.append({"role": "assistant", "content": raw_text})
    if not conv_id:
        conv_id = f"conv_{uuid.uuid4().hex[:12]}"
    save_conversation(conv_id, new_history)
    update_conv_stats(conv_id, len(new_history), provider_used)
    log_api_request("/v1/chat/completions", provider_used, True)

    if do_stream:
        return Response(
            stream_with_context(stream_text_response(raw_text, provider_used, conv_id)),
            content_type="text/event-stream",
            headers={"X-Conversation-Id": conv_id, "Cache-Control": "no-cache"},
        )
    resp = build_completion_response(raw_text, provider_used, messages=incoming_messages)
    return jsonify(resp), 200, {"X-Conversation-Id": conv_id}


# ── Conversation management ───────────────────────────────────────────────────

@app.route("/v1/conversations/<conv_id>", methods=["GET"])
def get_conversation(conv_id):
    """Ambil riwayat percakapan berdasarkan conversation_id."""
    messages = load_conversation(conv_id)
    if not messages:
        return jsonify({"error": f"Percakapan '{conv_id}' tidak ditemukan"}), 404
    return jsonify({"conversation_id": conv_id, "messages": messages, "count": len(messages)})


@app.route("/v1/conversations/<conv_id>", methods=["DELETE"])
def delete_conv(conv_id):
    """Hapus riwayat percakapan."""
    delete_conversation(conv_id)
    return jsonify({"deleted": True, "conversation_id": conv_id})


# ── Unified auto-fallback endpoints ───────────────────────────────────────────

@app.route("/chat", methods=["POST"])
def chat_auto():
    """Chat sederhana dengan auto-fallback dan opsional conversation memory."""
    data, err, code = parse_body("prompt")
    if err:
        return err, code

    conv_id     = data.get("conversation_id")
    system_txt  = data.get("system_prompt", "")
    prompt      = data["prompt"]

    # Susun messages
    messages = []
    if system_txt:
        messages.append({"role": "system", "content": system_txt})
    if conv_id:
        history = load_conversation(conv_id)
        messages += [m for m in history if m.get("role") != "system"]
    messages.append({"role": "user", "content": prompt})

    text, used, errors = run_chat_fallback(messages, data.get("model"))
    if not text:
        log_api_request("/chat", None, False, "Semua provider gagal")
        return jsonify({"error": "Semua provider gagal.", "details": errors}), 503

    # Simpan percakapan
    new_history = [m for m in messages if m.get("role") != "system"]
    new_history.append({"role": "assistant", "content": text})
    if not conv_id:
        conv_id = f"conv_{uuid.uuid4().hex[:12]}"
    save_conversation(conv_id, new_history)
    update_conv_stats(conv_id, len(new_history), used)
    log_api_request("/chat", used, True)

    return jsonify({
        "provider_used":   used,
        "response":        text,
        "conversation_id": conv_id,
        "skipped":         errors,
    })


@app.route("/image", methods=["POST"])
def image_auto():
    """
    POST /image
    Body JSON:
      - prompt  : deskripsi gambar (wajib)
      - model   : provider key, misal 'hf-flux-schnell' (opsional, default auto fallback)
      - width   : lebar gambar (opsional, default 1024)
      - height  : tinggi gambar (opsional, default 1024)

    Fallback order: hf-flux-schnell → hf-flux-dev → hf-sdxl → pollinations

    Response:
      { provider_used, model, image_urls, image_base64, content_type, skipped, author }
    """
    data, err, code = parse_body("prompt")
    if err:
        return err, code

    img_data, used, ctype, errors = run_image_fallback(
        data["prompt"],
        model=data.get("model"),
        width=data.get("width", 1024),
        height=data.get("height", 1024),
    )

    if img_data is None:
        log_api_request("/image", None, False, "Semua provider image gagal")
        return jsonify({"error": "Semua provider image gagal.", "details": errors, "author": "dzeck"}), 503

    log_api_request("/image", used, True)
    cfg = IMAGE_PROVIDERS[used]

    if ctype == "image/url":
        return jsonify({
            "provider_used": used,
            "model":         cfg["model"],
            "image_urls":    [img_data],
            "image_base64":  None,
            "content_type":  "image/png",
            "skipped":       errors,
            "author":        "dzeck",
        })
    else:
        return jsonify({
            "provider_used": used,
            "model":         cfg["model"],
            "image_urls":    [],
            "image_base64":  base64.b64encode(img_data).decode(),
            "content_type":  ctype,
            "size_bytes":    len(img_data),
            "skipped":       errors,
            "author":        "dzeck",
        })


@app.route("/audio", methods=["POST"])
def audio_auto():
    """
    POST /audio
    Body JSON:
      - text        : teks yang akan diucapkan (wajib)
      - model       : provider key, misal 'edge-id-female' (opsional, prioritas utama)
      - voice       : nama voice edge-tts, misal 'id-ID-GadisNeural' (opsional, fallback)
      - gender      : 'male' | 'female' (opsional, default auto)
      - return_type : 'base64' | 'binary' (opsional, default 'base64')

    Prioritas suara: model → voice → auto-detect bahasa → default Indonesia female.

    Response (base64 mode):
      { provider_used, model, voice, lang, gender, content_type, audio_base64, size_bytes, skipped, author }

    Response (binary mode):
      Content-Type: audio/mpeg  (langsung bytes MP3)
    """
    data, err, code = parse_body("text")
    if err:
        return err, code

    audio_bytes, used, ctype, errors = run_audio_fallback(
        data["text"],
        model=data.get("model"),
        voice_override=data.get("voice"),
        gender=data.get("gender"),
    )

    if not audio_bytes:
        log_api_request("/audio", None, False, "Semua provider audio gagal")
        return jsonify({"error": "Semua provider audio gagal.", "details": errors, "author": "dzeck"}), 503

    log_api_request("/audio", used, True)
    cfg = AUDIO_PROVIDERS[used]

    if data.get("return_type") == "binary":
        resp = make_response(audio_bytes)
        resp.headers["Content-Type"] = ctype
        resp.headers["X-Provider-Used"] = used
        resp.headers["X-Voice"] = cfg["voice"]
        return resp

    return jsonify({
        "provider_used": used,
        "model":         used,
        "voice":         cfg["voice"],
        "lang":          cfg["lang"],
        "gender":        cfg["gender"],
        "content_type":  ctype,
        "audio_base64":  base64.b64encode(audio_bytes).decode(),
        "size_bytes":    len(audio_bytes),
        "skipped":       errors,
        "author":        "dzeck",
    })


# ── Specific provider endpoints ───────────────────────────────────────────────

@app.route("/chat/<provider_key>", methods=["POST"])
def chat_specific(provider_key):
    pk = provider_key.lower()
    if pk not in CHAT_PROVIDERS:
        return jsonify({"error": f"Provider '{pk}' tidak ada.", "tersedia": CHAT_ORDER}), 404
    data, err, code = parse_body("prompt")
    if err:
        return err, code
    try:
        msgs = []
        if data.get("system_prompt"):
            msgs.append({"role": "system", "content": data["system_prompt"]})
        msgs.append({"role": "user", "content": data["prompt"]})
        text = run_chat(CHAT_PROVIDERS[pk], msgs, data.get("model"))
        log_api_request(f"/chat/{pk}", pk, True)
        return jsonify({"provider": pk, "model": data.get("model") or CHAT_PROVIDERS[pk]["model"], "response": text})
    except Exception as e:
        log_api_request(f"/chat/{pk}", pk, False, str(e))
        return jsonify({"error": str(e), "provider": pk}), 500


@app.route("/image/<provider_key>", methods=["POST"])
def image_specific(provider_key):
    pk = provider_key.lower()
    if pk not in IMAGE_PROVIDERS:
        return jsonify({"error": f"Provider '{pk}' tidak ada.", "tersedia": IMAGE_ORDER}), 404
    data, err, code = parse_body("prompt")
    if err:
        return err, code
    cfg = IMAGE_PROVIDERS[pk]
    try:
        w = data.get("width", 1024)
        h = data.get("height", 1024)
        if cfg["type"] == "huggingface":
            img_bytes = _hf_image_generate(data["prompt"], cfg["model"], w, h)
            log_api_request(f"/image/{pk}", pk, True)
            return jsonify({
                "provider_used": pk,
                "model":         cfg["model"],
                "image_urls":    [],
                "image_base64":  base64.b64encode(img_bytes).decode(),
                "content_type":  "image/png",
                "size_bytes":    len(img_bytes),
            })
        else:
            url = make_image_url(data["prompt"], cfg["model"], w, h)
            log_api_request(f"/image/{pk}", pk, True)
            return jsonify({
                "provider_used": pk,
                "model":         cfg["model"],
                "image_urls":    [url],
                "image_base64":  None,
                "content_type":  "image/png",
            })
    except Exception as e:
        log_api_request(f"/image/{pk}", pk, False, str(e))
        return jsonify({"error": str(e), "provider": pk}), 500


@app.route("/audio/<provider_key>", methods=["POST"])
def audio_specific(provider_key):
    """
    POST /audio/<provider_key>
    Gunakan voice tertentu secara langsung.
    Body JSON:
      - text        : teks yang akan diucapkan (wajib)
      - return_type : 'base64' | 'binary' (opsional, default 'base64')
    """
    pk = provider_key.lower()
    if pk not in AUDIO_PROVIDERS:
        return jsonify({
            "error": f"Provider '{pk}' tidak ada.",
            "tersedia": {k: {"voice": v["voice"], "lang": v["lang"], "gender": v["gender"], "desc": v["desc"]}
                         for k, v in AUDIO_PROVIDERS.items()},
            "author": "dzeck",
        }), 404
    data, err, code = parse_body("text")
    if err:
        return err, code
    cfg = AUDIO_PROVIDERS[pk]
    try:
        audio_bytes = _edge_tts_generate(data["text"], cfg["voice"])
        log_api_request(f"/audio/{pk}", pk, True)

        if data.get("return_type") == "binary":
            resp = make_response(audio_bytes)
            resp.headers["Content-Type"] = cfg["content_type"]
            resp.headers["X-Provider-Used"] = pk
            resp.headers["X-Voice"] = cfg["voice"]
            return resp

        return jsonify({
            "provider":     pk,
            "voice":        cfg["voice"],
            "lang":         cfg["lang"],
            "gender":       cfg["gender"],
            "content_type": cfg["content_type"],
            "audio_base64": base64.b64encode(audio_bytes).decode(),
            "size_bytes":   len(audio_bytes),
            "author":       "dzeck",
        })
    except Exception as e:
        log_api_request(f"/audio/{pk}", pk, False, str(e))
        return jsonify({"error": str(e), "provider": pk, "author": "dzeck"}), 500


# ── Analytics endpoint ────────────────────────────────────────────────────────

@app.route("/v1/providers", methods=["GET"])
def list_providers():
    """Daftar provider chat yang aktif beserta status (opsional vs bawaan)."""
    result = []
    for pid in CHAT_ORDER:
        cfg = CHAT_PROVIDERS.get(pid, {})
        is_optional = cfg.get("type") == "openai_compatible"
        result.append({
            "id":       pid,
            "desc":     cfg.get("desc", ""),
            "model":    cfg.get("model", ""),
            "type":     cfg.get("type", "g4f"),
            "optional": is_optional,
            "active":   True,
        })
    # Provider opsional yang belum aktif (env var belum di-set)
    for opt in _OPT_PROVIDERS:
        if opt["id"] not in CHAT_PROVIDERS:
            result.append({
                "id":       opt["id"],
                "desc":     opt["desc"],
                "model":    opt["model"],
                "type":     "openai_compatible",
                "optional": True,
                "active":   False,
                "activate": f"Set env var {opt['key_env']} untuk mengaktifkan",
            })
    return jsonify({
        "author":       "dzeck",
        "total_active": len(CHAT_ORDER),
        "chat_order":   CHAT_ORDER,
        "tool_capable": TOOL_CAPABLE_ORDER,
        "providers":    result,
    })


@app.route("/v1/analytics", methods=["GET"])
def analytics():
    """
    Statistik penggunaan API dari PostgreSQL.
    Query params: limit (default 50), endpoint, provider
    """
    conn = get_pg_conn()
    if not conn:
        return jsonify({"error": "PostgreSQL tidak terhubung"}), 503

    limit    = min(int(request.args.get("limit", 50)), 500)
    endpoint = request.args.get("endpoint")
    provider = request.args.get("provider")

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Log terbaru
            where_clauses = []
            params = []
            if endpoint:
                where_clauses.append("endpoint = %s")
                params.append(endpoint)
            if provider:
                where_clauses.append("provider = %s")
                params.append(provider)
            where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            params.append(limit)

            cur.execute(f"""
                SELECT id, endpoint, provider, success, error_msg, ip, created_at
                FROM api_logs {where_sql}
                ORDER BY created_at DESC LIMIT %s
            """, params)
            logs = cur.fetchall()

            # Ringkasan per endpoint
            cur.execute("""
                SELECT endpoint,
                       COUNT(*) AS total,
                       SUM(CASE WHEN success THEN 1 ELSE 0 END) AS sukses,
                       SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) AS gagal
                FROM api_logs
                GROUP BY endpoint ORDER BY total DESC
            """)
            summary = cur.fetchall()

            # Top providers
            cur.execute("""
                SELECT provider, COUNT(*) AS total
                FROM api_logs WHERE provider IS NOT NULL AND success = TRUE
                GROUP BY provider ORDER BY total DESC LIMIT 10
            """)
            top_providers = cur.fetchall()

            # Conversation stats
            cur.execute("""
                SELECT COUNT(*) AS total_conversations,
                       AVG(message_count) AS avg_messages
                FROM conversation_stats
            """)
            conv_stats = cur.fetchone()

        return jsonify({
            "summary_per_endpoint": [dict(r) for r in summary],
            "top_providers":        [dict(r) for r in top_providers],
            "conversation_stats":   dict(conv_stats) if conv_stats else {},
            "recent_logs":          [dict(r) for r in logs],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        release_pg_conn(conn)


if __name__ == "__main__":
    # Inisialisasi pool database saat startup
    _get_pg_pool()
    app.run(host="0.0.0.0", port=5000, debug=False)
