import os
from dotenv import load_dotenv
load_dotenv()
import json
import uuid
import time
import secrets
import hashlib
import functools
import urllib.parse
import requests
import redis
import psycopg2
import psycopg2.extras
import g4f
from g4f import Provider
from g4f.client import Client as G4FClient
from flask import Flask, request, jsonify, make_response, Response, stream_with_context, g
from pymongo import MongoClient, ASCENDING
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
g4f_client = G4FClient()

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
    "/", "/providers", "/v1/providers", "/v1/models",
    "/auth/register", "/auth/login",
}
_PUBLIC_PREFIXES = ("/static/",)

def _extract_bearer(req) -> str | None:
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    # Fallback: query param ?api_key=...
    return req.args.get("api_key") or req.json.get("api_key") if req.is_json else None

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
        return jsonify({"error": "API key diperlukan. Sertakan header: Authorization: Bearer sk-dzcx..."}), 401
    if not api_key.startswith("sk-dzcx"):
        return jsonify({"error": "Format API key tidak valid (harus dimulai sk-dzcx...)"}), 401
    user = get_user_by_api_key(api_key)
    if not user:
        return jsonify({"error": "API key tidak valid atau akun dinonaktifkan"}), 401
    # Simpan user ke request context
    g.current_user = user
    g.api_key = api_key


# ── PostgreSQL (Neon) ─────────────────────────────────────────────────────────
_pg_conn = None

def get_pg():
    global _pg_conn
    try:
        if _pg_conn is None or _pg_conn.closed:
            url = os.environ.get("POSTGRES_URL")
            if not url:
                return None
            _pg_conn = psycopg2.connect(url)
            _pg_conn.autocommit = True
            _init_pg_tables(_pg_conn)
    except Exception as e:
        print(f"[PostgreSQL] Gagal koneksi: {e}")
        _pg_conn = None
    return _pg_conn

def _init_pg_tables(conn):
    """Buat tabel jika belum ada."""
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

def log_api_request(endpoint: str, provider: str = None, success: bool = True, error: str = None):
    """Catat setiap request ke tabel api_logs di PostgreSQL (non-blocking)."""
    try:
        conn = get_pg()
        if not conn:
            return
        ip = request.remote_addr if request else None
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO api_logs (endpoint, provider, success, error_msg, ip) VALUES (%s, %s, %s, %s, %s)",
                (endpoint, provider, success, error, ip),
            )
    except Exception as e:
        print(f"[PostgreSQL] log_api_request gagal: {e}")
        global _pg_conn
        _pg_conn = None

def update_conv_stats(conv_id: str, msg_count: int, provider: str):
    """Update statistik percakapan di PostgreSQL."""
    try:
        conn = get_pg()
        if not conn:
            return
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO conversation_stats (conversation_id, message_count, last_provider, updated_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT DO NOTHING
            """, (conv_id, msg_count, provider))
            cur.execute("""
                UPDATE conversation_stats
                SET message_count=%s, last_provider=%s, updated_at=NOW()
                WHERE conversation_id=%s
            """, (msg_count, provider, conv_id))
    except Exception as e:
        print(f"[PostgreSQL] update_conv_stats gagal: {e}")


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

CHAT_PROVIDERS = {
    "pollinations": {
        "provider": Provider.PollinationsAI,
        "model":    "openai-fast",
        "desc":     "GPT-OSS 20B via Pollinations",
        "type":     "g4f",
    },
    "pollinations-direct": {
        "provider": None,
        "model":    "openai-fast",
        "desc":     "GPT-OSS via Pollinations HTTP",
        "type":     "pollinations_http",
    },
    "perplexity": {
        "provider": Provider.Perplexity,
        "model":    "auto",
        "desc":     "Perplexity AI + pencarian web real-time",
        "type":     "g4f",
    },
    "cohere": {
        "provider": Provider.CohereForAI_C4AI_Command,
        "model":    "command-a-03-2025",
        "desc":     "Cohere Command-A",
        "type":     "g4f",
    },
    "deepinfra": {
        "provider": Provider.DeepInfra,
        "model":    "MiniMaxAI/MiniMax-M2.5",
        "desc":     "MiniMax M2.5 via DeepInfra",
        "type":     "g4f",
    },
    "huggingspace": {
        "provider": Provider.HuggingSpace,
        "model":    "qwen-qwen2-72b-instruct",
        "desc":     "Qwen2 72B via HuggingFace Space",
        "type":     "g4f",
    },
    "aria": {
        "provider": Provider.OperaAria,
        "model":    "aria",
        "desc":     "Opera Aria",
        "type":     "g4f",
    },
    "yqcloud": {
        "provider": Provider.Yqcloud,
        "model":    "gpt-4",
        "desc":     "GPT-4 via Yqcloud",
        "type":     "g4f",
    },
}

CHAT_ORDER = [
    "pollinations", "pollinations-direct", "aria", "yqcloud",
    "cohere", "deepinfra", "huggingspace", "perplexity",
]

# Provider yang terbukti mengikuti format JSON tool call dengan baik
# (dicoba duluan saat require_tool_call=True)
TOOL_CAPABLE_ORDER = ["aria", "cohere", "deepinfra", "pollinations", "pollinations-direct"]

# ── Provider opsional berbasis env var (gratis, perlu daftar sekali) ──────────
# Format: type="openai_compatible" → panggil via HTTP OpenAI-compatible endpoint
_OPT_PROVIDERS = [
    {
        "key_env":   "GROQ_API_KEY",
        "id":        "groq",
        "url":       "https://api.groq.com/openai/v1/chat/completions",
        "model":     "llama-3.3-70b-versatile",
        "desc":      "Groq LPU – Llama 3.3 70B (ultra cepat, gratis)",
        "priority":  "first",   # masuk di depan antrian
        "tool_cap":  True,
    },
    {
        "key_env":   "GEMINI_API_KEY",
        "id":        "gemini",
        "url":       "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "model":     "gemini-2.0-flash",
        "desc":      "Google Gemini 2.0 Flash (1M token/hari gratis)",
        "priority":  "first",
        "tool_cap":  True,
    },
    {
        "key_env":   "MISTRAL_API_KEY",
        "id":        "mistral",
        "url":       "https://api.mistral.ai/v1/chat/completions",
        "model":     "mistral-small-latest",
        "desc":      "Mistral Small Latest (gratis tier)",
        "priority":  "last",
        "tool_cap":  True,
    },
    {
        "key_env":   "TOGETHER_API_KEY",
        "id":        "together",
        "url":       "https://api.together.xyz/v1/chat/completions",
        "model":     "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "desc":      "Together AI – Llama 3.3 70B Turbo (gratis kredit)",
        "priority":  "last",
        "tool_cap":  True,
    },
    {
        "key_env":   "CEREBRAS_API_KEY",
        "id":        "cerebras",
        "url":       "https://api.cerebras.ai/v1/chat/completions",
        "model":     "llama3.1-70b",
        "desc":      "Cerebras – Llama 3.1 70B (ultra cepat, gratis tier)",
        "priority":  "first",
        "tool_cap":  True,
    },
    {
        "key_env":   "SAMBANOVA_API_KEY",
        "id":        "sambanova",
        "url":       "https://api.sambanova.ai/v1/chat/completions",
        "model":     "Meta-Llama-3.3-70B-Instruct",
        "desc":      "SambaNova – Llama 3.3 70B (gratis tier)",
        "priority":  "last",
        "tool_cap":  True,
    },
    # HF Token – 4 provider via HF Inference Router (bypass cloud IP block)
    {
        "key_env":   "HF_TOKEN",
        "id":        "hf-cerebras",
        "url":       "https://router.huggingface.co/cerebras/v1/chat/completions",
        "model":     "gpt-oss-120b",
        "desc":      "Cerebras gpt-oss-120b via HF Router (NATIVE tool calls, ultra cepat)",
        "priority":  "first",
        "tool_cap":  True,
    },
    {
        "key_env":   "HF_TOKEN",
        "id":        "hf-cerebras-fast",
        "url":       "https://router.huggingface.co/cerebras/v1/chat/completions",
        "model":     "llama3.1-8b",
        "desc":      "Cerebras Llama 3.1 8B via HF Router (ultra cepat, gratis)",
        "priority":  "first",
        "tool_cap":  True,
    },
    {
        "key_env":   "HF_TOKEN",
        "id":        "hf-cerebras-qwen",
        "url":       "https://router.huggingface.co/cerebras/v1/chat/completions",
        "model":     "qwen-3-235b-a22b-instruct-2507",
        "desc":      "Cerebras Qwen3 235B via HF Router (model terbesar, gratis)",
        "priority":  "first",
        "tool_cap":  True,
    },
    {
        "key_env":   "HF_TOKEN",
        "id":        "hf-hyperbolic",
        "url":       "https://router.huggingface.co/hyperbolic/v1/chat/completions",
        "model":     "meta-llama/Llama-3.3-70B-Instruct",
        "desc":      "Hyperbolic Llama 3.3 70B via HF Router (gratis dengan HF_TOKEN)",
        "priority":  "last",
        "tool_cap":  True,
    },
]

for _opt in _OPT_PROVIDERS:
    _api_key = os.environ.get(_opt["key_env"], "")
    if _api_key:
        CHAT_PROVIDERS[_opt["id"]] = {
            "type":       "openai_compatible",
            "url":        _opt["url"],
            "model":      _opt["model"],
            "api_key":    _api_key,
            "desc":       _opt["desc"],
            "hf_provider": _opt["key_env"] == "HF_TOKEN",
        }
        if _opt["priority"] == "first":
            CHAT_ORDER.insert(0, _opt["id"])
            TOOL_CAPABLE_ORDER.insert(0, _opt["id"])
        else:
            CHAT_ORDER.append(_opt["id"])
            if _opt["tool_cap"]:
                TOOL_CAPABLE_ORDER.append(_opt["id"])

IMAGE_PROVIDERS = {
    "pollinations": {
        "model": "sana",
        "desc":  "Pollinations Image (Sana model)",
    },
}
IMAGE_ORDER = ["pollinations"]

AUDIO_PROVIDERS = {
    "pollinations-elevenlabs": {
        "provider": Provider.PollinationsAudio,
        "model":    "elevenlabs",
        "desc":     "ElevenLabs TTS via Pollinations",
    },
    "pollinations-openai-tts": {
        "provider": Provider.PollinationsAudio,
        "model":    "openai-audio",
        "desc":     "OpenAI TTS via Pollinations",
    },
}
AUDIO_ORDER = ["pollinations-elevenlabs", "pollinations-openai-tts"]


# ── Tool calling helpers ───────────────────────────────────────────────────────

TOOL_SYSTEM_INJECT = """
Kamu adalah AI agent yang memiliki akses ke tools/functions berikut:

{tools_json}

## Aturan Penting:
- Jika kamu perlu memanggil tool, balas HANYA dengan JSON berikut (tanpa teks tambahan):
  {{"tool_calls": [{{"id": "call_{rand_id}", "type": "function", "function": {{"name": "NAMA_TOOL", "arguments": "{{...json arguments...}}"}}}}]}}
- Kamu bisa memanggil lebih dari satu tool sekaligus dalam array tool_calls.
- Jika tidak perlu tool, balas dengan teks biasa.
- JANGAN campurkan tool_calls JSON dengan teks biasa.
"""

def build_tool_system_prompt(tools: list, forced_tool_name: str = None) -> str:
    tools_json = json.dumps(tools, ensure_ascii=False, indent=2)
    rand_id = uuid.uuid4().hex[:8]
    prompt = TOOL_SYSTEM_INJECT.format(tools_json=tools_json, rand_id=rand_id)
    if forced_tool_name:
        prompt += f"\n⚠️ KAMU WAJIB memanggil tool '{forced_tool_name}' sekarang. Jangan jawab dengan teks biasa."
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


def run_chat(cfg, messages: list, model_override=None):
    """Jalankan chat dengan daftar messages (multi-turn)."""
    model = model_override or cfg["model"]
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
        if cfg.get("native_tools"):
            payload["tools"] = cfg["native_tools"]
            payload["tool_choice"] = "auto"
        api_key = cfg["api_key"]
        r = requests.post(
            cfg["url"],
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )
        # Jika HF provider kena rate limit (429), otomatis coba HF_TOKEN_2
        if r.status_code == 429 and cfg.get("hf_provider"):
            hf_token_2 = os.environ.get("HF_TOKEN_2", "")
            if hf_token_2:
                print(f"[HF] Token 1 rate-limited, mencoba HF_TOKEN_2 untuk {cfg.get('url','')}")
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
    kwargs = {"provider": cfg["provider"], "messages": messages}
    if model:
        kwargs["model"] = model
    resp = g4f_client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content


def run_chat_fallback(messages: list, model_override=None, require_tool_call: bool = False):
    """
    Coba setiap provider secara berurutan.
    Jika require_tool_call=True, provider yang tidak menghasilkan tool_calls JSON
    dianggap 'tidak cocok' dan otomatis pindah ke provider berikutnya.
    """
    errors = {}
    # Saat require_tool_call, coba provider tool-capable dulu, baru sisanya
    order = TOOL_CAPABLE_ORDER + [p for p in CHAT_ORDER if p not in TOOL_CAPABLE_ORDER] \
            if require_tool_call else CHAT_ORDER
    for pk in order:
        try:
            text = run_chat(CHAT_PROVIDERS[pk], messages, model_override)
            if not text or not text.strip():
                errors[pk] = "Respons kosong"
                continue
            # Jika tools diperlukan, cek apakah model menghasilkan tool call
            if require_tool_call:
                _, is_tc = parse_tool_calls(text)
                if not is_tc:
                    errors[pk] = "Model tidak menghasilkan tool_calls"
                    continue
            return text, pk, errors
        except Exception as e:
            errors[pk] = str(e)
    # Semua gagal produce tool_call → fallback ke teks biasa (jawab apa adanya)
    if require_tool_call:
        for pk in CHAT_ORDER:
            try:
                text = run_chat(CHAT_PROVIDERS[pk], messages, model_override)
                if text and text.strip():
                    return text, pk, errors
            except Exception:
                pass
    return None, None, errors


def run_audio_fallback(text, model_override=None):
    errors = {}
    for pk in AUDIO_ORDER:
        cfg = AUDIO_PROVIDERS[pk]
        try:
            resp = g4f_client.chat.completions.create(
                model=model_override or cfg["model"],
                provider=cfg["provider"],
                messages=[{"role": "user", "content": text}],
            )
            url = resp.choices[0].message.content if resp.choices else None
            if url:
                return url, pk, errors
        except Exception as e:
            errors[pk] = str(e)
    return None, None, errors


def make_image_url(prompt, model="sana", width=1024, height=1024):
    enc = urllib.parse.quote(prompt)
    return f"https://image.pollinations.ai/prompt/{enc}?model={model}&width={width}&height={height}&nologo=true"


# ── OpenAI-compatible response builders ───────────────────────────────────────

def build_completion_response(content, provider_used, tool_calls=None, finish_reason="stop"):
    """Buat response dalam format OpenAI Chat Completions."""
    msg = {"role": "assistant"}
    if tool_calls:
        msg["tool_calls"] = tool_calls
        msg["content"] = None
        finish_reason = "tool_calls"
    else:
        msg["content"] = content
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": provider_used,
        "provider_used": provider_used,
        "choices": [
            {
                "index": 0,
                "message": msg,
                "finish_reason": finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens": -1,
            "completion_tokens": -1,
            "total_tokens": -1,
        },
    }


def _sse_chunk(resp_id, created, provider, delta, finish_reason=None):
    return "data: " + json.dumps({
        "id": resp_id, "object": "chat.completion.chunk",
        "created": created, "model": provider,
        "provider_used": provider,
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


# ── Documentation UI ──────────────────────────────────────────────────────────

def build_docs_html():
    # Provider rows for the Providers section
    chat_provider_rows = "".join(
        f'<div class="prov-row"><span class="prov-dot"></span><span class="prov-name">{k}</span><span class="prov-desc">{v.get("desc","")}</span></div>'
        for k, v in CHAT_PROVIDERS.items()
    )
    image_provider_rows = "".join(
        f'<div class="prov-row"><span class="prov-dot"></span><span class="prov-name">{k}</span><span class="prov-desc">{v.get("desc","")}</span></div>'
        for k, v in IMAGE_PROVIDERS.items()
    )
    audio_provider_rows = "".join(
        f'<div class="prov-row"><span class="prov-dot"></span><span class="prov-name">{k}</span><span class="prov-desc">{v.get("desc","")}</span></div>'
        for k, v in AUDIO_PROVIDERS.items()
    )

    return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AI API</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0e0e0e;--surface:#171717;--surface2:#202020;
  --border:#2a2a2a;--border-hover:#3a3a3a;
  --text:#ede8e0;--muted:#6b6b6b;--muted2:#4a4a4a;
  --accent:#d4a574;--accent-dim:rgba(212,165,116,.1);--accent-border:rgba(212,165,116,.25);
  --green:#4ade80;--red:#f87171;
  --mono:'JetBrains Mono','Fira Code',monospace;
  --r:12px;--r-sm:8px;
}}
body{{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.6;min-height:100vh}}
/* scrollbar */
::-webkit-scrollbar{{width:4px}}::-webkit-scrollbar-thumb{{background:var(--border);border-radius:4px}}

/* ── Header ── */
header{{border-bottom:1px solid var(--border);padding:16px 40px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:rgba(14,14,14,.92);backdrop-filter:blur(12px);z-index:100}}
.logo{{font-size:15px;font-weight:700;letter-spacing:-.3px;color:var(--text)}}
.logo em{{color:var(--accent);font-style:normal}}
.header-right{{display:flex;align-items:center;gap:10px}}
.version-pill{{background:var(--surface);border:1px solid var(--border);padding:3px 10px;border-radius:99px;font-size:11px;color:var(--muted);letter-spacing:.3px}}

/* ── Auth ── */
.auth-btn{{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:7px 16px;border-radius:var(--r-sm);font-size:13px;font-weight:500;cursor:pointer;transition:border-color .15s,background .15s;font-family:inherit}}
.auth-btn:hover{{border-color:var(--accent);background:var(--surface)}}
.auth-user{{display:flex;align-items:center;gap:8px}}
.auth-uname{{font-size:13px;font-weight:500;color:var(--accent)}}
.auth-logout{{background:none;border:1px solid var(--border);color:var(--muted);padding:5px 12px;border-radius:var(--r-sm);font-size:12px;cursor:pointer;font-family:inherit;transition:all .15s}}
.auth-logout:hover{{color:var(--red);border-color:var(--red)}}

/* ── Auth Modal ── */
.overlay{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;align-items:center;justify-content:center}}
.overlay.open{{display:flex}}
.modal{{background:var(--surface);border:1px solid var(--border);border-radius:16px;width:100%;max-width:400px;margin:16px;padding:28px 28px 24px;position:relative}}
.modal-close{{position:absolute;top:16px;right:18px;background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer;line-height:1;font-family:inherit}}
.modal-close:hover{{color:var(--text)}}
.modal h2{{font-size:17px;font-weight:700;margin-bottom:4px;letter-spacing:-.3px}}
.modal .sub{{color:var(--muted);font-size:13px;margin-bottom:22px}}
.tab-row{{display:flex;gap:4px;margin-bottom:20px;background:var(--surface2);border-radius:var(--r-sm);padding:4px}}
.tab{{flex:1;padding:6px;border-radius:6px;border:none;background:none;color:var(--muted);font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;font-family:inherit}}
.tab.active{{background:var(--surface);color:var(--text);box-shadow:0 1px 3px rgba(0,0,0,.3)}}
.modal .btn{{width:100%;justify-content:center;margin-top:6px}}
.modal-err{{color:var(--red);font-size:12.5px;margin-top:10px;display:none}}

/* ── Wrap ── */
.wrap{{max-width:820px;margin:0 auto;padding:48px 24px 100px}}

/* ── Hero ── */
.hero{{margin-bottom:40px}}
.hero h1{{font-size:28px;font-weight:700;letter-spacing:-.6px;margin-bottom:8px;line-height:1.2}}
.hero p{{color:var(--muted);font-size:14px;max-width:480px;line-height:1.65}}
.stats{{display:flex;gap:32px;margin-top:24px;flex-wrap:wrap}}
.stat{{display:flex;flex-direction:column;gap:2px}}
.stat-n{{font-size:22px;font-weight:700;color:var(--accent);letter-spacing:-.5px}}
.stat-l{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}}

/* ── Base URL ── */
.baseurl-box{{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px 18px;margin-bottom:24px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.baseurl-label{{font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--muted);white-space:nowrap}}
.baseurl-val{{font-family:var(--mono);font-size:12.5px;color:var(--accent);background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:5px 11px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.copy-btn{{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--muted);font-size:11.5px;padding:5px 12px;cursor:pointer;white-space:nowrap;transition:all .15s;font-family:inherit}}
.copy-btn:hover{{color:var(--text);border-color:var(--border-hover)}}

/* ── Lock / API Key ── */
.lock-notice{{background:rgba(248,113,113,.06);border:1px solid rgba(248,113,113,.2);border-radius:var(--r);padding:13px 16px;margin-bottom:20px;font-size:13px;color:#fca5a5;display:none;align-items:center;gap:10px;flex-wrap:wrap}}
.lock-notice.show{{display:flex}}
.apikey-bar{{background:var(--surface);border:1px solid var(--accent-border);border-radius:var(--r);padding:13px 18px;margin-bottom:24px;display:none;align-items:center;gap:10px;flex-wrap:wrap}}
.apikey-bar.show{{display:flex}}
.apikey-label{{font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--accent);white-space:nowrap}}
.apikey-val{{font-family:var(--mono);font-size:12.5px;color:var(--text);background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:5px 11px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.apikey-actions{{display:flex;gap:6px}}
.apikey-actions button{{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--muted);font-size:11.5px;padding:5px 10px;cursor:pointer;white-space:nowrap;font-family:inherit;transition:all .15s}}
.apikey-actions button:hover{{color:var(--text)}}

/* ── Section title ── */
.sec-title{{font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted);margin:40px 0 14px}}
hr{{border:none;border-top:1px solid var(--border);margin:36px 0}}

/* ── Cards ── */
.card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;margin-bottom:8px;transition:border-color .2s}}
.card:has(.card-body.open){{border-color:var(--accent-border)}}
.card-head{{display:flex;align-items:center;gap:10px;padding:14px 18px;cursor:pointer;user-select:none;transition:background .12s}}
.card-head:hover{{background:rgba(255,255,255,.02)}}
.card-body{{border-top:1px solid var(--border);padding:20px 18px;display:none}}
.card-body.open{{display:block}}
.mth{{font-size:10px;font-weight:700;letter-spacing:.5px;padding:3px 9px;border-radius:5px;min-width:44px;text-align:center}}
.mth.get{{background:rgba(96,165,250,.1);color:#93c5fd;border:1px solid rgba(96,165,250,.2)}}
.mth.post{{background:rgba(74,222,128,.1);color:#86efac;border:1px solid rgba(74,222,128,.2)}}
.ep{{font-family:var(--mono);font-size:12.5px;color:var(--text)}}
.tag{{margin-left:6px;font-size:10px;font-weight:600;padding:2px 7px;border-radius:99px;vertical-align:middle}}
.tag-compat{{background:rgba(212,165,116,.1);border:1px solid rgba(212,165,116,.25);color:var(--accent)}}
.tag-auto{{background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.2);color:#86efac}}
.sum{{color:var(--muted);font-size:12px;margin-left:auto}}

/* ── Form ── */
.url-preview{{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:8px 13px;font-family:var(--mono);font-size:12px;color:var(--muted);margin-bottom:16px;word-break:break-all}}
.url-preview strong{{color:var(--accent)}}
.card-desc{{color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:16px}}
.field{{margin-bottom:13px}}
label{{display:block;font-size:11.5px;color:var(--muted);margin-bottom:5px;font-weight:500}}
label .req{{color:var(--red)}}
label .opt{{color:var(--muted2);font-weight:400}}
input,select,textarea{{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:9px 12px;color:var(--text);font-family:inherit;font-size:13.5px;outline:none;transition:border-color .15s}}
input:focus,select:focus,textarea:focus{{border-color:var(--accent-border)}}
textarea{{resize:vertical;min-height:72px}}
select option{{background:var(--surface2)}}
.row{{display:flex;gap:10px}}.row .field{{flex:1}}
.btn{{background:var(--accent);color:#0e0e0e;border:none;padding:9px 20px;border-radius:var(--r-sm);font-size:13.5px;font-weight:600;cursor:pointer;transition:opacity .15s;display:inline-flex;align-items:center;gap:8px;font-family:inherit}}
.btn:hover{{opacity:.88}}.btn:disabled{{opacity:.35;cursor:not-allowed}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.spin{{width:13px;height:13px;border:2px solid rgba(14,14,14,.25);border-top-color:#0e0e0e;border-radius:50%;animation:spin .6s linear infinite;display:none}}

/* ── Response ── */
.res-wrap{{margin-top:14px}}
.res-header{{display:flex;align-items:center;gap:8px;margin-bottom:8px}}
.res-label{{font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--muted)}}
.status-pill{{font-size:11px;padding:2px 8px;border-radius:99px;font-weight:600}}
.ok{{background:rgba(74,222,128,.1);color:var(--green);border:1px solid rgba(74,222,128,.2)}}
.err{{background:rgba(248,113,113,.1);color:var(--red);border:1px solid rgba(248,113,113,.2)}}
.provider-used{{font-size:11px;color:#86efac;margin-bottom:3px}}
.res-box{{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:13px;font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:320px;overflow-y:auto;color:var(--text);display:none;line-height:1.55}}
.res-box.v{{display:block}}
.img-out{{margin-top:14px;max-width:100%;border-radius:var(--r-sm);border:1px solid var(--border);display:none}}

/* ── Providers list ── */
.prov-table{{display:flex;flex-direction:column;gap:1px;border-radius:var(--r);overflow:hidden;border:1px solid var(--border)}}
.prov-row{{display:flex;align-items:center;gap:12px;padding:11px 16px;background:var(--surface);transition:background .12s}}
.prov-row:hover{{background:var(--surface2)}}
.prov-dot{{width:6px;height:6px;border-radius:50%;background:var(--green);flex-shrink:0}}
.prov-name{{font-family:var(--mono);font-size:12px;color:var(--accent);min-width:160px;flex-shrink:0}}
.prov-desc{{font-size:12.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.prov-section-label{{font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-bottom:8px;margin-top:20px}}
.prov-section-label:first-child{{margin-top:0}}
code{{background:var(--surface2);padding:1px 6px;border-radius:4px;font-family:var(--mono);font-size:12px;color:var(--accent)}}

@media(max-width:600px){{
  header{{padding:14px 18px}}
  .wrap{{padding:32px 16px 80px}}
  .hero h1{{font-size:22px}}
  .sum,.prov-desc{{display:none}}
  .prov-name{{min-width:unset}}
}}
</style>
</head>
<body>

<!-- Auth Modal -->
<div class="overlay" id="auth-overlay" onclick="overlayClick(event)">
  <div class="modal">
    <button class="modal-close" onclick="closeModal()">✕</button>
    <h2 id="modal-title">Masuk</h2>
    <p class="sub" id="modal-sub">Gunakan API key Anda untuk mengakses semua endpoint</p>
    <div class="tab-row">
      <button class="tab active" id="tab-login" onclick="switchTab('login')">Login</button>
      <button class="tab" id="tab-register" onclick="switchTab('register')">Daftar</button>
    </div>
    <div id="form-login">
      <div class="field"><label>Email / Username</label><input id="m-email" placeholder="email@domain.com" autocomplete="email"/></div>
      <div class="field"><label>Password</label><input id="m-pass" type="password" placeholder="••••••••" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()"/></div>
      <button class="btn" onclick="doLogin()"><span>Masuk</span><div class="spin" id="sp-login"></div></button>
    </div>
    <div id="form-register" style="display:none">
      <div class="field"><label>Username</label><input id="m-uname" placeholder="username" autocomplete="username"/></div>
      <div class="field"><label>Email</label><input id="m-remail" placeholder="email@domain.com" autocomplete="email"/></div>
      <div class="field"><label>Password <span style="color:var(--muted2);font-size:11px">(min. 6 karakter)</span></label><input id="m-rpass" type="password" placeholder="••••••••" autocomplete="new-password" onkeydown="if(event.key==='Enter')doRegister()"/></div>
      <button class="btn" onclick="doRegister()"><span>Buat Akun</span><div class="spin" id="sp-reg"></div></button>
    </div>
    <div class="modal-err" id="modal-err"></div>
  </div>
</div>

<header>
  <div class="logo">multi<em>ai</em></div>
  <div class="header-right">
    <span class="version-pill">v4 · OpenAI Compatible</span>
    <div id="auth-header-guest">
      <button class="auth-btn" onclick="openModal()">Login / Daftar</button>
    </div>
    <div class="auth-user" id="auth-header-user" style="display:none">
      <span class="auth-uname" id="auth-uname-label"></span>
      <button class="auth-logout" onclick="doLogout()">Logout</button>
    </div>
  </div>
</header>

<div class="wrap">

  <div class="hero">
    <h1>AI API</h1>
    <p>Unified API dengan auto-fallback ke {len(CHAT_PROVIDERS)} model AI. Format kompatibel dengan OpenAI Chat Completions.</p>
    <div class="stats">
      <div class="stat"><div class="stat-n">{len(CHAT_PROVIDERS)}</div><div class="stat-l">Chat</div></div>
      <div class="stat"><div class="stat-n">{len(IMAGE_PROVIDERS)}</div><div class="stat-l">Image</div></div>
      <div class="stat"><div class="stat-n">{len(AUDIO_PROVIDERS)}</div><div class="stat-l">Audio</div></div>
    </div>
  </div>

  <div class="baseurl-box">
    <span class="baseurl-label">Base URL</span>
    <span class="baseurl-val" id="base-url-val">loading...</span>
    <button class="copy-btn" id="copy-base-btn" onclick="copyBase()">Copy</button>
  </div>

  <div class="lock-notice" id="lock-notice">
    <span>Semua endpoint memerlukan API key.</span>
    <button class="auth-btn" style="font-size:12px;padding:5px 14px" onclick="openModal()">Login / Daftar</button>
  </div>

  <div class="apikey-bar" id="apikey-bar">
    <span class="apikey-label">API Key</span>
    <span class="apikey-val" id="apikey-display"></span>
    <div class="apikey-actions">
      <button id="copy-key-btn" onclick="copyApiKey()">Copy</button>
      <button onclick="doRegenKey()">Regenerate</button>
    </div>
  </div>

  <!-- ── Endpoints ── -->
  <div class="sec-title">Endpoints</div>

  <!-- POST /v1/chat/completions -->
  <div class="card">
    <div class="card-head" onclick="toggle(this)">
      <span class="mth post">POST</span>
      <span class="ep">/v1/chat/completions<span class="tag tag-compat">OpenAI Compatible</span></span>
      <span class="sum">Chat AI · Tool Calling</span>
    </div>
    <div class="card-body">
      <div class="url-preview"><strong>POST</strong> <span class="base-url-span"></span>/v1/chat/completions</div>
      <p class="card-desc">Endpoint utama. Support <code>messages</code>, <code>tools</code>, <code>tool_choice</code>, dan <code>conversation_id</code> untuk multi-turn memory. Compatible dengan LangChain, AutoGen, CrewAI.</p>
      <div class="field">
        <label>Pesan <span class="req">*</span></label>
        <textarea id="v1-prompt" placeholder="Tulis pesan..."></textarea>
      </div>
      <div class="field">
        <label>System prompt <span class="opt">(opsional)</span></label>
        <input id="v1-system" placeholder="Kamu adalah asisten yang membantu..."/>
      </div>
      <div class="field">
        <label>Conversation ID <span class="opt">(opsional — untuk melanjutkan percakapan)</span></label>
        <input id="v1-conv-id" placeholder="Kosongkan untuk percakapan baru"/>
      </div>
      <div class="field">
        <label>Tools <span class="opt">(JSON array, opsional)</span></label>
        <textarea id="v1-tools" style="min-height:80px;font-family:var(--mono);font-size:12px" placeholder='[{{"type":"function","function":{{"name":"get_weather","description":"Get weather","parameters":{{"type":"object","properties":{{"location":{{"type":"string"}}}},"required":["location"]}}}}}}]'></textarea>
      </div>
      <button class="btn" onclick="execV1()"><span>Kirim</span><div class="spin" id="sp-v1"></div></button>
      <div class="res-wrap" id="wr-v1"></div>
    </div>
  </div>

  <!-- POST /image -->
  <div class="card">
    <div class="card-head" onclick="toggle(this)">
      <span class="mth post">POST</span>
      <span class="ep">/image<span class="tag tag-auto">Auto Fallback</span></span>
      <span class="sum">Generate gambar</span>
    </div>
    <div class="card-body">
      <div class="url-preview"><strong>POST</strong> <span class="base-url-span"></span>/image</div>
      <div class="field">
        <label>Prompt <span class="req">*</span></label>
        <textarea id="au-img-p" placeholder="Deskripsi gambar yang ingin dibuat..."></textarea>
      </div>
      <div class="row">
        <div class="field"><label>Width</label><input id="au-img-w" type="number" value="1024"/></div>
        <div class="field"><label>Height</label><input id="au-img-h" type="number" value="1024"/></div>
      </div>
      <button class="btn" onclick="execAutoImage()"><span>Generate</span><div class="spin" id="sp-au-img"></div></button>
      <div class="res-wrap" id="wr-au-img"></div>
      <img id="img-au-out" class="img-out"/>
    </div>
  </div>

  <!-- POST /audio -->
  <div class="card">
    <div class="card-head" onclick="toggle(this)">
      <span class="mth post">POST</span>
      <span class="ep">/audio<span class="tag tag-auto">Auto Fallback</span></span>
      <span class="sum">Text to Speech</span>
    </div>
    <div class="card-body">
      <div class="url-preview"><strong>POST</strong> <span class="base-url-span"></span>/audio</div>
      <div class="field">
        <label>Teks <span class="req">*</span></label>
        <textarea id="au-aud-text" placeholder="Teks yang akan diubah menjadi suara..."></textarea>
      </div>
      <button class="btn" onclick="execAutoAudio()"><span>Generate Audio</span><div class="spin" id="sp-au-aud"></div></button>
      <div class="res-wrap" id="wr-au-aud"></div>
    </div>
  </div>

  <!-- ── Providers ── -->
  <div class="sec-title">Providers</div>

  <div class="prov-section-label">Chat — {len(CHAT_PROVIDERS)} aktif · auto-fallback berurutan</div>
  <div class="prov-table">{chat_provider_rows}</div>

  <div class="prov-section-label">Image</div>
  <div class="prov-table">{image_provider_rows}</div>

  <div class="prov-section-label">Audio</div>
  <div class="prov-table">{audio_provider_rows}</div>

</div>

<script>
const BASE = window.location.origin;
document.getElementById('base-url-val').textContent = BASE;
document.querySelectorAll('.base-url-span').forEach(el => el.textContent = BASE);

// ── Auth state ──
let _apiKey = localStorage.getItem('api_key') || '';
let _username = localStorage.getItem('username') || '';

function authHeaders() {{
  const h = {{'Content-Type': 'application/json'}};
  if (_apiKey) h['Authorization'] = 'Bearer ' + _apiKey;
  return h;
}}
function setSession(k, u) {{
  _apiKey = k; _username = u;
  localStorage.setItem('api_key', k);
  localStorage.setItem('username', u);
  renderAuthState();
}}
function clearSession() {{
  _apiKey = ''; _username = '';
  localStorage.removeItem('api_key');
  localStorage.removeItem('username');
  renderAuthState();
}}
function renderAuthState() {{
  const in_ = !!_apiKey;
  document.getElementById('auth-header-guest').style.display = in_ ? 'none' : 'block';
  document.getElementById('auth-header-user').style.display  = in_ ? 'flex' : 'none';
  if (in_) document.getElementById('auth-uname-label').textContent = _username;
  const bar = document.getElementById('apikey-bar');
  const notice = document.getElementById('lock-notice');
  if (in_) {{
    bar.classList.add('show'); notice.classList.remove('show');
    document.getElementById('apikey-display').textContent = _apiKey;
  }} else {{
    bar.classList.remove('show'); notice.classList.add('show');
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
  const body = {{
    messages: [{{role:'user', content: document.getElementById('v1-prompt').value}}],
    conversation_id: document.getElementById('v1-conv-id').value || undefined,
    system: document.getElementById('v1-system').value || undefined,
    tools,
  }};
  try {{
    const r = await fetch('/v1/chat/completions', {{method:'POST',headers:authHeaders(),body:JSON.stringify(body)}});
    const d = await r.json();
    showResult('wr-v1','sp-v1',r.status,d,{{provider:d.provider_used,conv_id:d.conversation_id}});
  }} catch(e) {{ showResult('wr-v1','sp-v1',0,e.message); }}
}}

// ── /image ──
function execAutoImage() {{
  postJSON('/image', {{
    prompt: document.getElementById('au-img-p').value,
    width: +document.getElementById('au-img-w').value || 1024,
    height: +document.getElementById('au-img-h').value || 1024,
  }}, 'wr-au-img', 'sp-au-img', 'img-au-out');
}}

// ── /audio ──
function execAutoAudio() {{
  postJSON('/audio', {{text: document.getElementById('au-aud-text').value}}, 'wr-au-aud', 'sp-au-aud');
}}
</script>
</body>
</html>"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
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


@app.route("/providers", methods=["GET"])
def list_providers_legacy():
    return jsonify({
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

    system_parts = []
    if system_text:
        system_parts.append(system_text)
    if tools and tool_choice != "none":
        system_parts.append(build_tool_system_prompt(tools, forced_tool_name=forced_tool_name))

    final_messages = []
    if system_parts:
        final_messages.append({"role": "system", "content": "\n\n".join(system_parts)})

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
    # Tidak meneruskan requested_model ke provider — tiap provider pakai model konfigurasinya sendiri
    raw_text, provider_used, errors = run_chat_fallback(final_messages, None, require_tool_call=need_tc)

    if not raw_text:
        return jsonify({"error": "Semua provider gagal.", "details": errors}), 503

    # model label di response: pakai nama yang diminta client jika ada, fallback ke provider_used
    response_model_label = requested_model or provider_used

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
        resp = build_completion_response(None, response_model_label, tool_calls=tool_calls)
        resp["provider_used"] = provider_used
        resp["conversation_id"] = conv_id
        return jsonify(resp)

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
    resp = build_completion_response(raw_text, response_model_label)
    resp["provider_used"] = provider_used
    resp["conversation_id"] = conv_id
    return jsonify(resp)


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
    data, err, code = parse_body("prompt")
    if err:
        return err, code
    try:
        url = make_image_url(
            data["prompt"],
            data.get("model", "sana"),
            data.get("width", 1024),
            data.get("height", 1024),
        )
        log_api_request("/image", "pollinations", True)
        return jsonify({"provider_used": "pollinations", "image_urls": [url]})
    except Exception as e:
        log_api_request("/image", "pollinations", False, str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/audio", methods=["POST"])
def audio_auto():
    data, err, code = parse_body("text")
    if err:
        return err, code
    url, used, errors = run_audio_fallback(data["text"], data.get("model"))
    if url:
        log_api_request("/audio", used, True)
        return jsonify({"provider_used": used, "audio_url": url, "skipped": errors})
    log_api_request("/audio", None, False, "Semua provider audio gagal")
    return jsonify({"error": "Semua provider audio gagal.", "details": errors}), 503


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
    try:
        url = make_image_url(
            data["prompt"],
            data.get("model") or IMAGE_PROVIDERS[pk]["model"],
            data.get("width", 1024),
            data.get("height", 1024),
        )
        log_api_request(f"/image/{pk}", pk, True)
        return jsonify({"provider": pk, "image_urls": [url]})
    except Exception as e:
        log_api_request(f"/image/{pk}", pk, False, str(e))
        return jsonify({"error": str(e), "provider": pk}), 500


@app.route("/audio/<provider_key>", methods=["POST"])
def audio_specific(provider_key):
    pk = provider_key.lower()
    if pk not in AUDIO_PROVIDERS:
        return jsonify({"error": f"Provider '{pk}' tidak ada.", "tersedia": AUDIO_ORDER}), 404
    data, err, code = parse_body("text")
    if err:
        return err, code
    cfg = AUDIO_PROVIDERS[pk]
    try:
        resp = g4f_client.chat.completions.create(
            model=data.get("model") or cfg["model"],
            provider=cfg["provider"],
            messages=[{"role": "user", "content": data["text"]}],
        )
        audio_url = resp.choices[0].message.content if resp.choices else None
        log_api_request(f"/audio/{pk}", pk, True)
        return jsonify({"provider": pk, "audio_url": audio_url})
    except Exception as e:
        log_api_request(f"/audio/{pk}", pk, False, str(e))
        return jsonify({"error": str(e), "provider": pk}), 500


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
    conn = get_pg()
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


if __name__ == "__main__":
    # Inisialisasi koneksi database saat startup
    get_pg()
    app.run(host="0.0.0.0", port=5000, debug=False)
