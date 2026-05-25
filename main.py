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
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DzeckAPI — AI Gateway</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#1a1917;--surface:#242220;--surface2:#2c2a28;--surface3:#343230;
  --border:#3a3734;--border-hi:#4e4a46;
  --text:#ede8e0;--sub:#a09488;--muted:#6e6560;--muted2:#4e4a46;
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
.logo-icon{{width:24px;height:24px;background:var(--accent);border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;color:#fff;flex-shrink:0}}
.header-center{{display:flex;align-items:center;gap:5px}}
.hpill{{font-size:11px;font-weight:500;padding:3px 10px;border-radius:99px;border:1px solid var(--border);color:var(--muted);background:var(--surface)}}
.hpill.live{{border-color:var(--border-hi);color:var(--sub)}}
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
    <div class="logo-icon">D</div>
    <span class="logo-name">DzeckAPI</span>
  </div>
  <div class="header-center">
    <span class="hpill">v4</span>
    <span class="hpill">OpenAI Compatible</span>
    <span class="hpill green">● Live</span>
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
        <p class="hero-sub">Unified API with auto-fallback across {len(CHAT_PROVIDERS)} AI models. Drop-in replacement for OpenAI Chat Completions.</p>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-n">{len(CHAT_PROVIDERS)}</div><div class="stat-l">Chat Models</div></div>
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
      <span class="ep">/image<span class="badge">Auto Fallback</span></span>
      <span class="ep-meta">Image Generation</span>
      <span class="chevron">▾</span>
    </div>
    <div class="card-body">
      <div class="url-bar"><span class="mth post">POST</span><span class="url-text base-url-span"></span><span style="color:var(--muted)">/image</span></div>
      <div class="field">
        <label>Prompt<span class="req">*</span></label>
        <textarea id="au-img-p" placeholder="Describe the image you want to generate..."></textarea>
      </div>
      <div class="row">
        <div class="field"><label>Width</label><input id="au-img-w" type="number" value="1024"/></div>
        <div class="field"><label>Height</label><input id="au-img-h" type="number" value="1024"/></div>
      </div>
      <div class="form-actions">
        <button class="btn" onclick="execAutoImage()"><span>Generate</span><div class="spin" id="sp-au-img"></div></button>
      </div>
      <div class="res-wrap" id="wr-au-img"></div>
      <img id="img-au-out" class="img-out"/>
    </div>
  </div>

  <!-- POST /audio -->
  <div class="card">
    <div class="card-head" onclick="toggle(this)">
      <span class="mth post">POST</span>
      <span class="ep">/audio<span class="badge">Auto Fallback</span></span>
      <span class="ep-meta">Text to Speech</span>
      <span class="chevron">▾</span>
    </div>
    <div class="card-body">
      <div class="url-bar"><span class="mth post">POST</span><span class="url-text base-url-span"></span><span style="color:var(--muted)">/audio</span></div>
      <div class="field">
        <label>Text<span class="req">*</span></label>
        <textarea id="au-aud-text" placeholder="Enter text to convert to speech..."></textarea>
      </div>
      <div class="form-actions">
        <button class="btn" onclick="execAutoAudio()"><span>Generate Audio</span><div class="spin" id="sp-au-aud"></div></button>
      </div>
      <div class="res-wrap" id="wr-au-aud"></div>
    </div>
  </div>

  <div class="sec-head" style="margin-top:36px"><span class="sec-title">Providers</span><span class="sec-line"></span></div>

  <div class="prov-table">
    <div class="prov-sub-head">Chat — {len(CHAT_PROVIDERS)} active · sequential fallback</div>
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
