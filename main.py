from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import random
import string
import psycopg2
import psycopg2.extras
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ── CONFIG ──────────────────────────────────────────────────────
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "ton_mot_de_passe_admin")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
MAX_LOGS     = 200

CODE_VALUE   = "Fpsbn:Fpsbn:True"
BANNER_VALUE = "Banner:Banner:True"
BANNER_CODES = {"bob", "freez1x", "nezz", "pinpin", "sabry"}

# ── DATABASE ─────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode="disable")
    conn.autocommit = True
    return conn

def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    code_id        TEXT PRIMARY KEY,
                    value          TEXT NOT NULL,
                    locked_ip      TEXT,
                    player_name    TEXT,
                    fivem_name     TEXT,
                    first_seen     TIMESTAMPTZ,
                    last_seen      TIMESTAMPTZ,
                    expires_at     TIMESTAMPTZ,
                    duration_days  INTEGER,
                    banner         TEXT DEFAULT '',
                    theme          TEXT DEFAULT '',
                    lua_config     TEXT DEFAULT '',
                    created_at     TIMESTAMPTZ DEFAULT NOW()
                );
                -- Migrations : ajouter les colonnes si elles n'existent pas encore
                ALTER TABLE codes ADD COLUMN IF NOT EXISTS duration_days INTEGER;
                ALTER TABLE codes ADD COLUMN IF NOT EXISTS lua_config TEXT DEFAULT '';
                CREATE TABLE IF NOT EXISTS banned_ips (
                    ip TEXT PRIMARY KEY,
                    banned_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS logs (
                    id         SERIAL PRIMARY KEY,
                    ts         TIMESTAMPTZ DEFAULT NOW(),
                    action     TEXT,
                    details    TEXT,
                    ip         TEXT DEFAULT '',
                    code       TEXT DEFAULT '',
                    is_admin   BOOLEAN DEFAULT FALSE
                );
            """)

try:
    init_db()
    print("[DB] Tables initialisées avec succès")
except Exception as e:
    print(f"[DB] Erreur init: {e}")

# ── UTILS ────────────────────────────────────────────────────────
def generate_code_id():
    return ''.join(random.choices(string.digits, k=12))

def get_real_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def check_secret(body):
    return body.get("secret") == ADMIN_SECRET

def is_expired(expires_at):
    if not expires_at:
        return False
    from datetime import timezone
    now = datetime.now(timezone.utc)
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except Exception:
            return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < now

# ── CODES ────────────────────────────────────────────────────────
def load_all_codes():
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM codes")
            rows = cur.fetchall()
    codes = {}
    for row in rows:
        codes[row["code_id"]] = {
            "locked_ip":     row["locked_ip"],
            "player_name":   row["player_name"],
            "fivem_name":    row["fivem_name"],
            "first_seen":    row["first_seen"].isoformat() if row["first_seen"] else None,
            "last_seen":     row["last_seen"].isoformat()  if row["last_seen"]  else None,
            "expires_at":    row["expires_at"].isoformat() if row["expires_at"] else None,
            "duration_days": row["duration_days"],
            "banner":        row["banner"] or "",
            "theme":         row["theme"]  or "",
            "lua_config":    row["lua_config"] or "",
            "created_at":    row["created_at"].isoformat() if row["created_at"] else None,
        }
    return codes

def code_exists(code_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM codes WHERE code_id = %s", (code_id,))
            return cur.fetchone() is not None

def get_code_row(code_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM codes WHERE code_id = %s", (code_id,))
            return cur.fetchone()

# ── BANNED IPs ───────────────────────────────────────────────────
def get_banned_ips():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT ip FROM banned_ips")
            return [row[0] for row in cur.fetchall()]

# ── LOGS ─────────────────────────────────────────────────────────
def add_log(action, details, ip="", code="", admin=False):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO logs (action, details, ip, code, is_admin) VALUES (%s, %s, %s, %s, %s)",
                (action, details, ip, code, admin)
            )
            cur.execute(f"DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY ts DESC LIMIT {MAX_LOGS})")

def load_logs(limit=200):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM logs ORDER BY ts DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
    return [{
        "ts":      row["ts"].strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action":  row["action"],
        "details": row["details"],
        "ip":      row["ip"] or "",
        "code":    row["code"] or "",
        "admin":   row["is_admin"]
    } for row in rows]


@app.route("/status", methods=["GET"])
def status():
    if request.args.get("secret", "") != ADMIN_SECRET:
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    return jsonify({"ok": True, "codes": load_all_codes(), "banned_ips": get_banned_ips(), "logs": load_logs()})


@app.route("/check", methods=["GET"])
def check():
    code_id = (request.args.get("code") or "").strip()
    ip      = get_real_ip()
    if not code_id:
        return jsonify({"ok": False, "reason": "missing_fields"})
    row = get_code_row(code_id)
    if not row:
        add_log("CHECK_FAIL", f"Code invalide depuis {ip}", ip=ip, code=code_id)
        return jsonify({"ok": False, "reason": "invalid_code"})
    if ip in get_banned_ips():
        add_log("CHECK_FAIL", "IP bannie bloquée", ip=ip, code=code_id)
        return jsonify({"ok": False, "reason": "ip_banned"})
    if is_expired(row["expires_at"]):
        add_log("CHECK_FAIL", "Code expiré", ip=ip, code=code_id)
        return jsonify({"ok": False, "reason": "expired"})
    if row["locked_ip"] and row["locked_ip"] != ip:
        add_log("CHECK_FAIL", f"IP mismatch — attendu {row['locked_ip']}, reçu {ip}", ip=ip, code=code_id)
        return jsonify({"ok": False, "reason": "ip_mismatch"})
    return jsonify({"ok": True, "banner": row["banner"] or "", "theme": row["theme"] or "", "ip": ip, "lua_config": row["lua_config"] or ""})


@app.route("/config/save", methods=["GET", "POST"])
def config_save():
    """Sauvegarde la config Lua pour une key donnée (GET ou POST)."""
    if request.method == "POST":
        body    = request.get_json(force=True) or {}
        code_id = (body.get("code") or "").strip()
        config  = body.get("config") or ""
    else:
        code_id = (request.args.get("code") or "").strip()
        config  = (request.args.get("config") or "")
    ip = get_real_ip()
    if not code_id:
        return jsonify({"ok": False, "reason": "missing_fields"})
    row = get_code_row(code_id)
    if not row:
        return jsonify({"ok": False, "reason": "invalid_code"})
    if row["locked_ip"] and row["locked_ip"] != ip:
        return jsonify({"ok": False, "reason": "ip_mismatch"})
    if is_expired(row["expires_at"]):
        return jsonify({"ok": False, "reason": "expired"})
    if len(config) > 8000:
        return jsonify({"ok": False, "reason": "config_too_large"})
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE codes SET lua_config = %s WHERE code_id = %s", (config, code_id))
    return jsonify({"ok": True})


@app.route("/config/load", methods=["GET"])
def config_load():
    """Charge la config Lua d'une key."""
    code_id = (request.args.get("code") or "").strip()
    ip      = get_real_ip()
    if not code_id:
        return jsonify({"ok": False, "reason": "missing_fields"})
    row = get_code_row(code_id)
    if not row:
        return jsonify({"ok": False, "reason": "invalid_code"})
    if row["locked_ip"] and row["locked_ip"] != ip:
        return jsonify({"ok": False, "reason": "ip_mismatch"})
    if is_expired(row["expires_at"]):
        return jsonify({"ok": False, "reason": "expired"})
    return jsonify({"ok": True, "config": row["lua_config"] or ""})


@app.route("/claim", methods=["POST"])
def claim():
    body        = request.get_json(force=True) or {}
    code_id     = (body.get("code")        or "").strip()
    player_name = (body.get("player_name") or "").strip()
    fivem_name  = (body.get("fivem_name")  or "").strip()
    ip          = get_real_ip()
    if not code_id:
        return jsonify({"ok": False, "reason": "missing_fields"})
    row = get_code_row(code_id)
    if not row:
        return jsonify({"ok": False, "reason": "invalid_code"})
    if ip in get_banned_ips():
        return jsonify({"ok": False, "reason": "ip_banned"})
    if row["locked_ip"] and row["locked_ip"] != ip:
        return jsonify({"ok": False, "reason": "taken"})
    is_first = not row["locked_ip"]
    now_dt   = datetime.utcnow()

    # ── Timer démarre à la 1ère utilisation ──────────────────────────
    computed_expires = None
    if is_first and row["duration_days"]:
        from datetime import timezone, timedelta
        computed_expires = datetime.now(timezone.utc) + timedelta(days=row["duration_days"])

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE codes SET
                    locked_ip   = COALESCE(locked_ip, %s),
                    first_seen  = COALESCE(first_seen, %s),
                    last_seen   = %s,
                    player_name = COALESCE(%s, player_name),
                    fivem_name  = COALESCE(%s, fivem_name),
                    expires_at  = CASE WHEN locked_ip IS NULL AND %s IS NOT NULL THEN %s ELSE expires_at END
                WHERE code_id = %s
            """, (ip, now_dt, now_dt, player_name or None, fivem_name or None,
                  computed_expires, computed_expires, code_id))
    display = fivem_name or player_name or code_id
    action  = "FIRST_CONNECTION" if is_first else "CONNECTION"
    label   = "1ère connexion" if is_first else "Reconnexion"
    add_log(action, f"{label} — {display}", ip=ip, code=code_id)
    return jsonify({"ok": True})


@app.route("/generate", methods=["POST"])
def generate():
    body = request.get_json(force=True) or {}
    if not check_secret(body):
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    count         = min(int(body.get("count", 1)), 20)
    duration_days = body.get("duration_days")   # None = illimité
    if duration_days is not None:
        try:
            duration_days = int(duration_days)
        except Exception:
            duration_days = None
    generated = []
    with get_db() as conn:
        with conn.cursor() as cur:
            for _ in range(count):
                for _ in range(30):
                    code_id = generate_code_id()
                    cur.execute("SELECT 1 FROM codes WHERE code_id = %s", (code_id,))
                    if not cur.fetchone():
                        break
                cur.execute(
                    "INSERT INTO codes (code_id, value, duration_days, created_at) VALUES (%s, %s, %s, NOW())",
                    (code_id, CODE_VALUE, duration_days)
                )
                generated.append(code_id)
    add_log("ADMIN_GENERATE", f"{len(generated)} code(s): {', '.join(['CODE_'+c for c in generated])}", admin=True)
    return jsonify({"ok": True, "codes": generated})


@app.route("/add", methods=["POST"])
def add():
    body = request.get_json(force=True) or {}
    if not check_secret(body):
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    code_id = (body.get("code") or "").strip().lower()
    if not code_id:
        return jsonify({"ok": False, "reason": "missing_code"})
    if code_exists(code_id):
        return jsonify({"ok": False, "reason": "already_exists"})
    value         = BANNER_VALUE if code_id in BANNER_CODES else CODE_VALUE
    duration_days = body.get("duration_days")
    if duration_days is not None:
        try:
            duration_days = int(duration_days)
        except Exception:
            duration_days = None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO codes (code_id, value, duration_days, created_at) VALUES (%s, %s, %s, NOW())",
                (code_id, value, duration_days)
            )
    add_log("ADMIN_ADD", f"Code créé: CODE_{code_id} = {value}", admin=True)
    return jsonify({"ok": True, "code": code_id})


@app.route("/delete", methods=["POST"])
def delete():
    body = request.get_json(force=True) or {}
    if not check_secret(body):
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    code_id = (body.get("code") or "").strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM codes WHERE code_id = %s", (code_id,))
    add_log("ADMIN_DELETE", "Code supprimé", code=code_id, admin=True)
    return jsonify({"ok": True})


@app.route("/reset", methods=["POST"])
def reset():
    body = request.get_json(force=True) or {}
    if not check_secret(body):
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    code_id = (body.get("code") or "").strip()
    row = get_code_row(code_id)
    if not row:
        return jsonify({"ok": False, "reason": "code_not_found"})
    old_ip   = row["locked_ip"] or "—"
    old_name = row["fivem_name"] or row["player_name"] or "—"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE codes SET locked_ip=NULL, player_name=NULL, fivem_name=NULL, first_seen=NULL, last_seen=NULL WHERE code_id=%s", (code_id,))
    add_log("ADMIN_RESET", f"Libéré — était: {old_name} / {old_ip}", code=code_id, admin=True)
    return jsonify({"ok": True})


@app.route("/reset-all", methods=["POST"])
def reset_all():
    body = request.get_json(force=True) or {}
    if not check_secret(body):
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE codes SET locked_ip=NULL, player_name=NULL, fivem_name=NULL, first_seen=NULL, last_seen=NULL")
            cur.execute("SELECT COUNT(*) FROM codes")
            count = cur.fetchone()[0]
    add_log("ADMIN_RESET_ALL", f"Reset global — {count} codes libérés", admin=True)
    return jsonify({"ok": True})


@app.route("/edit", methods=["POST"])
def edit():
    body = request.get_json(force=True) or {}
    if not check_secret(body):
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    code_id = (body.get("code") or "").strip()
    if not code_exists(code_id):
        return jsonify({"ok": False, "reason": "code_not_found"})
    banner        = body.get("banner")
    theme         = body.get("theme")
    duration_days = body.get("duration_days")
    if duration_days is not None:
        try:
            duration_days = int(duration_days)
        except Exception:
            duration_days = None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE codes SET
                    duration_days = COALESCE(%s, duration_days),
                    banner        = COALESCE(%s, banner),
                    theme         = COALESCE(%s, theme)
                WHERE code_id = %s
            """, (duration_days, banner, theme, code_id))
    add_log("ADMIN_EDIT", "Code modifié", code=code_id, admin=True)
    return jsonify({"ok": True})


@app.route("/ban-ip", methods=["POST"])
def ban_ip():
    body = request.get_json(force=True) or {}
    if not check_secret(body):
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    ip = (body.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "reason": "missing_ip"})
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO banned_ips (ip) VALUES (%s) ON CONFLICT DO NOTHING", (ip,))
    add_log("ADMIN_BAN_IP", "IP bannie", ip=ip, admin=True)
    return jsonify({"ok": True})


@app.route("/unban-ip", methods=["POST"])
def unban_ip():
    body = request.get_json(force=True) or {}
    if not check_secret(body):
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    ip = (body.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "reason": "missing_ip"})
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM banned_ips WHERE ip = %s", (ip,))
    add_log("ADMIN_UNBAN_IP", "IP débannie", ip=ip, admin=True)
    return jsonify({"ok": True})


@app.route("/logs", methods=["GET"])
def get_logs():
    if request.args.get("secret", "") != ADMIN_SECRET:
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    limit = int(request.args.get("limit", 100))
    return jsonify({"ok": True, "logs": load_logs(limit)})


@app.route("/debug", methods=["GET"])
def debug():
    if request.args.get("secret", "") != ADMIN_SECRET:
        return jsonify({"ok": False, "reason": "unauthorized"}), 403
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM codes")
                codes_count = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM banned_ips")
                banned_count = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM logs")
                logs_count = cur.fetchone()[0]
        db_ok = True; db_error = None
    except Exception as e:
        db_ok = False; db_error = str(e)
        codes_count = banned_count = logs_count = 0
    return jsonify({"ok": True, "database": {"connected": db_ok, "error": db_error, "codes": codes_count, "banned_ips": banned_count, "logs": logs_count}})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
