from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import os
import json
import uuid
from typing import Dict, Any

# ----------------------------
# DATABASE CONFIG
# ----------------------------
# For XAMPP (no password):
# mysql+pymysql://root:@127.0.0.1:3306/silentchat
#
# For password:
# mysql+pymysql://root:password@127.0.0.1:3306/silentchat
#
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+pymysql://root:@127.0.0.1:3306/silentchat"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

# ----------------------------
# APP
# ----------------------------
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def root():
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    return {"ok": True, "has_ws": True}


# ----------------------------
# LIVE SOCKET STATE
# ----------------------------
rooms_live: Dict[str, Dict[str, WebSocket]] = {}


async def safe_send(ws: WebSocket, msg: Dict[str, Any]):
    await ws.send_text(json.dumps(msg))


# ----------------------------
# DATABASE HELPERS (SAFE)
# ----------------------------
def db_ok() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        print("DB NOT READY:", e)
        return False


def db_upsert_user_room_membership(room_id: str, client_id: str):
    with SessionLocal() as db:
        db.execute(text("INSERT IGNORE INTO users(id) VALUES (:id)"), {"id": client_id})
        db.execute(text("INSERT IGNORE INTO rooms(id) VALUES (:id)"), {"id": room_id})
        db.execute(
            text("INSERT IGNORE INTO room_members(room_id, user_id) VALUES (:r, :u)"),
            {"r": room_id, "u": client_id},
        )
        db.commit()


def db_save_message(room_id, sender_id, receiver_id, msg_type, iv_b64, ciphertext_b64):
    mid = str(uuid.uuid4())
    with SessionLocal() as db:
        db.execute(
            text("""
                INSERT INTO messages
                (id, room_id, sender_id, receiver_id, msg_type, iv_b64, ciphertext_b64)
                VALUES (:id, :room, :sender, :receiver, :type, :iv, :cipher)
            """),
            {
                "id": mid,
                "room": room_id,
                "sender": sender_id,
                "receiver": receiver_id,
                "type": msg_type,
                "iv": iv_b64,
                "cipher": ciphertext_b64,
            },
        )
        db.commit()


def db_load_history(room_id: str, client_id: str, limit: int = 50):
    with SessionLocal() as db:
        rows = db.execute(
            text("""
                SELECT id, room_id, sender_id, receiver_id,
                       msg_type, iv_b64, ciphertext_b64, created_at
                FROM messages
                WHERE room_id = :room
                  AND (
                    receiver_id IS NULL
                    OR receiver_id = :client
                    OR sender_id = :client
                  )
                ORDER BY created_at DESC
                LIMIT :lim
            """),
            {"room": room_id, "client": client_id, "lim": limit},
        ).mappings().all()

    rows.reverse()
    return [
        {
            "id": r["id"],
            "room": r["room_id"],
            "from": r["sender_id"],
            "to": r["receiver_id"],
            "msg_type": r["msg_type"],
            "iv": r["iv_b64"],
            "ciphertext": r["ciphertext_b64"],
            "created_at": str(r["created_at"]),
        }
        for r in rows
    ]


# ----------------------------
# WEBSOCKET
# ----------------------------
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    print("WS CONNECT ATTEMPT")
    await ws.accept()
    print("WS ACCEPTED")

    client_id = None
    room_id = None

    try:
        raw = await ws.receive_text()
        hello = json.loads(raw)

        if hello.get("type") != "join":
            await ws.close(code=1008)
            return

        room_id = hello.get("room")
        client_id = hello.get("client_id")

        if not room_id or not client_id:
            await ws.close(code=1008)
            return

        # Register live presence
        rooms_live.setdefault(room_id, {})
        rooms_live[room_id][client_id] = ws

        # DB (optional)
        if db_ok():
            try:
                db_upsert_user_room_membership(room_id, client_id)
            except Exception as e:
                print("DB UPSERT FAILED:", e)

        await safe_send(ws, {
            "type": "joined",
            "room": room_id,
            "client_id": client_id
        })

        # Send roster
        roster = list(rooms_live[room_id].keys())
        for sock in rooms_live[room_id].values():
            await safe_send(sock, {
                "type": "roster",
                "room": room_id,
                "clients": roster
            })

        # Send history
        history = []
        if db_ok():
            try:
                history = db_load_history(room_id, client_id)
            except Exception as e:
                print("DB HISTORY FAILED:", e)

        await safe_send(ws, {
            "type": "history",
            "room": room_id,
            "messages": history
        })

        # Main loop
        while True:
            msg = json.loads(await ws.receive_text())
            mtype = msg.get("type")

            if mtype == "pubkey":
                to_id = msg.get("to")
                if to_id in rooms_live.get(room_id, {}):
                    await safe_send(rooms_live[room_id][to_id], msg)

            elif mtype == "cipher":
                sender = msg.get("from")
                to_id = msg.get("to")
                iv = msg.get("iv")
                ciphertext = msg.get("ciphertext")
                msg_type = msg.get("msg_type", "unknown")

                if db_ok():
                    try:
                        db_save_message(room_id, sender, to_id, msg_type, iv, ciphertext)
                    except Exception as e:
                        print("DB SAVE FAILED:", e)

                if to_id in rooms_live.get(room_id, {}):
                    await safe_send(rooms_live[room_id][to_id], msg)

            elif mtype == "ping":
                await safe_send(ws, {"type": "pong"})

    except WebSocketDisconnect:
        print("WS DISCONNECT")
    except Exception as e:
        print("WS ERROR:", e)
    finally:
        if room_id and client_id and room_id in rooms_live:
            rooms_live[room_id].pop(client_id, None)
            if not rooms_live[room_id]:
                rooms_live.pop(room_id)
