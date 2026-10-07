#!/usr/bin/env python3
"""Mock Telegram Bot API for end-to-end tests of `aac listen --telegram`.

Bot API:  POST /bot<TOKEN>/<method>   (getMe, getUpdates, sendMessage, editMessageText, answerCallbackQuery)
Control:  GET  /_state                -> {"sent": [...], "edits": [...], "answers": [...], "methods": [...]}
          POST /_press {from, chat, message_id, data}   inject a button press
          POST /_say   {from, chat, text}               inject a chat message
"""
import json, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = sys.argv[2] if len(sys.argv) > 2 else "123456:E2E-TOKEN"
lock = threading.Condition()
state = {"sent": [], "edits": [], "answers": [], "methods": [], "updates": [], "next_mid": 0, "next_uid": 0}

def buttons(markup):
    if not markup:
        return []
    return [b["callback_data"] for row in markup.get("inline_keyboard", []) for b in row]

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/_state":
            with lock:
                self.reply({k: state[k] for k in ("sent", "edits", "answers", "methods")})
        else:
            self.reply({"ok": False}, 404)

    def push(self, upd):
        with lock:
            state["next_uid"] += 1
            upd["update_id"] = state["next_uid"]
            state["updates"].append(upd)
            lock.notify_all()

    def do_POST(self):
        b = self.body()
        if self.path == "/_press":
            self.push({"callback_query": {"id": "cb%d" % time.time_ns(), "from": {"id": b["from"], "is_bot": False, "first_name": "x"},
                       "message": {"message_id": b["message_id"], "chat": {"id": b["chat"], "type": "private"}}, "data": b["data"]}})
            return self.reply({"ok": True})
        if self.path == "/_say":
            self.push({"message": {"message_id": 7, "from": {"id": b["from"], "is_bot": False, "first_name": "x"},
                       "chat": {"id": b["chat"], "type": "private"}, "text": b["text"]}})
            return self.reply({"ok": True})
        parts = self.path.strip("/").split("/")
        if len(parts) != 2 or parts[0] != "bot" + TOKEN:
            return self.reply({"ok": False, "error_code": 401, "description": "Unauthorized"}, 401)
        m = parts[1]
        with lock:
            state["methods"].append(m)
        if m == "getMe":
            return self.reply({"ok": True, "result": {"id": 42, "is_bot": True, "username": "aac_e2e_bot"}})
        if m == "sendMessage":
            with lock:
                state["next_mid"] += 1
                msg = {"message_id": state["next_mid"], "chat_id": b["chat_id"], "text": b["text"], "buttons": buttons(b.get("reply_markup"))}
                state["sent"].append(msg)
            return self.reply({"ok": True, "result": {"message_id": msg["message_id"], "chat": {"id": b["chat_id"]}}})
        if m == "editMessageText":
            with lock:
                state["edits"].append({"message_id": b["message_id"], "text": b["text"], "buttons": buttons(b.get("reply_markup"))})
            return self.reply({"ok": True, "result": {"message_id": b["message_id"], "chat": {"id": b["chat_id"]}}})
        if m == "answerCallbackQuery":
            with lock:
                state["answers"].append(b.get("text", ""))
            return self.reply({"ok": True, "result": True})
        if m == "getUpdates":
            offset = b.get("offset", 0)
            deadline = time.time() + min(b.get("timeout", 0), 2)
            with lock:
                while True:
                    state["updates"] = [u for u in state["updates"] if u["update_id"] >= offset]
                    if state["updates"] or time.time() >= deadline:
                        return self.reply({"ok": True, "result": list(state["updates"])})
                    lock.wait(max(0.01, deadline - time.time()))
        return self.reply({"ok": False, "error_code": 404, "description": "Not Found"}, 404)

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
