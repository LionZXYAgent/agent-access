#!/usr/bin/env python3
"""End-to-end test: real ap-relay + `aac listen --headless --telegram` + `aac run` / `aac connect`,
against the mock Telegram Bot API. Uses the built-in `example` provider (no real vault, no real secrets).

Usage: e2e.py <aac-binary> <ap-relay-binary> [--listener-cmd-prefix "docker run ..."]
"""
import json, os, shlex, subprocess, sys, tempfile, time, urllib.request

AAC, RELAY = sys.argv[1], sys.argv[2]
LISTENER_PREFIX = shlex.split(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[3] == "--listener-cmd-prefix" else []
LISTENER_AAC = os.environ.get("LISTENER_AAC", AAC)
HOST = os.environ.get("E2E_HOST", "127.0.0.1")
TG_PORT, RELAY_PORT = 18081, 18080
TOKEN = "123456:E2E-TOKEN-abcdefghijklmnopqrstuvwxyz"
OWNER, STRANGER = 777000111, 999000222
SECRET = "ex@mple-p@ssw0rd!"  # example provider's demo password for example.com
TG = f"http://127.0.0.1:{TG_PORT}"
RELAY_URL = f"ws://{HOST}:{RELAY_PORT}"
here = os.path.dirname(os.path.abspath(__file__))
tmp = tempfile.mkdtemp(prefix="aac-e2e-")
results = []

def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""), flush=True)

def tg_state():
    return json.load(urllib.request.urlopen(TG + "/_state"))

def tg_post(path, obj):
    req = urllib.request.Request(TG + path, json.dumps(obj).encode(), {"Content-Type": "application/json"})
    urllib.request.urlopen(req).read()

def press(msg, action, who=OWNER, chat=OWNER):
    data = next(b for b in msg["buttons"] if b.endswith(":" + action))
    tg_post("/_press", {"from": who, "chat": chat, "message_id": msg["message_id"], "data": data})

def wait(pred, what, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        st = tg_state()
        r = pred(st)
        if r:
            return r
        time.sleep(0.1)
    raise AssertionError("timed out waiting for " + what)

def new_prompt(n_before):
    return wait(lambda st: len(st["sent"]) > n_before and st["sent"][n_before]["buttons"] and st["sent"][n_before], "prompt")

remote_home = os.path.join(tmp, "remote")
os.makedirs(remote_home)
def remote_env():
    e = dict(os.environ, HOME=remote_home, LLM="1", NO_COLOR="1")
    e.pop("AAC_TOKEN", None)
    return e

def aac_run(domain, token=None):
    cmd = [AAC, "run", "--relay-url", RELAY_URL, "--domain", domain, "--timeout", "60",
           "--env", "PW=password", "--env", "USER_NAME=username", "--"]
    if token:
        cmd[2:2] = ["--token", token]
    cmd += ["sh", "-c", 'echo "child: user=$USER_NAME pwlen=${#PW}"']
    return subprocess.Popen(cmd, env=remote_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def finish(p, timeout=60):
    out, err = p.communicate(timeout=timeout)
    return p.returncode, out, err

procs = []
try:
    procs.append(subprocess.Popen([sys.executable, os.path.join(here, "mock_telegram.py"), str(TG_PORT), TOKEN]))
    procs.append(subprocess.Popen([RELAY], env=dict(os.environ, BIND_ADDR=f"0.0.0.0:{RELAY_PORT}"),
                                  stdout=open(os.path.join(tmp, "relay.log"), "w"), stderr=subprocess.STDOUT))
    time.sleep(1)

    # ---------------- Headless listener, reusable PSK ----------------
    listen_home = os.path.join(tmp, "listener")
    os.makedirs(listen_home)
    token_file = os.path.join(listen_home, "psk-token")
    with open(os.path.join(listen_home, "bot-token"), "w") as f:
        f.write(TOKEN + "\n")
    lenv = dict(os.environ, HOME=listen_home, AAC_TELEGRAM_OWNER_ID=str(OWNER),
                AAC_TELEGRAM_API_URL=f"http://{HOST}:{TG_PORT}", AAC_TELEGRAM_TIMEOUT="6",
                AAC_TELEGRAM_BOT_TOKEN_FILE=os.path.join(listen_home, "bot-token"))
    lcmd = LISTENER_PREFIX + [LISTENER_AAC, "listen", "--headless", "--telegram", "--provider", "example",
                              "--reusable-psk", "--connection-name", "openclaw-e2e", "--token-file", token_file,
                              "--relay-url", RELAY_URL]
    if LISTENER_PREFIX:  # container: pass env via -e and mount the listener home
        lcmd = LISTENER_PREFIX[:-1] + sum([["-e", f"{k}={lenv[k]}"] for k in
               ("HOME", "AAC_TELEGRAM_OWNER_ID", "AAC_TELEGRAM_API_URL", "AAC_TELEGRAM_TIMEOUT", "AAC_TELEGRAM_BOT_TOKEN_FILE")], []) + \
               ["-v", f"{listen_home}:{listen_home}", LISTENER_PREFIX[-1]] + lcmd[len(LISTENER_PREFIX):]
    listen_log = open(os.path.join(tmp, "listener.log"), "w")
    listener = subprocess.Popen(lcmd, env=lenv, stdout=listen_log, stderr=subprocess.STDOUT)
    procs.append(listener)
    for _ in range(100):
        if os.path.exists(token_file) and open(token_file).read().strip():
            break
        time.sleep(0.2)
    psk = open(token_file).read().strip()
    check("headless listener starts, getMe ok, token written to file", len(psk) == 129 and "getMe" in tg_state()["methods"])
    check("token file is mode 0600", oct(os.stat(token_file).st_mode & 0o777) == "0o600")

    # 1. Allow once
    n = len(tg_state()["sent"])
    p = aac_run("example.com", token=psk)
    msg = new_prompt(n)
    check("prompt has 5 buttons (allow/decline/15m/1h/forever)", len(msg["buttons"]) == 5, msg["buttons"])
    check("prompt shows device name, query, request id, fields",
          all(s in msg["text"] for s in ("openclaw-e2e", 'domain "example.com"', "Request ID: ", "Fields to release: username, password")), msg["text"])
    check("prompt contains no secret", SECRET not in msg["text"] and "alice@example.com" not in msg["text"])
    press(msg, "a")
    rc, out, err = finish(p)
    check("allow once -> aac run injects credential into child env", rc == 0 and "child: user=alice@example.com pwlen=17" in out, (rc, out, err))
    check("secret not printed by aac run", SECRET not in out and SECRET not in err)
    wait(lambda st: any(e["message_id"] == msg["message_id"] and "ALLOWED once" in e["text"] for e in st["edits"]), "allow edit")
    check("message edited to ALLOWED once, buttons removed",
          any(e["message_id"] == msg["message_id"] and not e["buttons"] for e in tg_state()["edits"]))

    # 2. Replay of the same Allow button
    press(msg, "a")
    wait(lambda st: any("expired or was already handled" in a for a in st["answers"]), "replay answer")
    check("replayed callback rejected as expired", True)

    # 3. Decline
    n = len(tg_state()["sent"])
    p = aac_run("example.com")
    msg = new_prompt(n)
    press(msg, "d")
    rc, out, err = finish(p)
    check("decline -> aac run fails, child not run", rc != 0 and "child:" not in out, (rc, out, err[-300:]))

    # 4. Stranger press is ignored, then owner allows
    n = len(tg_state()["sent"])
    p = aac_run("example.com")
    msg = new_prompt(n)
    press(msg, "a", who=STRANGER, chat=STRANGER)
    press(msg, "a", who=STRANGER, chat=OWNER)
    wait(lambda st: st["answers"].count("Not authorized") >= 2, "not authorized answers")
    time.sleep(0.5)
    check("stranger presses rejected, request still pending", p.poll() is None)
    press(msg, "a")
    rc, out, err = finish(p)
    check("owner allow after stranger -> success", rc == 0 and "pwlen=17" in out, (rc, err[-300:]))

    # 5. Timeout auto-decline (AAC_TELEGRAM_TIMEOUT=6)
    n = len(tg_state()["sent"])
    p = aac_run("example.com")
    msg = new_prompt(n)
    rc, out, err = finish(p)
    check("unanswered -> auto-declined after timeout", rc != 0 and "child:" not in out, (rc, err[-300:]))
    wait(lambda st: any(e["message_id"] == msg["message_id"] and "TIMED OUT" in e["text"] for e in st["edits"]), "timeout edit")
    check("message edited to TIMED OUT", True)
    press(msg, "a")
    wait(lambda st: sum("expired" in a for a in st["answers"]) >= 2, "late press expired")
    check("late press after timeout rejected", True)

    # 6. Not-found domain: denied without a Telegram message
    n = len(tg_state()["sent"])
    rc, out, err = finish(aac_run("nope.invalid"))
    time.sleep(0.5)
    check("not-found request denied with no Telegram message", rc != 0 and len(tg_state()["sent"]) == n, (rc, len(tg_state()["sent"]), n))

    # 7. Grant 15m: first prompts, later identical requests auto-approved silently
    n = len(tg_state()["sent"])
    p = aac_run("example.com")
    msg = new_prompt(n)
    press(msg, "m15")
    rc, out, err = finish(p)
    check("Allow 15m -> success", rc == 0 and "pwlen=17" in out, (rc, err[-300:]))
    wait(lambda st: any(e["message_id"] == msg["message_id"] and "grant for 15 minutes" in e["text"] for e in st["edits"]), "grant edit")
    edit = [e for e in tg_state()["edits"] if e["message_id"] == msg["message_id"]][-1]
    check("grant message keeps a revoke button", len(edit["buttons"]) == 1 and edit["buttons"][0].endswith(":r"))
    n = len(tg_state()["sent"])
    ok = all(finish(aac_run("example.com"))[0] == 0 for _ in range(2))
    time.sleep(0.5)
    check("2 follow-up requests auto-approved under grant", ok)
    check("auto-approvals sent NO Telegram messages", len(tg_state()["sent"]) == n, (len(tg_state()["sent"]), n))
    # Different query (other domain in vault) from same device still prompts
    p = aac_run("github.com")
    m2 = new_prompt(n)
    check("different domain is outside grant scope -> prompts", 'domain "github.com"' in m2["text"])
    press(m2, "d")
    finish(p)

    # 8. /grants and /revoke all
    n = len(tg_state()["sent"])
    tg_post("/_say", {"from": STRANGER, "chat": STRANGER, "text": "/revoke all"})
    tg_post("/_say", {"from": OWNER, "chat": OWNER, "text": "/grants"})
    lst = wait(lambda st: next((m for m in st["sent"][n:] if m["text"].startswith("Active grants")), None), "grant list")
    check("/grants lists the grant (stranger /revoke ignored)", "#1 openclaw-e2e" in lst["text"] and len(lst["buttons"]) == 1, lst["text"])
    tg_post("/_say", {"from": OWNER, "chat": OWNER, "text": "/revoke all"})
    wait(lambda st: any("Revoked 1 grant" in m["text"] for m in st["sent"]), "revoke reply")
    n = len(tg_state()["sent"])
    p = aac_run("example.com")
    msg = new_prompt(n)
    check("after /revoke all the same request prompts again", True)

    # 9. Forever grant, revoke via button
    press(msg, "f")
    rc, out, err = finish(p)
    check("Allow forever -> success", rc == 0)
    wait(lambda st: any(e["message_id"] == msg["message_id"] and "until revoked" in e["text"] for e in st["edits"]), "forever edit")
    n = len(tg_state()["sent"])
    check("forever grant auto-approves", finish(aac_run("example.com"))[0] == 0 and len(tg_state()["sent"]) == n)
    edit = [e for e in tg_state()["edits"] if e["message_id"] == msg["message_id"]][-1]
    tg_post("/_press", {"from": OWNER, "chat": OWNER, "message_id": msg["message_id"], "data": edit["buttons"][0]})
    wait(lambda st: "Grant revoked" in st["answers"], "revoke via button")
    p = aac_run("example.com")
    msg = new_prompt(n)
    check("after revoke button the request prompts again", True)
    press(msg, "d")
    finish(p)

    listener.terminate()
    listener.wait(timeout=15)
    listen_log.close()
    log = open(os.path.join(tmp, "listener.log")).read()
    check("listener exits cleanly on SIGTERM", listener.returncode == 0, listener.returncode)
    check("listener log has no secret, PSK or bot token", SECRET not in log and TOKEN not in log and psk not in log)
    check("listener log records grant auto-approvals", "under grant" in log)
    check("no Telegram message ever contained the secret",
          all(SECRET not in m["text"] for m in tg_state()["sent"]) and all(SECRET not in e["text"] for e in tg_state()["edits"]))

    # ---------------- Headless listener, rendezvous pairing approved in Telegram ----------------
    if not LISTENER_PREFIX:
        h2 = os.path.join(tmp, "listener2"); os.makedirs(h2)
        r2 = os.path.join(tmp, "remote2"); os.makedirs(r2)
        code_file = os.path.join(h2, "code")
        l2env = dict(lenv, HOME=h2)
        l2 = subprocess.Popen([AAC, "listen", "--headless", "--telegram", "--provider", "example", "--token-file", code_file,
                               "--relay-url", RELAY_URL], env=l2env, stdout=open(os.path.join(tmp, "listener2.log"), "w"), stderr=subprocess.STDOUT)
        procs.append(l2)
        for _ in range(100):
            if os.path.exists(code_file) and open(code_file).read().strip():
                break
            time.sleep(0.2)
        code = open(code_file).read().strip()
        n = len(tg_state()["sent"])
        p = subprocess.Popen([AAC, "connect", "--relay-url", RELAY_URL, "--token", code, "--domain", "example.com", "--output", "json", "--timeout", "60"],
                             env=dict(remote_env(), HOME=r2), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pm = new_prompt(n)
        check("rendezvous pairing prompt in Telegram with only Allow/Decline", "new device pairing" in pm["text"] and len(pm["buttons"]) == 2, pm)
        press(pm, "a")
        cm = new_prompt(n + 1)
        press(cm, "a")
        rc, out, err = finish(p)
        check("pairing + credential approved via Telegram -> aac connect gets credential", rc == 0 and '"success":true' in out.replace(" ", ""), (rc, err[-300:]))
        l2.terminate(); l2.wait(timeout=15)
finally:
    for pr in procs:
        if pr.poll() is None:
            pr.terminate()
    if LISTENER_PREFIX:
        subprocess.run(["docker", "rm", "-f", "aac-e2e-listener"], capture_output=True)

passed = sum(ok for _, ok in results)
print(f"\n{passed}/{len(results)} checks passed (logs in {tmp})")
sys.exit(0 if passed == len(results) else 1)
