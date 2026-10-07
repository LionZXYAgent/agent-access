#!/usr/bin/env python3
"""E2E for the interactive TUI with --telegram: Telegram and the terminal race, first answer wins.
Drives the real ratatui TUI through a pseudo-terminal. Uses the `example` provider."""
import fcntl, json, os, pty, select, struct, subprocess, sys, tempfile, termios, threading, time, urllib.request

AAC, RELAY = sys.argv[1], sys.argv[2]
TG_PORT, RELAY_PORT = 18091, 18090
TOKEN = "123456:E2E-TOKEN-abcdefghijklmnopqrstuvwxyz"
OWNER = 777000111
TG = f"http://127.0.0.1:{TG_PORT}"
RELAY_URL = f"ws://127.0.0.1:{RELAY_PORT}"
here = os.path.dirname(os.path.abspath(__file__))
tmp = tempfile.mkdtemp(prefix="aac-e2e-tui-")
results = []

def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""), flush=True)

def tg_state():
    return json.load(urllib.request.urlopen(TG + "/_state"))

def tg_post(path, obj):
    urllib.request.urlopen(urllib.request.Request(TG + path, json.dumps(obj).encode(), {"Content-Type": "application/json"})).read()

def press(msg, action):
    data = next(b for b in msg["buttons"] if b.endswith(":" + action))
    tg_post("/_press", {"from": OWNER, "chat": OWNER, "message_id": msg["message_id"], "data": data})

def wait(pred, what, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        r = pred(tg_state())
        if r:
            return r
        time.sleep(0.1)
    raise AssertionError("timed out waiting for " + what)

def new_prompt(n):
    return wait(lambda st: len(st["sent"]) > n and st["sent"][n]["buttons"] and st["sent"][n], "prompt")

remote_home = os.path.join(tmp, "remote"); os.makedirs(remote_home)
def aac_run(token=None):
    cmd = [AAC, "run", "--relay-url", RELAY_URL, "--domain", "example.com", "--timeout", "60", "--env", "PW=password", "--"]
    if token:
        cmd[2:2] = ["--token", token]
    cmd += ["sh", "-c", 'echo "child pwlen=${#PW}"']
    return subprocess.Popen(cmd, env=dict(os.environ, HOME=remote_home, LLM="1"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def finish(p):
    out, err = p.communicate(timeout=60)
    return p.returncode, out, err

procs = []
try:
    procs.append(subprocess.Popen([sys.executable, os.path.join(here, "mock_telegram.py"), str(TG_PORT), TOKEN]))
    procs.append(subprocess.Popen([RELAY], env=dict(os.environ, BIND_ADDR=f"127.0.0.1:{RELAY_PORT}"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(1)
    home = os.path.join(tmp, "listener"); os.makedirs(home)
    env = dict(os.environ, HOME=home, AAC_TELEGRAM_BOT_TOKEN=TOKEN, AAC_TELEGRAM_OWNER_ID=str(OWNER),
               AAC_TELEGRAM_API_URL=TG, TERM="xterm-256color")
    # Create the reusable PSK once headless (writes token file), then reuse it from the TUI.
    tf = os.path.join(home, "tok")
    h = subprocess.Popen([AAC, "listen", "--headless", "--telegram", "--provider", "example", "--reusable-psk",
                          "--token-file", tf, "--relay-url", RELAY_URL], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        if os.path.exists(tf) and open(tf).read().strip():
            break
        time.sleep(0.1)
    psk = open(tf).read().strip()
    h.terminate(); h.wait()

    # Start TUI in a pty
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(AAC, [AAC, "listen", "--telegram", "--provider", "example", "--reusable-psk", "--relay-url", RELAY_URL], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
    screen = []
    stop = False
    def reader():
        while not stop:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    screen.append(os.read(fd, 65536).decode("utf-8", "replace"))
                except OSError:
                    return
    threading.Thread(target=reader, daemon=True).start()
    time.sleep(3)

    # A. Telegram answers while the TUI also shows the prompt
    n = len(tg_state()["sent"])
    p = aac_run(token=psk)
    msg = new_prompt(n)
    time.sleep(0.5)
    check("TUI mode: prompt mirrored to Telegram", 'domain "example.com"' in msg["text"])
    press(msg, "a")
    rc, out, err = finish(p)
    check("TUI mode: Telegram Allow resolves the TUI prompt -> credential delivered", rc == 0 and "child pwlen=17" in out, (rc, err[-300:]))
    time.sleep(0.5)
    check("TUI shows 'approved via Telegram'", "approved via Telegram" in "".join(screen))

    # B. Local 'y' answers first; Telegram message is updated
    n = len(tg_state()["sent"])
    p = aac_run()
    msg = new_prompt(n)
    time.sleep(0.8)
    os.write(fd, b"y")
    rc, out, err = finish(p)
    check("TUI mode: local 'y' approves -> credential delivered", rc == 0 and "child pwlen=17" in out, (rc, err[-300:]))
    wait(lambda st: any(e["message_id"] == msg["message_id"] and "ALLOWED locally" in e["text"] for e in st["edits"]), "local edit")
    check("Telegram message edited to 'ALLOWED locally' and buttons removed",
          any(e["message_id"] == msg["message_id"] and not e["buttons"] for e in tg_state()["edits"]))
    press(msg, "d")
    wait(lambda st: any("expired" in a for a in st["answers"]), "expired")
    check("Telegram press after local answer is rejected", True)

    # C. Local 'n' declines
    n = len(tg_state()["sent"])
    p = aac_run()
    msg = new_prompt(n)
    time.sleep(0.8)
    os.write(fd, b"n")
    rc, out, err = finish(p)
    check("TUI mode: local 'n' declines", rc != 0 and "child" not in out)
    wait(lambda st: any(e["message_id"] == msg["message_id"] and "DECLINED locally" in e["text"] for e in st["edits"]), "decline edit")
    check("Telegram message edited to 'DECLINED locally'", True)

    # D. Telegram 1h grant also applies in TUI mode (no TUI prompt, no Telegram message)
    n = len(tg_state()["sent"])
    p = aac_run()
    msg = new_prompt(n)
    press(msg, "h1")
    check("TUI mode: Allow 1h -> delivered", finish(p)[0] == 0)
    n = len(tg_state()["sent"])
    rc, out, err = finish(aac_run())
    time.sleep(0.5)
    check("TUI mode: follow-up auto-approved under Telegram grant, no Telegram message",
          rc == 0 and len(tg_state()["sent"]) == n and "Telegram grant" in "".join(screen))

    os.write(fd, b"\x03")  # Ctrl-C quits the TUI
    time.sleep(1)
    stop = True
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        pass
finally:
    for pr in procs:
        pr.terminate()

print(f"\n{sum(results)}/{len(results)} checks passed (logs in {tmp})")
sys.exit(0 if all(results) else 1)
