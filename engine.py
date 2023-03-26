import frida
import sys
import os
import json, time, pefile

HOOKS_PATH  = "hooks/hooks.ts"
HOOKS       = ""
CHILDS      = []
PID         = 0
session     = None
log         = open(f"Logs\\{round(time.time())}.log", "a")


with open(HOOKS_PATH, "r") as f:
    HOOKS = f.read()

def child_added(child):
    print(f"Killing child... {child.pid}")
    device.kill(child.pid)

def on_message(message, data):
    global PID
    try:
        payload = message['payload']
    except:
        print(message)
        return

    if data:
        fname = time.time()
        with open(f"output/{fname}.bin", "wb") as f:
            f.write(fix_pe(data))
        print(f"Buffer intercepted, possible unpacked payload saved at output\{fname}")

    log.write(json.dumps(payload) + "\n")

def main(path):
    global PID
    PID  = device.spawn(path)
    name = path.split('\\')[-1]
    session = device.attach(PID)
    script = session.create_script(HOOKS)
    script.on('message', on_message)
    script.load()
    time.sleep(1)
    device.resume(PID)
    input("Press ENTER to abort instrumentation...\n")
    device.kill(PID)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python %s <filepath>" % __file__.split('\\')[-1])
        sys.exit(1)
    device = frida.get_local_device()
    device.on("child-added", child_added)
    main(sys.argv[1])
    log.close()