from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey
from Crypto.Hash import RIPEMD160
import multiprocessing
from multiprocessing import Queue, Value
import hashlib
import os
import time
import subprocess
import threading
import select

# =========================
# CONFIG
# =========================
BATCH_SIZE = 2000

# =========================
# HASH160
# =========================
def public_key_to_hash160(pub):
    sha = hashlib.sha256(pub).digest()
    h = RIPEMD160.new()
    h.update(sha)
    return h.digest()

# =========================
# GENERATOR
# =========================
GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key

# =========================
# WORKER (SUPER CEPAT)
# =========================
def worker(queue, counter):
    batch = []

    priv_int = int.from_bytes(os.urandom(32), 'big')
    key = CCPrivateKey(priv_int.to_bytes(32, 'big'))
    pub = key.public_key

    local = 0

    while True:
        pub_bytes = pub.format(compressed=True)
        h160 = public_key_to_hash160(pub_bytes)

        batch.append(h160.hex())

        # point addition (cepat)
        pub = CCPublicKey.combine_keys([pub, GENERATOR_PUBLIC_KEY])
        priv_int += 1

        local += 1

        if len(batch) >= BATCH_SIZE:
            queue.put(batch)
            batch = []

        if local >= 5000:
            with counter.get_lock():
                counter.value += local
            local = 0

# =========================
# BRAINFLAYER HANDLER
# =========================
def brainflayer_worker(queue):
    bf = subprocess.Popen(
        [
            "./brainflayer/brainflayer",
            "-b", "database.blf",
            "-f", "/dev/stdin"
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    # THREAD: kirim batch ke BF
    def sender():
        while True:
            batch = queue.get()
            try:
                bf.stdin.write("\n".join(batch) + "\n")
            except BrokenPipeError:
                print("Brainflayer crashed (sender)")

    # THREAD: baca hasil (non-blocking)
    def reader():
        while True:
            ready, _, _ = select.select([bf.stdout], [], [], 0.1)
            if ready:
                line = bf.stdout.readline().strip()
                if line:
                    print(f"\n🔥 FOUND: {line}")
                    with open("found.txt", "a") as f:
                        f.write(line + "\n")

    threading.Thread(target=sender, daemon=True).start()
    threading.Thread(target=reader, daemon=True).start()

    while True:
        time.sleep(1)

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    cpu = multiprocessing.cpu_count() - 1
    if cpu < 1:
        cpu = 1

    print(f"🔥 Ultra mode with {cpu} CPU cores")

    queue = Queue(maxsize=100)
    counter = Value('i', 0)

    # start brainflayer handler
    bf_process = multiprocessing.Process(target=brainflayer_worker, args=(queue,))
    bf_process.start()

    # start workers
    workers = []
    for _ in range(cpu):
        p = multiprocessing.Process(target=worker, args=(queue, counter))
        p.start()
        workers.append(p)

    # monitor speed
    try:
        while True:
            time.sleep(1)
            with counter.get_lock():
                speed = counter.value
                counter.value = 0

            print(f"\r⚡ Speed: {speed} keys/sec", end='')

    except KeyboardInterrupt:
        print("\nStopping...")
        for p in workers:
            p.terminate()
        bf_process.terminate()
