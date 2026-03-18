from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey
from Crypto.Hash import RIPEMD160
import multiprocessing
from multiprocessing import Value, Lock
import hashlib
import binascii
import os
import time
import subprocess
import select
from collections import deque
import re
import random

# =========================
# KONSTANTA
# =========================
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key

BATCH_SIZE = 5000                # Jumlah hash160 per batch (kirim ke brainflayer)
MAX_HISTORY_KEYS = 5_000_000     # Maksimal hash160 yang disimpan per proses brainflayer (≈ 100 MB per proses)
UPDATE_INTERVAL = 5000            # Frekuensi update counter (keys)
BRAINFLAYER_WORKERS = 2           # Jumlah proses brainflayer (sesuaikan dengan kemampuan I/O)
RANDOM_JUMP_PROB = 0.001          # Probabilitas lompat ke kunci acak setiap iterasi (hybrid random+sequential)

# Regex untuk mencocokkan hash160 hex (40 karakter hex)
HASH160_HEX_REGEX = re.compile(r'^[0-9a-f]{40}$', re.IGNORECASE)

# =========================
# FUNGSI BANTU
# =========================
def public_key_to_hash160(public_key_bytes):
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    h = RIPEMD160.new()
    h.update(sha256_bpk)
    return h.digest()

def hash160_to_address(hash160):
    prepend_network_byte = b'\x00' + hash160
    checksum = hashlib.sha256(hashlib.sha256(prepend_network_byte).digest()).digest()[:4]
    address_bytes = prepend_network_byte + checksum

    value = int.from_bytes(address_bytes, 'big')
    output = []

    while value > 0:
        value, remainder = divmod(value, 58)
        output.append(ALPHABET[remainder])

    for byte in address_bytes:
        if byte == 0:
            output.append(ALPHABET[0])
        else:
            break

    return ''.join(output[::-1])

def private_key_to_wif(private_key_hex, compressed=True):
    extended_key = b'\x80' + binascii.unhexlify(private_key_hex)
    if compressed:
        extended_key += b'\x01'

    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum

    value = int.from_bytes(final_key, 'big')
    output = []

    while value > 0:
        value, remainder = divmod(value, 58)
        output.append(ALPHABET[remainder])

    for byte in final_key:
        if byte == 0:
            output.append(ALPHABET[0])
        else:
            break

    return ''.join(output[::-1])

def send_batch_to_brainflayer(bf, batch_hash160_hex):
    """Kirim batch hex ke stdin brainflayer."""
    bf.stdin.write("\n".join(batch_hash160_hex) + "\n")
    bf.stdin.flush()

def is_valid_hash160_hex(s):
    """Periksa apakah string adalah hash160 hex yang valid."""
    return bool(HASH160_HEX_REGEX.match(s))

# =========================
# GENERATOR WORKER (dengan hybrid random+sequential dan multi-range)
# =========================
def generator_worker(queue_list, speed_counter, total_counter, worker_id, range_start, range_end):
    # Inisialisasi kunci acak dalam rentang yang ditentukan
    private_key_int = random.randint(range_start, range_end)
    current_key = CCPrivateKey(private_key_int.to_bytes(32, 'big'))
    current_pub_key = current_key.public_key

    # Buffer batch lokal
    batch_private_start = private_key_int
    batch_hash160_bytes = []
    batch_hash160_hex = []
    local_counter = 0
    num_queues = len(queue_list)
    queue_index = worker_id % num_queues  # distribusi awal

    while True:
        # Generate hash160 untuk kunci saat ini
        public_key_bytes = current_pub_key.format(compressed=True)
        hash160_bytes = public_key_to_hash160(public_key_bytes)
        hash160_hex = hash160_bytes.hex()

        batch_hash160_bytes.append(hash160_bytes)
        batch_hash160_hex.append(hash160_hex)

        # Jika batch penuh, kirim ke brainflayer worker via queue
        if len(batch_hash160_bytes) >= BATCH_SIZE:
            # Gabungkan hash160 menjadi bytearray
            batch_ba = bytearray()
            for h in batch_hash160_bytes:
                batch_ba.extend(h)

            # Kirim ke queue yang dipilih (round-robin sederhana)
            queue_list[queue_index].put((batch_private_start, batch_ba))
            queue_index = (queue_index + 1) % num_queues

            # Reset batch
            batch_hash160_bytes = []
            batch_hash160_hex = []
            batch_private_start = None  # akan diisi setelah next key ditentukan

        # Update counter
        local_counter += 1
        if local_counter >= UPDATE_INTERVAL:
            with speed_counter.get_lock():
                speed_counter.value += local_counter
            with total_counter.get_lock():
                total_counter.value += local_counter
            local_counter = 0

        # Tentukan kunci berikutnya (hybrid random+sequential)
        next_key = None
        is_consecutive = False

        if random.random() < RANDOM_JUMP_PROB:
            # Lompat acak dalam rentang
            next_key = random.randint(range_start, range_end)
        else:
            # Sequential
            next_key = private_key_int + 1
            if next_key > range_end:
                next_key = range_start  # wrap around dalam rentang
            else:
                is_consecutive = True  # hanya sequential tanpa wrap

        # Jika kunci berikutnya tidak berurutan, kirim batch yang tersisa (jika ada)
        if not is_consecutive and batch_hash160_bytes:
            # Kirim batch yang belum penuh
            batch_ba = bytearray()
            for h in batch_hash160_bytes:
                batch_ba.extend(h)
            queue_list[queue_index].put((batch_private_start, batch_ba))
            queue_index = (queue_index + 1) % num_queues
            batch_hash160_bytes = []
            batch_hash160_hex = []
            batch_private_start = None

        # Set kunci berikutnya
        private_key_int = next_key
        current_key = CCPrivateKey(private_key_int.to_bytes(32, 'big'))
        current_pub_key = current_key.public_key

        # Jika batch baru dimulai, catat start private key-nya
        if batch_private_start is None:
            batch_private_start = private_key_int

# =========================
# BRAINFLAYER WORKER (tidak berubah)
# =========================
def brainflayer_worker(queue, lock, worker_id):
    # History: deque of (start_private_key, bytearray_of_hash160s)
    history = deque()
    total_keys_in_history = 0

    def start_brainflayer():
        return subprocess.Popen(
            [
                "./brainflayer/brainflayer",
                "-v", "-b", "040823BF.blf",
                "-f", "/dev/stdin"
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1
        )

    bf = start_brainflayer()

    while True:
        try:
            start_private_key, batch_ba = queue.get()
        except EOFError:
            break

        # Konversi bytearray ke daftar hex untuk dikirim ke brainflayer
        hex_list = []
        for i in range(0, len(batch_ba), 20):
            h_bytes = batch_ba[i:i+20]
            hex_list.append(h_bytes.hex())

        try:
            send_batch_to_brainflayer(bf, hex_list)
        except BrokenPipeError:
            print(f"\nBrainflayer worker {worker_id} crash, restarting...")
            try:
                bf.stdin.close()
                bf.stdout.close()
                bf.terminate()
                bf.wait(timeout=5)
            except:
                pass
            bf = start_brainflayer()
            for s_key, s_ba in history:
                s_hex_list = []
                for j in range(0, len(s_ba), 20):
                    s_hex_list.append(s_ba[j:j+20].hex())
                try:
                    send_batch_to_brainflayer(bf, s_hex_list)
                except BrokenPipeError:
                    print(f"Fatal: cannot resend history to brainflayer worker {worker_id}, exiting.")
                    return
            try:
                send_batch_to_brainflayer(bf, hex_list)
            except BrokenPipeError:
                print(f"Fatal: cannot send current batch to brainflayer worker {worker_id}, exiting.")
                return

        history.append((start_private_key, batch_ba))
        total_keys_in_history += len(batch_ba) // 20

        while total_keys_in_history > MAX_HISTORY_KEYS:
            oldest_start, oldest_ba = history.popleft()
            total_keys_in_history -= len(oldest_ba) // 20

        while select.select([bf.stdout], [], [], 0)[0]:
            line = bf.stdout.readline().strip()
            if not line or not is_valid_hash160_hex(line):
                continue
            match_hex = line
            match_bytes = bytes.fromhex(match_hex)

            found = False
            for start_key, batch_ba in reversed(history):
                batch_view = memoryview(batch_ba)
                for i in range(0, len(batch_ba), 20):
                    if batch_view[i:i+20] == match_bytes:
                        private_key_found = start_key + (i // 20)
                        private_key_hex = hex(private_key_found)[2:].zfill(64).upper()
                        address = hash160_to_address(match_bytes)

                        with lock:
                            with open("found.txt", "a") as f:
                                f.write(
                                    f"PRIVATE: {private_key_hex}\n"
                                    f"WIF: {private_key_to_wif(private_key_hex)}\n"
                                    f"HASH160: {match_hex}\n"
                                    f"ADDRESS: {address}\n\n"
                                )
                        print(f"\n🔥 FOUND: {address} (private key: {private_key_hex})")
                        found = True
                        break
                if found:
                    break

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    cpu_count = multiprocessing.cpu_count()
    generator_workers = max(1, cpu_count - BRAINFLAYER_WORKERS)
    print(f"Running with {generator_workers} generator cores and {BRAINFLAYER_WORKERS} brainflayer workers")
    print(f"Batch size: {BATCH_SIZE}, Max history per brainflayer worker: {MAX_HISTORY_KEYS} keys")
    print(f"Random jump probability: {RANDOM_JUMP_PROB}")

    # Shared counters
    speed_counter = Value('Q', 0)
    total_counter = Value('Q', 0)

    # Lock untuk file found.txt
    file_lock = Lock()

    # Buat queue untuk setiap brainflayer worker
    queues = [multiprocessing.Queue(maxsize=100) for _ in range(BRAINFLAYER_WORKERS)]

    # Tentukan rentang untuk setiap generator worker (membagi ruang kunci 2^256)
    total_space = 1 << 256  # 2^256
    range_size = total_space // generator_workers
    ranges = []
    for i in range(generator_workers):
        start = i * range_size
        end = (i+1) * range_size - 1 if i != generator_workers-1 else total_space - 1
        ranges.append((start, end))

    processes = []

    # Mulai brainflayer workers
    for i in range(BRAINFLAYER_WORKERS):
        p = multiprocessing.Process(target=brainflayer_worker, args=(queues[i], file_lock, i))
        p.start()
        processes.append(p)

    # Mulai generator workers dengan rentang masing-masing
    for i in range(generator_workers):
        start, end = ranges[i]
        p = multiprocessing.Process(target=generator_worker, args=(queues, speed_counter, total_counter, i, start, end))
        p.start()
        processes.append(p)

    try:
        while True:
            time.sleep(1)
            with speed_counter.get_lock():
                speed = speed_counter.value
                speed_counter.value = 0
            with total_counter.get_lock():
                total = total_counter.value

            print(f"\rSpeed: {speed:10} keys/sec | Total: {total:15} keys checked", end="", flush=True)

    except KeyboardInterrupt:
        print("\n\nStopping...")
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()
        print("All processes terminated.")
