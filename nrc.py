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
import struct
import sys
import traceback

# =========================
# KONSTANTA
# =========================
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key

BATCH_SIZE = 5000                # Jumlah hash160 per batch (kirim ke brainflayer)
MAX_HISTORY_KEYS = 5_000_000     # Maksimal hash160 yang disimpan per proses brainflayer (≈ 100 MB per proses)
UPDATE_INTERVAL = 5000            # Frekuensi update counter (keys)
BRAINFLAYER_WORKERS = 2           # Jumlah proses brainflayer (sesuaikan dengan kemampuan I/O)
BLOCK_SIZE = 1_000_000_000        # Ukuran blok per worker (1 milyar kunci)
CHECKPOINT_DIR = "checkpoints"    # Direktori penyimpanan checkpoint
NEXT_BLOCK_FILE = "next_block.txt" # File untuk menyimpan blok berikutnya yang tersedia

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
# FUNGSI CHECKPOINT & BLOK
# =========================
def save_checkpoint(worker_id, private_key_int, pub_key_bytes, keys_generated, block_number):
    """Simpan state worker ke file. private_key_int adalah kunci berikutnya yang akan diproses."""
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    filename = os.path.join(CHECKPOINT_DIR, f"checkpoint_{worker_id}.bin")
    with open(filename, "wb") as f:
        f.write(private_key_int.to_bytes(32, 'big'))
        f.write(pub_key_bytes)
        f.write(struct.pack('Q', keys_generated))
        f.write(struct.pack('Q', block_number))

def load_checkpoint(worker_id):
    """Muat state worker dari file jika ada."""
    filename = os.path.join(CHECKPOINT_DIR, f"checkpoint_{worker_id}.bin")
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            data = f.read()
            if len(data) == 32 + 33 + 8 + 8:
                private_key_int = int.from_bytes(data[:32], 'big')
                pub_key_bytes = data[32:32+33]
                keys_generated = struct.unpack('Q', data[32+33:32+33+8])[0]
                block_number = struct.unpack('Q', data[32+33+8:])[0]
                return private_key_int, pub_key_bytes, keys_generated, block_number
    return None

def get_next_block(lock):
    """Ambil nilai blok berikutnya dari file."""
    with lock:
        if os.path.exists(NEXT_BLOCK_FILE):
            with open(NEXT_BLOCK_FILE, "r") as f:
                return int(f.read().strip())
        else:
            return 0

def increment_next_block(lock):
    """Tambah blok berikutnya dan kembalikan nilai sebelum increment."""
    with lock:
        current = get_next_block(lock)
        next_val = current + 1
        with open(NEXT_BLOCK_FILE, "w") as f:
            f.write(str(next_val))
        return current

# =========================
# GENERATOR WORKER (dengan blok)
# =========================
def generator_worker(queue_list, speed_counter, total_counter, worker_id, next_block_lock):
    num_queues = len(queue_list)
    queue_index = worker_id % num_queues

    try:
        while True:
            # Coba muat checkpoint
            checkpoint = load_checkpoint(worker_id)
            if checkpoint:
                private_key_int, pub_key_bytes, keys_generated_in_block, block_number = checkpoint
                current_pub_key = CCPublicKey(pub_key_bytes)
                block_start = block_number * BLOCK_SIZE + 1
                print(f"Worker {worker_id} resumed at block {block_number}, offset {keys_generated_in_block}, next key {private_key_int}", file=sys.stderr)
            else:
                # Ambil blok baru
                block_number = increment_next_block(next_block_lock)
                block_start = block_number * BLOCK_SIZE + 1
                private_key_int = block_start
                # Buat kunci privat pertama di blok
                current_key = CCPrivateKey(private_key_int.to_bytes(32, 'big'))
                current_pub_key = current_key.public_key
                keys_generated_in_block = 0
                print(f"Worker {worker_id} starting new block {block_number} from {block_start}", file=sys.stderr)

            block_end = block_start + BLOCK_SIZE

            # Inisialisasi batch
            batch_private_start = private_key_int   # kunci pertama batch (saat ini)
            batch_hash160_bytes = []
            batch_hash160_hex = []
            local_counter = 0

            while private_key_int < block_end:
                # Generate hash160 dari current_pub_key (untuk private_key_int)
                public_key_bytes = current_pub_key.format(compressed=True)
                hash160_bytes = public_key_to_hash160(public_key_bytes)
                hash160_hex = hash160_bytes.hex()

                batch_hash160_bytes.append(hash160_bytes)
                batch_hash160_hex.append(hash160_hex)

                keys_generated_in_block += 1

                # Kirim batch jika penuh
                if len(batch_hash160_bytes) >= BATCH_SIZE:
                    batch_ba = bytearray()
                    for h in batch_hash160_bytes:
                        batch_ba.extend(h)
                    queue_list[queue_index].put((batch_private_start, batch_ba))
                    queue_index = (queue_index + 1) % num_queues
                    batch_hash160_bytes = []
                    batch_hash160_hex = []
                    # Batch berikutnya dimulai dari kunci setelah private_key_int saat ini
                    batch_private_start = private_key_int + 1

                # Update counter kecepatan
                local_counter += 1
                if local_counter >= UPDATE_INTERVAL:
                    with speed_counter.get_lock():
                        speed_counter.value += local_counter
                    with total_counter.get_lock():
                        total_counter.value += local_counter
                    local_counter = 0

                # Maju ke kunci berikutnya (point addition)
                current_pub_key = CCPublicKey.combine_keys([current_pub_key, GENERATOR_PUBLIC_KEY])
                private_key_int += 1

                # Simpan checkpoint periodik setelah maju
                if keys_generated_in_block % UPDATE_INTERVAL == 0:
                    save_checkpoint(worker_id, private_key_int, current_pub_key.format(compressed=True), keys_generated_in_block, block_number)

            # Selesai blok, hapus checkpoint
            try:
                os.remove(os.path.join(CHECKPOINT_DIR, f"checkpoint_{worker_id}.bin"))
            except:
                pass
            print(f"Worker {worker_id} finished block {block_number}", file=sys.stderr)
            # Lanjut ke blok berikutnya
    except Exception as e:
        print(f"ERROR in generator worker {worker_id}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        raise

# =========================
# BRAINFLAYER WORKER (tidak berubah)
# =========================
def brainflayer_worker(queue, lock, worker_id):
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

    try:
        while True:
            try:
                start_private_key, batch_ba = queue.get()
            except EOFError:
                break

            hex_list = []
            for i in range(0, len(batch_ba), 20):
                h_bytes = batch_ba[i:i+20]
                hex_list.append(h_bytes.hex())

            try:
                send_batch_to_brainflayer(bf, hex_list)
            except BrokenPipeError:
                print(f"\nBrainflayer worker {worker_id} crash, restarting...", file=sys.stderr)
                try:
                    bf.stdin.close()
                    bf.stdout.close()
                    bf.terminate()
                    bf.wait(timeout=5)
                except:
                    pass
                bf = start_brainflayer()
                # Kirim ulang semua history
                for s_key, s_ba in history:
                    s_hex_list = []
                    for j in range(0, len(s_ba), 20):
                        s_hex_list.append(s_ba[j:j+20].hex())
                    try:
                        send_batch_to_brainflayer(bf, s_hex_list)
                    except BrokenPipeError:
                        print(f"Fatal: cannot resend history to brainflayer worker {worker_id}, exiting.", file=sys.stderr)
                        return
                try:
                    send_batch_to_brainflayer(bf, hex_list)
                except BrokenPipeError:
                    print(f"Fatal: cannot send current batch to brainflayer worker {worker_id}, exiting.", file=sys.stderr)
                    return

            history.append((start_private_key, batch_ba))
            total_keys_in_history += len(batch_ba) // 20

            while total_keys_in_history > MAX_HISTORY_KEYS:
                oldest_start, oldest_ba = history.popleft()
                total_keys_in_history -= len(oldest_ba) // 20

            # Baca output brainflayer secara non‑blocking
            while select.select([bf.stdout], [], [], 0)[0]:
                line = bf.stdout.readline().strip()
                if not line:
                    continue
                if not is_valid_hash160_hex(line):
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
    except Exception as e:
        print(f"ERROR in brainflayer worker {worker_id}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    cpu_count = multiprocessing.cpu_count()
    generator_workers = max(1, cpu_count - BRAINFLAYER_WORKERS)
    print(f"Running with {generator_workers} generator cores and {BRAINFLAYER_WORKERS} brainflayer workers")
    print(f"Batch size: {BATCH_SIZE}, Max history per brainflayer worker: {MAX_HISTORY_KEYS} keys")
    print(f"Block size: {BLOCK_SIZE} keys per block")

    # Shared counters
    speed_counter = Value('Q', 0)
    total_counter = Value('Q', 0)
    file_lock = Lock()
    next_block_lock = multiprocessing.Lock()

    # Queue untuk setiap brainflayer worker
    queues = [multiprocessing.Queue(maxsize=100) for _ in range(BRAINFLAYER_WORKERS)]

    processes = []

    # Mulai brainflayer workers
    for i in range(BRAINFLAYER_WORKERS):
        p = multiprocessing.Process(target=brainflayer_worker, args=(queues[i], file_lock, i))
        p.start()
        processes.append(p)

    # Mulai generator workers
    for i in range(generator_workers):
        p = multiprocessing.Process(target=generator_worker, args=(queues, speed_counter, total_counter, i, next_block_lock))
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
