from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey
from Crypto.Hash import RIPEMD160
import multiprocessing
from multiprocessing import Value
import hashlib
import binascii
import os
import time
import subprocess
import select
from collections import deque

# =========================
# KONSTANTA
# =========================
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key

BATCH_SIZE = 5000                # Jumlah hash160 per batch (kirim ke brainflayer)
MAX_HISTORY_KEYS = 5_000_000     # Maksimal hash160 yang disimpan per proses (≈ 100 MB per proses)
UPDATE_INTERVAL = 5000            # Frekuensi update counter (keys)

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

# =========================
# WORKER
# =========================
def worker(speed_counter, total_counter):
    # Inisialisasi kunci acak
    private_key_int = int.from_bytes(os.urandom(32), 'big')
    current_key = CCPrivateKey(private_key_int.to_bytes(32, 'big'))
    current_pub_key = current_key.public_key

    # Buffer untuk menyimpan hash160 yang sudah dikirim ke brainflayer
    # Struktur: deque of (start_private_key, bytearray_of_hash160s)
    history = deque()
    total_keys_in_history = 0

    # Brainflayer process
    def start_brainflayer():
        return subprocess.Popen(
            [
                "./brainflayer/brainflayer",
                "-v", "-b", "database.blf",
                "-f", "/dev/stdin"
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )

    bf = start_brainflayer()

    batch_hash160_bytes = []   # list of bytes (untuk disimpan)
    batch_hash160_hex = []     # list of hex (untuk dikirim)
    start_private_key = private_key_int
    local_counter = 0

    while True:
        # Generate hash160
        public_key_bytes = current_pub_key.format(compressed=True)
        hash160_bytes = public_key_to_hash160(public_key_bytes)
        hash160_hex = hash160_bytes.hex()

        batch_hash160_bytes.append(hash160_bytes)
        batch_hash160_hex.append(hash160_hex)

        # Jika batch penuh, kirim ke brainflayer
        if len(batch_hash160_bytes) >= BATCH_SIZE:
            try:
                send_batch_to_brainflayer(bf, batch_hash160_hex)

                # Simpan batch ke history
                batch_ba = bytearray()
                for h in batch_hash160_bytes:
                    batch_ba.extend(h)
                history.append((start_private_key, batch_ba))
                total_keys_in_history += len(batch_hash160_bytes)

                # Hapus history tertua jika melebihi batas
                while total_keys_in_history > MAX_HISTORY_KEYS:
                    oldest_start, oldest_ba = history.popleft()
                    total_keys_in_history -= len(oldest_ba) // 20

                # Reset batch
                batch_hash160_bytes = []
                batch_hash160_hex = []
                start_private_key = private_key_int + 1   # private key berikutnya untuk batch selanjutnya

            except BrokenPipeError:
                # Brainflayer crash, restart dan kirim ulang semua batch yang belum diproses
                print("\nBrainflayer crash, restarting and resending history...")
                # Matikan proses lama
                try:
                    bf.stdin.close()
                    bf.stdout.close()
                    bf.terminate()
                    bf.wait(timeout=5)
                except:
                    pass
                # Buat proses baru
                bf = start_brainflayer()

                # Kirim ulang semua batch dari history
                for start_key, batch_ba in history:
                    # Konversi bytearray ke daftar hex
                    hex_list = []
                    for i in range(0, len(batch_ba), 20):
                        h_bytes = batch_ba[i:i+20]
                        hex_list.append(h_bytes.hex())
                    # Kirim
                    try:
                        send_batch_to_brainflayer(bf, hex_list)
                    except BrokenPipeError:
                        # Jika gagal lagi, mungkin masalah serius, hentikan worker?
                        print("Fatal: cannot send to brainflayer after restart, exiting worker.")
                        return

                # Kirim batch yang sedang diproses (yang gagal dikirim)
                if batch_hash160_hex:
                    try:
                        send_batch_to_brainflayer(bf, batch_hash160_hex)
                    except BrokenPipeError:
                        print("Fatal: cannot send current batch after restart, exiting worker.")
                        return

                # Simpan batch yang sedang diproses ke history (seharusnya sudah ada? Belum karena gagal)
                # Kita tambahkan ke history sekarang
                if batch_hash160_bytes:
                    batch_ba = bytearray()
                    for h in batch_hash160_bytes:
                        batch_ba.extend(h)
                    history.append((start_private_key, batch_ba))
                    total_keys_in_history += len(batch_hash160_bytes)

                # Reset batch (kosongkan, karena sudah dikirim dan disimpan)
                batch_hash160_bytes = []
                batch_hash160_hex = []
                start_private_key = private_key_int + 1   # start untuk batch berikutnya

        # Baca output brainflayer secara non‑blocking
        while select.select([bf.stdout], [], [], 0)[0]:
            result = bf.stdout.readline().strip()
            if result:
                # Hasil adalah hash160 yang cocok (dalam hex)
                match_hex = result
                match_bytes = bytes.fromhex(match_hex)

                # Cari di history (dari yang terbaru)
                found = False
                for start_key, batch_ba in reversed(history):
                    # Gunakan memoryview untuk scanning cepat
                    batch_view = memoryview(batch_ba)
                    for i in range(0, len(batch_ba), 20):
                        if batch_view[i:i+20] == match_bytes:
                            private_key_found = start_key + (i // 20)
                            private_key_hex = hex(private_key_found)[2:].zfill(64).upper()
                            address = hash160_to_address(match_bytes)

                            # Simpan ke file
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

        # Update counter
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

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    cpu_count = max(1, multiprocessing.cpu_count() - 1)
    print(f"Running with {cpu_count} CPU cores")
    print(f"Batch size: {BATCH_SIZE}, Max history per worker: {MAX_HISTORY_KEYS} keys")

    # Gunakan unsigned long long (8 byte) untuk counter agar tidak overflow
    speed_counter = Value('Q', 0)   # unsigned long long
    total_counter = Value('Q', 0)

    processes = []
    for _ in range(cpu_count):
        p = multiprocessing.Process(target=worker, args=(speed_counter, total_counter))
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
