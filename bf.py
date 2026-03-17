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

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key

BATCH_SIZE = 1000  # 🔥 bisa dinaikkan 5000+


# =========================
# HASH160
# =========================
def public_key_to_hash160(public_key_bytes):
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    h = RIPEMD160.new()
    h.update(sha256_bpk)
    return h.digest()


# =========================
# ADDRESS
# =========================
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


# =========================
# WIF
# =========================
def private_key_to_wif(private_key, compressed=True):
    extended_key = b'\x80' + binascii.unhexlify(private_key)
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


# =========================
# WORKER ULTRA CEPAT
# =========================
def worker(counter):

    private_key_int = int.from_bytes(os.urandom(32), 'big')
    current_key = CCPrivateKey(private_key_int.to_bytes(32, 'big'))
    current_pub_key = current_key.public_key

    # 🔥 Start brainflayer
    bf = subprocess.Popen(
        [
            "./brainflayer/brainflayer",
            "-b", "database.blf",
            "-f", "/dev/stdin"
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    batch = []
    local_counter = 0

    while True:
        public_key_bytes = current_pub_key.format(compressed=True)
        hash160 = public_key_to_hash160(public_key_bytes).hex()

        batch.append(hash160)

        # 🔥 kalau batch penuh → kirim sekaligus
        if len(batch) >= BATCH_SIZE:
            try:
                bf.stdin.write("\n".join(batch) + "\n")
                bf.stdin.flush()
                batch.clear()
            except BrokenPipeError:
                print("Brainflayer crash, restart...")
                bf = subprocess.Popen(
                    [
                        "./brainflayer/brainflayer",
                        "-b", "database.blf",
                        "-f", "/dev/stdin"
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1
                )

        # 🔥 NON-BLOCKING READ
        while select.select([bf.stdout], [], [], 0)[0]:
            result = bf.stdout.readline().strip()

            if result:
                private_key_hex = hex(private_key_int)[2:].zfill(64).upper()
                address = hash160_to_address(bytes.fromhex(hash160))

                with open("found.txt", "a") as f:
                    f.write(
                        f"PRIVATE: {private_key_hex}\n"
                        f"WIF: {private_key_to_wif(private_key_hex)}\n"
                        f"HASH160: {hash160}\n"
                        f"ADDRESS: {address}\n\n"
                    )

                print(f"\n🔥 FOUND: {address}")

        # counter
        local_counter += 1
        if local_counter >= 5000:
            with counter.get_lock():
                counter.value += local_counter
            local_counter = 0

        # 🔥 Point addition (FAST)
        current_pub_key = CCPublicKey.combine_keys(
            [current_pub_key, GENERATOR_PUBLIC_KEY]
        )
        private_key_int += 1


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    cpu_count = max(1, multiprocessing.cpu_count() - 1)

    print(f"Running with {cpu_count} CPU cores")

    counter = Value('i', 0)
    processes = []

    for _ in range(cpu_count):
        p = multiprocessing.Process(target=worker, args=(counter,))
        p.start()
        processes.append(p)

    try:
        while True:
            time.sleep(1)
            with counter.get_lock():
                rate = counter.value
                counter.value = 0

            print(f"\rSpeed: {rate} keys/sec", end="")

    except KeyboardInterrupt:
        print("\nStopping...")
        for p in processes:
            p.terminate()
