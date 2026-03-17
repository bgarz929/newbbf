from coincurve import PrivateKey as CCPrivateKey, PublicKey as CCPublicKey
import multiprocessing
from multiprocessing import Value
import hashlib
import binascii
import os
import time
import subprocess

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

GENERATOR_PUBLIC_KEY = CCPrivateKey(int(1).to_bytes(32, 'big')).public_key


# =========================
# HASH160 (FIX UTAMA)
# =========================

def public_key_to_hash160(public_key_bytes):
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    return ripemd160_bpk


# =========================
# ADDRESS (OPSIONAL LOG)
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
# WORKER
# =========================

def worker(counter):
    local_counter = 0

    # Random start
    private_key_int = int.from_bytes(os.urandom(32), 'big')
    current_key = CCPrivateKey(private_key_int.to_bytes(32, 'big'))
    current_pub_key = current_key.public_key

    # 🔥 Brainflayer (pakai .blf + optional table)
    bf = subprocess.Popen(
        [
            "./brainflayer/brainflayer",
            "-b", "database.blf",
            "-f", "/dev/stdin"
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    while True:
        public_key_bytes = current_pub_key.format(compressed=True)

        # ✅ FIX: pakai HASH160, bukan address
        hash160 = public_key_to_hash160(public_key_bytes)
        hash160_hex = hash160.hex()

        try:
            bf.stdin.write(hash160_hex + "\n")
            bf.stdin.flush()

            result = bf.stdout.readline().strip()

            if result:
                private_key_hex = hex(private_key_int)[2:].zfill(64).upper()
                address = hash160_to_address(hash160)

                with open('found.txt', 'a') as f:
                    f.write(
                        'PRIVATE HEX: ' + private_key_hex + '\n' +
                        'WIF: ' + private_key_to_wif(private_key_hex, True) + '\n' +
                        'HASH160: ' + hash160_hex + '\n' +
                        'ADDRESS: ' + address + '\n\n'
                    )

                print(f"\n🔥 FOUND: {address}")

        except BrokenPipeError:
            print("Brainflayer crashed, restarting...")
            bf = subprocess.Popen(
                [
                    "brainflayer",
                    "-b", "database.blf",
                    "-f", "/dev/stdin"
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                bufsize=1
            )

        # Counter
        local_counter += 1
        if local_counter >= 1000:
            with counter.get_lock():
                counter.value += local_counter
            local_counter = 0

        # 🔥 Point addition
        current_pub_key = CCPublicKey.combine_keys(
            [current_pub_key, GENERATOR_PUBLIC_KEY]
        )
        private_key_int += 1


# =========================
# MAIN
# =========================

if __name__ == "__main__":
    cpu_count = multiprocessing.cpu_count() - 1
    if cpu_count < 1:
        cpu_count = 1

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

            print(f"\rSpeed: {rate} keys/sec", end='')

    except KeyboardInterrupt:
        print("\nStopping...")
        for p in processes:
            p.terminate()
