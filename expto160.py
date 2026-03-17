import sys
import base58

def addresses_to_hash160(filein, fileout_txt):
    with open(filein, 'r') as inf, \
         open(fileout_txt, 'w') as outf_txt:

        count = 0
        skip = 0

        for line in inf:
            addr = line.strip()
            if not addr:
                continue

            try:
                decoded = base58.b58decode_check(addr)

                # Validasi panjang (1 byte version + 20 byte hash160)
                if len(decoded) != 21:
                    skip += 1
                    print(f"skipped (wrong length {len(decoded)}): {addr}")
                    continue

                # Ambil hash160 (20 byte)
                hash160 = decoded[1:]

                # Simpan dalam format HEX (untuk .blf)
                outf_txt.write(hash160.hex() + '\n')
                count += 1

            except Exception as e:
                skip += 1
                print(f"skipped {addr}: {e}")

        print(f"processed: {count} addresses")
        print(f"skipped  : {skip} addresses")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 tohash160.py addresses.txt hash160.txt")
    else:
        addresses_to_hash160(sys.argv[1], sys.argv[2])
