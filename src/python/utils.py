import json

def detect_hash_type(hash: str) -> str | None:
    hash = hash.lower()
    if len(hash) == 32:
        return "MD5"
    if len(hash) == 40:
        return "SHA1"
    if len(hash) == 64:
        return "SHA256"
    return None

def read_hashes(path: str) -> list:
    hashes = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                hashes.append(line)
    return hashes

def save_result(result: dict, path: str) -> bool:
    try:
        with open(path, 'w') as f:
            json.dump(result, f, indent=4)
        return True
    except Exception as e:
        print(e)
        return False

def display(list):
    print(len(list))
    for item in enumerate(list):
        print(item)