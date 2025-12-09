import json
import os
import time
import requests
from dotenv import load_dotenv

from utils import detect_hash_type, read_hashes, save_results, append_result
from logger import get_logger

load_dotenv()
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    raise ValueError("Error: unable to read an API key")

HASH_PATH = os.path.join(os.path.dirname(__file__), "hashes.txt")
RESULT_PATH = os.path.join(os.path.dirname(__file__), "results.json")
logger = get_logger()

def query(hash: str, hash_type: str) -> dict:
    url = "https://www.virustotal.com/api/v3/files/" + hash
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(url=url, headers=headers)

        if response.status_code == 429:
            logger.warning("Rate limit exceeded. Sleeping 10 seconds...")
            time.sleep(10)
            return query(hash, hash_type)

        if response.status_code != 200:
            logger.error(f"API error {response.status_code} for hash {hash}")
            return {
                "hash": hash,
                "error": f"API error {response.status_code}"
            }
        
        data = response.json()
        attrs = data.get("data").get("attributes")

        return {
            "hash": hash,
            "hash_type": hash_type,
            "meaningful_name": attrs.get("meaningful_name"),
            "type_tag": attrs.get("type_tag"),
            "sha256": attrs.get("sha256"),
            "sha1": attrs.get("sha1"),
            "md5": attrs.get("md5"),
            "type_description": attrs.get("type_description"),
            "total_votes": {
                "malicious": attrs.get("total_votes", {}).get("malicious"),
                "harmless": attrs.get("total_votes", {}).get("harmless"),
            },
            "type_description": attrs.get("type_description"),
            "first_seen": attrs.get("first_submission_date"),
            "av_stats": {
                "malicious": attrs.get("last_analysis_stats", {}).get("malicious"),
                "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious"),
                "undetected": attrs.get("last_analysis_stats", {}).get("undetected")
            },
        }
            
    except Exception as e:
        logger.error(f"Request error for hash: {hash} {e}")

def main():
    hashes = read_hashes(HASH_PATH)
    logger.info(f"Loaded {len(hashes)} hashes")
    
    results = []

    for hash in hashes:
        hash_type = detect_hash_type(hash)

        if not hash_type:
          logger.warning(f"Skipping invalid hash with length {len(hash)}")
          results.append({
              "input_hash": hash,
              "error": "unsupported hash length",
          })
          continue

        logger.info(f"Calling VirusTotal on {hash_type} hash {hash}")
        res = query(hash, hash_type)

        results.append(res)

        time.sleep(5)
         
    save_results(results, RESULT_PATH)
    logger.info(f"Processing {len(hashes)} hashes completed")

if __name__ == "__main__":
    main()
