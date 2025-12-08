import os
import time
import requests
from dotenv import load_dotenv

from utils import detect_hash_type, read_hashes, save_result, display
from logger import get_logger

load_dotenv()
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    raise ValueError("Error: unable to read an API key")

HASH_PATH = os.path.join(os.path.dirname(__file__), "hashes.txt")
RESULT_PATH = os.path.join(os.path.dirname(__file__), "results.json")
logger = get_logger()

def query(hash: str, hash_type: str) -> dict:
    """
    TODO 
    1. this will call the api
    2. return the result dict
    AND will check for errors (e.g., API rate limit exceeded)
    """
    return {"new": "value"}

VT_URL = "https://www.virustotal.com/api/v3/files/"


def vt_lookup(h: str) -> dict:
    headers = {"x-apikey": API_KEY}
    url = VT_URL + h

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 429:
            logger.warning("Rate limit exceeded (429). Sleeping 15 seconds...")
            time.sleep(15)
            return vt_lookup(h)

        if response.status_code == 404:
            logger.warning(f"Hash not found: {h}")
            return {"error": "Hash not found"}

        if response.status_code != 200:
            logger.error(f"API error {response.status_code} for hash {h}")
            return {"error": f"API error {response.status_code}"}

        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})

        return {
            "sha256": attrs.get("sha256"),
            "sha1": attrs.get("sha1"),
            "md5": attrs.get("md5"),
            "community_score": attrs.get("total_votes", {}).get("harmless", 0)
                                - attrs.get("total_votes", {}).get("malicious", 0),
            "type_description": attrs.get("type_description"),
            "first_seen": attrs.get("first_submission_date"),
            "av_detect": attrs.get("last_analysis_stats", {}).get("malicious"),
        }

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error for hash {h}: {e}")
        return {"error": str(e)}

def main():
    hashes = read_hashes(HASH_PATH)
    logger.info(f"Loaded {len(hashes)}")
    
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

        logger.info(f"Calling VirusTotal with hash {hash}")
        res = query(hash, hash_type)

        results.append(res)

        # time.sleep(16)  # Respect free-tier rate limits
    
    save_result(results, RESULT_PATH)
    logger.info("Processing completed")
    logger.info(f"Results are in {RESULT_PATH}")





if __name__ == "__main__":
    main()
    