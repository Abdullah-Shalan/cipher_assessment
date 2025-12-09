

# cipher_assessment

**A submission for a cybersecurity assessment**

## What’s Inside

[`solution.md`](https://github.com/Abdullah-Shalan/cipher_assessment/blob/main/solution.md) the submission for the assessment. Containing methodology, findings, and explanation of results.  

Collection of scripts under `src/`
- [`python/`](https://github.com/Abdullah-Shalan/cipher_assessment/tree/main/src/python) directory which has a python script that uses [VirusTotal API](https://docs.virustotal.com/docs/api-overview) to query [IoC](https://en.wikipedia.org/wiki/Indicator_of_compromise) from file hashes.
- [`shell/`](https://github.com/Abdullah-Shalan/cipher_assessment/tree/main/src/shell) directory have two shell scripts,  `domains.sh` which takes a *web logs* and generates a security report, and `passwords.sh` that extracts passwords form URL's.

## How to Use  

### 1. Clone the repo:  
   ```bash
   git clone https://github.com/Abdullah-Shalan/cipher_assessment.git
   cd cipher_assessment
   ```

### 2. Python Scripts

 Setup virtual environment (best practice):

  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  ```

Run: 
  ``` bash
  python src/python/<filename>.py
  ```

### 3. Shell Scripts

Make executable:

  ```bash
  chmod +x src/shell/<script>.sh
  ```
Run:
  ```bash
  ./src/shell/<filename>.sh
  ```