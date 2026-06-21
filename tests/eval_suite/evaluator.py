import asyncio
import aiohttp
import json
import os
import re
import sys

BASE_URL_LUMINA = "http://localhost:8085/index.html"
BASE_URL_MODSEC = "http://localhost:8085/modsec/index.html"
ERROR_LOG_PATH = "/home/sebastian/workspace/lumina-waf/test_nginx/logs/error.log"

async def fetch(session, url, method="GET"):
    async with session.request(method, url) as response:
        status = response.status
        rule_id = response.headers.get("X-Lumina-Rule-Id")
        return status, rule_id

async def run_evaluation():
    corpus_file = os.path.join(os.path.dirname(__file__), "corpus/ground_truth.jsonl")
    records = []
    with open(corpus_file, "r") as f:
        for line in f:
            records.append(json.loads(line))

    print(f"Loaded {len(records)} records. Sending requests...")

    # Wyczyść error.log przed testem
    os.system(f"echo '' > {ERROR_LOG_PATH}")

    async def worker(record, session):
        req_line = record['request'] # e.g. GET /?q=123
        method, path = req_line.split(" ", 1)
        
        # Append req_id
        if "?" in path:
            path += f"&req_id={record['id']}"
        else:
            path += f"?req_id={record['id']}"

        # URL
        path = path.replace("/api/data", "").replace("/search", "").replace("/products", "").replace("/login", "").replace("/api/orders", "").replace("/home", "").replace("/dashboard", "").replace("//", "/")
        if not path.startswith("/"):
            path = "/" + path

        lumina_url = BASE_URL_LUMINA.replace("/index.html", "") + path
        modsec_url = BASE_URL_MODSEC.replace("/modsec/index.html", "/modsec") + path

        try:
            lum_status, lum_rule = await fetch(session, lumina_url, method)
        except Exception:
            lum_status, lum_rule = 500, None

        try:
            mod_status, _ = await fetch(session, modsec_url, method)
        except Exception:
            mod_status = 500

        return record['id'], lum_status, lum_rule, mod_status

    results = []
    chunk_size = 500
    connector = aiohttp.TCPConnector(limit=500)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(records), chunk_size):
            chunk = records[i:i+chunk_size]
            tasks = [worker(r, session) for r in chunk]
            res = await asyncio.gather(*tasks)
            results.extend(res)
            print(f"Processed {i+len(chunk)}/{len(records)}...")

    print("Parsing ModSecurity error.log to extract rule IDs...")
    modsec_rules = {}
    
    with open(ERROR_LOG_PATH, "r") as f:
        for line in f:
            if "ModSecurity: Access denied" in line:
                # Szukamy req_id
                m_req = re.search(r'req_id=(rec_\d+)', line)
                if m_req:
                    req_id = m_req.group(1)
                    # Szukamy rule id
                    m_id = re.search(r'\[id "(\d+)"\]', line)
                    if m_id:
                        modsec_rules[req_id] = int(m_id.group(1))

    # Analiza wyników
    print("Calculating metrics...")
    
    tp_lum = 0
    fp_lum = 0
    fn_lum = 0
    tn_lum = 0

    tp_mod = 0
    fp_mod = 0
    fn_mod = 0
    tn_mod = 0

    rule_parity_mismatch = 0

    for r in records:
        rec_id = r['id']
        expected_verdict = r['expected_verdict']
        expected_rule = r['expected_rule']

        # Odszukaj wyniki
        lum_status, lum_rule, mod_status = None, None, None
        for res in results:
            if res[0] == rec_id:
                lum_status, lum_rule, mod_status = res[1], res[2], res[3]
                break
        
        mod_rule = modsec_rules.get(rec_id, None)

        lum_verdict = "BLOCK" if lum_status == 403 else "ALLOW"
        mod_verdict = "BLOCK" if mod_status == 403 else "ALLOW"

        # LuminaWAF Metrics
        if expected_verdict == "BLOCK":
            if lum_verdict == "BLOCK":
                tp_lum += 1
            else:
                fn_lum += 1
        else:
            if lum_verdict == "BLOCK":
                fp_lum += 1
            else:
                tn_lum += 1

        # ModSec Metrics
        if expected_verdict == "BLOCK":
            if mod_verdict == "BLOCK":
                tp_mod += 1
            else:
                fn_mod += 1
        else:
            if mod_verdict == "BLOCK":
                fp_mod += 1
            else:
                tn_mod += 1

        # Rule-Level Parity
        if expected_rule is not None:
            if lum_rule and int(lum_rule) != expected_rule:
                rule_parity_mismatch += 1
                
    def get_metrics(tp, fp, fn, tn):
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        return precision, recall, f1, accuracy

    p_lum, r_lum, f1_lum, a_lum = get_metrics(tp_lum, fp_lum, fn_lum, tn_lum)
    p_mod, r_mod, f1_mod, a_mod = get_metrics(tp_mod, fp_mod, fn_mod, tn_mod)

    print("\n" + "="*50)
    print(" LUEF: LUMINA ULTIMATE EVALUATION FRAMEWORK ")
    print("="*50)
    print(f"Total Records: {len(records)}")
    
    print("\n--- LUMINA WAF METRICS ---")
    print(f"True Positives (TP): {tp_lum}")
    print(f"False Positives (FP): {fp_lum}")
    print(f"True Negatives (TN):  {tn_lum}")
    print(f"False Negatives (FN): {fn_lum}")
    print(f"Precision: {p_lum:.4f}")
    print(f"Recall:    {r_lum:.4f}")
    print(f"F1-Score:  {f1_lum:.4f}")
    print(f"Accuracy:  {a_lum:.4f}")
    print(f"Rule Parity Mismatch: {rule_parity_mismatch}")

    print("\n--- MODSECURITY METRICS ---")
    print(f"True Positives (TP): {tp_mod}")
    print(f"False Positives (FP): {fp_mod}")
    print(f"True Negatives (TN):  {tn_mod}")
    print(f"False Negatives (FN): {fn_mod}")
    print(f"Precision: {p_mod:.4f}")
    print(f"Recall:    {r_mod:.4f}")
    print(f"F1-Score:  {f1_mod:.4f}")
    print(f"Accuracy:  {a_mod:.4f}")

    print("="*50)

if __name__ == "__main__":
    asyncio.run(run_evaluation())
