#!/usr/bin/env python3
import time
import json
import os
from collections import defaultdict
from prometheus_client import start_http_server, Counter, Summary

# This script tails the NGINX access.log (formatted as JSON by shadow_log)
# and exposes Prometheus metrics for the Shadow Mode Parity track.
# It correlates Lumina and ModSecurity subrequests by request_id.

LOG_FILE = os.environ.get("LOG_FILE", "/var/log/nginx/access.log")

PARITY_DISAGREEMENT = Counter('lumina_parity_disagreement_total', 'Count of disagreements between Lumina and ModSecurity')
PARITY_AGREEMENT = Counter('lumina_parity_agreement_total', 'Count of agreements')
LUMINA_DECISION_COST = Summary('lumina_decision_cost_us', 'Decision cost of LuminaWAF in microseconds')
MODSEC_DECISION_COST = Summary('modsec_decision_cost_us', 'Decision cost of ModSecurity in microseconds')

def follow(thefile):
    thefile.seek(0, 2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def main():
    # Start up the server to expose the metrics.
    start_http_server(8000)
    print(f"Started Prometheus exporter on port 8000. Tailing {LOG_FILE}")
    
    while not os.path.exists(LOG_FILE):
        print(f"Waiting for {LOG_FILE} to exist...")
        time.sleep(1)
        
    req_buffer = defaultdict(dict)
    
    with open(LOG_FILE, "r") as logfile:
        loglines = follow(logfile)
        for line in loglines:
            try:
                data = json.loads(line.strip())
                req_id = data.get("req_id")
                req_type = data.get("type")
                
                if not req_id or not req_type:
                    continue
                    
                req_buffer[req_id][req_type] = data
                
                # If we have both logs for this req_id, correlate and emit
                if "lumina" in req_buffer[req_id] and "modsec" in req_buffer[req_id]:
                    l_data = req_buffer[req_id]["lumina"]
                    m_data = req_buffer[req_id]["modsec"]
                    
                    lumina_status = l_data.get("status")
                    modsec_status = m_data.get("status")
                    
                    if lumina_status and modsec_status:
                        lumina_blocked = (int(lumina_status) == 403)
                        modsec_blocked = (int(modsec_status) == 403)
                        
                        if lumina_blocked == modsec_blocked:
                            PARITY_AGREEMENT.inc()
                        else:
                            PARITY_DISAGREEMENT.inc()
                    
                    l_time = l_data.get("latency")
                    m_time = m_data.get("latency")
                    
                    if l_time and l_time != "-":
                        LUMINA_DECISION_COST.observe(float(l_time) * 1000000)
                    
                    if m_time and m_time != "-":
                        MODSEC_DECISION_COST.observe(float(m_time) * 1000000)
                        
                    # Cleanup
                    del req_buffer[req_id]
                    
                # Periodic cleanup of old incomplete requests to prevent memory leak
                if len(req_buffer) > 10000:
                    req_buffer.clear()
                    
            except Exception:
                pass

if __name__ == '__main__':
    main()
