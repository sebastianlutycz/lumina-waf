#!/bin/bash
# export_metrics.sh - Scrapes local Prometheus metrics and pushes to Upstash Redis
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$(dirname $(dirname "$DIR"))"
DOCS_DIR="$REPO_ROOT/docs"
HISTORY_FILE="$DOCS_DIR/history.json"

if [ -z "$UPSTASH_REDIS_REST_URL" ] || [ -z "$UPSTASH_REDIS_REST_TOKEN" ]; then
    echo "ERROR: Upstash credentials not found in environment."
    exit 1
fi

echo "Starting Telemetry Shipper Daemon..."

# Initialize history.json if missing
if [ ! -f "$HISTORY_FILE" ]; then
    echo "[]" > "$HISTORY_FILE"
fi

while true; do
    # Fetch metrics from local shadow exporter
    METRICS=$(curl -s http://shadow_exporter:8000/metrics || echo "")

    if [ -n "$METRICS" ]; then
        LUMINA_AGREEMENTS=$(echo "$METRICS" | awk '/^lumina_parity_agreement_total / {print $2}' | cut -d'.' -f1)
        LUMINA_DISAGREEMENTS=$(echo "$METRICS" | awk '/^lumina_parity_disagreement_total / {print $2}' | cut -d'.' -f1)

        LUMINA_COST_SUM=$(echo "$METRICS" | awk '/^lumina_decision_cost_us_sum / {print $2}')
        LUMINA_COST_COUNT=$(echo "$METRICS" | awk '/^lumina_decision_cost_us_count / {print $2}' | cut -d'.' -f1)

        MODSEC_COST_SUM=$(echo "$METRICS" | awk '/^modsec_decision_cost_us_sum / {print $2}')
        MODSEC_COST_COUNT=$(echo "$METRICS" | awk '/^modsec_decision_cost_us_count / {print $2}' | cut -d'.' -f1)

        LUMINA_AGREEMENTS=${LUMINA_AGREEMENTS:-0}
        LUMINA_DISAGREEMENTS=${LUMINA_DISAGREEMENTS:-0}
        LUMINA_COST_COUNT=${LUMINA_COST_COUNT:-0}
        MODSEC_COST_COUNT=${MODSEC_COST_COUNT:-0}

        LUMINA_AVG_COST="0"
        if [ "$LUMINA_COST_COUNT" != "0" ] && [ -n "$LUMINA_COST_COUNT" ]; then
            LUMINA_AVG_COST=$(awk -v sum="$LUMINA_COST_SUM" -v count="$LUMINA_COST_COUNT" 'BEGIN { printf "%.2f", sum / count }')
        fi

        MODSEC_AVG_COST="0"
        if [ "$MODSEC_COST_COUNT" != "0" ] && [ -n "$MODSEC_COST_COUNT" ]; then
            MODSEC_AVG_COST=$(awk -v sum="$MODSEC_COST_SUM" -v count="$MODSEC_COST_COUNT" 'BEGIN { printf "%.2f", sum / count }')
        fi

        TOTAL_PARITY=$(awk -v a="$LUMINA_AGREEMENTS" -v d="$LUMINA_DISAGREEMENTS" 'BEGIN { printf "%.4f", (a / (a + d + 0.0001)) * 100 }')

        # Prepare new datapoint
        DATAPOINT=$(cat <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "parity_percentage": "$TOTAL_PARITY",
  "lumina_avg_cost_us": "$LUMINA_AVG_COST",
  "modsec_avg_cost_us": "$MODSEC_AVG_COST"
}
EOF
        )

        # Append and keep last 24 items
        jq ". + [$DATAPOINT] | .[-24:]" "$HISTORY_FILE" > "$HISTORY_FILE.tmp"
        mv "$HISTORY_FILE.tmp" "$HISTORY_FILE"

        JSON_PAYLOAD=$(cat "$HISTORY_FILE")
        
        # Push to Upstash
        RESP=$(curl -s -X POST "$UPSTASH_REDIS_REST_URL/set/lumina_telemetry" \
            -H "Authorization: Bearer $UPSTASH_REDIS_REST_TOKEN" \
            -d "$JSON_PAYLOAD")
        
        echo "Pushed telemetry: $RESP"
    else
        echo "Failed to fetch metrics, retrying in 5s..."
    fi

    sleep 5
done
