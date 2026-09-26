#!/usr/bin/env bash
# ==============================================================================
# NYX-PRIME // WRAITH E2E SEQUENCE RUNNER
# Executes 7 Kernel & Anonymization Scenarios Sequentially
# ==============================================================================
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

echo "========================================================================"
echo "    WRAITH E2E KERNEL INTEGRATION AUDIT SUITE (7 SCENARIOS)"
echo "========================================================================"

run_stage() {
    local script="$1"
    local name="$2"
    echo ""
    echo ">> [STAGE] $name ($script)"
    echo "------------------------------------------------------------------------"
    bash "$SCRIPT_DIR/$script"
    echo ">> [STAGE PASSED] $name"
}

run_stage "01-netfilter.sh"        "Netfilter Routing & TransPort Redirect"
run_stage "02-dns.sh"              "Sovereign DNS Resolution & DNSSEC Validation"
run_stage "03-tor-connectivity.sh" "Tor Circuit Readiness & TCP Egress Anonymity"
run_stage "04-dns-leak.sh"         "Wire-Level DNS Leak Audit (Zero UDP/53 Clearnet)"
run_stage "05-kill-switch.sh"      "Tor Daemon SIGKILL & Fail-Closed Kill-Switch"
run_stage "06-clean-shutdown.sh"   "Graceful Teardown & Netfilter Rollback"
run_stage "07-emergency-reset.sh"  "Emergency Recovery Script (reset.sh) Verification"

echo ""
echo "========================================================================"
echo "    ALL 7 E2E KERNEL INTEGRATION SCENARIOS COMPLETED SUCCESSFULLY"
echo "========================================================================"
