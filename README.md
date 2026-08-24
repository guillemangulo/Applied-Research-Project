# Artefact

Guide for the artefact for the MSc Applied Research Project "Trusting the Clock:
Evaluating the Security of Matter's Certificate Validation against Time
Synchronization Attacks" (Dublin Business School).

This repository contains the scripts, the raw per-iteration evidence, and the
statistical output for the two experiments reported in Chapter 4 of the report.

## Environment

- Host: Ubuntu 22.04 LTS virtual machine.
- SDK: connectedhomeip (Matter reference implementation), tag v1.5.1.0,
  commit abcc720b48c5e59c0edcfe65c516f76ca9448aa3.
- Two programs are built from that commit: chip-tool (controller) and
  chip-all-clusters-app (accessory / victim node).

The compiled binaries and the full virtual machine are not included, because of
their size. The environment is reproducible from the pinned commit above. The
only source change is the fault-injection patch in
Scripts/CASESession_fault_injection.patch.

## What each research question tests

- RQ1: whether a node accepts an already expired Node Operational Certificate
  when the validating party has no verified clock and falls back to Last Known
  Good Time.
- RQ2: whether advancing a node's clock with the standard SetUTCTime command
  makes valid certificates appear expired, causing an irreversible denial of
  service.

## Contents

### Scripts/

- case_revalidation_of_expired_NOC.py - RQ1. Runs the full pipeline
  per iteration (commission, install an expired NOC, re-open a CASE session,
  record the outcome). 

- run_rq1_attack.py - helper invoked automatically by the RQ1  script for each iteration. Signs an expired NOC with the fabric's real root key. Also runnable standalone given a raw NOCSRElements hex value for manual testing, but this is not part of the normal reproduction flow.

- utctime_forward_attack.py - RQ2. Sends SetUTCTime with a future
  timestamp, attempts a reconnection, and attempts a correction. 

- calculate_fisher.py - reads the result CSV files and computes Fisher's Exact
  Test for both research questions.

- CASESession_fault_injection.patch - the source modification applied to
  SetEffectiveTime() in src/protocols/secure_channel/CASESession.cpp. Reading
  the MATTER_FAULT_CLOCK environment variable forces the clock lookup to fail,
  reproducing a device with no reliable wall clock.

### Evidence/

Each of the four folders is one condition of one experiment, run for 50
iterations. Every folder contains a results.csv with the recorded outcome of
each iteration, and one subfolder per iteration (iter_1 ... iter_50) holding the
raw log files that each result is built from. 

- rq1_case_lkgt_acceptance_20260721_191115 - RQ1, attack condition (no verified
  clock, Last Known Good Time fallback). Expected: expired certificate accepted.

- rq1_case_realclock_control_20260721_193628 - RQ1, control condition (verified
  clock available). Expected: expired certificate rejected.

- rq2_utctime_forward_attack_20260723_210648 - RQ2, attack condition (clock
  advanced to a future time). Expected: valid certificates rejected (denial of
  service).

- rq2_utctime_baseline_control_20260723_215851 - RQ2, control condition (clock
  unmodified). Expected: reconnection succeeds.

### Statistics/

- fisher_output.txt - the output of calculate_fisher.py run on the result CSV
  files in the Evidence folders.