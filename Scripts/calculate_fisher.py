"""
Calculates Fisher's Exact Test for RQ1 and RQ2, directly from the
50-iteration result CSVs produced by the automation scripts
"""

from scipy.stats import fisher_exact
import csv

RQ1_ATTACK_CSV = "/home/guillem/tfm-evidence/rq1_case_lkgt_acceptance_20260721_191115/results.csv"
RQ1_CONTROL_CSV = "/home/guillem/tfm-evidence/rq1_case_realclock_control_20260721_193628/results.csv"
RQ2_ATTACK_CSV = "/home/guillem/tfm-evidence/rq2_utctime_forward_attack_20260723_210648/results.csv"
RQ2_CONTROL_CSV = "/home/guillem/tfm-evidence/rq2_utctime_baseline_control_20260723_215851/results.csv"


def count_outcomes(csv_path, outcome_col, positive_value):
    #how many rows match positive_value in outcome_col, vs everything else
    positive, negative = 0, 0
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            if row[outcome_col] == positive_value:
                positive += 1
            else:
                negative += 1
    return positive, negative


def run_fisher(label, table):
    odds_ratio, p_value = fisher_exact(table)
    print(f"=== {label} ===")
    print(f"Table (rows=condition, cols=outcome): {table}")
    print(f"Odds ratio: {odds_ratio}")
    print(f"p-value: {p_value:.6e}")
    print()
    return odds_ratio, p_value


if __name__ == "__main__":
    attack_yes, attack_no = count_outcomes(RQ1_ATTACK_CSV, "case_established", "TRUE")
    control_yes, control_no = count_outcomes(RQ1_CONTROL_CSV, "case_established", "TRUE")
    run_fisher("RQ1: expired NOC acceptance vs clock source",
               [[attack_yes, attack_no], [control_yes, control_no]])

    attack_rej, attack_est = count_outcomes(RQ2_ATTACK_CSV, "case_result", "rejected_expired")
    control_rej, control_est = count_outcomes(RQ2_CONTROL_CSV, "case_result", "rejected_expired")
    run_fisher("RQ2: CASE rejection after forward LKGT manipulation",
               [[attack_rej, attack_est], [control_rej, control_est]])
