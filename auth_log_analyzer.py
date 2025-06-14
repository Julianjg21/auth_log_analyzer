#!/usr/bin/env python3
"""
auth_log_analyzer.py

This script analyzes failed authentication attempts from log files,
summarizing them by IP address and optionally generating a JSON report.

Usage:
    python auth_log_analyzer.py -l /path/to/logfile -o /path/to/output.json
"""

import argparse
import json
import re
from collections import defaultdict

# ---------------------- Command-line Arguments ---------------------- #
parser = argparse.ArgumentParser(description="Analyze failed authentication attempts in logs.")
parser.add_argument(
    "-l", "--log", dest="log_file_path",
    help="Path to the log file to analyze",
    required=True
)
parser.add_argument(
    "-o", "--output", dest="json_output_path",
    help="Path to save the report as a JSON file (optional)"
)
args = parser.parse_args()

# ---------------------------- Read Log File ---------------------------- #
def read_log(file_path):
    print(f"\n[*] Opening log file: {file_path}")
    try:
        with open(file_path, 'r') as f:
            for line in f:
                yield line.strip()
    except FileNotFoundError:
        print(f"[!] Error: File '{file_path}' not found.")
        exit(1)
    print("[*] File reading completed.")

# ------------------------ Analyze Log Patterns ------------------------ #
def analyze_log():
    attack_counter = defaultdict(int)
    pattern = re.compile(r"Failed password for .*? user (\S+) from ([\d.]+)")

    try:
        for line in read_log(args.log_file_path):
            match = pattern.search(line)
            if match:
                ip_address = match.group(2)
                attack_counter[ip_address] += 1

        print("\n--- Attempt Summary by IP ---")
        for ip, count in sorted(attack_counter.items(), key=lambda x: x[1], reverse=True):
            print(f"[+] IP: {ip} - Attempts: {count}")

        final_report = {
            'analyzed_file': args.log_file_path,
            'unique_attackers': len(attack_counter),
            'attack_summary': dict(attack_counter)
        }

        if args.json_output_path:
            try:
                with open(args.json_output_path, 'w') as json_file:
                    json.dump(final_report, json_file, indent=4)
                    print(f"[+] JSON report saved at: {args.json_output_path}")
            except FileNotFoundError:
                print("[!] Error: Output path not found.")
            except Exception as e:
                print(f"[!] Error saving JSON: {e}")

    except Exception as e:
        print(f"[!] Error during analysis: {e}")

# ---------------------------- Run Analyzer ----------------------------- #
if __name__ == "__main__":
    analyze_log()
