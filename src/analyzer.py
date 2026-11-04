
# Security Log Analyzer

project_name = "Security Log Analyzer"
version = 1.0
is_active = True
alert_message = "Suspicious activity detected!"
FAILED_LOGIN_THRESHOLD = 3

import csv
import os

# Load login events from CSV

# open, open the CSV file containing sample logs
# "r" mode is used for reading the file
# with, the file is automatically closed after the block of code is executed
# csv.DictReader, reads the CSV file and returns each row as a dictionary
def load_logs():
    login_events = []

    with open("data/sample_logs.csv", "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for event in reader:
            login_events.append(event)

    return login_events

# Count the number of failed login attempts
def count_failed_logins(login_events):
    total_failed_count = 0

    for event in login_events:
        if event["status"] == "FAILED":
            total_failed_count += 1

    return total_failed_count

# Count failed login attempts by IP address
def count_failed_by_ip(login_events):
    failed_by_ip = {}

    for event in login_events:
        if event["status"] == "FAILED":
            ip = event["ip"]
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1
    return failed_by_ip

# Detect suspicious IPs based on a threshold of failed login attempts
def detect_suspicious_ips(failed_by_ip, threshold):
    suspicious_ips = []

    for ip, failed_count in failed_by_ip.items():
        if failed_count >= threshold:
            suspicious_ips.append((ip, failed_count))

    return suspicious_ips

# Generate a report of suspicious IPs
def generate_report(suspicious_ips):
    report_lines = ["Suspicious IP Report:"]
    for ip, failed_count in suspicious_ips:
        report_lines.append(f"IP: {ip} | Failed Attempts: {failed_count}")
    return "\n".join(report_lines)

# Save the report to a file
def save_report(report):
    report_file_path = "reports/security_report.txt"
    with open(report_file_path, "w", encoding="utf-8") as file:
        file.write(report)
    print(f"Report saved to {report_file_path}")

# Main execution block
if __name__ == "__main__":
    print("Project:", project_name)
    print("Version:", version)
    print("Active:", is_active)
    login_events = load_logs()

    total_failed_count = count_failed_logins(login_events)

    print("\nLOGIN EVENTS:")

    for event in login_events:
        print(
            "IP:", event["ip"],
            "| User:", event["username"],
            "| Status:", event["status"]
        )

    print("FAILED LOGIN ATTEMPTS:", total_failed_count)

    failed_by_ip = count_failed_by_ip(login_events)
    suspicious_ips = detect_suspicious_ips(failed_by_ip, FAILED_LOGIN_THRESHOLD)

    for ip, failed_count in suspicious_ips:
        print("\n" + alert_message)
        print(f"Suspicious IP: {ip} | Failed Attempts: {failed_count}")

    report = generate_report(suspicious_ips)
    save_report(report) 

