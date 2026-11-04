
# Security Log Analyzer

PROJECT_NAME = "Security Log Analyzer"
VERSION = 1.0
IS_ACTIVE = True
ALERT_MESSAGE = "Suspicious activity detected!"

import csv
import os
from datetime import datetime

FAILED_LOGIN_THRESHOLD = 3
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Load login events from CSV
def load_logs():
    login_events = []
    try:
        log_file_path = os.path.join(BASE_DIR, "data", "sample_logs.csv")
        with open(log_file_path, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for event in reader:
                login_events.append(event)
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error reading logs: {e}")
        return None

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
    if not suspicious_ips:
        return "No suspicious IPs detected."
    report_lines = ["Suspicious IP Report:"]
    report_lines.append("Date: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    report_lines.append("\nTotal Suspicious IPs: " + str(len(suspicious_ips)))
    total_failed = sum(failed_count for _, failed_count in suspicious_ips)
    report_lines.append(f"Total Failed Attempts: {total_failed}\n")
    for ip, failed_count in suspicious_ips:
        report_lines.append(f"IP: {ip} | Failed Attempts: {failed_count}")
    return "\n".join(report_lines)

# Save the report to a file
def save_report(report):
    try:
        os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)
        report_file_path = os.path.join(BASE_DIR, "reports", "security_report.txt")
        with open(report_file_path, "w", encoding="utf-8") as file:
            file.write(report)
        print(f"\nReport saved to {report_file_path}")
    except FileNotFoundError:
        print("Error: Report directory not found. Please ensure 'reports/' directory exists.")
    except Exception as e:
        print(f"Error saving report: {e}")

# Validate the login events to ensure they have the correct structure and values
def validate_logs(login_events):
    if not login_events:
        print("No login events found.")
        return False
    has_errors = False
    for event in login_events:
        if "ip" not in event or "username" not in event or "status" not in event:
            print(f"Invalid log entry found: {event}")
            has_errors = True  
            continue
        if not event["ip"].strip() or not event["username"].strip():
            has_errors = True
            print(f"Invalid log entry found: {event}")      
        if event["status"] not in ["SUCCESS", "FAILED"]:
            print(f"Invalid status found in event: {event}")
            has_errors = True
    return not has_errors

# Main execution block
def main():
    print("\nProject:", PROJECT_NAME)
    print("Version:", VERSION)
    print("Active:", IS_ACTIVE , "\n")
    login_events = load_logs()
    
    if login_events is None:
        print("Error: Log file not found. Please ensure 'data/sample_logs.csv' exists.")
        return
    
    if not validate_logs(login_events):
        print("\nLog validation failed. Please check the logs for errors.")
        return
    
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
        print("\n" + ALERT_MESSAGE)
        print(f"Suspicious IP: {ip} | Failed Attempts: {failed_count}")
    
    report = generate_report(suspicious_ips)
    save_report(report) 
    
    if not suspicious_ips:
        print("\nNo suspicious IPs detected.")
    else:
        print("\nReport generated successfully.")
        
if __name__ == "__main__":
    main()        

    

