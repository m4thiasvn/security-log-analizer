
# Security Log Analyzer

project_name = "Security Log Analyzer"
version = 1.0
is_active = True
alert_message = "Suspicious activity detected!"

import csv

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

# Detect suspicious activity based on failed login attempts
def detect_suspicious_ips(login_events,alert_message,threshold):
    checked_ips = []

    for event in login_events:

        ip = event["ip"]

        if ip not in checked_ips:

            checked_ips.append(ip)

            ip_failed_count = 0

            for login in login_events:
                if login["ip"] == ip and login["status"] == "FAILED":
                    ip_failed_count += 1

            if ip_failed_count >= threshold:
                print(f"\n{alert_message} "f"IP: {ip} | Failed attempts: {ip_failed_count}")



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

    print("\nFAILED LOGIN ATTEMPTS:", total_failed_count)

    detect_suspicious_ips(login_events, alert_message,3)