# Security Log Analyzer

A beginner-friendly cybersecurity project built with Python to analyze login logs and detect potentially suspicious activity.

## Description

Security Log Analyzer reads login events from a CSV file, analyzes failed login attempts, identifies suspicious IP addresses, and generates a security report.

This project was developed as a practical way to improve Python programming skills while exploring fundamental cybersecurity concepts.

## Features

- Load login events from CSV files.
- Validate log entries and detect invalid data.
- Count total failed login attempts.
- Track failed login attempts by IP address.
- Identify suspicious IP addresses using a configurable threshold.
- Generate timestamped security reports.
- Save reports automatically to a designated directory.
- Handle file errors and manage project paths.

## Technologies

- Python 3
- CSV
- Git
- GitHub

## Project Structure

```text
security-log-analizer/
├── data/
│   └── sample_logs.csv
├── reports/
│   └── security_report.txt
├── src/
│   └── analyzer.py
└── README.md
```

## Configuration

The detection threshold can be adjusted using the `FAILED_LOGIN_THRESHOLD` constant in `analyzer.py`.

Default threshold: `3` failed login attempts.

## How to Run

1. Clone this repository:

```bash
git clone <repository-url>
```

2. Navigate to the project directory:

```bash
cd security-log-analizer
```

3. Run the analyzer:

```bash
python3 src/analyzer.py
```

## Learning Goals

- Practice Python fundamentals and functions.
- Work with CSV files and dictionaries.
- Understand exception handling and file management.
- Explore basic security log analysis.
- Practice version control with Git and GitHub.

## Disclaimer

This is an educational project that uses sample login logs. It is not intended to replace a production security monitoring or intrusion detection system.