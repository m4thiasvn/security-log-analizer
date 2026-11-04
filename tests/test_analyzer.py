import unittest
from src.analyzer import (
    count_failed_logins,
    count_failed_by_ip,
    detect_suspicious_ips,
    generate_report,
    load_logs,
    save_report,
    validate_logs,
    main
)
from unittest.mock import patch
from unittest.mock import patch, mock_open
import runpy

class TestCountFailedLogins(unittest.TestCase):
    def test_count_failed_logins(self):
        login_events = [
            {"ip": "192.168.1.10", "username": "admin", "status": "FAILED"},
            {"ip": "192.168.1.15", "username": "mathias", "status": "SUCCESS"},
            {"ip": "192.168.1.20", "username": "guest", "status": "FAILED"}
        ]
        self.assertEqual(count_failed_logins(login_events), 2)

    def test_count_failed_logins_with_empty_list(self):
        login_events = []
        self.assertEqual(count_failed_logins(login_events), 0)

    def test_count_failed_logins_with_successful_logins(self):
        login_events = [
            {"ip": "192.168.1.10", "username": "admin", "status": "SUCCESS"},
            {"ip": "192.168.1.15", "username": "mathias", "status": "SUCCESS"},
            {"ip": "192.168.1.20", "username": "guest", "status": "SUCCESS"}
        ]
        self.assertEqual(count_failed_logins(login_events), 0)

class TestCountFailedByIp(unittest.TestCase):
    def test_count_failed_by_ip(self):
        login_events = [
            {"ip": "192.168.1.10", "username": "admin", "status": "FAILED"},
            {"ip": "192.168.1.10", "username": "user1", "status": "FAILED"},
            {"ip": "192.168.1.15", "username": "mathias", "status": "SUCCESS"}
        ]
        expected = {"192.168.1.10": 2}
        self.assertEqual(count_failed_by_ip(login_events), expected)

    def test_count_failed_by_ip_with_empty_list(self):
        login_events = []
        expected = {}
        self.assertEqual(count_failed_by_ip(login_events), expected)

class TestDetectSuspiciousIps(unittest.TestCase):
    def test_detect_suspicious_ips(self):
        failed_by_ip = {"192.168.1.10": 4,"192.168.1.15": 2,"192.168.1.20": 3   }
        threshold = 3
        expected = [("192.168.1.10", 4),("192.168.1.20", 3)]
        self.assertEqual(detect_suspicious_ips(failed_by_ip, threshold), expected)

    def test_detect_suspicious_ips_below_threshold(self):
        failed_by_ip = {"192.168.1.10": 2,"192.168.1.15": 1,"192.168.1.20": 2  }
        threshold = 3
        expected = []
        self.assertEqual(detect_suspicious_ips(failed_by_ip, threshold), expected)

class TestGenerateReport(unittest.TestCase):
    def test_generate_report_with_suspicious_ips(self):
        suspicious_ips = [("192.168.1.10", 4),("192.168.1.20", 3)]
        report = generate_report(suspicious_ips)
        self.assertIn("Suspicious IP Report:", report)
        self.assertIn("Total Suspicious IPs: 2", report)
        self.assertIn("Total Failed Attempts: 7", report)
        self.assertIn("IP: 192.168.1.10 | Failed Attempts: 4", report)
        self.assertIn("IP: 192.168.1.20 | Failed Attempts: 3", report)

    def test_generate_report_without_suspicious_ips(self):
        suspicious_ips = []
        expected = "No suspicious IPs detected."
        self.assertEqual(generate_report(suspicious_ips), expected)

class TestLoadLogs(unittest.TestCase):
    def test_load_logs(self):
        login_events = load_logs()
        self.assertIsNotNone(login_events)
        self.assertGreater(len(login_events), 0)

    def test_load_logs_file_not_found(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            login_events = load_logs()
        self.assertIsNone(login_events)

class TestValidateLogs(unittest.TestCase):
    def test_validate_logs_with_valid_data(self):
        login_events = [
            {"ip": "192.168.1.10", "username": "admin", "status": "FAILED"},
            {"ip": "192.168.1.15", "username": "mathias", "status": "SUCCESS"}
        ]
        self.assertTrue(validate_logs(login_events))

    def test_validate_logs_with_empty_list(self):
        login_events = []
        self.assertFalse(validate_logs(login_events))

    def test_validate_logs_with_missing_fields(self):
        login_events = [{"ip": "192.168.1.10", "status": "FAILED"}]
        self.assertFalse(validate_logs(login_events))

    def test_validate_logs_with_invalid_status(self):
        login_events = [{"ip": "192.168.1.10", "username": "admin", "status": "PENDING"}]
        self.assertFalse(validate_logs(login_events))

    def test_validate_logs_with_empty_ip(self):
        login_events = [{"ip": "", "username": "admin", "status": "FAILED"}]
        self.assertFalse(validate_logs(login_events))

    def test_validate_logs_with_empty_username(self):
        login_events = [{"ip": "192.168.1.10", "username": "", "status": "FAILED"}]
        self.assertFalse(validate_logs(login_events))

    def test_load_logs_with_unexpected_error(self):
            with patch("builtins.open", side_effect=PermissionError):
                login_events = load_logs()
            self.assertIsNone(login_events)

class TestSaveReport(unittest.TestCase):
    def test_save_report(self):
        report = "Test security report"
        with patch("builtins.open", mock_open()) as mocked_file:
            save_report(report)
        mocked_file.assert_called_once()
        mocked_file().write.assert_called_once_with(report)

    def test_save_report_with_error(self):
        report = "Test security report"
        with patch("builtins.open", side_effect=PermissionError), \
            patch("builtins.print") as mocked_print:
            save_report(report)
        mocked_print.assert_called_once()

    def test_save_report_with_directory_error(self):
        report = "Test security report"
        with patch("src.analyzer.os.makedirs", side_effect=PermissionError), \
            patch("builtins.print") as mocked_print:
            save_report(report)
        mocked_print.assert_called_once()

    def test_save_report_with_file_not_found(self):
        report = "Test security report"
        with patch("builtins.open", side_effect=FileNotFoundError), \
         patch("builtins.print") as mocked_print:
            save_report(report)
        mocked_print.assert_called_once()

class TestMain(unittest.TestCase):
    def test_main_with_missing_log_file(self):
        with patch("src.analyzer.load_logs", return_value=None):
            with self.assertRaises(SystemExit):
                main()
    def test_main_with_invalid_logs(self):
        login_events = [{"ip": "192.168.1.10", "username": "admin", "status": "PENDING"}]
        with patch("src.analyzer.load_logs", return_value=login_events):
            with patch("src.analyzer.validate_logs", return_value=False):
                with self.assertRaises(SystemExit):
                    main()

    def test_main_without_suspicious_ips(self):
        login_events = [{"ip": "192.168.1.15", "username": "mathias", "status": "SUCCESS"}]
        with patch("src.analyzer.load_logs", return_value=login_events):
            with patch("src.analyzer.save_report") as mocked_save:
                main()
        mocked_save.assert_called_once()

    def test_main_with_suspicious_ips(self):
        login_events = [
        {"ip": "192.168.1.10", "username": "admin", "status": "FAILED"},
        {"ip": "192.168.1.10", "username": "admin", "status": "FAILED"},
        {"ip": "192.168.1.10", "username": "admin", "status": "FAILED"}
    ]   
        with patch("src.analyzer.load_logs", return_value=login_events):
            with patch("src.analyzer.save_report") as mocked_save:
                main()
        mocked_save.assert_called_once()

    def test_run_as_main(self):
        with patch("src.analyzer.main") as mocked_main:
            runpy.run_module("src.analyzer", run_name="__main__")
        mocked_main.assert_called_once()