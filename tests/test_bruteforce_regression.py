"""Regression tests for single-line vs multiline failed-login counting."""
from app.services.sentinel_fusion import evaluate_rules, _count_failed_logins, _success_after_fail

def test_space_joined_six_counts_as_six():
    txt = " ".join(["2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401"]*6)
    assert _count_failed_logins(txt) == 6
    assert evaluate_rules(txt)["verdict"] == "needs_review"
    assert evaluate_rules(txt)["failed_count"] == 6

def test_newline_joined_six():
    txt = "\n".join(["2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401"]*6)
    assert _count_failed_logins(txt) == 6

def test_comma_joined_six():
    txt = ", ".join(["2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401"]*6)
    assert _count_failed_logins(txt) == 6

def test_pipe_joined_six():
    txt = " | ".join(["2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401"]*6)
    assert _count_failed_logins(txt) == 6

def test_semicolon_joined_six():
    txt = "; ".join(["2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401"]*6)
    assert _count_failed_logins(txt) == 6

def test_json_concatenated_six():
    txt = " ".join(['{"event":"login","status":401,"msg":"login failed","ip":"192.168.1.10"}']*6)
    assert _count_failed_logins(txt) == 6

def test_syslog_six():
    txt = "\n".join(['Jan 15 10:00:00 host sshd[123]: Failed password for admin from 192.168.1.10 port 22']*6)
    assert _count_failed_logins(txt) == 6

def test_mixed_timestamps():
    txt = "2024-01-01T10:00:00Z 192.168.1.10 login failed 401\nJan 15 10:00:05 host sshd: Failed password for root from 192.168.1.10\n2024-01-01 10:00:10 WARN 192.168.1.10 login failed 401\n2024-01-01 10:00:11 WARN 192.168.1.10 login failed 401\n2024-01-01 10:00:12 WARN 192.168.1.10 login failed 401\n2024-01-01 10:00:13 WARN 192.168.1.10 login failed 401"
    assert _count_failed_logins(txt) == 6

def test_benign_selection_no_fp():
    assert _count_failed_logins("User viewed SELECTION committee report") == 0
    assert evaluate_rules("2024-01-01 10:00:00 INFO user alice viewed SELECTION committee report 200")["verdict"] == "likely_benign"

def test_benign_passwd_without_traversal():
    assert evaluate_rules("backup stored etc/passwd snapshot without traversal 200")["verdict"] == "likely_benign"

def test_single_401_is_benign():
    r = evaluate_rules("2024-01-01 10:00:03 WARN 192.168.1.50 GET /login 401 one failure")
    assert r["failed_count"] == 1
    assert r["verdict"] == "likely_benign"

def test_two_failures_below_threshold():
    txt = "\n".join(["2024-01-01 10:00:12 WARN 192.168.1.10 login failed 401"]*2)
    assert _count_failed_logins(txt) == 2
    assert evaluate_rules(txt)["verdict"] == "likely_benign"

def test_success_after_fail_single_line():
    txt = " ".join(['login failed 401']*5) + " login success 200"
    assert _success_after_fail(txt) is True
    assert _count_failed_logins(txt) == 5
    assert evaluate_rules(txt)["verdict"] == "likely_threat"

def test_success_after_fail_newline():
    txt = "\n".join(['login failed 401']*5) + "\nlogin success 200"
    assert _success_after_fail(txt) is True

def test_single_line_401_and_failed_not_double_counted():
    # "login failed 401" is one event, not two
    assert _count_failed_logins("2024-01-01 10:00:00 WARN 192.168.1.10 login failed for user admin 401") == 1
