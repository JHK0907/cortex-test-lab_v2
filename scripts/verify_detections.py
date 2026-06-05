#!/usr/bin/env python3
"""
Cortex Cloud ASPM/DSPM/Code Security 탐지 검증 스크립트
배포 후 각 취약 엔드포인트를 호출하여 ASPM이 트래픽을 탐지하는지 확인
"""
import requests
import json
import sys
import os

BASE_URL = os.getenv("APP_URL", "http://localhost")


def print_result(name: str, passed: bool, detail: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"  {status}  {name}")
    if detail:
        print(f"         → {detail}")


def test_sqli():
    """SQL Injection 엔드포인트 테스트"""
    print("\n[1] SQL Injection 테스트 (ASPM 탐지 대상)")
    # 정상 요청
    r = requests.get(f"{BASE_URL}/users?id=1", timeout=5)
    print_result("정상 요청 /users?id=1", r.status_code == 200, f"HTTP {r.status_code}")

    # SQLi 공격 페이로드
    payloads = ["1 OR 1=1", "1; DROP TABLE users--", "' UNION SELECT 1,2,3--"]
    for payload in payloads:
        r = requests.get(f"{BASE_URL}/users", params={"id": payload}, timeout=5)
        print_result(f"SQLi 페이로드: {payload[:30]}", r.status_code in [200, 500],
                     f"HTTP {r.status_code}")


def test_xss():
    """XSS 엔드포인트 테스트"""
    print("\n[2] XSS 테스트 (ASPM 탐지 대상)")
    payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)"
    ]
    for payload in payloads:
        r = requests.get(f"{BASE_URL}/greet", params={"name": payload}, timeout=5)
        reflected = payload in r.text
        print_result(f"XSS 페이로드 반사 확인", reflected, payload[:40])


def test_admin_no_auth():
    """인증 없는 관리자 접근 테스트"""
    print("\n[3] 인증 없는 Admin 접근 (ASPM 탐지 대상)")
    r = requests.get(f"{BASE_URL}/admin", timeout=5)
    print_result("인증 없이 /admin 접근", r.status_code == 200, f"HTTP {r.status_code}")

    r = requests.get(f"{BASE_URL}/data/export", timeout=5)
    print_result("인증 없이 /data/export 접근", r.status_code == 200, f"HTTP {r.status_code}")


def test_sensitive_data_exposure():
    """민감 데이터 노출 테스트"""
    print("\n[4] 민감 데이터 노출 테스트 (DSPM 연계)")
    r = requests.get(f"{BASE_URL}/health", timeout=5)
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    has_env = "env_vars" in data
    print_result("/health에서 환경변수 노출", has_env, "env_vars 키 존재" if has_env else "없음")

    r = requests.get(f"{BASE_URL}/data/export", timeout=5)
    if r.status_code == 200:
        data = r.json()
        has_ssn    = any("ssn" in str(u) for u in data.get("users", []))
        has_cards  = len(data.get("credit_cards", [])) > 0
        print_result("SSN 데이터 노출", has_ssn)
        print_result("신용카드 데이터 노출", has_cards)


def test_command_injection():
    """Command Injection 엔드포인트 테스트"""
    print("\n[5] Command Injection 테스트 (ASPM 탐지 대상)")
    r = requests.get(f"{BASE_URL}/ping", params={"host": "127.0.0.1"}, timeout=10)
    print_result("정상 ping 요청", r.status_code == 200, f"HTTP {r.status_code}")

    # 위험한 페이로드 (실제 실행되면 안 됨 — 탐지 목적)
    r = requests.get(f"{BASE_URL}/ping", params={"host": "127.0.0.1; echo INJECTED"}, timeout=10)
    if r.status_code == 200:
        injected = "INJECTED" in r.text
        print_result("Command Injection 페이로드 탐지", True,
                     "실행됨 — ASPM이 이 요청을 탐지해야 함" if injected else "실행 안 됨")


def test_idor():
    """IDOR 테스트"""
    print("\n[6] IDOR 테스트 (ASPM 탐지 대상)")
    for user_id in [1, 2, 3]:
        r = requests.get(f"{BASE_URL}/profile/{user_id}", timeout=5)
        print_result(f"인증 없이 /profile/{user_id} 접근", r.status_code == 200,
                     f"HTTP {r.status_code}")


def main():
    print("=" * 60)
    print("Cortex Cloud ASPM/DSPM 탐지 검증 스크립트")
    print(f"대상 URL: {BASE_URL}")
    print("=" * 60)

    # 앱 연결 확인
    try:
        r = requests.get(f"{BASE_URL}/", timeout=5)
        print(f"\n✅ 앱 연결 성공 (HTTP {r.status_code})")
    except Exception as e:
        print(f"\n❌ 앱 연결 실패: {e}")
        print("APP_URL 환경변수를 확인하세요.")
        sys.exit(1)

    test_sqli()
    test_xss()
    test_admin_no_auth()
    test_sensitive_data_exposure()
    test_command_injection()
    test_idor()

    print("\n" + "=" * 60)
    print("✅ 테스트 완료")
    print("📌 Cortex Cloud 콘솔에서 다음 항목 확인:")
    print("   ASPM → API Security  : 위 요청들이 탐지되어야 함")
    print("   DSPM → Data Findings : 민감 데이터 분류 결과 확인")
    print("   Code Security        : GitHub 연동 후 시크릿/취약점 확인")
    print("=" * 60)


if __name__ == "__main__":
    main()
