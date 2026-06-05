"""
Cortex Cloud DSPM 테스트용 더미 데이터 생성 스크립트
실제 형식의 민감 데이터를 DB에 삽입하여 DSPM 스캔이 탐지하도록 구성
"""
import pymysql
import os
import random
import string

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASSWORD", "SuperSecret1234!")
DB_NAME = os.getenv("DB_NAME", "testdb")


def get_conn():
    return pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        database=DB_NAME, charset="utf8mb4"
    )


def create_tables(cursor):
    """DSPM 탐지 대상 테이블 생성"""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            name        VARCHAR(100),
            email       VARCHAR(150),
            phone       VARCHAR(20),
            ssn         VARCHAR(20),     -- 주민등록번호 (DSPM 탐지 대상)
            password    VARCHAR(255),
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credit_cards (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            user_id     INT,
            card_number VARCHAR(20),    -- 신용카드 번호 (DSPM 탐지 대상)
            expiry      VARCHAR(10),
            cvv         VARCHAR(5),     -- CVV 평문 저장 (DSPM 탐지 대상)
            card_holder VARCHAR(100)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS medical_records (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            user_id     INT,
            diagnosis   VARCHAR(255),   -- 진단명 (DSPM 탐지 대상)
            prescription TEXT,
            doctor      VARCHAR(100),
            visit_date  DATE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            service     VARCHAR(100),
            api_key     VARCHAR(255),   -- API Key 평문 저장 (DSPM/Code Security 탐지 대상)
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("✅ 테이블 생성 완료")


def insert_dummy_users(cursor):
    """주민번호·이메일·전화번호 포함 더미 사용자 데이터"""
    users = [
        ("김철수", "kim.chulsoo@example.com", "010-1234-5678", "900101-1234567", "hashed_pw_1"),
        ("이영희", "lee.younghee@example.com", "010-9876-5432", "850315-2345678", "hashed_pw_2"),
        ("박지민", "park.jimin@example.com",   "010-5555-6666", "920720-1111111", "hashed_pw_3"),
        ("최민준", "choi.minjun@example.com",  "010-7777-8888", "880505-2222222", "hashed_pw_4"),
        ("정수아", "jung.sua@example.com",     "010-3333-4444", "950912-1333333", "hashed_pw_5"),
    ]
    cursor.executemany(
        "INSERT INTO users (name, email, phone, ssn, password) VALUES (%s,%s,%s,%s,%s)",
        users
    )
    print(f"✅ 사용자 더미 데이터 {len(users)}건 삽입")


def insert_dummy_cards(cursor):
    """신용카드 번호·CVV 더미 데이터 (PCI DSS 탐지 대상)"""
    cards = [
        (1, "4532-1234-5678-9012", "12/26", "123", "김철수"),
        (2, "5425-2334-3010-9903", "08/25", "456", "이영희"),
        (3, "4916-5100-2345-6789", "03/27", "789", "박지민"),
        (4, "3782-822463-10005",   "11/24", "1234", "최민준"),  # Amex
        (5, "6011-1111-1111-1117", "06/26", "321", "정수아"),
    ]
    cursor.executemany(
        "INSERT INTO credit_cards (user_id, card_number, expiry, cvv, card_holder) VALUES (%s,%s,%s,%s,%s)",
        cards
    )
    print(f"✅ 신용카드 더미 데이터 {len(cards)}건 삽입")


def insert_dummy_medical(cursor):
    """의료 기록 더미 데이터 (PHI 탐지 대상)"""
    records = [
        (1, "고혈압 (Hypertension)",    "암로디핀 5mg 1일 1회",          "김의사", "2024-01-15"),
        (2, "당뇨병 2형 (T2DM)",        "메트포르민 500mg 1일 2회",       "이의사", "2024-02-20"),
        (3, "우울증 (Depression)",      "에스시탈로프람 10mg 1일 1회",    "박의사", "2024-03-10"),
        (4, "고지혈증 (Hyperlipidemia)", "아토르바스타틴 20mg 1일 1회",   "최의사", "2024-04-05"),
        (5, "불안장애 (Anxiety)",       "알프라졸람 0.25mg 필요시 복용",  "정의사", "2024-05-18"),
    ]
    cursor.executemany(
        "INSERT INTO medical_records (user_id, diagnosis, prescription, doctor, visit_date) VALUES (%s,%s,%s,%s,%s)",
        records
    )
    print(f"✅ 의료 기록 더미 데이터 {len(records)}건 삽입")


def insert_dummy_api_keys(cursor):
    """API 키 평문 저장 (DSPM/Code Security 탐지 대상)"""
    keys = [
        ("AWS",        "AKIAIOSFODNN7EXAMPLE"),
        ("Stripe",     "sk_live_4eC39HqLyjWDarjtT1zdp7dc"),
        ("SendGrid",   "SG.xxxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"),
        ("Slack",      "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"),
        ("GitHub PAT", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
    ]
    cursor.executemany(
        "INSERT INTO api_keys (service, api_key) VALUES (%s,%s)",
        keys
    )
    print(f"✅ API Key 더미 데이터 {len(keys)}건 삽입")


def main():
    print("🚀 DSPM 테스트용 더미 데이터 삽입 시작...")
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            create_tables(cursor)
            insert_dummy_users(cursor)
            insert_dummy_cards(cursor)
            insert_dummy_medical(cursor)
            insert_dummy_api_keys(cursor)
        conn.commit()
        print("\n✅ 모든 더미 데이터 삽입 완료!")
        print("📌 Cortex Cloud DSPM에서 다음 데이터 유형이 탐지되어야 합니다:")
        print("   - 주민등록번호 (Korean SSN)")
        print("   - 신용카드 번호 (PCI DSS)")
        print("   - 의료 기록 (PHI/HIPAA)")
        print("   - API Key (시크릿)")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
