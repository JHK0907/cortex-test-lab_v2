"""
Cortex Cloud DSPM 테스트용 S3 더미 데이터 업로드 스크립트
민감 데이터가 포함된 파일을 취약 버킷과 보안 버킷에 업로드
"""
import boto3
import os
import csv
import json
import io

REGION          = os.getenv("AWS_REGION", "ap-northeast-2")
VULNERABLE_BUCKET = os.getenv("S3_VULNERABLE_BUCKET", "")
SECURE_BUCKET     = os.getenv("S3_SECURE_BUCKET", "")

s3 = boto3.client("s3", region_name=REGION)


def create_pii_csv() -> str:
    """개인정보(PII) 포함 CSV 생성 — DSPM 탐지 대상"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["이름", "주민번호", "이메일", "전화번호", "주소"])
    writer.writerows([
        ["김철수", "900101-1234567", "kim@example.com",  "010-1234-5678", "서울시 강남구"],
        ["이영희", "850315-2345678", "lee@example.com",  "010-9876-5432", "경기도 성남시"],
        ["박지민", "920720-1111111", "park@example.com", "010-5555-6666", "서울시 서초구"],
        ["최민준", "880505-2222222", "choi@example.com", "010-7777-8888", "부산시 해운대구"],
        ["정수아", "950912-1333333", "jung@example.com", "010-3333-4444", "인천시 연수구"],
    ])
    return output.getvalue()


def create_credit_card_csv() -> str:
    """신용카드 정보 CSV — PCI DSS DSPM 탐지 대상"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["이름", "카드번호", "만료일", "CVV", "청구주소"])
    writer.writerows([
        ["김철수", "4532-1234-5678-9012", "12/26", "123", "서울시 강남구"],
        ["이영희", "5425-2334-3010-9903", "08/25", "456", "경기도 성남시"],
        ["박지민", "4916-5100-2345-6789", "03/27", "789", "서울시 서초구"],
    ])
    return output.getvalue()


def create_medical_json() -> str:
    """의료 기록 JSON — PHI DSPM 탐지 대상"""
    records = [
        {
            "patient_id": "P001",
            "name": "김철수",
            "ssn": "900101-1234567",
            "diagnosis": "고혈압 (Hypertension)",
            "medications": ["암로디핀 5mg", "아스피린 100mg"],
            "doctor": "김의사",
            "hospital": "서울대학교병원",
            "visit_date": "2024-01-15"
        },
        {
            "patient_id": "P002",
            "name": "이영희",
            "ssn": "850315-2345678",
            "diagnosis": "당뇨병 2형 (T2DM)",
            "medications": ["메트포르민 500mg"],
            "doctor": "이의사",
            "hospital": "삼성서울병원",
            "visit_date": "2024-02-20"
        }
    ]
    return json.dumps(records, ensure_ascii=False, indent=2)


def create_api_keys_txt() -> str:
    """API 키 평문 저장 파일 — Code Security/DSPM 탐지 대상"""
    return """# API Keys - DO NOT COMMIT (intentionally vulnerable for Cortex test)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
DATABASE_URL=mysql://admin:SuperSecret1234!@rds.example.com/testdb
"""


def upload_to_bucket(bucket: str, key: str, content: str, content_type: str = "text/plain"):
    try:
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=content.encode("utf-8"),
            ContentType=content_type
        )
        print(f"  ✅ s3://{bucket}/{key}")
    except Exception as e:
        print(f"  ❌ 업로드 실패 s3://{bucket}/{key}: {e}")


def main():
    if not VULNERABLE_BUCKET or not SECURE_BUCKET:
        print("❌ 환경변수 S3_VULNERABLE_BUCKET, S3_SECURE_BUCKET 설정 필요")
        print("   export S3_VULNERABLE_BUCKET=$(terraform output -raw s3_vulnerable_bucket)")
        print("   export S3_SECURE_BUCKET=$(terraform output -raw s3_secure_bucket)")
        return

    print(f"🚀 S3 DSPM 더미 데이터 업로드 시작...")
    print(f"   취약 버킷: {VULNERABLE_BUCKET}")
    print(f"   보안 버킷: {SECURE_BUCKET}")

    # 취약 버킷에 민감 데이터 업로드 (DSPM 탐지 대상)
    print("\n📂 취약 버킷 업로드 (DSPM 탐지 대상):")
    upload_to_bucket(VULNERABLE_BUCKET, "personal/users_pii.csv",          create_pii_csv(),          "text/csv")
    upload_to_bucket(VULNERABLE_BUCKET, "financial/credit_cards.csv",      create_credit_card_csv(),  "text/csv")
    upload_to_bucket(VULNERABLE_BUCKET, "medical/patient_records.json",    create_medical_json(),     "application/json")
    upload_to_bucket(VULNERABLE_BUCKET, "config/api_keys.txt",             create_api_keys_txt(),     "text/plain")
    upload_to_bucket(VULNERABLE_BUCKET, "backup/db_export_users_pii.csv",  create_pii_csv(),          "text/csv")

    # 보안 버킷에도 일부 업로드 (비교 기준용)
    print("\n📂 보안 버킷 업로드 (비교 기준):")
    upload_to_bucket(SECURE_BUCKET, "reports/summary.json",
                     json.dumps({"report": "monthly", "records": 5}, ensure_ascii=False), "application/json")

    print("\n✅ 업로드 완료!")
    print("📌 Cortex Cloud DSPM에서 다음 항목 확인:")
    print(f"   - s3://{VULNERABLE_BUCKET}/ → 민감 데이터 다수 탐지 예상")
    print(f"   - s3://{SECURE_BUCKET}/    → 민감 데이터 없음 (기준)")


if __name__ == "__main__":
    main()
