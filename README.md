# Cortex Cloud DSPM / ASPM / Code Security 테스트 랩

> ⚠️  이 레포지토리는 Cortex Cloud 보안 기능 테스트 전용입니다.
> 취약 코드와 더미 민감 데이터가 의도적으로 포함되어 있습니다.
> 실제 운영 환경에 절대 사용하지 마세요.

---

## 전체 구성 개요

```
GitHub Repo (Code Security 스캔)
    ↓ GitHub Actions CI/CD
EC2 t3.small — FastAPI 취약 앱 (ASPM 탐지)
    ├── RDS MySQL — 민감 더미 데이터 (DSPM 탐지)
    └── S3 버킷 2개 — PII/카드/의료 파일 (DSPM 탐지)
         ↓ AWS 온보딩
Cortex Cloud — DSPM / ASPM / Code Security / CSPM / CIEM
```

---

## Step 1 — 사전 준비

```bash
# 필수 도구 설치 확인
terraform --version   # >= 1.5
aws --version         # AWS CLI v2
python3 --version     # >= 3.10
git --version

# AWS 자격증명 설정
aws configure
# AWS Access Key ID: [your key]
# AWS Secret Access Key: [your secret]
# Default region: ap-northeast-2

# SSH 키 생성 (없으면)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/cortex-test-key
```

---

## Step 2 — Terraform으로 AWS 인프라 배포

```bash
cd terraform/

# 초기화
terraform init

# 플랜 확인 (취약 설정 목록 미리 확인)
terraform plan

# 배포 (약 10분 소요)
terraform apply -auto-approve

# 출력값 저장
EC2_IP=$(terraform output -raw ec2_public_ip)
RDS_ENDPOINT=$(terraform output -raw rds_endpoint)
S3_VULN=$(terraform output -raw s3_vulnerable_bucket)
S3_SECURE=$(terraform output -raw s3_secure_bucket)

echo "EC2 IP      : $EC2_IP"
echo "RDS Endpoint: $RDS_ENDPOINT"
echo "S3 Vuln     : $S3_VULN"
echo "S3 Secure   : $S3_SECURE"
```

---

## Step 3 — DB 더미 데이터 삽입 (DSPM 대상)

```bash
# EC2가 준비될 때까지 대기 (약 2분)
sleep 120

# RDS 엔드포인트 환경변수 설정
export DB_HOST=$RDS_ENDPOINT
export DB_USER=admin
export DB_PASSWORD=SuperSecret1234!
export DB_NAME=testdb

# DB 초기화 + 더미 데이터 삽입
python3 scripts/init_db.py
```

---

## Step 4 — S3 민감 데이터 업로드 (DSPM 대상)

```bash
export S3_VULNERABLE_BUCKET=$S3_VULN
export S3_SECURE_BUCKET=$S3_SECURE
export AWS_REGION=ap-northeast-2

python3 scripts/upload_s3_data.py
```

---

## Step 5 — GitHub 저장소 설정

```bash
# GitHub에 레포 생성 후 push
git init
git add .
git commit -m "Initial commit (intentionally vulnerable)"
git remote add origin https://github.com/YOUR_ORG/cortex-test-lab.git
git push -u origin main
```

### GitHub Secrets 설정 (Settings → Secrets → Actions)

| Secret 이름       | 값                                    |
|-------------------|--------------------------------------|
| `EC2_HOST`        | Terraform output의 EC2 IP            |
| `EC2_SSH_KEY`     | `cat ~/.ssh/cortex-test-key` 내용     |
| `DB_HOST`         | Terraform output의 RDS endpoint      |
| `DB_USER`         | `admin`                              |
| `DB_PASSWORD`     | `SuperSecret1234!`                   |
| `APP_SECRET_KEY`  | `mysecretkey123`                     |

---

## Step 6 — Cortex Cloud 연동

### 6-1. GitHub 연동 (Code Security) — 가장 먼저
```
Cortex Cloud → Code Security → Source Code Management
→ GitHub 연동 → 레포 선택 → 스캔 시작
탐지 예상: 시크릿 노출 5건, IaC 취약점 10건+, CVE 패키지 4건
```

### 6-2. AWS 계정 온보딩 (CSPM + CIEM + DSPM)
```
Cortex Cloud → Settings → Cloud Accounts → Add AWS Account
→ Terraform/CloudFormation으로 권한 부여
→ CSPM: SG 취약 설정, S3 퍼블릭 접근 탐지
→ CIEM: AdministratorAccess 과도 권한 탐지
→ DSPM: S3/RDS 민감 데이터 탐지 (스캔 24~48시간 소요)
```

### 6-3. Cortex Agent 설치 (ASPM)
```bash
# EC2에 SSH 접속
ssh -i ~/.ssh/cortex-test-key ubuntu@$EC2_IP

# Cortex Console에서 설치 명령어 복사 후 실행
# (Cortex Cloud → Endpoint Security → Add Agent)
```

---

## Step 7 — 탐지 검증

```bash
export APP_URL=http://$EC2_IP

# 취약 엔드포인트 호출하여 ASPM 트래픽 생성
python3 scripts/verify_detections.py
```

---

## 탐지 예상 결과 요약

| 기능 | 탐지 예상 항목 | 심각도 |
|------|--------------|--------|
| Code Security | AWS Key 하드코딩 (.env, workflow) | Critical |
| Code Security | DB 패스워드 평문 노출 | High |
| Code Security | CVE 취약 패키지 4건 (cryptography, urllib3 등) | High |
| Code Security | Terraform SG 0.0.0.0/0 허용 | High |
| CSPM | RDS 암호화 비활성화 | High |
| CSPM | S3 퍼블릭 접근 허용 | High |
| CSPM | RDS 퍼블릭 접근 허용 | Critical |
| CIEM | EC2 Role AdministratorAccess 과도 권한 | Critical |
| DSPM | 주민등록번호 (Korean SSN) — DB/S3 | Critical |
| DSPM | 신용카드 번호 (PAN) — DB/S3 | Critical |
| DSPM | 의료 기록 (PHI) — DB/S3 | High |
| DSPM | API Key 평문 저장 — DB/S3 | Critical |
| ASPM | SQL Injection (여러 엔드포인트) | Critical |
| ASPM | Command Injection (/ping) | Critical |
| ASPM | XSS (/greet) | High |
| ASPM | 인증 없는 관리자 접근 (/admin) | Critical |

---

## 비용 절감 팁

```bash
# 테스트 후 리소스 중지 (EC2/RDS만 중지 — 삭제 아님)
aws ec2 stop-instances --instance-ids $(terraform output -raw ec2_instance_id)
aws rds stop-db-instance --db-instance-identifier cortex-test-mysql

# 완전 삭제
cd terraform && terraform destroy -auto-approve
```

> 평일 9-18시만 사용 시 월 비용 약 $8~10 수준으로 절감 가능

---

## 디렉토리 구조

```
cortex-test-lab/
├── terraform/
│   ├── main.tf          # VPC, EC2, RDS, S3, IAM
│   ├── variables.tf     # 변수 정의
│   ├── outputs.tf       # 출력값
│   └── terraform.tfvars # 변수값 (시크릿 노출 — Code Security 탐지 대상)
├── app/
│   ├── main.py          # FastAPI 취약 앱 (ASPM 탐지 대상)
│   ├── requirements.txt # 취약 버전 패키지 (SCA 탐지 대상)
│   ├── nginx.conf       # Nginx 설정
│   └── .env             # 시크릿 평문 (Code Security 탐지 대상)
├── scripts/
│   ├── init_db.py       # DB 더미 데이터 삽입 (DSPM 탐지 대상)
│   ├── upload_s3_data.py # S3 민감 데이터 업로드 (DSPM 탐지 대상)
│   └── verify_detections.py # 탐지 검증 스크립트
└── .github/
    └── workflows/
        └── deploy.yml   # CI/CD 파이프라인 (시크릿 노출 포함)
```
