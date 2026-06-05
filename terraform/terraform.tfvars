# ⚠️  Code Security 탐지 테스트용 — 실제 운영에서는 절대 사용 금지
# Cortex Code Security가 이 파일의 시크릿 노출을 탐지해야 함

aws_region   = "ap-northeast-2"
project_name = "cortex-test"

# VULNERABLE: 패스워드 평문 하드코딩 → Code Security 탐지 대상
db_password = "SuperSecret1234!"

# VULNERABLE: SSH 키 경로 하드코딩
ssh_public_key_path = "~/.ssh/id_rsa.pub"
