terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ────────────────────────────────────────────
# VPC
# ────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-igw" }
}

# Public Subnet (EC2)
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public" }
}

# Private Subnet (RDS)
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Name = "${var.project_name}-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "${var.aws_region}b"

  tags = { Name = "${var.project_name}-private-b" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${var.project_name}-rt-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ────────────────────────────────────────────
# Security Groups
# ────────────────────────────────────────────

# [취약 설정] EC2 SG — CSPM/DSPM 탐지 대상
resource "aws_security_group" "ec2" {
  name        = "${var.project_name}-ec2-sg"
  description = "EC2 Security Group (intentionally vulnerable for Cortex test)"
  vpc_id      = aws_vpc.main.id

  # VULNERABLE: 모든 포트 인바운드 허용 → CSPM 탐지 대상
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "VULN: All traffic allowed - CSPM detection target"
  }

  # VULNERABLE: SSH 전체 개방
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "VULN: SSH open to all - CSPM detection target"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-ec2-sg", Environment = "test-vulnerable" }
}

# RDS SG
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-rds-sg"
  description = "RDS Security Group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
  }

  # VULNERABLE: 퍼블릭 접근 허용 → DSPM/CSPM 탐지 대상
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "VULN: MySQL open to all - DSPM/CSPM detection target"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-rds-sg" }
}

# ────────────────────────────────────────────
# EC2 Instance
# ────────────────────────────────────────────
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

resource "aws_key_pair" "deployer" {
  key_name   = "${var.project_name}-key"
  public_key = file(var.ssh_public_key_path)
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.ec2.id]
  key_name               = aws_key_pair.deployer.key_name

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y python3 python3-pip python3-venv nginx mysql-client git
    pip3 install fastapi uvicorn sqlalchemy pymysql python-jose passlib python-multipart
    systemctl enable nginx
    systemctl start nginx
  EOF

  tags = {
    Name        = "${var.project_name}-app"
    Environment = "test"
    CortexScan  = "enabled"
  }
}

resource "aws_eip" "app" {
  instance = aws_instance.app.id
  domain   = "vpc"
  tags     = { Name = "${var.project_name}-eip" }
}

# ────────────────────────────────────────────
# RDS MySQL
# ────────────────────────────────────────────
resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags       = { Name = "${var.project_name}-db-subnet" }
}

resource "aws_db_instance" "mysql" {
  identifier        = "${var.project_name}-mysql"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t4g.micro"
  allocated_storage = 20

  db_name  = "testdb"
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  # VULNERABLE: 암호화 비활성화 → DSPM 탐지 대상
  storage_encrypted = false

  # VULNERABLE: 퍼블릭 접근 허용 → DSPM 탐지 대상
  publicly_accessible = true

  # VULNERABLE: 자동 백업 비활성화
  backup_retention_period = 0

  skip_final_snapshot = true

  tags = {
    Name       = "${var.project_name}-mysql"
    DSPMTarget = "true"
  }
}

# ────────────────────────────────────────────
# S3 Buckets
# ────────────────────────────────────────────

# S3 버킷 1: 암호화 없음 + 퍼블릭 접근 (DSPM 탐지 대상)
resource "aws_s3_bucket" "vulnerable" {
  bucket        = "${var.project_name}-vulnerable-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name       = "vulnerable-bucket"
    DSPMTarget = "true"
    Encrypted  = "false"
  }
}

resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  # VULNERABLE: 퍼블릭 접근 허용 → DSPM 탐지 대상
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_versioning" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id
  versioning_configuration { status = "Suspended" }
}

# S3 버킷 2: 암호화 O (비교 기준용)
resource "aws_s3_bucket" "secure" {
  bucket        = "${var.project_name}-secure-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name      = "secure-bucket"
    Encrypted = "true"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "random_id" "suffix" {
  byte_length = 4
}

# ────────────────────────────────────────────
# IAM Role (CIEM 탐지용 — 과도한 권한)
# ────────────────────────────────────────────
resource "aws_iam_role" "app_role" {
  name = "${var.project_name}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# VULNERABLE: AdministratorAccess → CIEM 탐지 대상
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.app_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project_name}-profile"
  role = aws_iam_role.app_role.name
}
