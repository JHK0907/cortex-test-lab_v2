output "ec2_public_ip" {
  description = "EC2 Public IP (Elastic IP)"
  value       = aws_eip.app.public_ip
}

output "ec2_instance_id" {
  description = "EC2 Instance ID"
  value       = aws_instance.app.id
}

output "rds_endpoint" {
  description = "RDS MySQL endpoint"
  value       = aws_db_instance.mysql.address
}

output "rds_port" {
  description = "RDS MySQL port"
  value       = aws_db_instance.mysql.port
}

output "s3_vulnerable_bucket" {
  description = "Vulnerable S3 bucket name (DSPM target)"
  value       = aws_s3_bucket.vulnerable.bucket
}

output "s3_secure_bucket" {
  description = "Secure S3 bucket name (baseline)"
  value       = aws_s3_bucket.secure.bucket
}

output "app_url" {
  description = "Application URL"
  value       = "http://${aws_eip.app.public_ip}"
}
