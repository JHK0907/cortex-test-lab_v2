variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-2"
}

variable "project_name" {
  description = "Project prefix for all resources"
  type        = string
  default     = "cortex-test"
}

variable "ssh_public_key_path" {
  description = "Path to your SSH public key (e.g. ~/.ssh/id_rsa.pub)"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "db_username" {
  description = "RDS master username"
  type        = string
  default     = "admin"
}

variable "db_password" {
  description = "RDS master password"
  type        = string
  sensitive   = true
}
