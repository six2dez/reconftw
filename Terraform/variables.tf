variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "eu-central-1"
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t3.medium"
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH to the instance (e.g., 1.2.3.4/32)."
  type        = string
}

variable "key_name" {
  description = "Name of the EC2 key pair to create/use."
  type        = string
  default     = "terraform-keys"
}

variable "public_key_path" {
  description = "Public key file path (relative to this Terraform folder)."
  type        = string
  default     = "terraform-keys.pub"
}

variable "private_key_path" {
  description = "Private key file path (relative to this Terraform folder)."
  type        = string
  default     = "terraform-keys"
}

variable "ssh_user" {
  description = "SSH username for the selected AMI."
  type        = string
  default     = "admin"
}

variable "reconftw_branch" {
  description = "Git branch/tag to deploy on the instance via Ansible."
  type        = string
  default     = "main"
}

variable "tags" {
  description = "Extra tags to apply to created resources."
  type        = map(string)
  default     = {}
}

