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

  validation {
    # Restrict to the characters Git ref names commonly use. Blocks shell
    # metacharacters (space, ;, |, &, $, backtick, newline, quotes) that would
    # otherwise break out of the `-e reconftw_branch=...` arg to ansible-playbook
    # in the local-exec provisioner.
    condition     = can(regex("^[0-9A-Za-z._/-]+$", var.reconftw_branch))
    error_message = "reconftw_branch may contain only letters, digits, dot, underscore, slash, and dash."
  }
}

variable "reconftw_commit" {
  description = "Optional immutable reconFTW commit SHA (40 hex chars). If set, the Ansible playbook checks out this exact commit and aborts if HEAD does not match, mitigating unpinned-ref supply-chain drift. Leave empty to keep branch-based deploys."
  type        = string
  default     = ""

  validation {
    condition     = var.reconftw_commit == "" || can(regex("^[0-9a-fA-F]{40}$", var.reconftw_commit))
    error_message = "reconftw_commit must be empty or a 40-character hex commit SHA."
  }
}

variable "tags" {
  description = "Extra tags to apply to created resources."
  type        = map(string)
  default     = {}
}

