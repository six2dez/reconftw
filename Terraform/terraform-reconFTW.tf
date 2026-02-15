terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Best-effort: Debian AMI naming/owners can change. Adjust filters if needed.
data "aws_ami" "debian" {
  most_recent = true
  owners      = ["136693071363"] # Debian

  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

resource "aws_key_pair" "reconftw" {
  key_name   = var.key_name
  public_key = file("${path.module}/${var.public_key_path}")

  tags = merge({ Name = "reconftw" }, var.tags)
}

resource "aws_security_group" "reconftw" {
  name_prefix = "reconftw-"
  description = "Security group for reconFTW"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge({ Name = "reconftw" }, var.tags)
}

resource "aws_instance" "reconftw" {
  ami                         = data.aws_ami.debian.id
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.reconftw.key_name
  vpc_security_group_ids      = [aws_security_group.reconftw.id]
  associate_public_ip_address = true

  tags = merge({ Name = "reconftw" }, var.tags)

  provisioner "remote-exec" {
    inline = ["sudo hostname"]

    connection {
      host        = self.public_ip
      type        = "ssh"
      user        = var.ssh_user
      private_key = file("${path.module}/${var.private_key_path}")
    }
  }

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i '${self.public_ip},' -u ${var.ssh_user} --private-key ${var.private_key_path} -e reconftw_branch=${var.reconftw_branch} reconFTW.yml"
  }
}

