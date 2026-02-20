output "public_ip" {
  description = "Public IP address of the reconFTW instance."
  value       = aws_instance.reconftw.public_ip
}

output "ssh_command" {
  description = "SSH command example (run from Terraform/ directory unless you use an absolute key path)."
  value       = "ssh ${var.ssh_user}@${aws_instance.reconftw.public_ip} -i ${var.private_key_path}"
}

