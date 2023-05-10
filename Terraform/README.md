# reconFTW loves Ansible+Terraform <3

This is an automated script created to work under AWS by using Terraform and Ansible. It allows you to easily deploy it or to easily adapt it into your IaaC strategy.

## Requirements

You would need to have installed:

- AWS CLI (<https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html>)
- Terraform (<https://learn.hashicorp.com/tutorials/terraform/install-cli>)
- Ansible (<https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html>)

As well as both `access_key` and `secret_key` (<https://aws.amazon.com/premiumsupport/knowledge-center/create-access-key/>)

## Deploying reconFTW on the AWS Cloud using Terraform and Ansible

Note: **this will charge costs (unless you are in the Free Tier)**

1. Move to the Terraform folder (optional but recommended): `cd terraform`
    - Put your own Amass config file and reconFTW config file on the files/ folder
1. Create a key pair to be used, e.g: `ssh-keygen -f terraform-keys -t ecdsa -b 521`
1. Run `terraform init`
1. Run `terraform apply`
1. Type "yes" and hit enter
1. Wait, because it can take up to 15 min.
1. Once the process has finished, you can now login, using `ssh admin@ip -i terraform-keys`
1. ???
1. If you have finished playing with reconFTW and hacking the world, remember to destroy the instance using `terraform destroy`
