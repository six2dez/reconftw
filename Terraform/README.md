# reconFTW loves Ansible+Terraform <3
This is an automatized script created to work under AWS by using Terraform and Ansible. It allows you to easily deploy it or to easily adapt it into your IaaC strategy.

## Requirements
You would need to have installed:
- AWS CLI (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- Terraform (https://learn.hashicorp.com/tutorials/terraform/install-cli)
- Ansible (https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)

As well as both access_key  and secret_key (https://aws.amazon.com/premiumsupport/knowledge-center/create-access-key/)

## Deploying reconFTW on the AWS Cloud
- Please note that this will have a cost (unless you are in the Free Tier)
1. Move to the Terraform folder
(Optional an recommended) 1.1 Put your own Amass config file and reconFTW config file on the files/ folder
2. Create a key pair to be used:  ssh-keygen -f terraform-keys -t ecdsa -b 521
3. Use the terraform init command 
4. Use the terraform apply commmand
5. Click on "yes" when Terraform asks you
6. Wait, because it can take up to 15 min.
4. Once the process has finished, you can now login with:
ssh admin@ip -i terraform-keys
5. ???
6. If you have finished playing with ReconFTW and hacking the world remember to destroy the instance with the terraform destroy command
