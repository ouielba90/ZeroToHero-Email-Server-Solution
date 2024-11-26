#!/bin/bash

user=${SUDO_USER:-$(whoami)}

echo "Setting up initial resources..."
{
    sudo apt install -y apache2 &> /dev/null
}

sudo mkdir -p /var/www/mail_server
sudo chown $user:$user /var/www/mail_server

sudo cp -r README.txt deploy_mail_server.sh source_code/* /var/www/mail_server

cd /var/www/mail_server
sudo chmod +x deploy_mail_server.sh

BOLD="\e[1m"
CYAN="\e[36m"
RESET="\e[0m"

echo -e "${CYAN}${BOLD}Done.${RESET}\n"
echo -e "${BOLD}Install the agent through Wazuh.${RESET}\n"
echo -e "Navigate to the directory ${BOLD}/var/www/mail_server/${RESET}.\n"

echo -e "By default, access to the mail server will be permitted only to the following subnets:"
echo -e "${CYAN}192.168.10.0/24, 192.168.20.0/24, 192.168.30.0/24, and 10.0.2.0/24.${RESET}"
echo -e "You can change this configuration in the ${BOLD}main.py${RESET} file by modifying the ${BOLD}PERMITTED_SUBNETS${RESET} variable.\n"

echo -e "Before running the installer, ensure you have configured a valid VirusTotal API key in the ${BOLD}virustotal_checker.py${RESET} file."
echo -e "This is essential for enabling virus-scanning functionality during email attachment handling.\n"

echo -e "Then run the installer. Example:"
echo -e "${CYAN}${BOLD}sudo ./deploy_mail_server.sh cybermail.es 192.168.30.5 192.168.20.10 5432 admin example${RESET}\n"