# ZeroToHero Email Server Solution

## Overview

**ZeroToHero Email Server Solution** is a comprehensive, automated project developed as part of The Bridge Cybersecurity Bootcamp. It provides a robust email server implementation supporting SMTP and POP3 protocols, with a strong emphasis on security. The solution has been designed for potential deployment in enterprise-grade internal infrastructures and rigorously validated in a controlled laboratory environment utilizing VirtualBox. It leverages Bash and Python scripts to automate the setup and configuration processes, ensuring efficient resource management and robust security measures.  

> **Note:** The email server is configured to send and receive emails exclusively within the internal infrastructure.

The solution incorporates Apache as part of its infrastructure, which is automatically installed and configured to manage web access to the email server interface. This interface, powered by Flask, facilitates server management and provides additional functionalities like user session handling.

> **Disclaimer:** This project was developed during The Bridge Cybersecurity Bootcamp as a practical demonstration of email server deployment, security practices, and monitoring techniques. While it is not a production-ready solution, it provides a solid foundation for further development and customization. Use at your own discretion and risk.
---

## Prerequisites

Before proceeding with the installation, ensure the operating system is updated to avoid compatibility issues:

```bash
sudo apt update -y && sudo apt upgrade -y
```

> **Note:** This step is optional since the `deploy_mail_server.sh` script includes system updates during the installation process.


It is recommended to perform the installation on **Ubuntu Server** to ensure service compatibility (**tested on version 24.04**). Additionally, a **PostgreSQL service** must be installed and running, as it is used to store the server's data.

> **Important:** Ensure that you provide a valid API key for VirusTotal in the `virustotal_checker.py` file before running the `deploy_mail_server.sh` script. This is necessary for proper functionality of the virus-checking component.

---

## Initial Preparation

### 1. Install Wazuh Agent (on the email server)

If Wazuh Agent is not installed on your server, follow the official Wazuh documentation for installation. This is required to monitor application logs.

### 2. Prepare Installation Files

Run the following commands to prepare the necessary files for installation:

```bash
unzip aio_mail_server_3.0.zip
chmod +x preinstall_setup.sh
sudo ./preinstall_setup.sh
```

---

## Installation

The main configuration of the email server is handled by the `deploy_mail_server.sh` script. This script requires several parameters, such as the domain, domain IP address, and PostgreSQL settings, to automatically install and configure all required services.

### Using the Script

Grant execution permissions to the installation script with:

```bash
sudo chmod +x deploy_mail_server.sh
```

Then execute the script using the following format:

```bash
sudo ./deploy_mail_server.sh <domain> <domain_ip> <postgres_ip> <postgres_port> <postgres_user> <postgres_password>
```

#### Example

```bash
sudo ./deploy_mail_server.sh cybermail.es 192.168.30.5 192.168.20.10 5432 admin example
```

In this example:
- `domain`: The domain configured for the email server.
- `domain_ip`: The IP assigned to the domain.
- `postgres_ip`: The PostgreSQL server's IP.
- `postgres_port`: The PostgreSQL service port.
- `postgres_user`: The PostgreSQL database user.
- `postgres_password`: The PostgreSQL user password.

---

## Monitoring Configuration with Wazuh

Follow these steps to integrate Wazuh with the email server logs:

### Wazuh Agent Configuration

1. Add the following lines to the **`/var/ossec/etc/ossec.conf`** file on the Wazuh agent, within the `<ossec_config>` block:

   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/www/mail_server/logs/app.log</location>
   </localfile>
   ```

2. Restart the Wazuh agent to apply the changes:

   ```bash
   sudo systemctl restart wazuh-agent
   ```

### Wazuh Server Configuration

1. Create a file named **`cybermail_wsgi_decoder.xml`** in **`/var/ossec/etc/decoders/`** with the following content:

   ```xml
   <decoder name="app-wsgi">
      <prematch>^[(\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)]</prematch>
      <regex>^[(\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)] [(\w+)] - [(\w+)] - [(/\w+)] - (.+)</regex>
      <order>timestamp,type,location,resource,message</order>
   </decoder>
   ```

2. Create another file named **`cybermail_wsgi_rules.xml`** in **`/var/ossec/etc/rules/`** with the following content:

   ```xml
   <group name="syslog">
       <rule id="100100" level="0">
           <decoded_as>app-wsgi</decoded_as>
           <description>Reading WSGI log</description>
       </rule>
   
       <rule id="100101" level="14">
           <if_sid>100100</if_sid>
           <field name="message">numerous login attempts</field>
           <description>Cybermail.es: Brute force detected</description>
       </rule>
   
       <rule id="100102" level="8">
           <if_sid>100100</if_sid>
           <field name="message">Attempted access to registration from a suspicious IP</field>
           <description>Cybermail.es: Suspicious registry access detected</description>
       </rule>
   
       <rule id="100103" level="8">
           <if_sid>100100</if_sid>
           <field name="message">Login attempt from a suspicious IP</field>
           <description>Cybermail.es: Suspicious login attempt detected</description>
       </rule>
   
       <rule id="100104" level="12">
           <if_sid>100100</if_sid>
           <field name="message">malicious file</field>
           <description>Cybermail.es: Malicious attachment detected</description>
       </rule>
   
       <rule id="100105" level="12">
           <if_sid>100100</if_sid>
           <field name="message">reverse shell</field>
           <description>Cybermail.es: Malicious attachment with reverse shell detected</description>
       </rule>
   </group>
   ```

3. Assign proper permissions and restart the Wazuh Manager:

   ```bash
   sudo chown wazuh:wazuh /var/ossec/etc/decoders/cybermail_wsgi_decoder.xml
   sudo chown wazuh:wazuh /var/ossec/etc/rules/cybermail_wsgi_rules.xml
   sudo systemctl restart wazuh-manager
   ```

Now, Wazuh will monitor email server logs and trigger alerts based on the defined rules.

---

## Key Features

- **Complete Automation**: Installation and configuration are streamlined using the `deploy_mail_server.sh` script, simplifying the deployment of critical services like Apache, PostgreSQL, and the email server.
- **Web Interface**: Apache hosts a secure web interface for managing email services, enhanced with Flask for user authentication and session management.
- **Security Management**: Built-in configurations include user authentication, data encryption, and protection against common threats.
- **Monitoring and Alerts**: Custom Wazuh rules detect security events, including brute force attacks, suspicious access attempts, and malicious attachments.
- **Compatibility**: Supports custom domains and IP assignments, making it adaptable to diverse infrastructures.

---

## Warnings

- Superuser privileges (`sudo`) are required to execute the scripts.
- Verify that the domain and IP addresses are properly configured in DNS records (MX, A, PTR) before running the installation.
- **DNS Resolution Issues**: In some cases, SMTP and POP3 services may fail due to misconfigured `/etc/resolv.conf` after a system reboot. This may require manual adjustments or reinstallation to restore proper configurations.
