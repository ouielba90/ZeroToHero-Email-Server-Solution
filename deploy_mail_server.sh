#!/bin/bash

# https://github.com/pollev/bash_progress_bar - See license at end of file

# Constants
CODE_SAVE_CURSOR="\033[s"
CODE_RESTORE_CURSOR="\033[u"
CODE_CURSOR_IN_SCROLL_AREA="\033[1A"
COLOR_FG="\e[30m"
COLOR_BG="\e[42m"
COLOR_BG_BLOCKED="\e[43m"
RESTORE_FG="\e[39m"
RESTORE_BG="\e[49m"

# Variables
PROGRESS_BLOCKED="false"
TRAPPING_ENABLED="false"
ETA_ENABLED="false"
TRAP_SET="false"

CURRENT_NR_LINES=0
PROGRESS_TITLE=""
PROGRESS_TOTAL=100
PROGRESS_START=0
BLOCKED_START=0

setup_scroll_area() {
    if [ "$TRAPPING_ENABLED" = "true" ]; then
        trap_on_interrupt
    fi

    [ -n "$1" ] && PROGRESS_TITLE="$1" || PROGRESS_TITLE="Progreso"
    [ -n "$2" ] && PROGRESS_TOTAL=$2 || PROGRESS_TOTAL=100

    lines=$(tput lines)
    CURRENT_NR_LINES=$lines
    lines=$((lines-1))
    echo -en "\n"

    echo -en "$CODE_SAVE_CURSOR"
    echo -en "\033[0;${lines}r"

    echo -en "$CODE_RESTORE_CURSOR"
    echo -en "$CODE_CURSOR_IN_SCROLL_AREA"

    if [ "$ETA_ENABLED" = "true" ]; then
      PROGRESS_START=$( date +%s )
    fi

    draw_progress_bar 0
}

destroy_scroll_area() {
    lines=$(tput lines)
    echo -en "$CODE_SAVE_CURSOR"
    echo -en "\033[0;${lines}r"
    echo -en "$CODE_RESTORE_CURSOR"
    echo -en "$CODE_CURSOR_IN_SCROLL_AREA"
    clear_progress_bar
    echo -en "\n\n"
    PROGRESS_TITLE=""
    if [ "$TRAP_SET" = "true" ]; then
        trap - EXIT
    fi
}

draw_progress_bar() {
    eta=""
    if [ "$ETA_ENABLED" = "true" -a $1 -gt 0 ]; then
        if [ "$PROGRESS_BLOCKED" = "true" ]; then
            blocked_duration=$(($(date +%s)-$BLOCKED_START))
            PROGRESS_START=$((PROGRESS_START+blocked_duration))
        fi
        running_time=$(($(date +%s)-PROGRESS_START))
        total_time=$((PROGRESS_TOTAL*running_time/$1))
        eta=$( format_eta $(($total_time-$running_time)) )
    fi

    percentage=$1
    if [ $PROGRESS_TOTAL -ne 100 ]
    then
        [ $PROGRESS_TOTAL -eq 0 ] && percentage=100 || percentage=$((percentage*100/$PROGRESS_TOTAL))
    fi
    extra=$2

    lines=$(tput lines)
    lines=$((lines))

    if [ "$lines" -ne "$CURRENT_NR_LINES" ]; then
        setup_scroll_area
    fi

    echo -en "$CODE_SAVE_CURSOR"
    echo -en "\033[${lines};0f"
    tput el

    PROGRESS_BLOCKED="false"
    print_bar_text $percentage "$extra" "$eta"

    echo -en "$CODE_RESTORE_CURSOR"
}

print_bar_text() {
    local percentage=$1
    local extra=$2
    [ -n "$extra" ] && extra=" ($extra)"
    local eta=$3
    if [ -n "$eta" ]; then
        [ -n "$extra" ] && extra="$extra "
        extra="$extra$eta"
    fi
    local cols=$(tput cols)
    bar_size=$((cols-9-${#PROGRESS_TITLE}-${#extra}))

    local color="${COLOR_FG}${COLOR_BG}"
    if [ "$PROGRESS_BLOCKED" = "true" ]; then
        color="${COLOR_FG}${COLOR_BG_BLOCKED}"
    fi

    complete_size=$(((bar_size*percentage)/100))
    remainder_size=$((bar_size-complete_size))
    progress_bar=$(echo -ne "["; echo -en "${color}"; printf_new "#" $complete_size; echo -en "${RESTORE_FG}${RESTORE_BG}"; printf_new "." $remainder_size; echo -ne "]");

    echo -ne " $PROGRESS_TITLE ${percentage}% ${progress_bar}${extra}"
}

clear_progress_bar() {
    lines=$(tput lines)
    lines=$((lines))
    echo -en "$CODE_SAVE_CURSOR"
    echo -en "\033[${lines};0f"
    tput el
    echo -en "$CODE_RESTORE_CURSOR"
}

printf_new() {
    str=$1
    num=$2
    v=$(printf "%-${num}s" "$str")
    echo -ne "${v// /$str}"
}

#!/bin/bash
# Integración de barra de progreso basada en https://github.com/pollev/bash_progress_bar

# Se incluyeron las funciones de la barra de progreso
# Funciones originales de la barra de progreso aquí
# ...

# Variables de progreso
total_steps=16
current_step=0

echo "======= ZeroToHero Email Server Solution ======="
echo "==================Version 3.0==================="
echo "****** Email Server Installation ******"

# Check if running with sudo and if there are 6 arguments
[ "$EUID" -ne 0 ] && { echo "Run with sudo."; exit 1; }
[ $# -ne 6 ] && { echo "Usage: sudo $0 <domain> <domain_ip> <postgres_password>"; exit 1; }

# Assign variables
domain=$1
domain_ip=$2
postgres_ip=$3
postgres_port=$4
postgres_user=$5
postgres_password=$6

# Validate IP and password
[[ ! $domain_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { echo "Invalid IP."; exit 1; }
[ -z "$postgres_password" ] && { echo "Postgres password cannot be empty."; exit 1; }

# Display results
echo "Domain: $domain"
echo "Domain IP: $domain_ip"
echo "PostgreSQL Configuration: $postgres_ip:$postgres_port"
echo "Postgres Password: (hidden)"
curr_dir=$(pwd)

echo ""

# Extract IP parts
IFS='.' read -r -a ip_parts <<< "$domain_ip"
ip_last="${ip_parts[3]}"
ip_domain_zero="${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.0"
ip_reverse="${ip_parts[2]}.${ip_parts[1]}.${ip_parts[0]}"

# Update the system and suppress output
echo "Updating the system..."
{
    sudo apt update -y && sudo apt upgrade -y
} &> /dev/null

# Install required packages and verify installation
echo "Installing required packages..."
{
    sudo apt install -y apache2 libapache2-mod-wsgi-py3 pipenv gunicorn python3-gunicorn nmap python3-pip postgresql bind9 bind9utils bind9-doc dovecot-imapd dovecot-pop3d dovecot-pgsql postfix ufw dnsutils
}

# Verify installed packages
missing_packages=()
for package in apache2 libapache2-mod-wsgi-py3 pipenv gunicorn python3-gunicorn nmap python3-pip postgresql bind9 bind9utils bind9-doc dovecot-imapd dovecot-pop3d dovecot-pgsql postfix ufw dnsutils; do
    if ! dpkg -l | grep -q "^ii\s\+$package"; then
        missing_packages+=($package)
    fi
done

if [ ${#missing_packages[@]} -eq 0 ]; then
    echo "All packages installed successfully."
else
    echo "The following packages were not installed: ${missing_packages[@]}"
fi

## PIPENV
user=${SUDO_USER:-$(whoami)}

# Install Python dependencies
echo "Installing some Python dependencies..."
{
    pip install scikit-learn nltk joblib --break-system-packages
}

# Check if the command failed due to an externally managed environment
if [[ $? -ne 0 ]]; then
    echo "The pip command failed due to an externally managed environment. Retrying with --break-system-packages..."
    {
        pip install scikit-learn nltk joblib --break-system-packages
    }
fi

echo "[[source]]
name = \"pypi\"
url = \"https://pypi.org/simple\"
verify_ssl = true

[dev-packages]

[packages]
flask = \"*\"
psycopg2-binary = \"*\"
flask-mail = \"*\"
cryptography = \"*\"
werkzeug = \"*\"
aiosmtpd = \"*\"
faker = \"*\"
scikit-learn = \"*\"
nltk = \"*\"
requests = \"*\"

[requires]
python_version = \"3.12.3\"" > $curr_dir/Pipfile

sudo chown $user:$user Pipfile
echo "Configuring Python virtual environment"
{
    sudo -u "$SUDO_USER" pipenv install
} &> /dev/null

PIPENV_VENV_DIR=$(sudo -u "$SUDO_USER" pipenv --venv)

# Initialize scroll area and progress bar
setup_scroll_area "Progress" $total_steps

# Hostname configuration
echo "Configuring hostname..."
{
    sudo hostnamectl set-hostname $domain
} &> /dev/null
current_step=$((current_step + 1))
draw_progress_bar $current_step

# visudo configuration
echo "Configuring permissions..."
LINE_TO_ADD="$user ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/usermod, /usr/bin/openssl, /usr/sbin/userdel"
TEMP_FILE=$(mktemp /tmp/sudoers_temp.XXXXXX)  # Securely create a temporary file

# Check if the line already exists in sudoers
if ! sudo grep -qF "$LINE_TO_ADD" /etc/sudoers; then
    # Create a temporary file with the changes
    sudo cp /etc/sudoers "$TEMP_FILE" || { echo "Error copying the sudoers file"; exit 1; }

    # Use sed to add the line just before @includedir
    sudo sed -i "/^@includedir/i $LINE_TO_ADD" "$TEMP_FILE" || { echo "Error modifying the temporary file"; exit 1; }

    # Validate the syntax of the modified file
    sudo visudo -cf "$TEMP_FILE"
    
    if [ $? -eq 0 ]; then
        # If no errors, overwrite the sudoers file
        sudo cp "$TEMP_FILE" /etc/sudoers || { echo "Error overwriting the sudoers file"; exit 1; }
        echo "Line successfully added to sudoers."
    else
        echo "Error: The syntax in the sudoers file is invalid. No changes were made."
    fi
else
    echo "The line already exists in sudoers; no addition needed."
fi

# Safely delete the temporary file
sudo rm -f "$TEMP_FILE" || { echo "Error deleting the temporary file"; exit 1; }

current_step=$((current_step + 1))
draw_progress_bar $current_step

# resolv.conf configuration
echo "Configuring resolv.conf..."
sudo chattr -i /etc/resolv.conf 
{
    sudo bash -c "cat > /etc/resolv.conf" <<EOF
nameserver $domain_ip
nameserver 127.0.0.53
options edns0 trust-ad
search $domain
EOF

    sudo chattr +i /etc/resolv.conf 
} &> /dev/null
current_step=$((current_step + 1))
draw_progress_bar $current_step

# Update /etc/hosts
echo "Updating /etc/hosts file..."
{
    # Remove any line containing 127.0.0.1 followed by the domain
    sudo sed -i "/127.0.0.1\s\+$domain/d" /etc/hosts

    # Insert the new line 127.0.0.1 $domain just before 127.0.0.1 localhost if not already present
    sudo sed -i "/127.0.0.1\s\+localhost/i 127.0.0.1\t$domain" /etc/hosts
} &> /dev/null
current_step=$((current_step + 1))
draw_progress_bar $current_step

# Postfix configuration
echo "Configuring Postfix..."
{
    sudo bash -c "cat > /etc/postfix/main.cf" <<EOF
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level=may
smtpd_tls_auth_only = no

smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination

myhostname = $domain
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = \$myhostname, $domain, localhost.es, , localhost
relayhost = 
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 $ip_domain_zero/24
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
home_mailbox = Maildir/

smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname
smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination
smtpd_tls_auth_only = yes
EOF
} &> /dev/null
current_step=$((current_step + 1))
draw_progress_bar $current_step

# Dovecot configuration
echo "Configuring Dovecot..."
{
    sudo bash -c "echo 'protocols = imap pop3' >> /etc/dovecot/dovecot.conf"
    sudo sed -i 's|^mail_location = mbox:~/mail:INBOX=/var/mail/%u|mail_location = maildir:~/Maildir|' /etc/dovecot/conf.d/10-mail.conf
} &> /dev/null
current_step=$((current_step + 1))
draw_progress_bar $current_step

# Bind9 configuration
echo "Configuring Bind9..."
{
    sudo mkdir -p /etc/bind/zones
    sudo bash -c "cat > /etc/bind/named.conf.local" <<EOF
zone "$domain" IN {
    type master;
    file "/etc/bind/zones/db.$domain";
};
zone "$ip_reverse.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.$ip_reverse";
};
EOF
    sudo bash -c "cat > /etc/bind/named.conf.options" <<EOF
options {
    directory "/var/cache/bind";
    allow-query { localhost; $ip_domain_zero/24; };
    listen-on { any; };
    forwarders {
        8.8.8.8;
    };
    dnssec-validation no;
};
EOF
    sudo bash -c "cat > /etc/bind/zones/db.$domain" <<EOF
; BIND data file for local loopback interface
;
\$TTL    604800
@   IN  SOA servidor.$domain. root.$domain. (
            25        ; Serial
            604800    ; Refresh
            86400     ; Retry
            2419200   ; Expire
            604800 )  ; Negative Cache TTL
        IN  NS  servidor.$domain.

servidor    IN  A   $domain_ip
server      IN  CNAME   servidor

; MX records for mail
@   IN  MX  10  mail.$domain.

; Mail servers
mail    IN  A   $domain_ip  ; IP address of the mail server

; Optional: Additional A records for POP3 and SMTP if they are on separate servers
pop3    IN  A   $domain_ip  ; IP address of the POP3 server
smtp    IN  A   $domain_ip  ; IP address of the SMTP server
EOF
    sudo bash -c "cat > /etc/bind/zones/db.$ip_reverse" <<EOF
; BIND data file for reverse lookup zone
;
\$TTL    604800
@   IN  SOA servidor.$domain. root.$domain. (
            25        ; Serial
            604800    ; Refresh
            86400     ; Retry
            2419200   ; Expire
            604800 )  ; Negative Cache TTL
;
            IN      NS      servidor.$domain.
$ip_last      IN      PTR     servidor.$domain
$ip_last    IN  PTR mail.$domain.
$ip_last    IN  PTR pop3.$domain.
$ip_last    IN  PTR smtp.$domain
EOF
} &> /dev/null
current_step=$((current_step + 1))
draw_progress_bar $current_step

# Configuring resolvconf in /etc/default/named
echo "Configuring resolvconf in /etc/default/named..."
{
    sudo bash -c "cat > /etc/default/named" <<EOF
#
# Run resolvconf?
RESOLVCONF=no

# Startup options for the server
OPTIONS="-u bind -4"
EOF
} &> /dev/null
current_step=$((current_step + 1))
draw_progress_bar $current_step

# Certificate generation and server configuration
echo "Configuring SSL certificates for domain $domain..."

# Define file paths for configuration and certificates
KEY_FILE="$curr_dir/$domain.key"
CERT_FILE="$curr_dir/$domain.cert"
CA_KEY_FILE="$curr_dir/myCA.key"
CA_CERT_FILE="$curr_dir/myCA.pem"
CSR_FILE="$curr_dir/$domain.csr"
SERIAL_FILE="$curr_dir/myCA.srl"

# Create the openssl_san.cnf file with the domain variable
cat > openssl_san.cnf <<EOL
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
CN = $domain

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $domain
DNS.2 = www.$domain
EOL

echo "openssl_san.cnf file created with domain: $domain"

# Create a CA certificate if it doesn't exist
if [[ ! -f "$CA_KEY_FILE" ]] || [[ ! -f "$CA_CERT_FILE" ]]; then
    echo "Creating the CA certificate..."

    # Generate the private key for the CA
    sudo openssl genrsa -out "$CA_KEY_FILE" 4096 &> /dev/null

    # Generate the CA self-signed certificate
    sudo openssl req -x509 -new -key "$CA_KEY_FILE" -days 3650 -out "$CA_CERT_FILE" -subj "/CN=MyCA" &> /dev/null

    echo "CA certificate successfully created."
else
    echo "The CA certificate already exists."
fi

# Create the private key and CSR for the domain
if [[ ! -f "$KEY_FILE" ]] || [[ ! -f "$CERT_FILE" ]]; then
    echo "Creating the private key and CSR for the domain..."

    # Generate the private key for the domain
    sudo openssl genrsa -out "$KEY_FILE" 4096 &> /dev/null

    # Generate the Certificate Signing Request (CSR) for the domain
    sudo openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -config openssl_san.cnf &> /dev/null

    echo "CSR successfully created."

    # Sign the domain certificate with the CA
    echo "Signing the domain certificate with the CA..."

    # Generate the signed certificate for the domain
    sudo openssl x509 -req -in "$CSR_FILE" -CA "$CA_CERT_FILE" -CAkey "$CA_KEY_FILE" -CAcreateserial -out "$CERT_FILE" -days 365 -extensions v3_req -extfile openssl_san.cnf &> /dev/null

    echo "Domain certificate successfully signed."
else
    echo "The private key and the domain certificate already exist."
fi

echo "Private key: $KEY_FILE"
echo "Signed certificate: $CERT_FILE"

# Advance the progress bar
current_step=$((current_step + 1))
draw_progress_bar $current_step

# PostgreSQL database configuration
echo "Configuring PostgreSQL database..."

# Replace this variable with your password
POSTGRES_PASSWORD=$postgres_password

# Stop the Apache service to modify databases
{
    sudo systemctl stop apache2
} &> /dev/null

# Check if databases exist
DB_SMTP_EXISTS=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h $postgres_ip -p $postgres_port -U $postgres_user -tAc "SELECT 1 FROM pg_database WHERE datname='smtp_server'")
DB_MALWARE_EXISTS=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h $postgres_ip -p $postgres_port -U $postgres_user -tAc "SELECT 1 FROM pg_database WHERE datname='malware_db'")

# Ask the user if they want to keep existing databases
if [ "$DB_SMTP_EXISTS" == "1" ] || [ "$DB_MALWARE_EXISTS" == "1" ]; then
    while true; do
        read -p "Existing databases detected. Do you want to keep them? (y/n): " keep_dbs
        if [[ "$keep_dbs" == "y" || "$keep_dbs" == "n" ]]; then
            break
        else
            echo "Please enter 'y' to keep the databases or 'n' to delete them."
        fi
    done
else
    keep_dbs="n"
fi

# Function to delete existing system users
delete_users() {
    local users_=($(PGPASSWORD=$POSTGRES_PASSWORD psql -h $postgres_ip -p $postgres_port -U $postgres_user -d smtp_server -tAc "SELECT name FROM users;"))
    
    for user_ in "${users_[@]}"; do
        if id "$user_" &>/dev/null; then
            echo "Deleting system user: $user_"
            sudo userdel -r "$user_" > /dev/null 2>&1
        else
            echo "User $user_ does not exist on the system."
        fi
    done
}

# Function to delete a PostgreSQL database if it exists
delete_database() {
    local dbname=$1
    local DB_EXISTS=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h $postgres_ip -p $postgres_port -U $postgres_user -tAc "SELECT 1 FROM pg_database WHERE datname='$dbname'")

    if [ "$DB_EXISTS" == "1" ]; then
        echo "Terminating all active connections to the database: $dbname"
        PGPASSWORD=$POSTGRES_PASSWORD psql -h $postgres_ip -p $postgres_port -U $postgres_user -c "
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = '$dbname' AND pid <> pg_backend_pid();" > /dev/null 2>&1

        echo "Deleting the database: $dbname"
        PGPASSWORD=$POSTGRES_PASSWORD psql -h $postgres_ip -p $postgres_port -U $postgres_user -c "DROP DATABASE IF EXISTS $dbname;"
    else
        echo "The database $dbname does not exist."
    fi
}

# Condition to delete or keep the databases
if [ "$keep_dbs" != "y" ]; then
    delete_users
    delete_database "smtp_server"
    delete_database "malware_db"

    if [ -d "/home/$user/contents" ]; then
        echo "Deleting the folder /home/$user/contents"
        rm -rf "/home/$user/contents"
    fi

    if [ -d "/home/$user/uploads" ]; then
        echo "Deleting the folder /home/$user/uploads"
        rm -rf "/home/$user/uploads"
    fi
else
    echo "Keeping the existing databases."
fi

echo "Configuration process completed."

# Generate the required databases and tables
{
    DB_EXISTS=$(psql -h $postgres_ip -p $postgres_port -U $postgres_user -tAc "SELECT 1 FROM pg_database WHERE datname='smtp_server'")

    if [ "$DB_EXISTS" != "1" ]; then
        PGPASSWORD=$POSTGRES_PASSWORD psql -h $postgres_ip -p $postgres_port -U $postgres_user <<EOF
-- Change the password for the PostgreSQL user
ALTER USER $postgres_user WITH PASSWORD '$POSTGRES_PASSWORD';

-- Crear base de datos smtp_server
CREATE DATABASE smtp_server;
\c smtp_server

-- Crear tablas en smtp_server
CREATE TABLE IF NOT EXISTS email_attachments (
    id SERIAL PRIMARY KEY,
    email_id VARCHAR(255) NOT NULL,
    filename VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS sent_emails (
    id SERIAL PRIMARY KEY,
    sender_email VARCHAR(255) NOT NULL,
    receiver_email VARCHAR(255) NOT NULL,
    encrypted_subject VARCHAR(255),
    encrypted_body TEXT,
    message_id VARCHAR(255) NOT NULL,
    has_attachments BOOLEAN DEFAULT false,
    security_status VARCHAR(255),
    encrypted_key VARCHAR(500),
    deliver_time TIMESTAMP WITHOUT TIME ZONE,
    sent_time TIMESTAMP WITHOUT TIME ZONE,
    delivered BOOLEAN DEFAULT false,
    CONSTRAINT sent_emails_message_id_key UNIQUE (message_id)
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    CONSTRAINT users_email_key UNIQUE (email)
);

CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    session_token VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT user_sessions_email_fkey FOREIGN KEY (email)
        REFERENCES users(email) ON DELETE CASCADE
);

CREATE TABLE login_attempts (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    attempt_count INT DEFAULT 0,
    last_attempt TIMESTAMP,
    blocked_until TIMESTAMP,
    CONSTRAINT unique_ip UNIQUE (ip_address)
);

-- Crear base de datos malware_db
CREATE DATABASE malware_db;
\c malware_db

-- Crear tabla en malware_db
CREATE TABLE IF NOT EXISTS api_usage (
    api_key VARCHAR(100) NOT NULL,
    usage_count INTEGER NOT NULL DEFAULT 0,
    last_used TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (api_key)
);
EOF
    fi
} &> /dev/null
current_step=$((current_step + 1))
draw_progress_bar $current_step

# Configure the main.py file
echo "Configuring main.py..."
sudo cp $curr_dir/main.py $curr_dir/main_server.py

main_py_file="$curr_dir/main_server.py"
virustotal_py_file="$curr_dir/virustotal_checker.py"
placeholder="MAIL_DOMAIN"  # Change this to the string you want to replace
placeholder_="POSTGRES_PASSWORD"
title_page=$(echo "$domain" | sed 's/^www\.//' | cut -d '.' -f 1 | awk '{print toupper(substr($0, 1, 1)) tolower(substr($0, 2))}')

# Replace placeholders in main.py
sudo sed -i "s/$placeholder/$domain/g" "$main_py_file"
sudo sed -i "s/$placeholder_/$postgres_password/g" "$main_py_file" "$virustotal_py_file"
sudo sed -i "s/POSTGRES_IP/$postgres_ip/g" "$main_py_file" "$virustotal_py_file"
sudo sed -i "s/POSTGRES_PORT/$postgres_port/g" "$main_py_file" "$virustotal_py_file"
sudo sed -i "s/POSTGRES_USER/$postgres_user/g" "$main_py_file" "$virustotal_py_file"
sudo sed -i "s/CURR_USER/$user/g" "$main_py_file"

echo "main.py configured successfully."

# Update template files
cp $curr_dir/templates/base.html.back $curr_dir/templates/base.html
cp $curr_dir/templates/register.html.back $curr_dir/templates/register.html
sudo sed -i "s/CyberMail_Domain/$domain/g" $curr_dir/templates/base.html $curr_dir/templates/register.html
sudo sed -i "s/Title_server/$title_page/g" $curr_dir/templates/base.html

# Progress the progress bar
current_step=$((current_step + 1))
draw_progress_bar $current_step

# Verify DNS records
echo "Checking DNS records..."
{
    mx_record=$(dig MX $domain | grep "ANSWER SECTION" -A 1 | sed 1d)
    if [ -z "$mx_record" ]; then
        echo "No response for MX record"
    else
        echo "Positive response: $mx_record"
    fi

    smtp_record=$(dig A smtp.$domain | grep "ANSWER SECTION" -A 1 | sed 1d)
    if [ -z "$smtp_record" ]; then
        echo "No response for smtp.$domain"
    else
        echo "Positive response: $smtp_record"
    fi

    pop3_record=$(dig A pop3.$domain | grep "ANSWER SECTION" -A 1 | sed 1d)
    if [ -z "$pop3_record" ]; then
        echo "No response for pop3.$domain"
    else
        echo "Positive response: $pop3_record"
    fi

    ptr_record=$(dig -x $domain_ip | grep "ANSWER SECTION" -A 1 | sed 1d)
    if [ -z "$ptr_record" ]; then
        echo "No response for the IP $domain_ip"
    else
        echo "Positive response: $ptr_record"
    fi
}

current_step=$((current_step + 1))
draw_progress_bar $current_step

# Train ML models
echo "Training ML models..."
echo "from email_ml import train_model_once
train_model_once()" > ML_model.py
python3 ML_model.py 

current_step=$((current_step + 1))
draw_progress_bar $current_step

# Apache2 Configuration
sudo echo "import sys
import logging
from datetime import datetime

class MicrosecondFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created)
        if datefmt:
            return dt.strftime(datefmt).replace('f', f\"{dt.microsecond // 1000:03}\")
        return super().formatTime(record, datefmt)

formatter = MicrosecondFormatter(
    fmt='[%(asctime)s] [%(levelname)s] - [%(user_name)s] - [%(resource)s] - %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S.fZ'
)

handler = logging.FileHandler('/var/www/mail_server/logs/app.log')
handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.handlers = [handler]

from datetime import datetime
dt = datetime.now()
print(f\"Manual format: {dt.strftime('%Y-%m-%dT%H:%M:%S.')}{dt.microsecond // 1000:03}Z\")


class ContextFilter(logging.Filter):
    def filter(self, record):
        record.user_name = getattr(record, 'user_name', 'System')
        record.resource = getattr(record, 'resource', 'N/A')
        return True

context_filter = ContextFilter()
logger.addFilter(context_filter)

logger.info(\"WSGI initialized.\")

sys.path.insert(0, \"/var/www/mail_server\")

activate_this=\"$PIPENV_VENV_DIR/bin/activate_this.py\"
with open(activate_this) as file_:
        exec(file_.read(), dict(__file__=activate_this))

from main_server import app as application
" > $curr_dir/main_server.wsgi

chown $user:$user $curr_dir/main_server.wsgi

sudo -u "$SUDO_USER" mkdir -p $curr_dir/logs/

sudo echo "<VirtualHost *:443>
    ServerName $domain_ip

    SSLEngine on
    SSLCertificateFile \"$CERT_FILE\"
    SSLCertificateKeyFile \"$KEY_FILE\"
    SSLCertificateChainFile \"$CA_CERT_FILE\"

    WSGIDaemonProcess mail_server user=$user group=$user threads=5
    WSGIScriptAlias / /var/www/mail_server/main_server.wsgi

    <Directory /var/www/mail_server>
        WSGIProcessGroup mail_server
        WSGIApplicationGroup %{GLOBAL}
        Order deny,allow
        Allow from all
    </Directory>

    Alias /static /var/www/mail_server/static

    <Directory /var/www/mail_server/static>
        Order deny,allow
        Allow from all
    </Directory>

    ErrorLog /var/www/mail_server/logs/app.log
    CustomLog  /var/log/apache2/access.log combined

</VirtualHost>
" > /etc/apache2/sites-available/mail_server.conf


sudo chown $user:$user $curr_dir
sudo touch /var/www/mail_server/logs/app.log
sudo chown $user:$user /var/www/mail_server/logs/app.log
sudo a2enmod wsgi

sudo a2ensite mail_server.conf
sudo a2dissite 000-default.conf
sudo a2enmod ssl

# Restarting services
echo "Restarting services..."
{
    sudo systemctl restart postfix dovecot bind9 apache2
} &> /dev/null
current_step=$((current_step + 1))
draw_progress_bar $current_step

# Destroy scroll area and finalize
destroy_scroll_area

# Style codes
BOLD="\e[1m"
GREEN="\e[32m"
BLUE="\e[34m"
RESET="\e[0m"

# Final message
echo -e "${GREEN}${BOLD}CONFIGURATION COMPLETED.${RESET}\n"
echo -e "To configure SSL certificates through ${BOLD}NGINX Proxy Manager${RESET}, use these files:"
echo -e "KEY = ${BLUE}${BOLD}$KEY_FILE${RESET}"
echo -e "CERT = ${BLUE}${BOLD}$CERT_FILE${RESET}\n"
echo -e "In the browser, import ${BLUE}${BOLD}$CA_CERT_FILE${RESET} (CA)"

echo ""
echo -e "Press any key to continue to display the configuration of ${BOLD}WAZUH${RESET}"
read -n 1 -s 

echo ""
echo -e "${BOLD}******${RESET}"
echo -e "${BOLD}AGENT${RESET}"
echo -e "${BOLD}******${RESET}"
echo -e "Add these XML code lines to the file ${BLUE}${BOLD}/var/ossec/etc/ossec.conf${RESET} (at the end, within <osec_config>)

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/www/mail_server/logs/app.log</location>
  </localfile>

And execute on the machine where the agent is installed: 
${BOLD}sudo systemctl restart wazuh-agent${RESET}"

echo ""
echo "Once the agent is configured, press any key to display the configuration for the decoder and rules on the server..."
read -n 1 -s 
echo ""

echo -e "${BOLD}*******${RESET}"
echo -e "${BOLD}SERVER${RESET}"
echo -e "${BOLD}*******${RESET}"

echo -e "In ${GREEN}${BOLD}/var/ossec/etc/decoders/${RESET}, create a file named ${BLUE}${BOLD}cybermail_wsgi_decoder.xml${RESET} with the following XML code:

<decoder name=\"app-wsgi\">
        <prematch>^[(\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)]</prematch>
        <regex>^[(\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)] [(\w+)] - [(\w+)] - [(/\w+)] - (\.+)</regex>
            <order>timestamp,type,location,resource,message</order>
</decoder>"

echo ""
echo "Once the decoder is configured, press any key to display the configuration of the rules on the server..."
read -n 1 -s 
echo ""

echo -e "In ${GREEN}${BOLD}/var/ossec/etc/rules/${RESET}, create a file named ${BLUE}${BOLD}cybermail_wsgi_rules.xml${RESET} with the following content:

<group name=\"syslog\">
    <rule id=\"100100\" level=\"0\">
        <decoded_as>app-wsgi</decoded_as>
        <description>Reading WSGI log</description>
    </rule>

    <rule id=\"100101\" level=\"14\">
        <if_sid>100100</if_sid>
        <field name=\"message\">numerous login attempts</field>
        <description>Cybermail.es: Brute force detected</description>
    </rule>

    <rule id=\"100102\" level=\"8\">
        <if_sid>100100</if_sid>
        <field name=\"message\">Attempted access to registration from a suspicious IP</field>
        <description>Cybermail.es: Suspicious registry access detected</description>
    </rule>

    <rule id=\"100103\" level=\"8\">
        <if_sid>100100</if_sid>
        <field name=\"message\">Login attempt from a suspicious IP</field>
        <description>Cybermail.es: Suspicious login attempt detected</description>
    </rule>

    <rule id=\"100104\" level=\"12\">
        <if_sid>100100</if_sid>
        <field name=\"message\">malicious file</field>
        <description>Cybermail.es: Malicious attachment detected</description>
    </rule>

    <rule id=\"100105\" level=\"12\">
        <if_sid>100100</if_sid>
        <field name=\"message\">reverse shell</field>
        <description>Cybermail.es: Malicious attachment with reverse shell detected</description>
    </rule>
</group>

And execute on the Wazuh server:
${BOLD}sudo chown wazuh:wazuh /var/ossec/etc/decoders/cybermail_wsgi_decoder.xml${RESET}
${BOLD}sudo chown wazuh:wazuh /var/ossec/etc/rules/cybermail_wsgi_rules.xml${RESET}
${BOLD}sudo systemctl restart wazuh-manager${RESET}"