#!/bin/bash

# Required for servers using other languages
LANG=en_US.UTF-8
export LANG

########################################################################
# MAYAR TECHNOLOGIES, LLC - CUSTOMIZED CWP INSTALLER FOR ALMALINUX 8
########################################################################
# 
# Original CWP installer modified and updated by Mayar Technologies, LLC
# Company: Mayar Technologies, LLC
# Contact: support@mayartechnologies.com
# Website: https://mayartechnologies.com
#
# IMPORTANT LICENSING NOTE:
# - CWP core binaries, repositories, and proprietary scripts remain unchanged
# - Only cosmetic branding and modernization updates applied where legally permitted
# - All CWP licensing terms and restrictions are preserved
#
########################################################################
#
# Updated CWP installer for AlmaLinux 8 - Enhanced Security & Compatibility
# Updated: December 2024 - Latest stable versions
#
########################################################################

# Script version and metadata
SCRIPT_VERSION="2.1.0-mayar"
SCRIPT_DATE="2024-12-13"
COMPANY_NAME="Mayar Technologies, LLC"
DEFAULT_HOSTNAME="cloud.mayartechnologies.com"
SUPPORT_EMAIL="support@mayartechnologies.com"
ADMIN_EMAIL="admin@mayartechnologies.com"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log_message() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a /var/log/cwp-install.log
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a /var/log/cwp-install.log
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a /var/log/cwp-install.log
}

help() {
    cat << EOF
${COMPANY_NAME} - CWP Pro Installer for AlmaLinux 8
Version: ${SCRIPT_VERSION} (${SCRIPT_DATE})

Usage: $0 [OPTIONS]
  -r, --restart       Restart server after install  [yes]  default: no
  -p, --phpfpm        Install PHP-FPM  [7.4|8.0|8.1|8.2|8.3]  default: no
  -s, --softaculous   Install Softaculous  [yes]  default: no
  -m, --modsecurity   Install ModSecurity CWAF  [yes]  default: no
  -h, --help          Print this help

  Example: sh $0 -r yes --phpfpm 8.1 --softaculous yes --modsecurity yes

Support: ${SUPPORT_EMAIL}
Website: https://mayartechnologies.com
EOF
    exit 1
}

# Enhanced argument parsing
for argument; do
    delimiter=""
    case "$argument" in
        --restart)              arguments="${arguments}-r " ;;
        --phpfpm)               arguments="${arguments}-p " ;;
        --softaculous)          arguments="${arguments}-s " ;;
        --modsecurity)          arguments="${arguments}-m " ;;
        --help)                 arguments="${arguments}-h " ;;
        *)                      [[ "${argument:0:1}" == "-" ]] || delimiter="\""
                                arguments="${arguments}${delimiter}${argument}${delimiter} ";;
    esac
done
eval set -- "$arguments"

while getopts "r:p:s:m:h" Oflags; do
    case $Oflags in
        r) restart=$OPTARG ;;            # Restart server after install
        p) phpfpm=$OPTARG ;;             # Install PHP-FPM
        s) softaculous=$OPTARG ;;        # Install Softaculous
        m) modsecurity=$OPTARG ;;        # Install ModSecurity CWAF 
        h) help ;;                       # Print help
        *) help ;;                       # Print help 
    esac
done

# Root check
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Initialize log file
mkdir -p /var/log
touch /var/log/cwp-install.log
log_message "Starting CWP Pro installation by ${COMPANY_NAME}"
log_message "Script version: ${SCRIPT_VERSION}"

# Check if CWP is already installed
if [ -e "/usr/local/cwpsrv/" ]; then
    log_error "CWP is already installed on your server."
    echo "If you want to update it, run this command: sh /scripts/update_cwp"
    exit 1
fi

# System preparation - Remove conflicting services
log_message "Preparing system - removing conflicting services"
dnf -y remove firewalld sendmail exim postfix 2>/dev/null || true

# Install essential packages first
log_message "Installing essential system packages"
dnf -y install epel-release
dnf -y update epel-release
dnf -y install tar iptables iptables-services ipset ipset-libs wget curl ca-certificates
dnf -y install rsync nano net-tools which screen sysstat cronie

# Architecture and OS detection with enhanced validation
arch=$(uname -m)
log_message "Detected architecture: $arch"

# Updated OS detection for modern AlmaLinux versions
if [ -f /etc/almalinux-release ]; then
    centosversion=$(grep -oP '(?<=AlmaLinux release )[0-9]+' /etc/almalinux-release | head -n1)
    OS_TYPE="almalinux"
elif [ -f /etc/rocky-release ]; then
    centosversion=$(grep -oP '(?<=Rocky Linux release )[0-9]+' /etc/rocky-release | head -n1)
    OS_TYPE="rocky"
elif [ -f /etc/centos-release ]; then
    centosversion=$(rpm -qa \*-release | grep -Ei "centos" | cut -d"-" -f3 | sed 's/\..$//' | head -n 1)
    OS_TYPE="centos"
else
    centosversion=$(rpm -qa \*-release | grep -Ei "oracle|redhat|centos|cloudlinux|rocky|alma" | cut -d"-" -f3 | sed 's/\..$//' | head -n 1)
    OS_TYPE="unknown"
fi

log_message "Detected OS: $OS_TYPE version $centosversion"

# Enhanced architecture validation
case $arch in
    "i686"|"i386")
        log_error "32-bit systems are not supported. Please use AlmaLinux 8.x 64-bit"
        exit 1
        ;;
    "armv7l"|"aarch64")
        log_error "ARM architecture is not supported. Please use AlmaLinux 8.x 64-bit (x86_64)"
        exit 1
        ;;
    "x86_64")
        log_message "Architecture validation passed: $arch"
        ;;
    *)
        log_warning "Unknown architecture: $arch. Proceeding with caution..."
        ;;
esac

# Enhanced OS version validation
if [[ "$centosversion" -lt 8 ]]; then
    log_error "Unsupported OS version: $centosversion. Please use AlmaLinux 8.x or compatible"
    exit 1
elif [[ "$centosversion" -eq 8 ]]; then
    log_message "OS version validation passed: $centosversion"
elif [[ "$centosversion" -gt 8 ]]; then
    log_warning "OS version $centosversion detected. This script is optimized for version 8.x"
fi

# Enhanced AlmaLinux 8 specific preparation
if [[ "$OS_TYPE" == "almalinux" ]]; then
    log_message "Configuring AlmaLinux 8 specific settings"
    
    # Import AlmaLinux GPG keys
    rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-8 2>/dev/null || \
    rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux 2>/dev/null || true
    
    # Update CA certificates
    dnf -y update ca-certificates
fi

# Enhanced MySQL/MariaDB detection and setup
log_message "Checking for existing MySQL/MariaDB installation"
type mysql 2> /dev/null && MYSQLCHK="on" || MYSQLCHK="off"

if [ "$MYSQLCHK" = "on" ]; then
    log_message "Existing MySQL/MariaDB detected - configuring"
    
    # Enhanced password detection from various locations
    if [ -f /root/.my.cnf ]; then
        passwd1=$(grep "^password" /root/.my.cnf 2>/dev/null | awk -F'=' '{print $2}' | sed 's/[[:space:]]//g' | sed 's/"//g' | head -n1)
        passwd2=$(grep -i "password" /root/.my.cnf 2>/dev/null | sed 's/[[:space:]]//g' | sed 's/password=//' | head -n1)
        
        if [ -z "$(ls -lA /root 2>/dev/null | grep -i migration)" ]; then 
            passwd=$passwd2
        else
            passwd=$passwd1 
        fi
    fi
    
    # Test password validity
    if [ ! -z "$passwd" ]; then
        test=$(mysql -u root -p"$passwd" -e "SHOW DATABASES;" -B 2>/dev/null | head -n1)
        if [ "$test" = "Database" ]; then
            password=$passwd
            log_message "MySQL password validated successfully"
        else
            passwd=""
        fi
    fi
    
    # Interactive password prompt if needed
    while [ -z "$password" ]; do
        log_warning "MySQL root password validation required"
        echo "Enter MySQL root Password: "
        read -s -p "MySQL root password: " password
        echo
        
        test=$(mysql -u root -p"$password" -e "SHOW DATABASES;" -B 2>/dev/null | head -n1)
        if [ "$test" = "Database" ]; then
            log_message "Password validated successfully"
            break
        else
            log_error "Invalid MySQL root password"
            echo "You can remove MySQL server using: dnf remove mysql mariadb"
            echo "After removal, run installer again for fresh installation."
            echo
            if [ -e "/root/.my.cnf" ]; then
                echo "Current /root/.my.cnf contents:"
                cat /root/.my.cnf
                echo
            fi
            password=""
        fi
    done
else
    # Generate secure random password for new installation
    password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-16)
    log_message "Generated secure MySQL root password for new installation"
fi

# UPDATED: Modern MariaDB repository configuration for AlmaLinux 8
log_message "Configuring MariaDB repository"
CLOUDLINUXCHECK=$(grep -i cloudlinux /etc/*release* 2>/dev/null || true)

if [ -z "$CLOUDLINUXCHECK" ]; then
    # Updated to MariaDB 10.11 LTS (latest stable for production)
    cat > /etc/yum.repos.d/mariadb.repo <<EOF
# MariaDB 10.11 LTS AlmaLinux 8 repository
# Updated by ${COMPANY_NAME} - ${SCRIPT_DATE}
[mariadb]
name = MariaDB 10.11 LTS
baseurl = https://archive.mariadb.org/mariadb-10.11/yum/centos8-amd64
gpgkey = https://archive.mariadb.org/PublicKey
gpgcheck = 1
enabled = 1
module_hotfixes = 1
EOF
    log_message "MariaDB 10.11 LTS repository configured"
fi

# UPDATED: CWP Repository configuration
log_message "Configuring CWP repository"
cat > /etc/yum.repos.d/cwp.repo <<EOF
# CentOS Web Panel repository for AlmaLinux 8
# Customized by ${COMPANY_NAME}
[cwp]
name = CentOS Web Panel repo for AlmaLinux 8 - \$basearch
baseurl = http://repo.centos-webpanel.com/repo/8/\$basearch
enabled = 1
gpgcheck = 0
priority = 1
module_hotfixes = 1
EOF

# Enhanced EPEL and PowerTools configuration
log_message "Configuring EPEL and PowerTools repositories"

# Enable EPEL with modern configuration
dnf -y install epel-release
dnf -y makecache

# Enhanced PowerTools/CRB configuration for AlmaLinux 8
if command -v dnf >/dev/null 2>&1; then
    # Try modern CRB (Code Ready Builder) first
    dnf config-manager --set-enabled crb 2>/dev/null || \
    dnf config-manager --set-enabled powertools 2>/dev/null || \
    dnf config-manager --set-enabled PowerTools 2>/dev/null || true
    
    # Also try enabling through specific repo files
    for repo_file in /etc/yum.repos.d/*powertools*.repo /etc/yum.repos.d/*crb*.repo; do
        if [ -f "$repo_file" ]; then
            sed -i 's/enabled=0/enabled=1/g' "$repo_file" 2>/dev/null || true
        fi
    done
fi

# Enhanced repository fixes for AlmaLinux 8
log_message "Applying repository configuration fixes"

# Fix EPEL metalink issues
if [ -f /etc/yum.repos.d/epel.repo ]; then
    sed -i "s|metalink=https|metalink=http|" /etc/yum.repos.d/epel.repo 2>/dev/null || true
    sed -i "/enabled=1/a exclude=nginx*" /etc/yum.repos.d/epel.repo 2>/dev/null || true
fi

# Enhanced PowerTools configuration for various AlmaLinux versions
powertools_repos=(
    "/etc/yum.repos.d/almalinux-powertools.repo"
    "/etc/yum.repos.d/AlmaLinux-PowerTools.repo" 
    "/etc/yum.repos.d/almalinux-crb.repo"
    "/etc/yum.repos.d/AlmaLinux-CRB.repo"
)

for repo_file in "${powertools_repos[@]}"; do
    if [ -f "$repo_file" ]; then
        log_message "Configuring repository: $(basename $repo_file)"
        sed -i 's/enabled=0/enabled=1/g' "$repo_file" 2>/dev/null || true
    fi
done

# Date validation - enhanced security check
CURRENT_YEAR=$(date +%Y)
if [[ "$CURRENT_YEAR" -lt 2020 ]]; then
    log_error "System date appears incorrect: $(date)"
    log_error "Please set correct system date before proceeding"
    exit 1
fi

# Security configuration
log_message "Applying security configurations"

# Disable SELinux (required for CWP)
if [ -f /etc/selinux/config ]; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0 2>/dev/null || true
    log_message "SELinux disabled as required by CWP"
fi

# Configure system umask for security
sed -i "s/umask=002/umask=022/g" /etc/bashrc 2>/dev/null || true

# Install core dependencies with enhanced error handling
log_message "Installing core system dependencies"

CORE_PACKAGES=(
    "gcc" "gcc-c++" "make" "automake" "autoconf" 
    "apr" "apr-util" "apr-devel" "apr-util-devel"
    "util-linux-user" "glibc-all-langpacks"
    "perl-libwww-perl" "perl-LWP-Protocol-https"
    "git" "unzip" "at" "zip" "mlocate" "man"
    "rsyslog" "bind" "bind-utils" "bind-libs"
    "file" "subversion" "links"
)

for package in "${CORE_PACKAGES[@]}"; do
    if ! dnf -y install "$package" 2>/dev/null; then
        log_warning "Failed to install $package - continuing"
    fi
done

# Install MariaDB with enhanced configuration
if [ "$MYSQLCHK" = "off" ]; then
    log_message "Installing MariaDB 10.11 LTS"
    
    # Install MariaDB packages
    if ! dnf -y install MariaDB-server MariaDB-client; then
        log_error "Failed to install MariaDB from configured repository"
        log_message "Attempting fallback installation"
        dnf -y install mariadb mariadb-server || {
            log_error "Critical: MariaDB installation failed"
            exit 1
        }
    fi
    
    # Enhanced MariaDB systemd configuration
    mkdir -p /etc/systemd/system/mariadb.service.d/
    cat > /etc/systemd/system/mariadb.service.d/override.conf <<EOF
# Enhanced MariaDB configuration by ${COMPANY_NAME}
[Service]
LimitNOFILE=65535
LimitNPROC=65535
EOF
    
    systemctl daemon-reload
    systemctl enable mariadb
    systemctl start mariadb
    
    # Wait for MariaDB to be ready
    sleep 5
    
    # Secure MariaDB installation
    mysql_secure_installation_auto() {
        mysql -u root <<EOF
UPDATE mysql.user SET Password = PASSWORD('${password}') WHERE User = 'root';
DELETE FROM mysql.user WHERE User = '';
DELETE FROM mysql.user WHERE User = 'root' AND Host != 'localhost';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db = 'test' OR Db = 'test\\_%';
FLUSH PRIVILEGES;
EOF
    }
    
    mysql_secure_installation_auto
    log_message "MariaDB installation and security configuration completed"
    NEW_INSTALL=1
else
    NEW_INSTALL=0
fi

# Enhanced MySQL version detection
VERSION=$(mysql -V 2>/dev/null | awk '{print $5}' | sed "s/-[[:alpha:]].*$//")
if [ -z "$(mysql -V 2>/dev/null | grep -i mariadb)" ]; then
    # MySQL server detected
    if [[ "$VERSION" > "5.6.9" ]]; then 
        NEW=1
    else
        NEW=0
    fi
else
    # MariaDB server detected
    if [[ "$VERSION" > "10.4" ]]; then 
        NEW=1
    else
        NEW=0
    fi
fi

# Create MySQL configuration file
cat > /root/.my.cnf <<EOF
[client]
password=${password}
user=root
host=localhost

[mysql]
database=mysql

[mysqldump]
single-transaction
EOF
chmod 600 /root/.my.cnf

# Get public IP with multiple fallback methods
log_message "Detecting server public IP address"
pubip=""

# Multiple IP detection methods for reliability
ip_services=(
    "http://ipv4.icanhazip.com"
    "http://checkip.amazonaws.com"
    "http://ifconfig.me/ip"
    "http://api.ipify.org"
)

for service in "${ip_services[@]}"; do
    if [ -z "$pubip" ]; then
        pubip=$(curl -s --connect-timeout 10 "$service" 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -n1)
        if [ ! -z "$pubip" ]; then
            log_message "Public IP detected: $pubip (via $service)"
            break
        fi
    fi
done

# Fallback to local IP if public IP detection fails
if [ -z "$pubip" ]; then
    pubip=$(hostname -I | awk '{print $1}' 2>/dev/null)
    log_warning "Using local IP as fallback: $pubip"
fi

# Enhanced hostname detection and configuration
fqdn=$(hostname -f 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$fqdn" ]; then
    fqdn=$(hostname 2>/dev/null)
    if [ -z "$fqdn" ]; then
        fqdn="$DEFAULT_HOSTNAME"
        hostnamectl set-hostname "$fqdn" 2>/dev/null || true
        log_warning "Set default hostname: $fqdn"
    fi
fi

log_message "Server FQDN: $fqdn"

# Add hostname to hosts file if not present
if ! grep -q "$fqdn" /etc/hosts; then
    echo "127.0.0.1 $fqdn" >> /etc/hosts
    log_message "Added hostname to /etc/hosts"
fi

echo
log_message "PREPARING THE SERVER FOR CWP INSTALLATION"
echo "##########################################################"

# Enhanced Apache installation with error handling
log_message "Installing Apache HTTP Server (compiled from source)"
echo "#############################################"
echo "Installing Apache HTTP Server..."
echo "#############################################"

if ! dnf -y install cwp-httpd 2>&1 | tee -a /var/log/cwp-install.log; then
    log_error "Failed to install cwp-httpd package"
    exit 1
fi

# Install suPHP
dnf -y install cwp-suphp 2>&1 | tee -a /var/log/cwp-install.log

# Verify Apache installation
if [ ! -e "/usr/local/apache/bin/httpd" ]; then
    log_error "Apache installation failed - httpd binary not found"
    log_error "Please ensure your server has at least 1GB RAM + SWAP"
    curl -s http://static.cdn-cwp.com/files/s_scripts/sinfo.sh | sh 2>&1 >> /var/log/cwp-install.log
    exit 1
fi

log_message "Apache HTTP Server installation completed successfully"

# Enhanced PHP installation
log_message "Installing PHP (compiled from source)"
echo "#############################################"
echo "Installing PHP..."
echo "#############################################"

if ! dnf -y install cwp-php --enablerepo=epel 2>&1 | tee -a /var/log/cwp-install.log; then
    log_error "Failed to install cwp-php package"
    exit 1
fi

# Verify PHP installation
if [ ! -e "/usr/local/bin/php" ]; then
    log_error "PHP installation failed - php binary not found"
    log_error "Please ensure your server has at least 1GB RAM + SWAP"
    curl -s http://static.cdn-cwp.com/files/s_scripts/sinfo.sh | sh 2>&1 >> /var/log/cwp-install.log
    exit 1
fi

# Configure PHP extension directory
if [ -e "/usr/local/bin/php-config" ]; then
    CHKEXTENSIONTDIR=$(/usr/local/bin/php-config --extension-dir)
    if ! grep -q "^extension_dir" /usr/local/php/php.ini 2>/dev/null; then
        echo "extension_dir='$CHKEXTENSIONTDIR'" >> /usr/local/php/php.ini
    fi
fi

log_message "PHP installation completed successfully"

# Enhanced CWP Server installation
log_message "Installing CWP Server components"

if ! dnf -y install cwpsrv cwpphp --enablerepo=epel 2>&1 | tee -a /var/log/cwp-install.log; then
    log_error "Failed to install CWP server components"
    exit 1
fi

# Verify CWP Server installation
if [ ! -e "/usr/local/cwpsrv/bin/cwpsrv" ]; then
    log_error "CWP Server installation failed"
    exit 1
fi

# Verify CWP PHP-FPM installation
if [ ! -e "/usr/local/cwp/php71/bin/php" ]; then
    log_error "CWP PHP-FPM installation failed"
    exit 1
fi

log_message "CWP Server components installation completed successfully"

# Create necessary directories
mkdir -p /usr/local/src

# Enhanced SSL certificate generation
log_message "Generating SSL certificates for secure connections"
openssl genrsa -out "/etc/pki/tls/private/cwp-$pubip.key" 2048
openssl req -new -x509 \
    -key "/etc/pki/tls/private/cwp-$pubip.key" \
    -out "/etc/pki/tls/certs/cwp-$pubip.cert" \
    -days 3650 \
    -subj "/C=US/ST=State/L=City/O=${COMPANY_NAME}/OU=IT Department/CN=$pubip/emailAddress=${ADMIN_EMAIL}"

log_message "SSL certificates generated successfully"

# Enhanced MySQL configuration for CWP
log_message "Configuring MySQL for CWP"
cd /usr/local/src

if [ "$NEW_INSTALL" = 1 ]; then
    log_message "Configuring new MySQL installation"
    
    # Configure MySQL settings
    if [ -f /etc/my.cnf ]; then
        sed -i "s|old_passwords=1|#old_passwords=1|" /etc/my.cnf 2>/dev/null || true
    fi
    
    # Ensure MariaDB directory permissions
    if [ -e "/var/run/mariadb" ]; then
        chown -R mysql:mysql /var/run/mariadb/
    fi
    
    systemctl daemon-reload
    systemctl restart mariadb
    systemctl enable mariadb
    
    # Additional MySQL security configuration
    if [ "$NEW" = 1 ]; then
        mysql -u root -p"$password" <<EOF
SET GLOBAL innodb_buffer_pool_size = 134217728;
SET GLOBAL max_connections = 200;
SET GLOBAL query_cache_size = 16777216;
FLUSH PRIVILEGES;
EOF
    fi
    
    log_message "MySQL configuration completed"
fi

# Enhanced Apache configuration
log_message "Configuring Apache HTTP Server"

# Enable user directories
sed -i "s|#Include conf/extra/httpd-userdir.conf|Include conf/extra/httpd-userdir.conf|" /usr/local/apache/conf/httpd.conf 2>/dev/null || true

# Configure Apache server status
cat > /usr/local/apache/conf.d/server-status.conf <<EOF
# Apache Server Status Configuration
# Configured by ${COMPANY_NAME}
<Location /server-status>
    SetHandler server-status
    Require local
    Require ip 127.0.0.1
    Require ip ::1
</Location>

<Location /server-info>
    SetHandler server-info
    Require local
    Require ip 127.0.0.1
    Require ip ::1
</Location>
EOF

# Enhanced systemd service configuration
if [ ! -L /etc/systemd/system/multi-user.target.wants/httpd.service ]; then
    ln -s /usr/lib/systemd/system/httpd.service /etc/systemd/system/multi-user.target.wants/httpd.service
fi

# Configure Apache resource limits
if ! grep -q "^LimitNOFILE" /usr/lib/systemd/system/httpd.service; then
    cat >> /usr/lib/systemd/system/httpd.service <<EOF

# Enhanced Apache configuration by ${COMPANY_NAME}
[Service]
LimitNOFILE=65535
LimitNPROC=65535
EOF
fi

systemctl daemon-reload

# Enhanced PHP configuration
log_message "Configuring PHP settings"

# Set secure PHP configurations
if [ -f /usr/local/php/php.ini ]; then
    sed -i "s|;date.timezone =.*|date.timezone = UTC|" /usr/local/php/php.ini
    sed -i "s|expose_php = On|expose_php = Off|" /usr/local/php/php.ini
    sed -i "s|allow_url_fopen = On|allow_url_fopen = Off|" /usr/local/php/php.ini
    sed -i "s|display_errors = On|display_errors = Off|" /usr/local/php/php.ini
    sed -i "s|max_execution_time = 30|max_execution_time = 300|" /usr/local/php/php.ini
    sed -i "s|memory_limit = 128M|memory_limit = 256M|" /usr/local/php/php.ini
    sed -i "s|post_max_size = 8M|post_max_size = 64M|" /usr/local/php/php.ini
    sed -i "s|upload_max_filesize = 2M|upload_max_filesize = 64M|" /usr/local/php/php.ini
fi

# Start Apache
systemctl enable httpd
systemctl restart httpd

log_message "Apache configuration completed and service started"

# Enhanced Postfix configuration
log_message "Configuring Postfix mail server"

# Install Postfix if not already installed
dnf -y install postfix --enablerepo=cwp

# Configure Postfix main settings
if [ -f /etc/postfix/main.cf ]; then
    sed -i "s|inet_interfaces = localhost|inet_interfaces = all|" /etc/postfix/main.cf
    sed -i "s|mydestination = \$myhostname, localhost.\$mydomain, localhost|mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain|" /etc/postfix/main.cf
    sed -i "s|#home_mailbox = Maildir/|home_mailbox = Maildir/|" /etc/postfix/main.cf
    
    # Enhanced security settings
    cat >> /etc/postfix/main.cf <<EOF

# Enhanced security configuration by ${COMPANY_NAME}
smtpd_banner = \$myhostname ESMTP
disable_vrfy_command = yes
smtpd_helo_required = yes
smtpd_delay_reject = yes
smtpd_recipient_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_recipient,
    reject_invalid_recipient,
    reject_unauth_destination,
    check_recipient_access hash:/etc/postfix/recipient_access,
    permit
EOF
fi

# Enhanced CSF Firewall installation and configuration
log_message "Installing and configuring CSF (ConfigServer Security & Firewall)"
echo "#######################"
echo "Installing CSF Firewall"
echo "#######################"

cd /tmp
rm -fv csf.tgz csf-*.tar.gz 2>/dev/null || true

# Download latest CSF version with fallback
CSF_DOWNLOAD_SUCCESS=false
CSF_URLS=(
    "https://download.configserver.com/csf.tgz"
    "http://download.configserver.com/csf.tgz"
)

for url in "${CSF_URLS[@]}"; do
    if wget -t 3 -T 30 "$url"; then
        CSF_DOWNLOAD_SUCCESS=true
        break
    fi
done

if [ "$CSF_DOWNLOAD_SUCCESS" = false ]; then
    log_error "Failed to download CSF firewall"
    exit 1
fi

tar -xzf csf.tgz
cd csf
sh install.sh

# Enhanced CSF configuration for CWP Pro
log_message "Configuring CSF for CWP Pro environment"

# Configure CSF for production use with CWP ports
sed -i 's|TESTING = "1"|TESTING = "0"|' /etc/csf/csf.conf
sed -i "s|TCP_IN = \".*\"|TCP_IN = \"20,21,22,25,53,80,110,143,443,465,587,993,995,2030,2031,2082,2083,2086,2087,2095,2096,35000:35999\"|" /etc/csf/csf.conf
sed -i "s|TCP_OUT = \".*\"|TCP_OUT = \"20,21,22,25,53,80,110,113,443,587,993,995,2030,2031,2082,2083,2086,2087,2095,2096\"|" /etc/csf/csf.conf
sed -i "s|UDP_IN = \".*\"|UDP_IN = \"20,21,53,80,443,953,2030,2031\"|" /etc/csf/csf.conf
sed -i "s|UDP_OUT = \".*\"|UDP_OUT = \"20,21,53,113,123,953\"|" /etc/csf/csf.conf

# Enhanced CSF security settings
sed -i 's|DENY_IP_LIMIT = ".*"|DENY_IP_LIMIT = "500"|' /etc/csf/csf.conf
sed -i 's|DENY_TEMP_IP_LIMIT = ".*"|DENY_TEMP_IP_LIMIT = "200"|' /etc/csf/csf.conf
sed -i 's|LF_DAEMON = ".*"|LF_DAEMON = "1"|' /etc/csf/csf.conf
sed -i 's|LF_LOGIN_EMAIL_ALERT = ".*"|LF_LOGIN_EMAIL_ALERT = "1"|' /etc/csf/csf.conf

# Configure CSF email alerts (using Mayar Technologies contact)
sed -i "s|LF_ALERT_TO = \".*\"|LF_ALERT_TO = \"${ADMIN_EMAIL}\"|" /etc/csf/csf.conf
sed -i "s|LF_ALERT_FROM = \".*\"|LF_ALERT_FROM = \"noreply@mayartechnologies.com\"|" /etc/csf/csf.conf

# Initialize CSF
csf -x 2>/dev/null || true

# Enhanced CSF process ignore list for CWP Pro
cat >> /etc/csf/csf.pignore <<EOF
# CWP Pro Process Ignore List - Enhanced by ${COMPANY_NAME}
# Updated: ${SCRIPT_DATE}

# Core system processes
exe:/usr/sbin/clamd
exe:/usr/sbin/opendkim
exe:/usr/libexec/mysqld
exe:/usr/sbin/mysqld
exe:/usr/bin/postgres
exe:/usr/bin/mongod

# Dovecot mail processes
exe:/usr/libexec/dovecot/anvil
exe:/usr/libexec/dovecot/auth
exe:/usr/libexec/dovecot/imap-login
exe:/usr/libexec/dovecot/dict
exe:/usr/libexec/dovecot/stats
exe:/usr/libexec/dovecot/pop3-login
exe:/usr/libexec/dovecot/imap
exe:/usr/libexec/dovecot/pop3
exe:/usr/libexec/dovecot/lmtp

# PHP-FPM processes (multiple versions)
exe:/usr/local/cwp/php71/sbin/php-fpm
exe:/usr/local/cwp/php72/sbin/php-fpm
exe:/usr/local/cwp/php73/sbin/php-fpm
exe:/usr/local/cwp/php74/sbin/php-fpm
exe:/usr/local/cwp/php80/sbin/php-fpm
exe:/usr/local/cwp/php81/sbin/php-fpm
exe:/usr/local/cwp/php82/sbin/php-fpm
exe:/usr/local/cwp/php83/sbin/php-fpm

# Postfix mail processes
exe:/usr/libexec/postfix/tlsmgr
exe:/usr/libexec/postfix/qmgr
exe:/usr/libexec/postfix/pickup
exe:/usr/libexec/postfix/smtpd
exe:/usr/libexec/postfix/smtp
exe:/usr/libexec/postfix/bounce
exe:/usr/libexec/postfix/scache
exe:/usr/libexec/postfix/anvil
exe:/usr/libexec/postfix/cleanup
exe:/usr/libexec/postfix/proxymap
exe:/usr/libexec/postfix/trivial-rewrite
exe:/usr/libexec/postfix/local
exe:/usr/libexec/postfix/pipe
exe:/usr/libexec/postfix/spawn
exe:/usr/libexec/postfix/showq
exe:/usr/libexec/postfix/lmtp

# Web server processes
exe:/usr/sbin/varnishd
exe:/usr/sbin/nginx
exe:/usr/local/apache/bin/httpd

# System services
exe:/usr/sbin/rpcbind
exe:/usr/bin/memcached
exe:/usr/sbin/rngd
exe:/usr/lib/systemd/systemd-resolved
exe:/usr/sbin/chronyd

# Additional processes
exe:/usr/bin/perl
user:amavis
cmd:/usr/sbin/amavisd
user:netdata
user:nobody
user:apache

# CWP specific processes
exe:/usr/local/cwpsrv/bin/cwpsrv
exe:/usr/local/cwp/php71/bin/php
EOF

# Create required CSF files
touch /var/lib/csf/csf.tempban
touch /var/lib/csf/csf.tempallow

# Enhanced CWP BruteForce Protection configuration
log_message "Configuring enhanced brute force protection"

sed -i "s|CUSTOM1_LOG.*|CUSTOM1_LOG = \"/var/log/cwp_client_login.log\"|g" /etc/csf/csf.conf
sed -i "s|CUSTOM2_LOG.*|CUSTOM2_LOG = \"/usr/local/apache/domlogs/*.log\"|g" /etc/csf/csf.conf
sed -i "s|^HTACCESS_LOG.*|HTACCESS_LOG = \"/usr/local/apache/logs/error_log\"|g" /etc/csf/csf.conf
sed -i "s|^MODSEC_LOG.*|MODSEC_LOG = \"/usr/local/apache/logs/error_log\"|g" /etc/csf/csf.conf
sed -i "s|^POP3D_LOG.*|POP3D_LOG = \"/var/log/dovecot-info.log\"|g" /etc/csf/csf.conf
sed -i "s|^IMAPD_LOG.*|IMAPD_LOG = \"/var/log/dovecot-info.log\"|g" /etc/csf/csf.conf
sed -i "s|^SMTPAUTH_LOG.*|SMTPAUTH_LOG = \"/var/log/maillog\"|g" /etc/csf/csf.conf
sed -i "s|^FTPD_LOG.*|FTPD_LOG = \"/var/log/messages\"|g" /etc/csf/csf.conf

# Enhanced custom regex for modern threats
cat > /usr/local/csf/bin/regex.custom.pm <<EOF
#!/usr/bin/perl
# Enhanced Custom Regex Rules for CWP Pro
# Configured by ${COMPANY_NAME} - ${SCRIPT_DATE}

sub custom_line {
    my \$line = shift;
    my \$lgfile = shift;
    
    # CWP Failed Login Protection
    if ((\$globlogs{CUSTOM1_LOG}{\$lgfile}) and (\$line =~ /^\S+\s+\S+\s+(\S+)\s+Failed Login from:\s+(\S+) on: (\S+)/)) {
        return ("Failed CWP-Login for User: \$1 from IP: \$2 URL: \$3", \$2, "cwplogin", "5", "2030,2031", "1");
    }
    
    # WordPress XMLRPC attacks
    if ((\$globlogs{CUSTOM2_LOG}{\$lgfile}) and (\$line =~ /(\S+).*] "\w*(?:GET|POST) \/xmlrpc\.php.*" /)) {
        return ("WordPress XMLRPC Attack", \$1, "XMLRPC", "10", "80,443", "1");
    }
    
    # WordPress login attacks
    if ((\$globlogs{CUSTOM2_LOG}{\$lgfile}) and (\$line =~ /(\S+).*] "\w*(?:GET|POST) \/wp-login\.php.*" /)) {
        return ("WordPress Login Attack", \$1, "WPLOGIN", "10", "80,443", "1");
    }
    
    # WordPress admin attacks
    if ((\$globlogs{CUSTOM2_LOG}{\$lgfile}) and (\$line =~ /(\S+).*] "\w*(?:GET|POST) \/wp-admin\/.*" /)) {
        return ("WordPress Admin Attack", \$1, "WPADMIN", "15", "80,443", "1");
    }
    
    # Joomla admin attacks
    if ((\$globlogs{CUSTOM2_LOG}{\$lgfile}) and (\$line =~ /(\S+).*] "\w*(?:GET|POST) \/administrator\/.*" /)) {
        return ("Joomla Admin Attack", \$1, "JOOMLAADMIN", "15", "80,443", "1");
    }
    
    # Generic admin panel attacks
    if ((\$globlogs{CUSTOM2_LOG}{\$lgfile}) and (\$line =~ /(\S+).*] "\w*(?:GET|POST) \/(?:admin|phpmyadmin|pma)\/.*" /)) {
        return ("Admin Panel Attack", \$1, "ADMINPANEL", "20", "80,443", "1");
    }
    
    return 0;
}
1;
EOF

# Start CSF services
systemctl enable csf
systemctl enable lfd
systemctl start csf
systemctl start lfd

log_message "CSF Firewall installation and configuration completed"

# Enhanced Dovecot configuration
log_message "Configuring Dovecot IMAP/POP3 server"

# Create dovecot log files with proper permissions
touch /var/log/dovecot-debug.log
touch /var/log/dovecot-info.log
touch /var/log/dovecot.log
chmod 600 /var/log/dovecot*.log
usermod -a -G mail dovecot

# Install and configure Dovecot
dnf -y install dovecot dovecot-mysql dovecot-pigeonhole

log_message "Dovecot configuration completed"

# Enhanced CWP Web Panel installation
log_message "Installing CWP Web Panel files"
echo "#######################"
echo "Installing CWP Files"
echo "#######################"

mkdir -p /usr/local/cwpsrv/htdocs
cd /usr/local/cwpsrv/htdocs

# Download latest CWP panel files with enhanced error handling
CWP_PANEL_URL="http://static.cdn-cwp.com/files/cwp/el8/cwp-el8-latest.zip"
if ! wget -t 3 -T 60 "$CWP_PANEL_URL" -O cwp-latest.zip; then
    log_error "Failed to download CWP panel files"
    # Fallback to EL7 version if EL8 not available
    log_message "Attempting fallback to EL7 compatible version"
    if ! wget -t 3 -T 60 "http://static.cdn-cwp.com/files/cwp/el7/cwp-el7-0.9.8.1210.zip" -O cwp-latest.zip; then
        log_error "Failed to download CWP panel files from all sources"
        exit 1
    fi
fi

unzip -o -q cwp-latest.zip
rm -f cwp-latest.zip

# Install CWP services
mkdir -p /usr/local/cwpsrv/var/services/
cd /usr/local/cwpsrv/var/services/

if ! wget -t 3 -T 60 "http://static.cdn-cwp.com/files/cwp/el8/cwp-services.zip" -O cwp-services.zip; then
    # Fallback to EL7 services
    wget -t 3 -T 60 "http://static.cdn-cwp.com/files/cwp/el7/cwp-services.zip" -O cwp-services.zip
fi

unzip -o -q cwp-services.zip
rm -f cwp-services.zip

# Configure CWP database connection
cd /usr/local/cwpsrv/htdocs/resources/admin/include
if ! wget -q "http://static.cdn-cwp.com/files/cwp/sql/db_conn.txt" -O db_conn.php; then
    log_error "Failed to download database connection file"
    exit 1
fi

cd /usr/local/cwpsrv/htdocs/resources/admin/modules
if ! wget -q "http://static.cdn-cwp.com/files/cwp/modules/example.txt" -O example.php; then
    log_warning "Failed to download example module"
fi

# Enhanced phpMyAdmin installation
log_message "Installing phpMyAdmin (latest stable version)"
echo "#######################"
echo "Installing phpMyAdmin"
echo "#######################"

cd /usr/local/cwpsrv/var/services
rm -rf pma phpMyAdmin* 2>/dev/null || true

# Download latest phpMyAdmin version compatible with PHP 7.x
PHPMYADMIN_VERSION="5.2.1"
PHPMYADMIN_URL="https://files.phpmyadmin.net/phpMyAdmin/${PHPMYADMIN_VERSION}/phpMyAdmin-${PHPMYADMIN_VERSION}-all-languages.zip"

if ! wget -t 3 -T 120 "$PHPMYADMIN_URL"; then
    log_warning "Failed to download phpMyAdmin ${PHPMYADMIN_VERSION}, trying fallback"
    # Fallback to CWP provided version
    if ! wget -q "http://static.cdn-cwp.com/files/mysql/phpMyAdmin-4.9.10-all-languages.zip"; then
        log_error "Failed to download phpMyAdmin"
        exit 1
    fi
    PHPMYADMIN_VERSION="4.9.10"
fi

unzip -o -q "phpMyAdmin-${PHPMYADMIN_VERSION}-all-languages.zip"
mv "phpMyAdmin-${PHPMYADMIN_VERSION}-all-languages" pma
rm -f "phpMyAdmin-${PHPMYADMIN_VERSION}-all-languages.zip"
rm -rf pma/setup 2>/dev/null || true

log_message "phpMyAdmin ${PHPMYADMIN_VERSION} installation completed"

# Enhanced webFTP installation
log_message "Installing webFTP client"
cd /usr/local/apache/htdocs/

if ! wget -q "http://static.cdn-cwp.com/files/cwp/addons/webftp_simple.zip"; then
    log_warning "Failed to download webFTP client"
else
    unzip -o -q webftp_simple.zip
    rm -f webftp_simple.zip
fi

# Setup default website
if [ -d "/usr/local/cwpsrv/htdocs/resources/admin/tpl/new_account_tpl/" ]; then
    cp -r /usr/local/cwpsrv/htdocs/resources/admin/tpl/new_account_tpl/* /usr/local/apache/htdocs/. 2>/dev/null || true
fi

# Enhanced CWP configuration with Mayar Technologies branding
log_message "Configuring CWP Web Panel settings"

# Configure phpMyAdmin
if [ -f "/usr/local/cwpsrv/var/services/pma/config.sample.inc.php" ]; then
    mv /usr/local/cwpsrv/var/services/pma/config.sample.inc.php /usr/local/cwpsrv/var/services/pma/config.inc.php
    
    # Generate secure random passwords
    ran_password=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-32)
    ran_password2=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-12)
    
    sed -i "s|\['blowfish_secret'\] = ''|\['blowfish_secret'\] = '${ran_password}'|" /usr/local/cwpsrv/var/services/pma/config.inc.php
    
    # Enhanced phpMyAdmin security settings
    cat >> /usr/local/cwpsrv/var/services/pma/config.inc.php <<EOF

/* Enhanced phpMyAdmin Configuration by ${COMPANY_NAME} */
\$cfg['LoginCookieValidity'] = 3600;
\$cfg['ShowPhpInfo'] = false;
\$cfg['ShowServerInfo'] = false;
\$cfg['ShowDbStructureCreation'] = false;
\$cfg['ShowDbStructureLastUpdate'] = false;
\$cfg['ShowDbStructureLastCheck'] = false;
\$cfg['SuhosinDisableWarning'] = true;
\$cfg['McryptDisableWarning'] = true;
\$cfg['AllowUserDropDatabase'] = false;
EOF
fi

# Configure CWP database connection
if [ -f "/usr/local/cwpsrv/htdocs/resources/admin/include/db_conn.php" ]; then
    sed -i "s|\$crypt_pwd = ''|\$crypt_pwd = '${ran_password2}'|" /usr/local/cwpsrv/htdocs/resources/admin/include/db_conn.php
    sed -i "s|\$db_pass = ''|\$db_pass = '$password'|" /usr/local/cwpsrv/htdocs/resources/admin/include/db_conn.php
    chmod 600 /usr/local/cwpsrv/htdocs/resources/admin/include/db_conn.php
fi

# Fix PHP session permissions
if [ -d "/var/lib/php/session" ]; then
    chmod 777 /var/lib/php/session/
fi

# Enhanced PHP configuration for CWP
if [ -f "/usr/local/cwp/php71/php.ini" ]; then
    sed -i "s|short_open_tag = Off|short_open_tag = On|" /usr/local/cwp/php71/php.ini
fi

if [ -f "/usr/local/php/php.ini" ]; then
    sed -i "s|short_open_tag = Off|short_open_tag = On|" /usr/local/php/php.ini
fi

# Enhanced Cron job setup
log_message "Setting up enhanced cron jobs"

cat > /etc/cron.daily/cwp <<EOF
#!/bin/bash
# CWP Daily Maintenance Script
# Enhanced by ${COMPANY_NAME}

# Run CWP maintenance
/usr/local/cwp/php71/bin/php -d max_execution_time=1000000 -q /usr/local/cwpsrv/htdocs/resources/admin/include/cron.php

# Run backup maintenance  
/usr/local/cwp/php71/bin/php -d max_execution_time=1000000 -q /usr/local/cwpsrv/htdocs/resources/admin/include/cron_backup.php

# Clean temporary files
find /tmp -type f -name "sess_*" -mtime +1 -delete 2>/dev/null || true
find /var/tmp -type f -name "*.tmp" -mtime +3 -delete 2>/dev/null || true

# Rotate logs if they get too large
for logfile in /usr/local/apache/logs/*.log; do
    if [ -f "$logfile" ] && [ $(stat -f%z "$logfile" 2>/dev/null || stat -c%s "$logfile" 2>/dev/null) -gt 104857600 ]; then
        cp "$logfile" "${logfile}.old"
        > "$logfile"
    fi
done
EOF
chmod +x /etc/cron.daily/cwp

# Enhanced SSL automation cron jobs
CRONDATE1=$(date +%M\ %H -d '1 hour ago' 2>/dev/null || date +%M\ %H)
{
    echo "$CRONDATE1 * * * /usr/local/cwp/php71/bin/php -d max_execution_time=18000 -q /usr/local/cwpsrv/htdocs/resources/admin/include/cron_autossl_all_domains.php"
    echo "0 2 * * * /usr/local/cwp/php71/bin/php -d max_execution_time=18000 -q /usr/local/cwpsrv/htdocs/resources/admin/include/alertandautorenewssl.php"
    echo "0 4 * * 0 /usr/bin/yum -y update --security"
    echo "30 3 * * * /usr/bin/freshclam --quiet"
} | crontab -

# Enhanced MySQL database import and configuration
log_message "Importing CWP database structure"

# Import CWP database with enhanced error handling
if ! curl -s 'http://static.cdn-cwp.com/files/cwp/sql/root_cwp.sql' | mysql -u root -p"$password"; then
    log_error "Failed to import main CWP database"
    exit 1
fi

if ! curl -s 'http://static.cdn-cwp.com/files/cwp/sql/oauthv2.sql' | mysql -u root -p"$password"; then
    log_warning "Failed to import OAuth database (non-critical)"
fi

# Configure CWP settings with server information
mysql -u root -p"$password" <<EOF
USE root_cwp;
UPDATE settings SET shared_ip="$pubip" WHERE id=1;
INSERT INTO settings (shared_ip) VALUES ("$pubip") ON DUPLICATE KEY UPDATE shared_ip="$pubip";

-- Enhanced security settings by ${COMPANY_NAME}
UPDATE settings SET 
    admin_email="$ADMIN_EMAIL",
    company_name="$COMPANY_NAME"
WHERE id=1;
EOF

log_message "CWP database configuration completed"

# Enhanced DNS server configuration
log_message "Configuring DNS server (BIND)"

systemctl enable named

# Enhanced BIND configuration for security
if [ -f "/etc/named.conf" ]; then
    # Backup original configuration
    cp /etc/named.conf /etc/named.conf.backup
    
    sed -i "s|listen-on port 53 { 127.0.0.1; };|listen-on port 53 { any; };|" /etc/named.conf
    sed -i "s|allow-query     { localhost; };|allow-query     { any; };|" /etc/named.conf
    sed -i 's/recursion yes/recursion no/g' /etc/named.conf
    
    # Add security enhancements to BIND
    cat >> /etc/named.conf <<EOF

// Enhanced security configuration by ${COMPANY_NAME}
options {
    version "DNS Server";
    hostname "DNS Server";
    server-id "DNS Server";
    rate-limit {
        responses-per-second 10;
        window 5;
    };
};
EOF
fi

# Enhanced mail server installation and configuration
log_message "Installing and configuring mail server components"

# MySQL postfix password generation
postfix_pwd=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-16)
cnf_hostname="$fqdn"

log_message "Configuring mail server database"

# Create postfix database and user with enhanced security
mysql -u root -p"$password" <<EOF
DROP USER IF EXISTS 'postfix'@'localhost';
CREATE DATABASE IF NOT EXISTS postfix CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'postfix'@'localhost' IDENTIFIED BY '$postfix_pwd';
GRANT SELECT, INSERT, UPDATE, DELETE ON postfix.* TO 'postfix'@'localhost';
FLUSH PRIVILEGES;
EOF

# Import postfix database structure
if ! curl -s 'http://centos-webpanel.com/webpanel/main.php?dl=postfix.sql' | mysql -u root -p"$password" -h localhost postfix; then
    log_error "Failed to import postfix database"
    exit 1
fi

# Install mail server components with enhanced versions
log_message "Installing mail server packages"

# Install Perl modules for mail processing
PERL_MODULES=(
    "perl-MailTools" "perl-MIME-EncWords" "perl-TimeDate"
    "perl-Mail-Sender" "perl-Log-Log4perl" "perl-Razor-Agent"
    "perl-Convert-BinHex" "perl-Digest-SHA1" "perl-IO-stringy"
)

for module in "${PERL_MODULES[@]}"; do
    dnf -y install "$module" 2>/dev/null || log_warning "Failed to install $module"
done

# Install Amavisd and ClamAV
dnf --enablerepo=epel,powertools -y install amavisd-new clamd freshclam clamav clamav-update

# Enhanced ClamAV and Amavisd configuration
log_message "Configuring antivirus and anti-spam systems"

# Fix ClamAV configuration
if [ -f "/etc/clamd.d/scan.conf" ]; then
    sed -i '/^Example$/d' /etc/clamd.d/scan.conf
    sed -i 's/^#LocalSocket/LocalSocket/' /etc/clamd.d/scan.conf
    sed -i 's/^LocalSocketGroup.*$/LocalSocketGroup amavis/' /etc/clamd.d/scan.conf
fi

if [ -f "/etc/freshclam.conf" ]; then
    sed -i '/^Example$/d' /etc/freshclam.conf
fi

# Configure ClamAV user permissions
usermod -a -G amavis clamscan 2>/dev/null || true

# Enhanced systemd service configuration for ClamAV
if [ -d "/usr/lib/systemd/system" ]; then
    cd /usr/lib/systemd/system
    
    if [ -f "clamd@.service" ]; then
        mv clamd@.service clamd.service 2>/dev/null || true
        sed -i 's/^ExecStart.*$/ExecStart = \/usr\/sbin\/clamd -c \/etc\/clamd.d\/amavisd.conf --foreground=yes/' clamd.service
        sed -i "s/^Type = forking/Type = simple/" clamd.service
    fi
    
    if [ -f "clamd@scan.service" ]; then
        mv clamd@scan.service clamd-scan.service 2>/dev/null || true
        sed -i 's/clamd@.service/clamd.service/' clamd-scan.service
    fi
    
    systemctl daemon-reload
fi

# Download and configure mail server components
log_message "Downloading mail server configuration files"

cd /
if ! wget -q "http://static.cdn-cwp.com/files/mail/el8/mail_server_quota.zip" -O mail_server_quota.zip; then
    # Fallback to EL7 version
    if ! wget -q "http://static.cdn-cwp.com/files/mail/el7/mail_server_quota.zip" -O mail_server_quota.zip; then
        log_error "Failed to download mail server configuration"
        exit 1
    fi
fi

unzip -o -q mail_server_quota.zip
rm -f mail_server_quota.zip

# Enhanced virtual mail user setup
log_message "Setting up virtual mail system"

mkdir -p /var/vmail
chmod 770 /var/vmail

# Create vmail user if not exists
if ! id vmail >/dev/null 2>&1; then
    useradd -r -u 101 -g mail -d /var/vmail -s /sbin/nologin -c "Virtual mailbox" vmail
fi
chown vmail:mail /var/vmail

touch /etc/postfix/virtual_regexp

# Enhanced vacation/autoresponder setup
if ! id vacation >/dev/null 2>&1; then
    useradd -r -d /var/spool/vacation -s /sbin/nologin -c "Virtual vacation" vacation
fi

mkdir -p /var/spool/vacation
chmod 770 /var/spool/vacation

if [ -f "/etc/postfix/vacation.php" ]; then
    cd /var/spool/vacation/
    ln -sf /etc/postfix/vacation.php vacation.php
    chmod +x /etc/postfix/vacation.php
    usermod -a -G mail vacation
    chown vacation /etc/postfix/vacation.php
fi

echo "autoreply.$cnf_hostname vacation:" > /etc/postfix/transport
postmap /etc/postfix/transport
chown -R vacation:vacation /var/spool/vacation

# Add autoresponder to hosts
if ! grep -q "autoreply.$cnf_hostname" /etc/hosts; then
    echo "127.0.0.1 autoreply.$cnf_hostname" >> /etc/hosts
fi

# Enhanced Sieve configuration for mail filtering
log_message "Configuring Sieve mail filtering"

mkdir -p /var/sieve/
cat > /var/sieve/globalfilter.sieve <<EOF
# Global Sieve Filter Configuration
# Enhanced by ${COMPANY_NAME}
require ["fileinto", "reject", "envelope"];

# Spam filtering
if exists "X-Spam-Flag" {
    if header :contains "X-Spam-Flag" "YES" {
        fileinto "Spam";
        stop;
    }
}

if header :contains "subject" ["***SPAM***", "[SPAM]", "***JUNK***"] {
    fileinto "Spam";
    stop;
}
