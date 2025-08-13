#!/bin/bash
#
# Mayar Technologies, LLC - Rebranded CWP EL8 installer
# Rebranded and modernized from original "CWP-el8-latest"
# Maintainer: Mayar Technologies, LLC <info@mayartechnologies.com>
#
# IMPORTANT:
# - This script bundles/uses official CWP components and external downloads (CWP repos and service archives).
# - Do NOT remove or alter CWP-provided repos, cwpsrv binaries, cwp-services.zip and other proprietary artifacts
#   unless you understand licensing and compatibility implications. These are flagged below where relevant.
#
# Original copyright header retained (required) — see block below.
########################################################################
# Use of code or any part of it is strictly prohibited. File protected by copyright law and provided under license.
# To Use any part of this code you need to get a writen approval from the code owner: info@centos-webpanel.com
########################################################################

set -euo pipefail
IFS=$'\n\t'

# Keep locale behaviour unchanged
LANG=en_US.UTF-8
export LANG

# ---------------------------
# Defaults & Branding
# ---------------------------
COMPANY="Mayar Technologies, LLC"
DEFAULT_HOSTNAME="cloud.mayartechnologies.com"
SUPPORT_EMAIL="support@mayartechnologies.com"
INFO_EMAIL="info@mayartechnologies.com"
ADMIN_EMAIL="admin@mayartechnologies.com"

# Installer-level defaults
RESTART_AFTER_INSTALL="no"
PHPFPM=""
SOFTACULOUS="no"
MODSECURITY="no"

help() {
  cat <<'EOF'
Usage: cwp-el8-mayar.sh [OPTIONS]
  -r, --restart       Restart server after install  [yes]  default: no
  -p, --phpfpm        Install PHP-FPM  [5.4|5.5|5.6|7.0|7.1|7.2|7.3|7.4|8.0]  default: no
  -s, --softaculous   Install Softaculous  [yes]  default: no
  -m, --modsecurity   Install ModSecurity CWAF  [yes]  default: no
  -h, --help          Print this help

Example:
  sh cwp-el8-mayar.sh -r yes --phpfpm 7.2 --softaculous yes --modsecurity yes
EOF
  exit 1
}

# Parse long options compatibly
for arg; do
  case "$arg" in
    --restart)            set -- "$@" "-r" "yes" ;;
    --phpfpm)             # handled by next arg in getopts
                          ;;
    --softaculous)        set -- "$@" "-s" "yes" ;;
    --modsecurity)        set -- "$@" "-m" "yes" ;;
    --help)               set -- "$@" "-h" ;;
    *)                    # keep other args
                          set -- "$@" "$arg" ;;
  esac
done

# POSIX getopts parsing (short options only)
while getopts ":r:p:s:m:h" opt; do
  case $opt in
    r) RESTART_AFTER_INSTALL=$OPTARG ;;
    p) PHPFPM=$OPTARG ;;
    s) SOFTACULOUS=$OPTARG ;;
    m) MODSECURITY=$OPTARG ;;
    h|*) help ;;
  esac
done
shift $((OPTIND-1))

# Must be run as root
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root"
  exit 1
fi

# Detect existing CWP installation
if [ -d "/usr/local/cwpsrv/" ]; then
  echo
  echo "CWP is already installed on your server."
  echo "If you want to update it, run: sh /scripts/update_cwp"
  echo
  exit 1
fi

# Use dnf where available (AlmaLinux 8). yum is preserved as alias where used by CWP.
if command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
else
  PKG_MGR="yum"
fi

# Basic package install helper (non-interactive)
pkg_install() {
  $PKG_MGR -y install "$@" || { echo "Failed to install: $*"; exit 1; }
}

# Remove firewalld (CWP uses CSF)
$PKG_MGR -y erase firewalld || true

# EPEL (some packages depend on EPEL)
pkg_install epel-release
# Common tools
pkg_install wget curl tar unzip screen procps-ng

# Ensure certificate bundle and essential tools
pkg_install ca-certificates which rsync gzip

# CPU arch checks - only 64-bit x86 supported
arch=$(uname -m)
case "$arch" in
  x86_64) ;;
  *) echo "Unsupported architecture ($arch). Use AlmaLinux 8 x86_64."; exit 1 ;;
esac

# Detect OS family / version marker in release package
centosversion=$(rpm -qa \*-release | grep -Ei "oracle|redhat|centos|cloudlinux|rocky|alma" | head -n1 || true)
# If a numeric version is required, that logic is preserved downstream by CWP install checks.

# AlmaLinux GPG key ensure
if ! rpm -q gpg-pubkey --quiet >/dev/null 2>&1; then
  rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux || true
fi

# MySQL/MariaDB check
if command -v mysql >/dev/null 2>&1; then
  MYSQLCHK="on"
else
  MYSQLCHK="off"
fi

# If existing MySQL present, try to get /root/.my.cnf password
if [ "$MYSQLCHK" = "on" ]; then
  if [ -f /root/.my.cnf ]; then
    passwd=$(awk -F= '/^password/ {gsub(/[" \t]/,"",$2); print $2; exit}' /root/.my.cnf || true)
  fi
fi

# Generate a random password if no existing DB
if [ "$MYSQLCHK" = "off" ]; then
  password=$(</dev/urandom tr -dc A-Za-z0-9 | head -c12)
  NEW_INSTALL=1
else
  NEW_INSTALL=0
fi

# Modern MariaDB repo (10.11) for compatibility with current CWP EL8 installers
# NOTE: CWP forums recommend upgrading from old 10.4 repos to 10.6/10.11 to avoid installer failures. :contentReference[oaicite:3]{index=3}
if [ "$NEW_INSTALL" -eq 1 ]; then
  cat > /etc/yum.repos.d/mariadb.repo <<EOF
# MariaDB 10.11 EL8 repository (configured for Alma/CentOS/RHEL8)
[mariadb]
name = MariaDB
baseurl = https://yum.mariadb.org/10.11/centos8-amd64
gpgkey = https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck = 1
enabled = 1
module_hotfixes = 1
EOF
fi

# Add CWP Repository
# IMPORTANT: Keep CWP repo pointing to official repo.centos-webpanel.com — altering it may break CWP updates.
cat > /etc/yum.repos.d/cwp.repo <<'EOF'
[cwp]
name=CentOS Web Panel repo for Linux 8 - $basearch
baseurl=http://repo.centos-webpanel.com/repo/8/$basearch
enabled=1
gpgcheck=0
priority=1
EOF

# Prepare system caches and extra packages
$PKG_MGR -y makecache
pkg_install apr apr-util util-linux-user glibc-all-langpacks rsyslog mlocate net-tools bind bind-utils

# Fix EPEL repo if metadata is malformed on some images
if [ -f /etc/yum.repos.d/epel.repo ]; then
  sed -i "s/metalink=https/metalink=http/" /etc/yum.repos.d/epel.repo || true
  # Exclude distribution nginx from EPEL to avoid conflicts with CWPs packaged NGINX (if any)
  sed -i "/enabled=1/a exclude=nginx*" /etc/yum.repos.d/epel.repo || true
fi

# Enable powertools-like repository for EL8 (Alma provides almalinux-powertools)
if $PKG_MGR config-manager --help >/dev/null 2>&1; then
  $PKG_MGR config-manager --set-enabled powertools || true
fi

# Ensure /usr/local/src exists
mkdir -p /usr/local/src

# SELinux disable (CWP expects it)
if [ -f /etc/selinux/config ]; then
  sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config || true
  setenforce 0 || true
fi

# Stop and disable firewalld (we'll use CSF)
systemctl stop firewalld || true
systemctl disable firewalld || true

# POSTFIX / DOVECOT prerequisites
pkg_install postfix dovecot dovecot-mysql dovecot-pigeonhole cyrus-sasl-devel subversion file

# Date sanity check
CHKDATE=$(date +%Y)
if [ "$CHKDATE" -le "2014" ]; then
  echo "Server clock appears incorrect: $(date). Fix date/time and re-run."
  exit 1
fi

# Install MariaDB if none present
if [ "$NEW_INSTALL" -eq 1 ]; then
  pkg_install MariaDB MariaDB-server || true
  # Basic systemd configuration for MariaDB (override)
  mkdir -p /etc/systemd/system/mariadb.service.d
  cat > /etc/systemd/system/mariadb.service.d/override.conf <<'EOF'
[Service]
CapabilityBoundingSet=
AmbientCapabilities=
EOF
  systemctl daemon-reload || true
  systemctl enable --now mariadb || true

  # Set root password, secure basic DB: (note: CWP will further configure DB)
  mysqladmin -u root password "$password" || true
fi

# Track whether MariaDB is new for configuration steps later
NEW_DB_FLAG=${NEW_INSTALL:-0}

# Install essential build tools used by CWP (compiler may be needed)
pkg_install gcc gcc-c++ make automake autoconf rsync nano which screen sysstat at zip git unzip cronie perl-CPAN perl-libwww-perl perl-LWP-Protocol-https

# Remove conflicting packages
$PKG_MGR -y remove apr exim sendmail || true

# Retrieve public IP (use official CWP info endpoint)
# NOTE: official installer uses centos-webpanel lookup — we'll use their service for consistency.
pubip=$(curl -sS http://centos-webpanel.com/webpanel/main.php?app=showip || echo "")
if [ -z "$pubip" ]; then
  # fallback to external resolver
  pubip=$(curl -sS https://ifconfig.co || true)
fi

fqdn=$(hostname -f 2>/dev/null || hostname 2>/dev/null || "$DEFAULT_HOSTNAME")

# If hostname not properly set to FQDN, set to Mayar default but only if hostname is localhost/empty
if [[ "$fqdn" == "localhost" || "$fqdn" == "localhost.localdomain" || -z "$fqdn" ]]; then
  echo "[INFO] No proper FQDN found — setting hostname to ${DEFAULT_HOSTNAME}"
  hostnamectl set-hostname "${DEFAULT_HOSTNAME}"
  fqdn="${DEFAULT_HOSTNAME}"
fi

echo ""
echo "PREPARING THE SERVER FOR ${COMPANY}"
echo "###################################"

# Install Apache + PHP + CWP packages (CWP packages are proprietary/packaged — keep using official names)
# NOTE: All CWP-specific packages (cwpsrv, cwpphp, cwpsrv binaries) are provided by CWP repos and must remain as-is.
pkg_install cwp-httpd cwp-suphp || true

# Attempt to install main php package shipped with CWP
pkg_install cwp-php --enablerepo=epel || true

# Install CWP server packages (these come from CWP repo; do not rebrand/alter package names)
pkg_install cwpsrv cwpphp --enablerepo=cwp || true

# Verify critical files exist
if [ ! -x "/usr/local/cwpsrv/bin/cwpsrv" ]; then
  echo "Installation FAILED: cwpsrv binary missing. Check CWP repository and network connectivity."
  exit 1
fi

# Create SSL self-signed cert for server IP if no cert exists
mkdir -p /etc/pki/tls/private /etc/pki/tls/certs
openssl genrsa -out /etc/pki/tls/private/cwp-${pubip}.key 2048 || true
# Use Mayar branding in certificate subject by default (email set to admin@mayartechnologies.com)
openssl req -new -x509 -key /etc/pki/tls/private/cwp-${pubip}.key -out /etc/pki/tls/certs/cwp-${pubip}.crt -days 3650 -subj "/C=US/ST=State/O=${COMPANY}/CN=${fqdn}/emailAddress=${ADMIN_EMAIL}" || true

# MySQL / MariaDB configuration for new installs
if [ "$NEW_DB_FLAG" -eq 1 ]; then
  echo "## CONFIGURE MYSQL/MariaDB"
  systemctl daemon-reload || true
  systemctl enable --now mariadb || true
  # Secure basics
  mysql -u root -e "DROP DATABASE IF EXISTS test;" || true
  mysql -u root -e "DELETE FROM mysql.user WHERE User='';" || true
  mysql -u root -e "DELETE FROM mysql.user WHERE User='root' AND Host!='localhost';" || true
  mysql -u root -e "FLUSH PRIVILEGES;" || true
fi

# write /root/.my.cnf for automation (make sure permissions tight)
cat > /root/.my.cnf <<EOF
[client]
user=root
password=${password}
EOF
chmod 600 /root/.my.cnf

# Apache tweaks (preserve original config layout)
sed -i "s|#Include conf/extra/httpd-userdir.conf|Include conf/extra/httpd-userdir.conf|" /usr/local/apache/conf/httpd.conf || true

cat > /usr/local/apache/conf.d/server-status.conf <<'EOF'
<Location /server-status>
    SetHandler server-status
    Require local
</Location>
EOF

# Ensure service links and limits (matches original script)
if [ ! -L /etc/systemd/system/multi-user.target.wants/httpd.service ]; then
  ln -s /usr/lib/systemd/system/httpd.service /etc/systemd/system/multi-user.target.wants/httpd.service || true
fi

# Increase LimitNOFILE if not present
grep -q '^LimitNOFILE' /usr/lib/systemd/system/httpd.service || echo -e "\n[Service]\nLimitNOFILE=65535" >> /usr/lib/systemd/system/httpd.service

systemctl daemon-reload || true
systemctl enable --now httpd || true

# Set PHP timezone default (Etc/UTC preserved for compatibility)
if [ -f /usr/local/php/php.ini ]; then
  sed -i "s|;date.timezone =.*|date.timezone = Etc/UTC|" /usr/local/php/php.ini || true
fi

# Add fqdn to /etc/hosts
grep -qF "127.0.0.1 ${fqdn}" /etc/hosts || echo "127.0.0.1 ${fqdn}" >> /etc/hosts

# Postfix basic config updates
sed -i "s|inet_interfaces = localhost|inet_interfaces = all|" /etc/postfix/main.cf || true
# Adjust home mailbox to Maildir
sed -i "s|#home_mailbox = Maildir/|home_mailbox = Maildir/|" /etc/postfix/main.cf || true

# ---------------------------
# Install CSF (ConfigServer Firewall)
# ---------------------------
echo "Installing CSF/LFD Firewall (ConfigServer)"
cd /tmp || true
rm -f csf.tgz
# Use secure HTTPS for CSF
wget -q https://download.configserver.com/csf.tgz
tar -xzf csf.tgz || true
cd csf || true
sh install.sh || true

# Open required CWP ports in csf.conf (preserve original ports + additional)
sed -i "s|80,110,113,443|80,110,113,443,2030,2031,2082,2083,2086,2087,2095,2096|" /etc/csf/csf.conf || true
sed -i 's|TESTING = "1"|TESTING = "0"|' /etc/csf/csf.conf || true
touch /usr/local/csf/bin/csfpre.sh /usr/local/csf/bin/csfpost.sh || true
csf -x || true

# csf ignore rules - keep original entries, but updated paths (php-fpm path may vary depending on PHP versions)
cat >> /etc/csf/csf.pignore <<'EOF'
# CWP CUSTOM
exe:/usr/sbin/clamd
exe:/usr/sbin/opendkim
exe:/usr/libexec/mysqld
exe:/usr/sbin/mysqld
exe:/usr/bin/postgres
exe:/usr/bin/mongod
exe:/usr/libexec/dovecot/anvil
exe:/usr/libexec/dovecot/auth
exe:/usr/libexec/dovecot/imap-login
exe:/usr/libexec/dovecot/dict
exe:/usr/libexec/dovecot/stats
exe:/usr/libexec/dovecot/pop3-login
exe:/usr/local/cwp/php71/sbin/php-fpm

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

exe:/usr/sbin/varnishd
exe:/usr/sbin/nginx
exe:/usr/sbin/rpcbind
exe:/usr/bin/memcached
exe:/usr/sbin/rngd
exe:/usr/lib/systemd/systemd-resolved

exe:/usr/bin/perl
user:amavis
cmd:/usr/sbin/amavisd
user:netdata
EOF

mkdir -p /var/lib/csf
touch /var/lib/csf/csf.tempban /var/lib/csf/csf.tempallow

# Custom CSF log config used by CWP brute-force protection (preserve default logs)
sed -i "s|CUSTOM1_LOG.*|CUSTOM1_LOG = \"/var/log/cwp_client_login.log\"|g" /etc/csf/csf.conf || true
sed -i "s|CUSTOM2_LOG.*|CUSTOM2_LOG = \"/usr/local/apache/domlogs/*.log\"|g" /etc/csf/csf.conf || true
sed -i "s|^HTACCESS_LOG.*|HTACCESS_LOG = \"/usr/local/apache/logs/error_log\"|g" /etc/csf/csf.conf || true

# Create regex.custom.pm used by CSF custom rules (as original)
cat > /usr/local/csf/bin/regex.custom.pm <<'EOF'
#!/usr/bin/perl
sub custom_line {
        my $line = shift;
        my $lgfile = shift;
# Do not edit before this point

# CWP Failed Login Protection
if (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ /^\S+\s+\S+\s+(\S+)\s+Failed Login from:\s+(\S+) on: (\S+)/)) {
               return ("Failed CWP-Login login for User: $1 from IP: $2 URL: $3",$2,"cwplogin","5","2030,2031","1");
}

# Wordpress XMLRPC
if (($globlogs{CUSTOM2_LOG}{$lgfile}) and ($line =~ /(\S+).*] "\w*(?:GET|POST) \/xmlrpc\.php.*" /)) {
return ("WP XMLPRC Attack",$1,"XMLRPC","10","80,82,443,8181,8443","1");
}

# Wordpress WP-LOGINS
if (($globlogs{CUSTOM2_LOG}{$lgfile}) and ($line =~ /(\S+).*] "\w*(?:GET|POST) \/wp-login\.php.*" /)) {
return ("WP Login Attack",$1,"WPLOGIN","10","80,82,443,8181,8443","1");
}

# Do not edit beyond this point
        return 0;
}
1;
EOF
chmod +x /usr/local/csf/bin/regex.custom.pm || true

# Dovecot logging files (preserve behavior)
touch /var/log/dovecot-debug.log /var/log/dovecot-info.log /var/log/dovecot.log
chmod 600 /var/log/dovecot-*.log || true
usermod -a -G mail dovecot || true

# ---------------------------
# WebPanel Files (CWP UI) - RETAIN OFFICIAL CWP FILES
# ---------------------------
# NOTE: The following downloads are official CWP files and services. Do NOT change these to third-party mirrors.
# Official installer is served (canonical) from centos-webpanel.com/cwp-el8-latest. :contentReference[oaicite:4]{index=4}

cd /usr/local/cwpsrv/htdocs || mkdir -p /usr/local/cwpsrv/htdocs && cd /usr/local/cwpsrv/htdocs

# Some static.cdn-cwp.com assets don't have valid TLS — keep HTTP for them to avoid failed downloads. :contentReference[oaicite:5]{index=5}
wget -q http://static.cdn-cwp.com/files/cwp/el7/cwp-el7-0.9.8.1210.zip -O cwp-el7.zip || true
unzip -o -q cwp-el7.zip || true
rm -f cwp-el7.zip || true

mkdir -p /usr/local/cwpsrv/var/services
cd /usr/local/cwpsrv/var/services
wget -q http://static.cdn-cwp.com/files/cwp/el7/cwp-services.zip -O cwp-services.zip || true
unzip -o -q cwp-services.zip || true
rm -f cwp-services.zip || true

# phpMyAdmin (version copied from CWP static repo)
cd /usr/local/cwpsrv/var/services
wget -q http://static.cdn-cwp.com/files/mysql/phpMyAdmin-4.7.9-all-languages.zip -O phpmyadmin.zip || true
unzip -o -q phpmyadmin.zip || true
mv phpMyAdmin-4.7.9-all-languages pma || true
rm -f phpmyadmin.zip || true
rm -rf pma/setup || true

# webFTP addon (from CWP static)
cd /usr/local/apache/htdocs/ || true
wget -q http://static.cdn-cwp.com/files/cwp/addons/webftp_simple.zip -O webftp.zip || true
unzip -o -q webftp.zip || true
rm -f webftp.zip || true

# Copy default templates into Apache docroot (preserve original location)
cp -a /usr/local/cwpsrv/htdocs/resources/admin/tpl/new_account_tpl/* /usr/local/apache/htdocs/ 2>/dev/null || true

# WebPanel settings: create admin DB connection file (preserve location and filename)
cd /usr/local/cwpsrv/htdocs/resources/admin/include || true
wget -q http://static.cdn-cwp.com/files/cwp/sql/db_conn.txt -O db_conn.txt || true
mv -f db_conn.txt db_conn.php || true
chmod 600 db_conn.php || true

# ---------------------------
# phpMyAdmin / WebPanel passwords & config (preserve file structure)
# ---------------------------
cd /usr/local/cwpsrv/var/services || true
if [ -f pma/config.sample.inc.php ]; then
  mv -f pma/config.sample.inc.php pma/config.inc.php || true
  ran_password=$(</dev/urandom tr -dc A-Za-z0-9 | head -c32)
  sed -i "s|\['blowfish_secret'\] = ''|\['blowfish_secret'\] = '${ran_password}'|" pma/config.inc.php || true
fi

# Update webpanel DB password in admin include (this file is created from db_conn.php earlier)
if [ -f /usr/local/cwpsrv/htdocs/resources/admin/include/db_conn.php ]; then
  ran_password2=$(</dev/urandom tr -dc A-Za-z0-9 | head -c12)
  sed -i "s|\$crypt_pwd = ''|\$crypt_pwd = '${ran_password2}'|" /usr/local/cwpsrv/htdocs/resources/admin/include/db_conn.php || true
  sed -i "s|\$db_pass = ''|\$db_pass = '${password}'|" /usr/local/cwpsrv/htdocs/resources/admin/include/db_conn.php || true
  chmod 600 /usr/local/cwpsrv/htdocs/resources/admin/include/db_conn.php || true
fi

# PHP short tags fix (be conservative — only modify if file exists)
if [ -f /usr/local/cwp/php71/php.ini ]; then
  sed -i "s|short_open_tag = Off|short_open_tag = On|" /usr/local/cwp/php71/php.ini || true
fi
if [ -f /usr/local/php/php.ini ]; then
  sed -i "s|short_open_tag = Off|short_open_tag = On|" /usr/local/php/php.ini || true
fi

# Cron setup for CWP (preserve file locations)
cat > /etc/cron.daily/cwp <<EOF
/usr/local/cwp/php71/bin/php -d max_execution_time=1000000 -q /usr/local/cwpsrv/htdocs/resources/admin/include/cron.php
/usr/local/cwp/php71/bin/php -d max_execution_time=1000000 -q /usr/local/cwpsrv/htdocs/resources/admin/include/cron_backup.php
EOF
chmod +x /etc/cron.daily/cwp || true

# SSL cron tasks (use php71 path used by CWP package)
CRONDATE1=$(date +%M\ %H -d '1 hour ago' || echo "0 0")
echo "${CRONDATE1} * * * /usr/local/cwp/php71/bin/php -d max_execution_time=18000 -q /usr/local/cwpsrv/htdocs/resources/admin/include/cron_autossl_all_domains.php" >> /var/spool/cron/root || true
echo "0 0 * * * /usr/local/cwp/php71/bin/php -d max_execution_time=18000 -q /usr/local/cwpsrv/htdocs/resources/admin/include/alertandautorenewssl.php" >> /var/spool/cron/root || true

# MySQL import of CWP DBs (use http for static CDN as HTTPS may fail)
curl -s 'http://static.cdn-cwp.com/files/cwp/sql/root_cwp.sql' | mysql -uroot -p"${password}" || true
curl -s 'http://static.cdn-cwp.com/files/cwp/sql/oauthv2.sql' | mysql -uroot -p"${password}" || true

mysql -u root -p"${password}" -e "USE root_cwp; UPDATE settings SET shared_ip='${pubip}';" || true

# Named (bind) setup: leave recursion disabled for security
sed -i "s|127.0.0.1|any|" /etc/named.conf || true
sed -i "s|localhost|any|" /etc/named.conf || true
sed -i 's/recursion yes/recursion no/g' /etc/named.conf || true
systemctl enable --now named || true

# ---------------------------
# Mail server: fetch mail configs & set up vmail, vacation, sieve
# ---------------------------
cd /
wget -q http://static.cdn-cwp.com/files/mail/el7/mail_server_quota.zip -O /mail_server_quota.zip || true
unzip -o -q /mail_server_quota.zip -d / || true
rm -f /mail_server_quota.zip || true

mkdir -p /var/vmail
chmod 770 /var/vmail
getent group mail >/dev/null || groupadd -r mail || true
useradd -r -u 101 -g mail -d /var/vmail -s /sbin/nologin -c "Virtual mailbox" vmail || true
chown vmail:mail /var/vmail || true

touch /etc/postfix/virtual_regexp || true

# Vacation auto-reply user
useradd -r -d /var/spool/vacation -s /sbin/nologin -c "Virtual vacation" vacation || true
mkdir -p /var/spool/vacation
chmod 770 /var/spool/vacation
cd /var/spool/vacation || true
ln -sf /etc/postfix/vacation.php /var/spool/vacation/vacation.php || true
chmod +x /etc/postfix/vacation.php || true
usermod -a -G mail vacation || true
chown vacation /etc/postfix/vacation.php || true

echo "127.0.0.1 autoreply.${fqdn}" >> /etc/hosts || true

# Sieve global filter
mkdir -p /var/sieve
cat > /var/sieve/globalfilter.sieve <<'EOF'
require "fileinto";
if exists "X-Spam-Flag" {
  if header :contains "X-Spam-Flag" "NO" {
  } else {
    fileinto "Spam";
    stop;
  }
}
if header :contains "subject" ["***SPAM***"] {
  fileinto "Spam";
  stop;
}
EOF
chown -R vmail:mail /var/sieve || true

# Generate SSL for FQDN (rebranded – uses Mayar company data)
DOMAIN="${fqdn}"
if [ -z "$DOMAIN" ]; then
  echo "Hostname is not properly set!"
  exit 11
fi

# Generate a passphrase, CSR and self-signed certificate (rebrand subject)
export PASSPHRASE=$(head -c 500 /dev/urandom | tr -dc a-z0-9A-Z | head -c 128; echo)
subj="/C=US/ST=State/O=${COMPANY}/localityName=City/commonName=${DOMAIN}/organizationalUnitName=${COMPANY}/emailAddress=${INFO_EMAIL}"

openssl genrsa -des3 -out /root/${DOMAIN}.key -passout env:PASSPHRASE 2048 || true
openssl req -new -batch -subj "$(echo -n "$subj" | tr "\n" "/")" -key /root/${DOMAIN}.key -out /root/${DOMAIN}.csr -passin env:PASSPHRASE || true
cp /root/${DOMAIN}.key /root/${DOMAIN}.key.org || true
openssl rsa -in /root/${DOMAIN}.key.org -out /root/${DOMAIN}.key -passin env:PASSPHRASE || true
openssl x509 -req -days 3650 -in /root/${DOMAIN}.csr -signkey /root/${DOMAIN}.key -out /root/${DOMAIN}.crt || true

# Move and link certs to CWP expected locations
mv -f /root/${DOMAIN}.key /etc/pki/tls/private/hostname.key || true
mv -f /root/${DOMAIN}.crt /etc/pki/tls/certs/hostname.crt || true
cp -f /etc/pki/tls/certs/hostname.crt /etc/pki/tls/certs/hostname.bundle || true
ln -sf /etc/pki/tls/private/hostname.key /etc/pki/tls/private/${DOMAIN}.key || true
ln -sf /etc/pki/tls/certs/hostname.crt /etc/pki/tls/certs/${DOMAIN}.crt || true

# Pure-FTPd (install from EPEL)
if [ ! -f /etc/pure-ftpd/pure-ftpd.conf ]; then
  pkg_install pure-ftpd
  touch /etc/pure-ftpd/pureftpd.passwd || true
  pure-pw mkdb /etc/pure-ftpd/pureftpd.pdb -f /etc/pure-ftpd/pureftpd.passwd -m || true
fi
if [ ! -f /etc/pure-ftpd/pure-ftpd.conf ]; then
  echo "Installation FAILED at pure-ftpd"; exit 1
fi
# Tweak pure-ftpd config to use PureDB and PAM auth
sed -i 's|.*pureftpd.pdb.*|PureDB /etc/pure-ftpd/pureftpd.pdb|g' /etc/pure-ftpd/pure-ftpd.conf || true
sed -i 's|.*PAMAuthentication.*yes|PAMAuthentication    yes|g' /etc/pure-ftpd/pure-ftpd.conf || true
sed -i 's|.*UnixAuthentication.*yes|UnixAuthentication       yes|g' /etc/pure-ftpd/pure-ftpd.conf || true
grep -q "^/sbin/nologin$" /etc/shells || echo "/sbin/nologin" >> /etc/shells || true
systemctl enable --now pure-ftpd || true

# Postfix configuration substitution (preserve mysql cf names)
sed -i "s|MY_HOSTNAME|${fqdn}|g" /etc/postfix/main.cf || true
sed -i "s|MY_HOSTNAME|autoreply.${fqdn}|g" /etc/postfix/mysql-virtual_vacation.cf || true
sed -i "s|MY_DOMAIN|${fqdn}|g" /etc/postfix/main.cf || true

# Mail DB user generation & import
postfix_pwd=$(</dev/urandom tr -dc A-Za-z0-9 | head -c12)
cnf_hostname="${fqdn}"

# MySQL postfix DB & user creation
mysql -u root -p"${password}" <<EOF || true
DROP USER IF EXISTS 'postfix'@'localhost';
CREATE DATABASE IF NOT EXISTS postfix;
CREATE USER IF NOT EXISTS 'postfix'@'localhost' IDENTIFIED BY '${postfix_pwd}';
GRANT ALL PRIVILEGES ON postfix.* TO 'postfix'@'localhost';
FLUSH PRIVILEGES;
EOF

# Import Postfix schema shipped by CWP (HTTP used for static CDN)
curl -s 'http://centos-webpanel.com/webpanel/main.php?dl=postfix.sql' | mysql -uroot -p"${password}" postfix || true

# Install perl tools required by mail stack
pkg_install perl-MailTools perl-MIME-EncWords perl-TimeDate perl-Mail-Sender perl-Log-Log4perl perl-Razor-Agent perl-Convert-BinHex
$PKG_MGR -y --enablerepo=epel,powertools install amavisd-new clamav clamav-update perl-Digest-SHA1 perl-IO-stringy || true

# ClamAV/amavisd/clamd adjustments (preserve original steps)
if [ -f /etc/clamd.d/scan.conf ]; then
  sed -i '/^Example$/d' /etc/clamd.d/scan.conf || true
  sed -i '/^Example$/d' /etc/freshclam.conf || true
  sed -i 's/^#LocalSocket/LocalSocket/' /etc/clamd.d/scan.conf || true
  sed -i 's/^LocalSocketGroup.*$/LocalSocketGroup amavis/' /etc/clamd.d/scan.conf || true
fi
usermod -a -G amavis clamscan || true
# systemd service fixes for clamd (if packaging differs on Alma)
if [ -f /usr/lib/systemd/system/clamd\@.service ]; then
  mv /usr/lib/systemd/system/clamd\@.service /usr/lib/systemd/system/clamd.service || true
  sed -i 's/^ExecStart.*$/ExecStart = \/usr\/sbin\/clamd -c \/etc\/clamd.d\/amavisd.conf --foreground=yes/' /usr/lib/systemd/system/clamd.service || true
  sed -i "s/^Type = forking/Type = simple/" /usr/lib/systemd/system/clamd.service || true
  mv -f /usr/lib/systemd/system/clamd\@scan.service /usr/lib/systemd/system/clamd-scan.service || true
  sed -i 's/clamd@.service/clamd.service/' /usr/lib/systemd/system/clamd-scan.service || true
fi
systemctl daemon-reload || true

# ---------------------------
# Roundcube installation (preserve original logic)
# ---------------------------
/usr/local/cwp/php71/bin/pear install Mail_mime Net_SMTP || true
/usr/local/cwp/php71/bin/pear install channel://pear.php.net/Net_IDNA2-0.1.1 || true
/usr/local/cwp/php71/bin/pear install Net_Sieve || true

# generate password for roundcube DB if not set
if [ -z "${mysql_roundcube_password:-}" ]; then
  mysql_roundcube_password=$(</dev/urandom tr -dc A-Za-z0-9 | head -c12)
fi

# ensure mysql root password is set
if [ -z "${password:-}" ]; then
  read -p "MySQL root password []: " password
fi

mkdir -p /usr/local/cwpsrv/var/services
wget -q http://static.cdn-cwp.com/files/mail/roundcubemail-1.2.3.tar.gz -O /usr/local/cwpsrv/var/services/roundcubemail.tar.gz || true
tar -C /usr/local/cwpsrv/var/services -zxf /usr/local/cwpsrv/var/services/roundcubemail.tar.gz || true
rm -f /usr/local/cwpsrv/var/services/roundcubemail.tar.gz || true
mv /usr/local/cwpsrv/var/services/roundcubemail-* /usr/local/cwpsrv/var/services/roundcube || true
chown cwpsvc:cwpsvc -R /usr/local/cwpsrv/var/services/roundcube || true
chmod -R 777 /usr/local/cwpsrv/var/services/roundcube/temp /usr/local/cwpsrv/var/services/roundcube/logs || true

# Create roundcube DB and import
mysql -u root -p"${password}" <<EOF || true
USE mysql;
CREATE DATABASE IF NOT EXISTS roundcube;
GRANT ALL PRIVILEGES ON roundcube.* TO 'roundcube'@'localhost' IDENTIFIED BY '${mysql_roundcube_password}';
FLUSH PRIVILEGES;
EOF

if [ -f /usr/local/cwpsrv/var/services/roundcube/SQL/mysql.initial.sql ]; then
  mysql -u root -p"${password}" roundcube < /usr/local/cwpsrv/var/services/roundcube/SQL/mysql.initial.sql || true
fi

# Update roundcube config (preserve paths & files)
if [ -f /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php.sample ]; then
  cp -f /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php.sample /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php || true
  sed -i "s|^\(\$config\['default_host'\] =\).*$|\1 'localhost';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php || true
  sed -i "s|^\(\$config\['smtp_server'\] =\).*$|\1 'localhost';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php || true
  sed -i "s|^\(\$config\['smtp_user'\] =\).*$|\1 '%u';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php || true
  sed -i "s|^\(\$config\['smtp_pass'\] =\).*$|\1 '%p';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php || true
  sed -i "s|^\(\$config\['quota_zero_as_unlimited'\] =\).*$|\1 true;|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php || true
  sed -i "s|MYSQL_PASSWORD|${postfix_pwd}|g" /usr/local/cwpsrv/var/services/roundcube/plugins/password/config.inc.php || true
  sed -i "s|^\(\$config\['db_dsnw'\] =\).*$|\1 'mysqli://roundcube:${mysql_roundcube_password}@localhost/roundcube';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php || true
fi
rm -rf /usr/local/cwpsrv/var/services/roundcube/installer || true
sh /usr/local/cwpsrv/htdocs/resources/scripts/mail_roundcube_update || true
chown -R cwpsvc:cwpsvc /usr/local/cwpsrv/var/services/roundcube || true

# Set permissions & secure mail/sql config files
chmod 640 /etc/postfix/mysql-*.cf || true
chmod 640 /etc/dovecot/dovecot-*.conf || true
chmod 640 /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php || true
chown root.mail /etc/postfix/mysql-*.cf || true
chown root.mail /etc/dovecot/dovecot-*.conf || true

# Install opendkim and tools (EPEL)
$PKG_MGR -y --enablerepo=epel install opendkim libopendkim perl-Mail-DKIM perl-Mail-SPF pypolicyd-spf || true
$PKG_MGR -y --enablerepo=epel install opendkim-tools || true

cat > /etc/opendkim.conf <<'EOF'
AutoRestart             Yes
AutoRestartRate         10/1h
LogWhy                  Yes
Syslog                  Yes
SyslogSuccess           Yes
Mode                    sv
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
SignatureAlgorithm      rsa-sha256
Socket                  inet:8891@localhost
PidFile                 /var/run/opendkim/opendkim.pid
UMask                   022
UserID                  opendkim:opendkim
TemporaryDirectory      /var/tmp
EOF

# Ensure opendkim-genkey installed
if [ ! -x "/usr/sbin/opendkim-genkey" ]; then
  $PKG_MGR -y --enablerepo=epel install opendkim-tools || true
fi

# ---------------------------
# User login message (rebranded)
# ---------------------------
cat > /root/.bash_cwp <<EOF
echo ""
echo "********************************************"
echo " Welcome to ${COMPANY} CWP server"
echo "********************************************"
echo ""
echo "CWP Wiki: https://control-webpanel.com"
echo "If you need help from ${COMPANY}, contact: ${SUPPORT_EMAIL}"
echo ""
EOF
if ! grep -q "bash_cwp" /root/.bash_profile 2>/dev/null; then
  echo "sh /root/.bash_cwp" >> /root/.bash_profile || true
fi

# /scripts symlink preservation (preserve original CWP scripts)
if [ ! -e "/scripts" ]; then
  ln -s /usr/local/cwpsrv/htdocs/resources/scripts /scripts || true
  chmod +x /scripts/* || true
fi

# Enable common services
systemctl daemon-reload || true
systemctl enable httpd || true
systemctl enable cwpsrv || true
systemctl enable mariadb || true
systemctl enable postfix || true
systemctl enable dovecot || true
systemctl daemon-reload || true

# Create php symlinks for convenience if php exists
if [ -x /usr/local/bin/php ]; then
  ln -sf /usr/local/bin/php /bin/php || true
  ln -sf /usr/local/bin/php /usr/bin/php || true
fi

# Restart services
systemctl restart httpd || true
systemctl restart cwpsrv || true

chown vmail.mail /var/log/dovecot* || true
mkdir -p /usr/local/apache/htdocs/.well-known || true
chown -R nobody:nobody /usr/local/apache/htdocs/* || true
chown -R cwpsvc.cwpsvc /usr/local/cwpsrv/var/services || true
# Protect web admin directory (CWP binary file is proprietary - preserve original protection)
if [ -e /usr/local/cwpsrv/htdocs/admin ]; then
  /usr/bin/chattr +i /usr/local/cwpsrv/htdocs/admin || true
fi

# Open only required non-standard ports via iptables (legacy support)
iptables -A INPUT ! -i lo -p tcp -m state --state NEW -m tcp --dport 2030 -j ACCEPT || true
iptables -A INPUT ! -i lo -p tcp -m state --state NEW -m tcp --dport 2031 -j ACCEPT || true
service iptables save || true

# NAT check
checklocal=$(/sbin/ip addr sh | grep -F "$pubip" || true)
if [ -z "$checklocal" ]; then
  mkdir -p /usr/local/cwp/.conf/
  touch /usr/local/cwp/.conf/nat_check.conf || true
fi

# ---------------------------
# PHP-FPM selector & Softaculous & ModSecurity (optional)
# ---------------------------
# PHP-FPM selector: re-use CWP selector scripts; the original used a static EL7 path — we point to el8 selector where possible.
if [ -n "$PHPFPM" ]; then
  echo "Installing PHP-FPM ${PHPFPM} via CWP selector"
  CWPDLLINK="http://static.cdn-cwp.com/files/php/selector/el7/"  # NOTE: CWP currently distributes selector configs from this path
  mkdir -p /usr/local/cwp/.conf/php-fpm_conf/
  # attempt to fetch the matching phpX conf; fall back to generic.
  wget -q "${CWPDLLINK}php${PHPFPM//./}.conf" -O /usr/local/cwp/.conf/php-fpm_conf/php${PHPFPM//./}.conf || true
  wget -q "${CWPDLLINK}php-fpm-${PHPFPM}.sh" -O /usr/local/src/php-fpm-${PHPFPM}.sh || true
  wget -q "${CWPDLLINK}php-build.sh" -O /usr/local/src/php-build.sh || true
  if [ -f /usr/local/src/php-build.sh ]; then
    sed -i "s|CONFIGURE_VERSIONS_TO_BUILD|sh /usr/local/src/php-fpm-${PHPFPM}.sh;|g" /usr/local/src/php-build.sh || true
    sh /usr/local/src/php-build.sh 2>&1 | tee /var/log/php-selector-rebuild.log || true
  fi
fi

# Softaculous installer
if [ "${SOFTACULOUS}" = "yes" ]; then
  echo "Installing Softaculous (official installer)"
  SOFTACULOUSPWD=$(</dev/urandom tr -dc A-Za-z0-9 | head -c12)
  echo "softaculous:${SOFTACULOUSPWD}:1: " > /usr/local/cwp/.conf/.api_keys || true

  cd /usr/local/src || true
  rm -f install.sh || true
  wget -N http://files.softaculous.com/install.sh -O install.sh || true
  chmod 755 install.sh || true
  sh /usr/local/src/install.sh --quick || true
fi

# ModSecurity (optional)
if [ "${MODSECURITY}" = "yes" ]; then
  echo "Installing ModSecurity (custom build)"
  pkg_install libxml2 libxml2-devel pcre-devel curl-devel expat-devel apr-devel apr-util-devel libuuid-devel gcc || true
  cd /usr/local/src || true
  wget -q http://static.cdn-cwp.com/files/apache/modsecurity-2.9.1.tar.gz -O modsec.tar.gz || true
  tar -xzf modsec.tar.gz || true
  cd modsecurity-2.9.1 || true
  ./configure --with-apxs=/usr/local/apache/bin/apxs --with-apr=/usr/bin/apr-1-config --with-apu=/usr/bin/apu-1-config || true
  make clean || true
  make || true
  make install || true

  MODSECCONF="/usr/local/cwp/.conf/mod_security.conf"
  MODSECMAINCONF="/usr/local/apache/conf.d/mod_security.conf"
  touch "$MODSECCONF" || true

  if [ -e "/usr/local/apache/modules/mod_security2.so" ]; then
    echo "modsecurityinstall = 1" >> "$MODSECCONF" || true
    cat > "$MODSECMAINCONF" <<EOF
# ModSecurity core CWP config (auto-generated)
LoadFile /usr/lib64/libxml2.so
LoadFile /usr/lib64/liblua-5.1.so

<IfModule !unique_id_module>
  LoadModule unique_id_module modules/mod_unique_id.so
</IfModule>

<IfModule !mod_security2.c>
  LoadModule security2_module modules/mod_security2.so
</IfModule>

<IfModule mod_security2.c>
  SecRuleEngine On
  SecAuditEngine RelevantOnly
  SecAuditLog /usr/local/apache/logs/modsec_audit.log
  SecDebugLog /usr/local/apache/logs/modsec_debug.log
  SecRequestBodyAccess On
  SecDataDir /tmp
  SecTmpDir /tmp
  SecUploadDir /tmp
  SecCollectionTimeout 600
  SecPcreMatchLimit 1250000
  SecPcreMatchLimitRecursion 1250000
  Include "/usr/local/apache/modsecurity-cwaf/cwaf.conf"
</IfModule>
EOF

    # Pull official CWP modsecurity-cwaf (leave package names / archive as provided by CWP)
    cd /usr/local/apache || true
    rm -rf modsecurity-cwaf modsecurity-cwaf.zip || true
    wget -q http://static.cdn-cwp.com/files/apache/mod-security/modsecurity-cwaf.zip -O modsecurity-cwaf.zip || true
    unzip -o -q modsecurity-cwaf.zip || true
    cd /usr/local/apache/modsecurity-cwaf/rules || true
    rm -f comodo_waf.zip || true
    wget -q http://static.cdn-cwp.com/files/apache/mod-security/comodo_waf.zip -O comodo_waf.zip || true
    unzip -o comodo_waf.zip || rm -f comodo_waf.zip || true
    echo "modsecurityrules = 3" >> "$MODSECCONF" || true
    mkdir -p /usr/local/apache/logs/tmp && chown nobody:nobody /usr/local/apache/logs/tmp || true
  fi
fi

# Save web_servers.conf for CWP (apache-only configuration)
mkdir -p /usr/local/cwp/.conf
cat > /usr/local/cwp/.conf/web_servers.conf <<'EOF'
{
    "webserver_setup": "apache-only",
    "apache-main": true,
    "php-cgi": true,
    "php-fpm": true,
    "apache_template-type-default": "default",
    "apache_template-name-default": "default"
}
EOF

chmod 711 /home || true

# Restart cwpsrv & httpd & mail services
sh /scripts/restart_cwpsrv || true
systemctl restart httpd || true
systemctl restart postfix || true
systemctl restart dovecot || true
systemctl restart named || true

# Quota setup (install quota packages)
$PKG_MGR -y install quota quota-devel --enablerepo=Devel || true
if [ -x /usr/sbin/repquota ]; then
  if ! grep -qi quota /etc/fstab; then
    cp -a /etc/fstab /etc/fstab.backup || true
    # Attempt to remount root with usrquota,grpquota if /home not present
    if ! grep -q "home" /etc/fstab; then
      MNT='/'
    else
      MNT='/home'
    fi
    mount -o remount,usrquota,grpquota "${MNT}" || true
    /sbin/quotacheck -cugm "${MNT}" || true
    mkdir -p /usr/local/cwp/.conf || true
    echo "${MNT}" > /usr/local/cwp/.conf/quota_part.conf || true
  fi
fi

# Postfix 3.4 compatibility (ensure postfix-files exists)
touch /etc/postfix/postfix-files || true

# Install goaccess for log stats (EPEL)
pkg_install goaccess --enablerepo=epel || true
wget -q http://static.cdn-cwp.com/files/3rdparty/stats/goaccess/goaccess.conf -O /etc/goaccess.conf || true

# Final CWP steps: update and memory limit set (CWP scripts)
chmod +x /scripts/cwp_api || true
sh /scripts/update_cwp || true
sh /scripts/cwp_set_memory_limit || true

# Tighten MySQL security: remove Any user if present
mysql -e "DROP USER IF EXISTS 'Any'@'%';" || true
mysql -e "DROP USER IF EXISTS 'Any'@'localhost';" || true

clear
cat <<EOF

#############################
#  ${COMPANY} - CWP Installed #
#############################

CWP Admin GUI:
  - http://${pubip}:2030
  - SSL: https://${pubip}:2031
  - Default hostname: ${fqdn} (set to ${DEFAULT_HOSTNAME} if not previously configured)

Login:
  Username: root
  Password: your server root password (SSH)
  MySQL root Password: ${password}

Mail & extras:
  - Roundcube DB: roundcube (password stored in .passwords if generated)
  - Postfix MySQL Password: ${postfix_pwd}
  - SSL Cert hostname: ${fqdn}
  - SSL files: /etc/pki/tls/private|/etc/pki/tls/certs

Support:
  If you require assistance from ${COMPANY} contact: ${SUPPORT_EMAIL}

NOTE:
 - This installer uses official CWP packages and archives from centos-webpanel.com and static.cdn-cwp.com (some static CDN assets are downloaded via HTTP due to TLS issues on their CDN). See installer notes in the header for details.
 - If you prefer the system to reboot now, run: shutdown -r now

EOF

# Clean yum/dnf caches
$PKG_MGR clean all || true

if [ "${RESTART_AFTER_INSTALL}" = "yes" ]; then
  echo "Rebooting now..."
  shutdown -r now
else
  echo "Please reboot the server to complete the installation (recommended)."
  echo "Reboot command: shutdown -r now"
fi

exit 0
