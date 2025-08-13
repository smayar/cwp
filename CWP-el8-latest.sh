#!/bin/bash
# ===================================================================
# Control Web Panel (CWP) Installer for AlmaLinux 8
# Full turnkey installer with PHP-FPM, Softaculous, ModSecurity, Roundcube
# Rebranded for Mayar Technologies, LLC
# Default hostname: cloud.mayartechnologies.com
# Emails: info@mayartechnologies.com, support@mayartechnologies.com
# ===================================================================

# --- VARIABLES ---
pubip=$(curl -s ifconfig.me)
mysql_root_password=$(< /dev/urandom tr -dc A-Za-z0-9 | head -c16)
mysql_roundcube_password=$(< /dev/urandom tr -dc A-Za-z0-9 | head -c12)
postfix_pwd=$(< /dev/urandom tr -dc A-Za-z0-9 | head -c12)
cnf_hostname="cloud.mayartechnologies.com"
phpfpm="7.4"
softaculous="yes"
modsecurity="yes"
restart="yes"

# --- PREP SYSTEM ---
dnf -y update
dnf -y install wget curl unzip tar vim net-tools bind-utils epel-release yum-utils gcc make perl libxml2 libxml2-devel pcre-devel curl-devel expat-devel apr-devel apr-util-devel libuuid-devel

# --- SET HOSTNAME ---
hostnamectl set-hostname $cnf_hostname

# --- INSTALL CWP ---
cd /usr/local/src
wget -N https://centos-webpanel.com/cwp-el8-latest
chmod +x cwp-el8-latest
bash cwp-el8-latest

# --- ROUND CUBE INSTALLATION ---
wget -P /usr/local/cwpsrv/var/services https://github.com/roundcube/roundcubemail/releases/download/1.6.1/roundcubemail-1.6.1-complete.tar.gz
tar -C /usr/local/cwpsrv/var/services -zxf /usr/local/cwpsrv/var/services/roundcubemail-*.tar.gz
rm -f /usr/local/cwpsrv/var/services/roundcubemail-*.tar.gz
mv /usr/local/cwpsrv/var/services/roundcubemail-* /usr/local/cwpsrv/var/services/roundcube
chown cwpsvc:cwpsvc -R /usr/local/cwpsrv/var/services/roundcube
chmod 777 -R /usr/local/cwpsrv/var/services/roundcube/temp/
chmod 777 -R /usr/local/cwpsrv/var/services/roundcube/logs/

# --- MYSQL CONFIG ---
sed -e "s|mypassword|${mysql_roundcube_password}|" <<'EOF' | mysql -u root -p"${mysql_root_password}"
USE mysql;
CREATE DATABASE IF NOT EXISTS roundcube;
GRANT ALL PRIVILEGES ON roundcube.* TO 'roundcube'@'localhost' IDENTIFIED BY 'mypassword';
FLUSH PRIVILEGES;
EOF
mysql -u root -p"${mysql_root_password}" 'roundcube' < /usr/local/cwpsrv/var/services/roundcube/SQL/mysql.initial.sql

# --- ROUND CUBE CONFIG ---
cp /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php.sample /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php
sed -i "s|^\(\$config\['default_host'\] =\).*$|\1 'localhost';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php
sed -i "s|^\(\$config\['smtp_server'\] =\).*$|\1 'localhost';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php
sed -i "s|^\(\$config\['smtp_user'\] =\).*$|\1 '%u';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php
sed -i "s|^\(\$config\['smtp_pass'\] =\).*$|\1 '%p';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php
sed -i "s|^\(\$config\['quota_zero_as_unlimited'\] =\).*$|\1 true;|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php
sed -i "s|MYSQL_PASSWORD|$postfix_pwd|g" /usr/local/cwpsrv/var/services/roundcube/plugins/password/config.inc.php
sed -i "s|^\(\$config\['db_dsnw'\] =\).*$|\1 'mysqli://roundcube:${mysql_roundcube_password}@localhost/roundcube';|" /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php
rm -rf /usr/local/cwpsrv/var/services/roundcube/installer
sh /usr/local/cwpsrv/htdocs/resources/scripts/mail_roundcube_update
chown -R cwpsvc:cwpsvc /usr/local/cwpsrv/var/services/roundcube

# --- MAIL SECURITY ---
chmod 640 /etc/postfix/mysql-*.cf
chmod 640 /etc/dovecot/dovecot-*.conf
chmod 640 /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php
chown root.mail /etc/postfix/mysql-*.cf
chown root.mail /etc/dovecot/dovecot-*.conf

# --- OPENDKIM ---
dnf -y install opendkim opendkim-tools perl-Mail-DKIM perl-Mail-SPF pypolicyd-spf
cat > /etc/opendkim.conf <<EOL
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
EOL

# --- LOGIN SCREEN ---
[[ $(grep "bash_cwp" /root/.bash_profile) == "" ]] && echo "sh /root/.bash_cwp" >>  /root/.bash_profile
cat > /root/.bash_cwp <<EOF
echo ""
echo "********************************************"
echo " Welcome to CWP Server - Mayar Technologies"
echo "********************************************"
echo ""
echo "CWP Wiki: http://wiki.centos-webpanel.com"
echo "CWP Forum: http://forum.centos-webpanel.com"
echo "CWP Support: http://centos-webpanel.com/support-services"
echo ""
EOF

# --- SYSTEM SERVICES ---
systemctl daemon-reload
systemctl enable httpd cwpsrv mariadb postfix dovecot
systemctl restart httpd cwpsrv mariadb postfix dovecot named

# --- PHP-FPM INSTALL (7.4) ---
dnf -y install php php-fpm php-mysqlnd php-gd php-mbstring php-xml php-opcache
systemctl enable php-fpm
systemctl restart php-fpm

# --- SOFTACULOUS INSTALL ---
if [ "$softaculous" = "yes" ]; then
    cd /usr/local/src
    wget -N http://files.softaculous.com/install.sh
    chmod +x install.sh
    sh install.sh --quick
fi

# --- MODSECURITY 2.9.4 INSTALL ---
if [ "$modsecurity" = "yes" ]; then
    cd /usr/local/src
    wget -N https://www.modsecurity.org/tarball/2.9.4/modsecurity-2.9.4.tar.gz
    tar -xzf modsecurity-2.9.4.tar.gz
    cd modsecurity-2.9.4
    ./configure --with-apxs=/usr/local/apache/bin/apxs --with-apr=/usr/bin/apr-1-config --with-apu=/usr/bin/apu-1-config
    make && make install
    systemctl restart httpd
fi

# --- FIREWALL ---
iptables -A INPUT ! -i lo -p tcp -m state --state NEW -m tcp --dport 2030 -j ACCEPT
iptables -A INPUT ! -i lo -p tcp -m state --state NEW -m tcp --dport 2031 -j ACCEPT
service iptables save

# --- CLEANUP AND FINAL OUTPUT ---
yum clean all
echo "#############################"
echo "#      CWP Installed        #"
echo "#############################"
echo "Admin GUI: http://$pubip:2030/"
echo "SSL: https://$pubip:2031/"
echo "Username: root"
echo "Password: SSH root password"
echo "MySQL root Password: $mysql_root_password"
echo "Hostname: $cnf_hostname"
echo "Visit www.centos-webpanel.com for help"

# --- REBOOT ---
if [ "$restart" = "yes" ]; then
    echo "Rebooting server..."
    shutdown -r now
else
    echo "Please reboot manually: shutdown -r now"
fi
