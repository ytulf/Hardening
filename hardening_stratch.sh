#!/bin/sh

#  hardening_stratch.sh
#
#
#  Created by SAVIO Thomas on 31/10/2018.
#

#------------------------
# Variables globales
#------------------------
active_interface=`ip addr show | awk '/inet.*brd/{print $NF; exit}'`

#•••••••••••••••••••••••••••••
# Création des fonctions
#•••••••••••••••••••••••••••••
update_system() {
yum clean all 2>&1 /dev/null
yum check-update 2>&1 /dev/null
yum update -y 2>&1 /dev/null
}

kernel_hardeninig() {
### Configuration du Kernel
cat << EOF
# Pas de routage entre les interfaces
net.ipv4.ip_forward = 0

# Filtrage par chemin inverse
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ne pas envoyer de redirections ICMP
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Refuser les paquets de source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ne pas accepter les ICMP de type redirect
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Loguer les paquets ayant des IPs anormales
net.ipv4.conf.all.log_martians = 1

# RFC 1337
net.ipv4.tcp_rfc1337 = 1

# Ignorer les réponses non conformes à la RFC 1122
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Augmenter la plage pour les ports éphémères
net.ipv4.ip_local_port_range = 32768 65535

# Utiliser les SYN cookies
net.ipv4.tcp_syncookies = 1

# Désactiver le support des " router solicitations "
net.ipv6.conf.all.router_solicitations = 0
net.ipv6.conf.default.router_solicitations = 0

# Ne pas accepter les " router preferences " par " router advertisements "
net.ipv6.conf.all.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0

# Pas de configuration auto des prefix par " router advertisements "
net.ipv6.conf.all.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_pinfo = 0

# Pas d’ apprentissage du routeur par dé faut par " router advertisements "
net.ipv6.conf.all.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_defrtr = 0

# Pas de configuration auto des adresses à partir des " router advertisements "
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0

# Ne pas accepter les ICMP de type redirect
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Refuser les packets de source routing
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Nombre maximal d’ adresses autoconfigur ées par interface
net.ipv6.conf.all.max_addresses = 1
net.ipv6.conf.default.max_addresses = 1

# Désactivation des SysReq
kernel.sysrq = 0

# Pas de core dump des exé cutables setuid
fs.suid_dumpable = 0

# Interdiction de déréfé rencer des liens vers des fichiers dont
# l’utilisateur courant n’est pas le propriétaire
# Peut empêcher certains programmes de fonctionner correctement
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# Activation de l’ASLR
kernel.randomize_va_space = 2

# Interdiction de mapper de la mémoire dans les adresses basses (0)
vm.mmap_min_addr = 65536

# Espace de choix plus grand pour les valeurs de PID
kernel.pid_max = 65536

# Obfuscation des adresses mémoire kernel
kernel.kptr_restrict = 1

# Restriction d’accès au buffer dmesg
kernel.dmesg_restrict = 1

# Restreint l’ utilisation du sous système perf
kernel.perf_event_paranoid = 2
kernel.perf_event_max_sample_rate = 1
kernel.perf_cpu_time_max_percent = 1

# Interdiction de chargement des modules ( sauf ceux déjà chargés à ce point )
kernel.modules_disabled = 1

# Configurer le module de sécurité Yama
kernel.yama.ptrace_scope = 1
EOF
>> /etc/sysctl.conf
}

#### Installation NTP pour être horodaté
ntp() {
packageList="ntp ntpdate"
for packageName in $packageList; do
rpm --quiet --query $packageName || yum install -y $packageName
done
chkconfig ntpd on ; ntpdate pool.ntp.org ; systemctl start ntpd
}
#### Désactivation de prelink
prelink() {
if [[ rpm -qa | grep prelink ]]
then
if grep -q ^PRELINKING /etc/sysconfig/prelink
then
sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink
else
echo -e "\n# Set PRELINKING=no per security requirements" >> /etc/sysconfig/prelink
echo "PRELINKING=no" >> /etc/sysconfig/prelink
fi
else
echo "\nPrelink not installed.\n"
fi
}
#### Installation de AIDE (Advanced Intrusion Detection Environment)
aide() {
rpm --quiet --query aide || yum -y install aide 2>&1 /dev/null && /usr/sbin/aide --init && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz && /usr/sbin/aide --check
echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
}
prevent_usb() {
#### Prevent Users Mounting USB Storage
echo "install usb-storage /bin/false" > /etc/modprobe.d/usb-storage.conf
}
password_policy() {
#### Enable Secure (high quality) Password Policy
authconfig --passalgo=sha512 —update
cat << EOF >/etc/security/pwquality.conf
# Configuration for systemwide password quality limits
# Defaults:
#
# Number of characters in the new password that must not be present in the
# old password.
difok = 5
#
# Minimum acceptable size for the new password (plus one if
# credits are not disabled which is the default). (See pam_cracklib manual.)
# Cannot be set to lower value than 6.
minlen = 14
#
# The maximum credit for having digits in the new password. If less than 0
# it is the minimum number of digits in the new password.
dcredit = 1
#
# The maximum credit for having uppercase characters in the new password.
# If less than 0 it is the minimum number of uppercase characters in the new
# password.
ucredit = 1
#
# The maximum credit for having lowercase characters in the new password.
# If less than 0 it is the minimum number of lowercase characters in the new
# password.
lcredit = 1
#
# The maximum credit for having other characters in the new password.
# If less than 0 it is the minimum number of other characters in the new
# password.
ocredit = 1
#
# The minimum number of required classes of characters for the new
# password (digits, uppercase, lowercase, others).
minclass = 4
#
# The maximum number of allowed consecutive same characters in the new password.
# The check is disabled if the value is 0.
maxrepeat = 3
#
# The maximum number of allowed consecutive characters of the same class in the
# new password.
# The check is disabled if the value is 0.
maxclassrepeat = 3
#
# Whether to check for the words from the passwd entry GECOS string of the user.
# The check is enabled if the value is not 0.
gecoscheck = 1
#
# Path to the cracklib dictionaries. Default is to use the cracklib default.
# dictpath =
EOF
}

#### PAM && login.defs
pam_logindefs() {
# Secure /etc/login.defs Pasword Policy
sed -i 's/^PASS_MAX_DAYS.*99999/PASS_MAX_DAYS 30/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*0/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs

# Set Last Logon/Access Notification
sed -i '/session     required      pam_limits.so/ a session     required      pam_lastlog.so      showfailed' /etc/pam.d/system-auth

# Set Deny For Failed Password Attempts
sed -i '/session     required      pam_unix.so/ a auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900\nauth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900' /etc/pam.d/system-auth
sed -i '/session     required      pam_unix.so/ a auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900\nauth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900' /etc/pam.d/password-auth

# Limit Password Reuse preventing users from reusing passwords, remembering 24 times is the DoD standard.
sed -i '/^password    sufficient    pam_unix.so*/ s/$/ remember=24/' /etc/pam.d/system-auth
}
#### Grub
grub_umask_prune() {
# Verify /boot/grub2/grub.cfg Permissions
chmod 600 /boot/grub2/grub.cfg

# Set Boot Loader Password (password = crtinformatique)
sed '/export superusers/ a password_pbkdf2 superusers-account grub.pbkdf2.sha512.10000.EB21F580ACEC3C4328424C0C90ADBE977A98752DD348F75068F8DD13061E6062749E7AC288DB98C9983FCB7BFF0F6B39A1BF603587B45589F32CF33D8B78A80A.0D14F67B09BF0D35A3FF17462785CA61BE15F65A75CCF1E5F07AB6D9C2BD710158931F8A3D9BF61200ABB34190EA18C74BB320120B5FA6AFC612C5AB3FBB7574' /etc/grub.d/01_users
grub2-mkconfig -o /boot/grub2/grub.cfg

# Require root password when entering single user mode
echo "SINGLE=/sbin/sulogin" >> /etc/systemctl/init

# Zeroconf network typically occours when you fail to get an address via DHCP, the interface will be assigned a 169.254.0.0 address.
echo "NOZEROCONF=yes" >> /etc/sysconfig/network

# Enable UMASK 077
sed 's/umask\s+0\d2/umask 077/g' -i /etc/csh.cshrc
sed 's/umask\s+0\d2/umask 077/g' -i /etc/bashrc

# Prune Idle Users
echo "Idle users will be removed after 15 minutes"
echo "readonly TMOUT=900" >> /etc/profile.d/os-security.sh
echo "readonly HISTFILE" >> /etc/profile.d/os-security.sh
chmod +x /etc/profile.d/os-security.sh
}
# Securing Cron
cron() {
echo "Locking down Cron"
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
echo "Locking down AT"
touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

# Deny All TCP Wrappers : TCP wrappers can provide a quick and easy method for controlling access to applications linked to them. Examples of TCP Wrapper aware applications are sshd, and portmap.
echo "ALL:ALL" >> /etc/hosts.deny
echo "sshd:ALL" >> /etc/hosts.allow
}

# Disable Uncommon Protocols
uncommon_protocols() {
echo "install dccp /bin/false" > /etc/modprobe.d/dccp.conf
echo "install sctp /bin/false" > /etc/modprobe.d/sctp.conf
echo "install rds /bin/false" > /etc/modprobe.d/rds.conf
echo "install tipc /bin/false" > /etc/modprobe.d/tipc.conf
}
# Install rsyslog and audit & enable
rsyslog() {
rpm --quiet --query rsyslog || yum -y install rsyslog 2>&1 /dev/null
systemctl enable rsyslog.service
systemctl start rsyslog.service
systemctl enable auditd.service
systemctl start auditd.service
echo "kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet audit=1" >> /etc/grub.conf
# active l'envoie des fichiers vers un serveur syslog
sed -i 's/^active = no/active = yes/' /etc/audisp/plugins.d/syslog.conf
sed -i 's/^$RepeatedMsgReduction off/$RepeatedMsgReduction on/' /etc/rsyslog.confg
#sed -i 's/^/' /etc/rsyslog.conf
mkdir /var/log/security
grep -rli '/var/log/messages' /etc/ | xargs sed -i 's/var/log/auth.log /var/log/security/messages.g'
systemctl restart rsyslog
}
audit() {
cat << EOF > /etc/audit/audit.rules
# audit_time_rules - Record attempts to alter time through adjtime
-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules

# audit_time_rules - Record attempts to alter time through settimeofday
-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules

# audit_time_rules - Record Attempts to Alter Time Through stime
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime
-k audit_time_rules

# audit_time_rules - Record Attempts to Alter Time Through clock_settime
-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules

# Record Attempts to Alter the localtime File
-w /etc/localtime -p wa -k audit_time_rules

# Record Events that Modify User/Group Information
# audit_account_changes
-w /etc/group -p wa -k audit_account_changes
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes

# Record Events that Modify the System's Network Environment
# audit_network_modifications
-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications

#Record Events that Modify the System's Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy

#Record Events that Modify the System's Discretionary Access Controls - chmod
-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - chown
-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchmod
-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchmodat
-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchown
-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchownat
-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fremovexattr
-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - lchown
-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - lremovexattr
-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - lsetxattr
-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - removexattr
-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchown
-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchownat
-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fremovexattr
-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - removexattr
-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - setxattr
-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Attempts to Alter Logon and Logout Events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

#Record Attempts to Alter Process and Session Initiation Information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

#Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful)
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

#Ensure auditd Collects Information on the Use of Privileged Commands
#
#  Find setuid / setgid programs then modify and uncomment the line below.
#
##  sudo find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null
#
# -a always,exit -F path=SETUID_PROG_PATH -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

#Ensure auditd Collects Information on Exporting to Media (successful)
-a always,exit -F arch=ARCH -S mount -F auid>=500 -F auid!=4294967295 -k export

#Ensure auditd Collects File Deletion Events by User
-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

#Ensure auditd Collects System Administrator Actions
-w /etc/sudoers -p wa -k actions

#Ensure auditd Collects Information on Kernel Module Loading and Unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

#Make the auditd Configuration Immutable
-e 2
EOF
}
###  Bulk Remove of Services
bulk_remove_service() {
yum remove -y xinetd telnet-server rsh-server telnet rsh-server rsh ypbind ypserv tftp-server cronie-anacron bind vsftpd httpd dovecot squid net-snmpd
systemctl disable xinetd
systemctl disable rexec
systemctl disable rsh
systemctl disable rlogin
systemctl disable ypbind
systemctl disable tftp
systemctl disable certmonger
systemctl disable cgconfig
systemctl disable cgred
systemctl disable cpuspeed
systemctl enable irqbalance
systemctl disable kdump
systemctl disable mdmonitor
systemctl disable messagebus
systemctl disable netconsole
systemctl disable ntpdate
systemctl disable oddjobd
systemctl disable portreserve
systemctl enable psacct
systemctl disable qpidd
systemctl disable quota_nld
systemctl disable rdisc
systemctl disable rhnsd
systemctl disable rhsmcertd
systemctl disable saslauthd
systemctl disable smartd
systemctl disable sysstat
systemctl enable crond
systemctl disable atd
systemctl disable nfslock
systemctl disable named
systemctl disable httpd
systemctl disable dovecot
systemctl disable squid
systemctl disable snmpd
}
# enable postfix
postfix_sendmail() {
systemctl enable postfix

# Remove Sendmail
yum remove sendmail -y

# Postfix Disable Network Listening
grep "inet_protocols = all" /etc/postfix/main.cf > /dev/null
if [ $? -eq 0 ]; then
sed -i 's/inet_protocols = all/inet_protocols = localhost/g' /etc/postfix/main.cf
systemctl restart postfix
fi
}
# System Audit Logs Must Be Owned By Root
audit_log() {
chown root /var/log
# Disable autofs
chkconfig --level 0123456 autofs off
service autofs stop
}
uncommon_filesystems() {
# Disable uncommon filesystems
echo "install cramfs /bin/false" > /etc/modprobe.d/cramfs.conf
echo "install freevxfs /bin/false" > /etc/modprobe.d/freevxfs.conf
echo "install jffs2 /bin/false" > /etc/modprobe.d/jffs2.conf
echo "install hfs /bin/false" > /etc/modprobe.d/hfs.conf
echo "install hfsplus /bin/false" > /etc/modprobe.d/hfsplus.conf
echo "install squashfs /bin/false" > /etc/modprobe.d/squashfs.conf
echo "install udf /bin/false" > /etc/modprobe.d/udf.conf
}
security_limits() {
# Disable core dumps for all users
sed '/#@student        -       maxlogins       4/ a *                hard    core            0' /etc/security/limits.conf

## Disable core dumps for SUID programs
sysctl -q -n -w fs.suid_dumpable=0
#
# If fs.suid_dumpable present in /etc/sysctl.conf, change value to "0"
#     else, add "fs.suid_dumpable = 0" to /etc/sysctl.conf
#
if grep --silent ^fs.suid_dumpable /etc/sysctl.conf ; then
sed -i 's/^fs.suid_dumpable.*/fs.suid_dumpable = 0/g' /etc/sysctl.conf
else
echo "" >> /etc/sysctl.conf
echo "# Set fs.suid_dumpable to 0 per security requirements" >> /etc/sysctl.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
fi

## Buffer Overflow Protection
# Enable ExecShield
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
# Check / Enable ASLR
sysctl -q -n -w kernel.randomize_va_space=2
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
# Modifier le swap. Le kernel swappera à partir de 80% d'utilisation de la RAM
echo "vm.swappiness=10" >>/etc/sysctl.conf
sysctl -p /etc/sysctl.conf

# Limiter les nproc par user pour éviter les fork bomb ou tout autre problème
sed -i '$d' /etc/security/limits.conf
echo "@users      soft      nproc      50
@users      hard      nproc      100
@linux-ad      soft      nproc      50
@linux-ad      hard      nproc      100
@linux-ad-stagiaire      soft      nproc      50
@linux-ad-stagiaire      hard      nproc      100
# End of file" >> /etc/security/limits.conf
## Peut être testé avec "stress"
}

### SSHD
sshd() {
echo "********************************************************************
*                                                                  *
* This system is for the use of authorized users only.  Usage of   *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************
********************************************************************
*                                                                  *
* Ce système est réservé aux utilisateurs autorisés. L'utilisation *
* de ce système est surveillée et enregistrée.                     *
*                                                                  *
* Quiconque utilise ce système consent expressément à une telle    *
* surveillance et est avisé que si une telle surveillance révèle   *
* des preuves possibles d'activités criminelles, le personnel du   *
* système peut fournir les preuves de cette surveillance aux       *
* autorités policières.                                            *
*                                                                  *
********************************************************************" > /etc/issue

echo "###########################################################################
Unauthorized access to this machine is prohibited
Press <Ctrl-D> if you are not an authorized user

L'accès non autorisé à cette machine est interdit.
Appuyez sur <Ctrl-D> si vous n'êtes pas un utilisateur autorisé.
###########################################################################
" > /etc/motd

cat << EOF > /etc/ssh/sshd_config
Protocol 2
ListenAddress $IP_ADDR:22222

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 2048
StrictModes yes
ClientAliveInterval 600
ClientAliveCountMax 0

Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication yes
PasswordAuthentication yes
MaxAuthTries 3

AllowTcpForwarding no
PermitUserEnvironment no
X11Forwarding no
PrintMotd no
PrintLastLog yes
Banner /etc/issue.net

PermitTunnel no

Subsystem sftp internal-sftp

UsePam yes
UseDNS yes

AllowGroups adminlocal
LogLevel INFO
SyslogFacility AUTH

LoginGraceTime 120
EOF
systemctl enable sshd
systemctl restart sshd
}
# OS Update
yum_boolean() {
rpm --quiet --query yum-cron || yum -y install yum-cron 2>&1 /dev/null
chkconfig yum-cron on

### booléan
setsebool -P allow_execheap=off
setsebool -P allow_execmem=off
setsebool -P allow_execstack=off
setsebool -P secure_mode_insmod=off
setsebool -P ssh_sysadm_login=off
}
vmware_tools(){
rpm --quiet --query open-vm-tools || yum -y install open-vm-tools 2>&1 /dev/null
}
honeypot_ssh(){
iptables -A INPUT -i $active_interface -p tcp --dport 22222 -j ACCEPT
iptables -A INPUT -i $active_interface -p tcp --dport 22 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
yum -y upgrade
rpm --quiet --query epel-release || yum install -y epel-release 2>&1 /dev/null
packageList="gcc libffi-devel python-devel openssl-devel git python-pip pycrypto"
for packageName in $packageList; do
  rpm --quiet --query $packageName || yum install -y $packageName 2>&1 /dev/null
done
pip install --upgrade pip
pip install configparser pyOpenSSL tftpy twisted==15.2.0 
useradd cowrie ; echo cowrie:U6aMy0wojraho | chpasswd -e
su - cowrie
git clone https://github.com/micheloosterhof/cowrie.git
cd cowrie
mv etc/cowrie.cfg.dist etc/cowrie.cfg
#cowrie ecoute sur le port 2222 de base. On a redirigé tout ce qui viens de 22 vers cowrie pour honeypot.

}

## Iptables
iptables_ferm() {
rpm --quiet --query ferm || yum -y install ferm 2>&1 /dev/null
cat << EOF > ~/ferm.conf
# ------------------------------------
# Regles iptables avec Ferm
# ------------------------------------

@def $WAN_IF = $active_interface;

# ---------------------

chain ( INPUT OUTPUT FORWARD ) policy DROP;

# ---------------------
# Local
# ---------------------

chain INPUT if lo ACCEPT;
chain OUTPUT of lo ACCEPT;

# ---------------------
# Pre-Limit
# ---------------------
# But: interdire le brut-force sur ssh

# Liste des IPs qui echappent a la pre-limit

@def $PRE_LIMIT_AUTHORIZED = (
82.67.215.202 # au hasard...
212.27.48.10
207.46.197.32/24
);

table filter chain PRE_LIMIT_DROP {
mod limit limit 5/s LOG log-prefix 'FW=pre_limit_drop ' log-level info;
DROP;
}

table filter chain PRE_LIMIT {
saddr $PRE_LIMIT_AUTHORIZED RETURN;
mod state state NEW mod recent set rsource name "pre_limit" NOP;
mod state state NEW mod recent update seconds 120 hitcount 4 rsource name "pre_limit" jump PRE_LIMIT_DROP;
}

# ---------------------
# WAN
# ---------------------

chain INPUT if $WAN_IF proto tcp dport ssh {
jump PRE_LIMIT;
ACCEPT;
}

# ---------------------
EOF

ferm ~/ferm.conf
}
iptables_normal() {
###############################################################################
# 1. COMMON HEADER                                                            #
#                                                                             #
# This section is a generic header that should be suitable for most hosts.    #
###############################################################################

*filter

# Base policy
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Don't attempt to firewall internal traffic on the loopback device.
-A INPUT -i lo -j ACCEPT

# Continue connections that are already established or related to an established 
# connection.
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Drop non-conforming packets, such as malformed headers, etc.
-A INPUT -m conntrack --ctstate INVALID -j DROP

# Block remote packets claiming to be from a loopback address.
-4 -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
-6 -A INPUT -s ::1/128 ! -i lo -j DROP

# Drop all packets that are going to broadcast, multicast or anycast address.
-4 -A INPUT -m addrtype --dst-type BROADCAST -j DROP
-4 -A INPUT -m addrtype --dst-type MULTICAST -j DROP
-4 -A INPUT -m addrtype --dst-type ANYCAST -j DROP
-4 -A INPUT -d 224.0.0.0/4 -j DROP

# Chain for preventing SSH brute-force attacks.
# Permits 10 new connections within 5 minutes from a single host then drops 
# incomming connections from that host. Beyond a burst of 100 connections we 
# log at up 1 attempt per second to prevent filling of logs.
-N SSHBRUTE
-A SSHBRUTE -m recent --name SSH --set
-A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 10 -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[SSH-brute]: "
-A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 10 -j DROP
-A SSHBRUTE -j ACCEPT

# Chain for preventing ping flooding - up to 6 pings per second from a single 
# source, again with log limiting. Also prevents us from ICMP REPLY flooding 
# some victim when replying to ICMP ECHO from a spoofed source.
-N ICMPFLOOD
-A ICMPFLOOD -m recent --set --name ICMP --rsource
-A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "iptables[ICMP-flood]: "
-A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -j DROP
-A ICMPFLOOD -j ACCEPT


###############################################################################
# 2. HOST SPECIFIC RULES                                                      #
#                                                                             #
# This section is a good place to enable your host-specific services.         #
###############################################################################

# Accept HTTP and HTTPS, If need
#-A INPUT -p tcp -m multiport --dports 80,443 --syn -m conntrack --ctstate NEW -j ACCEPT

# Accept FTP only for IPv4, If Need
#-4 -A INPUT -p tcp --dport 21 --syn -m conntrack --ctstate NEW -j ACCEPT

# Accept AD communciation
#-4 -A INPUT -p udp -m multiport -dports ldap --syn -m conntrack --ctstate NEW -j ACCEPT

###############################################################################
# 3. GENERAL RULES                                                            #
#                                                                             #
# This section contains general rules that should be suitable for most hosts. #
###############################################################################

# Accept worldwide access to SSH and use SSHBRUTE chain for preventing 
# brute-force attacks.
-A INPUT -p tcp --dport 22 --syn -m conntrack --ctstate NEW -j SSHBRUTE

# Permit useful IMCP packet types for IPv4
# Note: RFC 792 states that all hosts MUST respond to ICMP ECHO requests.
# Blocking these can make diagnosing of even simple faults much more tricky.
# Real security lies in locking down and hardening all services, not by hiding.
-4 -A INPUT -p icmp --icmp-type 0  -m conntrack --ctstate NEW -j ACCEPT
-4 -A INPUT -p icmp --icmp-type 3  -m conntrack --ctstate NEW -j ACCEPT
-4 -A INPUT -p icmp --icmp-type 11 -m conntrack --ctstate NEW -j ACCEPT

# Permit needed ICMP packet types for IPv6 per RFC 4890.
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 1   -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 2   -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 3   -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 4   -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 133 -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 134 -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 135 -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 136 -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 137 -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 141 -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 142 -j ACCEPT
-6 -A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type 130 -j ACCEPT
-6 -A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type 131 -j ACCEPT
-6 -A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type 132 -j ACCEPT
-6 -A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type 143 -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 148 -j ACCEPT
-6 -A INPUT              -p ipv6-icmp --icmpv6-type 149 -j ACCEPT
-6 -A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type 151 -j ACCEPT
-6 -A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type 152 -j ACCEPT
-6 -A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type 153 -j ACCEPT

# Permit IMCP echo requests (ping) and use ICMPFLOOD chain for preventing ping 
# flooding.
-4 -A INPUT -p icmp --icmp-type 8  -m conntrack --ctstate NEW -j ICMPFLOOD
-6 -A INPUT -p ipv6-icmp --icmpv6-type 128 -j ICMPFLOOD

# Do not log packets that are going to ports used by SMB
# (Samba / Windows Sharing).
-A INPUT -p udp -m multiport --dports 135,445 -j DROP
-A INPUT -p udp --dport 137:139 -j DROP
-A INPUT -p udp --sport 137 --dport 1024:65535 -j DROP
-A INPUT -p tcp -m multiport --dports 135,139,445 -j DROP

# Do not log packets that are going to port used by UPnP protocol.
-A INPUT -p udp --dport 1900 -j DROP

# Do not log late replies from nameservers.
-A INPUT -p udp --sport 53 -j DROP

# Good practise is to explicately reject AUTH traffic so that it fails fast.
-A INPUT -p tcp --dport 113 --syn -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset

# Prevent DOS by filling log files.
-A INPUT -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[DOS]: "

COMMIT
}
post_pre_yum() {
packageList="yum-plugin-pre-transaction-action yum-plugin-pre-transaction-action"
for packageName in $packageList; do
rpm --quiet --query $packageName || yum install -y $packageName
done
# premier * pour utilisateur, deuxieme * pour la fonction (update, install, whatprovides,...)
# Reste à compléter
cat << EOF > /etc/yum/pre-action/remoutrw.action
#!/bin/bash
*:*:/usr/bin/mount /boot -o remount,rw
*:*:/usr/bin/mount /usr -o remount,rw
*:*:/usr/bin/mount /tmp -o remount,suid,dev,exec,async
*:*:/usr/bin/mount /var/tmp -o remount,suid,dev,exec,async,bind
EOF

cat << EOF > /etc/yum/post-action/remoutro.action
#!/bin/bash
*:*:/usr/bin/mount /boot -o remount,ro
*:*:/usr/bin/mount /usr -o remount,ro
*:*:/usr/bin/mount /tmp -o remount,nosuid,nodev,noexec,async
*:*:/usr/bin/mount /var/tmp -o remount,nosuid,nodev,noexec,async,bind
EOF

}
knock() {
yum install -y knock*
> /etc/knockd.conf
/sbin/iptables -I INPUT -i $active_interface -p tcp --dport 22 -j ACCEPT
cat << EOF >> /etc/knockd.conf
[options]
logfile = /var/log/knockd.log
Interface = $active_interface
[openSSH]
sequence = 2222:tcp,3333:udp,4444:tcp
seq_timeout = 1
tcpflags = syn
Start_command = /sbin/iptables -I INPUT -i $active_interface -s %IP% -p tcp --dport 22 -j ACCEPT

[closeSSH]
sequence = 22222:tcp,33333:udp,44444:tcp
seq_timeout = 1
command = /sbin/iptables -D INPUT -i $active_interface -s %IP% -p tcp --dport 22 -j ACCEPT
tcpflags = syn
EOF
}
blackchain() {
wget -qO - http://infiltrated.net/blacklisted|awk '!/#|[a-z]/&&/./{print "iptables -A INPUT -s "$1" -j DROP"}' 
}
#--------------------------------------
# Appel des fonctions
#--------------------------------------
update_system
kernel_hardeninig
ntp
prelink
aide
prevent_usb
password_policy
pam_logindefs
grub_umask_prune
cron
uncommon_protocols
rsyslog
audit
bulk_remove_service
postfix_sendmail
audit_log
vmware_tools
# honeypot_ssh
uncommon_filesystems
security_limits
sshd
yum_boolean
# iptables_ferm
iptables_normal
knock
blackchain

# A regarder
# cgroups (ce qui est à la base de LXC et Docker)
