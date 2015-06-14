#!/bin/bash
#  Fetch3d
# By : Lucifer-HR

#tput colors if you want add something ..
txtund=$(tput sgr 0 1) # Underline
txtbld=$(tput bold) # Bold
txtred=$(tput setaf 1) # Red
txtgrn=$(tput setaf 2) # Green
txtylw=$(tput setaf 3) # Yellow
txtblu=$(tput setaf 4) # Blue
txtpur=$(tput setaf 5) # Purple
txtcyn=$(tput setaf 6) # Cyan
txtwht=$(tput setaf 7) # White
txtrst=$(tput sgr0) # Text reset

echo ""
echo 'Running The Detect1ve...' | grep --color 'Running The Detect1ve' 

echo '/etc/samba/smb.conf....' | grep --color '/etc/samba/smb.conf' 
cat /etc/samba/smb.conf

echo 'OS Information' | grep --color 'OS Information' 
uname -a
echo ""

if [ -f /etc/issue ]
then
	echo "/etc/issue : `cat /etc/issue`"
fi
echo 'OS Distro Information' | grep --color 'OS Distro Information' 
cat /etc/*-release
echo ""
echo 'Kernel Information' | grep --color 'Kernel Information' 
echo $(tput setaf 7)

cat /proc/version 
uname -mrs
	
which rpm
OUT=$?
if [ $OUT -eq 0 ];then
   rpm -q kernel
fi
echo ""
echo 'dmesg Kernel Information :' | grep --color 'dmesg Kernel Information :' 
dmesg | grep Linux
ls /boot | grep vmlinuz-

echo ""
echo 'Environment Variables...' | grep --color 'Environment Variables' 
if [ -f /etc/profile ]
then
echo $(tput setaf 1)
	echo "Profiles: " 
echo $(tput setaf 7)
	echo ""
	cat /etc/profile
	echo ""
fi

if [ -f /etc/bashrc ]
then
echo 'bashrc...' | grep --color 'bashrc' 
	echo ""
	cat /etc/bashrc
	echo ""
fi

if [ -f ~/.bash_profile ]
then
echo 'bash profile...' | grep --color 'bash profile' 
	echo ""
	cat ~/.bash_profile
	echo ""
fi

if [ -f ~/.bash_logout ]
then
echo 'bash logout...' | grep --color 'bash logout' 
	echo ""
	cat ~/.bash_logout
	echo ""
fi

echo 'bash logout...' | grep --color 'bash logout' 
cat ~/.bash_logout
echo ""

echo 'env...' | grep --color 'env' 
env
echo ""

echo 'set...' | grep --color 'set' 
set
echo ""

echo "" >>got_repo

echo 'Services...' | grep --color 'Services' 
echo "" >> got_repo
echo "" >> got_repo 
ps -aux >> got_repo
echo "" >> got_repo
echo 'Running Processes Fetch3d....' | grep --color 'Running Processes Fetch3d' 



echo "" >> binaries
echo 'User Binaries...' | grep --color 'User Binaries' 
echo "" >> binaries
echo "" >> binaries
ls -alh /usr/bin/ >> binaries
echo "" >> binaries
echo 'User Binaries Fetch3d....' | grep --color 'User Binaries Fetch3d' 




echo "" >> binaries
echo 'System Binaries...' | grep --color 'System Binaries' 
echo "" >> binaries
echo "" >> binaries
ls -alh /sbin/ >> binaries
echo "" >> binaries
echo 'System Binaries Fetch3d....' | grep --color 'System Binaries Fetch3d' 



echo "" >> installed_apps
echo 'Installed Applications...' | grep --color 'Installed Applications' 
echo "" >> installed_apps
echo "" >> installed_apps
which dpkg
OUT=$?
if [ $OUT -eq 0 ];then
   dpkg -l >> installed_apps
fi

echo "" >> installed_apps

which rpm
OUT=$?
if [ $OUT -eq 0 ];then
   rpm -qa >> installed_apps 
fi

echo "" >> installed_apps

echo ""
echo 'MYSql Version...' | grep --color 'MYSql Version' 
which mysql
OUT=$?
if [ $OUT -eq 0 ];then
   mysql -V
fi
echo ""

echo 'apache2 Version...' | grep --color 'apache2 Version' 
which apache2
OUT=$?
if [ $OUT -eq 0 ];then
   apache2 -v
fi
echo "'"

echo 'Config Dump Fetch3d...' | grep --color 'Config Dump Fetch3d' 
if [ -f /etc/syslog.conf ]
then
	echo "" >> config_dump
	echo "/etc/syslog.conf   : " >> config_dump
	echo "" >> config_dump 
	echo ""  >> config_dump
	cat /etc/syslog.conf >> config_dump
	echo "" >> config_dump
	echo 'System Binaries Fetch3d....' | grep --color 'System Binaries Fetch3d' 
fi

if [ -f /etc/chttp.conf ]
then
	echo "" >> config_dump
	echo "/etc/chttp.conf   : " >> config_dump 
	echo ""   >> config_dump    
	echo "" >> config_dump
	cat /etc/chttp.conf >> config_dump >> config_dump
	echo "" >> config_dump
	echo 'chttp.conf Fetch3d...' | grep --color 'chttp.conf Fetch3d' 

fi

if [ -f /etc/lighttpd.conf ]
then
	echo "" >> config_dump
	echo "/etc/lighttpd.conf   : "  >> config_dump
	echo ""  >> config_dump     
	echo "" >> config_dump
	cat /etc/lighttpd.conf >> config_dump
	echo "" >> config_dump
	echo 'lighttpd.conf  Fetch3d....' | grep --color 'lighttpd.conf  Fetch3d' 
fi

if [ -f /etc/cups/cupsd.conf ]
then
	echo "" >> config_dump
echo '/etc/cups/cupsd.conf...' | grep --color '/etc/cups/cupsd.conf' 
	echo ""  >> config_dump
	echo ""  >> config_fetch     
	echo "" >> config_fetch
	cat /etc/cups/cupsd.conf >> config_dump
	echo "" >> config_fetch
	echo "cupsd.conf Fetch3d...."
fi

if [ -f /etc/inetd.conf ]
then
	echo "" >> config_dump
	echo "/etc/inetd.conf   : "  >> config_dump
	echo ""   >> config_dump    
	echo "" >> config_dump
	cat /etc/inetd.conf >> config_dump
	echo "" >> config_dump
	echo "inetd.conf Fetch3d...."
	
fi

if [ -f /etc/apache2/apache2.conf ]
then
	echo "" >> config_dump
echo '/etc/apache2/apache2.conf..' | grep --color '/etc/apache2/apache2.conf' 
	echo ""  >> config_dump
	echo ""  >> config_dump     
	echo "" >> config_dump
	cat /etc/apache2/apache2.conf >> config_dump
	echo "" >> config_dump
	echo "apache2.conf Fetch3d...."
fi

if [ -f /etc/my.conf ]
then
	echo "" >> config_dump
	echo "/etc/my.conf   : "  >> config_dump
	echo ""     >> config_dump  
	echo "" >> config_dump
	cat /etc/my.conf >> config_dump 
	echo "" >> config_dump
fi

if [ -f /etc/httpd/conf/httpd.conf ]
then
	echo "" >> config_dump
echo '/etc/httpd/conf/httpd.conf :' | grep --color '/etc/httpd/conf/httpd.conf' 
	echo ""  >> config_dump
	echo ""  >> config_dump     
	echo "" >> config_dump
	cat /etc/httpd/conf/httpd.conf >> config_dump
	echo "" >> config_dump
	echo "httpd.conf Fetch3d...."
fi

if [ -f /opt/lampp/etc/httpd.conf ]
then
	echo "" >> config_dump
echo '/opt/lampp/etc/httpd.conf  :' | grep --color '/opt/lampp/etc/httpd.conf' 
	echo ""  >> config_dump
	echo ""  >> config_dump     
	echo "" >> config_dump
	cat /opt/lampp/etc/httpd.conf >> config_dump
	echo "" >> config_dump
	echo "lampp httpd.conf Fetch3d...."
fi

echo 'Cron Jobs ': | grep --color 'Cron Jobs' 
crontab -l
echo ""

echo 'Confidential...' | grep --color 'Confidential' 
id
who
last

if [ -f /etc/passwd ]
then
	echo "" >> sensitive
echo '/etc/passwd....' | grep --color '/etc/passwd' 
	echo ""   >> sensitive
	echo ""  >> sensitive
	cat /etc/passwd >> sensitive
	echo "" >> sensitive
	
fi

if [ -f /etc/group ]
then
	echo "" >> sensitive
echo 'cat /etc/group....' | grep --color 'cat /etc/group' 
	echo ""   >> sensitive
	echo ""  >> sensitive
	cat /etc/group >> sensitive
	echo "" >> sensitive
	echo "group file Fetch3d...."	
fi

if [ -f /etc/shadow ]
then
	echo "" >> sensitive
echo '/etc/shadow :' | grep --color '/etc/shadow' 
	echo ""  >> sensitive
	echo ""  >> sensitive
	cat /etc/shadow >> sensitive
	echo "" >> sensitive
	echo "shadow file Fetch3d...."	
fi


if [ -f /var/apache2/config.inc ]
then
	echo "" >> sensitive
echo '/var/apache2/config.inc :' | grep --color '/var/apache2/config.inc' 
	echo ""  >> sensitive 
	echo ""  >> sensitive
	cat  /var/apache2/config.inc >> sensitive
	echo "" >> sensitive
	echo "config.inc file Fetch3d...."	
fi


if [ -f /var/lib/mysql/mysql/user.MYD ]
then
	echo "" >> sensitive
echo '/var/lib/mysql/mysql/user.MYD :' | grep --color '/var/lib/mysql/mysql/user.MYD' 
	echo " "  >> sensitive 
	echo ""  >> sensitive
	cat  /var/lib/mysql/mysql/user.MYD >> sensitive
	echo "" >> sensitive
	echo "MYD file Fetch3d...."	
fi

if [ -f /root/anaconda-ks.cfg ]
then
	echo "" >> sensitive
	echo "/root/anaconda-ks.cfg : "   >> sensitive
	echo ""  >> sensitive
	cat  /root/anaconda-ks.cfg >> sensitive
	echo "" >> sensitive
	echo "anaconda-ks.cfg file Fetch3d...."	
fi

if [ -f /etc/sudoers ]
then
echo '/etc/sudoers : ' | grep --color '/etc/sudoers' 
	echo "" >> sensitive
	echo ""   >> sensitive
	echo ""  >> sensitive
	cat /etc/sudoers >> sensitive
	sudo -l
	echo "" >> sensitive
	echo "sudoers file Fetch3d...."	
fi



if [ -f ~/.ssh/authorized_keys ]
then
	echo "" >> sshinfo
	echo "~/.ssh/authorized_keys : "    >> sshinfo
	echo ""   >> sshinfo
	cat ~/.ssh/authorized_keys  >> sshinfo
	echo ""  >> sshinfo
	echo "authorized_keys file Fetch3d...."	
fi

if [ -f ~/.ssh/identity.pub ]
then
	echo "" >> sshinfo
	echo "~/.ssh/identity.pub : "    >> sshinfo
	echo ""   >> sshinfo
	cat ~/.ssh/identity.pub  >> sshinfo
	echo ""  >> sshinfo
	echo "identity.pub file Fetch3d...."	
fi

if [ -f ~/.ssh/identity ]
then
	echo "" >> sshinfo
	echo "~/.ssh/identity : "    >> sshinfo
	echo ""   >> sshinfo
	cat ~/.ssh/identity  >> sshinfo
	echo ""  >> sshinfo
	echo "identity file Fetch3d...."	
fi


if [ -f ~/.ssh/id_rsa.pub ]
then
	echo "" >> sshinfo
	echo "~/.ssh/id_rsa.pub : "    >> sshinfo
	echo ""   >> sshinfo
	cat ~/.ssh/id_rsa.pub  >> sshinfo
	echo ""  >> sshinfo
	echo "id_rsa.pub file Fetch3d...."	
fi

if [ -f ~/.ssh/id_rsa ]
then
	echo "" >> sshinfo
	echo "~/.ssh/id_rsa : "    >> sshinfo
	echo ""   >> sshinfo
	cat ~/.ssh/id_rsa  >> sshinfo
	echo ""  >> sshinfo
	echo "id_rsa file Fetch3d...."	
fi


if [ -f ~/.ssh/id_dsa.pub ]
then
	echo "" >> sshinfo
	echo "~/.ssh/id_dsa.pub : "    >> sshinfo
	echo ""   >> sshinfo
	cat ~/.ssh/id_dsa.pub >> sshinfo
	echo ""  >> sshinfo
	echo "id_dsa.pub file Fetch3d...."	
fi


if [ -f ~/.ssh/id_dsa ]
then
	echo "" >> sshinfo
	echo "~/.ssh/id_dsa : "    >> sshinfo
	echo ""   >> sshinfo
	cat ~/.ssh/id_dsa >> sshinfo
	echo ""  >> sshinfo
	echo "id_dsa.pub file Fetch3d...."	
fi



if [ -f /etc/ssh/ssh_config ]
then
	echo "" >> sshinfo
	echo "/etc/ssh/ssh_config : "    >> sshinfo
	echo ""   >> sshinfo
	cat /etc/ssh/ssh_config >> sshinfo
	echo ""  >> sshinfo
	echo "ssh_config file Fetch3d...."	
fi

if [ -f /etc/ssh/ssh_config ]
then
	echo "" >> sshinfo
	echo "/etc/ssh/sshd_config : "    >> sshinfo
	echo ""   >> sshinfo
	cat /etc/ssh/sshd_config >> sshinfo
	echo ""  >> sshinfo
	echo "sshd_config file Fetch3d...."	
fi


echo ""  >> writable_configs
echo 'Writable Configuration Files : ' | grep --color 'Writable Configuration Files' 
echo ""  >> writable_configs
echo ""  >> writable_configs

echo "">> writable_configs
echo "Writable by ALL">> writable_configs
echo "">> writable_configs
echo `ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null` >> writable_configs
echo "">> writable_configs

echo "">> writable_configs
echo "Writable by Owner">> writable_configs
echo "">> writable_configs
echo `ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null`  >> writable_configs
echo "">> writable_configs


echo "">> writable_configs
echo 'Writable by Group :' | grep --color 'Writable by Group' 
echo "">> writable_configs
echo "">> writable_configs
echo `ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null`  >> writable_configs
echo "">> writable_configs


echo "" >> writable_configs
echo "Writable by Other" >> writable_configs
echo "" >> writable_configs
echo `ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null`   >> writable_configs
echo "">> writable_configs


echo "" >> writable_configs
echo "Readable by ALL" >> writable_configs
echo "" >> writable_configs
find /etc/ -readable -type f 2>/dev/null   >> writable_configs
echo "">> writable_configs
  
echo "" >> writable_configs
echo "World Writable Folders:" >> writable_configs
echo "" >> writable_configs
find / -writable -type d 2>/dev/null   >> writable_configs
echo "">> writable_configs

echo "" >> writable_configs
echo "World Executabke Folders:" >> writable_configs
echo "" >> writable_configs
find / -perm -o+x -type d 2>/dev/null   >> writable_configs
echo "">> writable_configs



echo 'File System' | grep --color 'File System' 
mount 
echo ""
df -h
echo ""

echo '/etc/fstab' | grep --color '/etc/fstab' 
cat /etc/fstab 
echo ""

echo "" >> exploits
echo 'Sticky bits' | grep --color 'Sticky bits' 
echo "">> exploits
echo "">> exploits
find / -perm -1000 -type d 2>/dev/null>> exploits
echo "">> exploits


echo "">> exploits
echo "SUID">> exploits
echo "">> exploits
find / -perm -u=s -type f 2>/dev/null>> exploits
echo ""

echo "">> exploits
echo "SGUID">> exploits
echo "">> exploits
find / -perm -g=s -type f 2>/dev/null>> exploits
echo "">> exploits

echo "">> exploits
echo 'which exploits can work?' | grep --color 'which exploits can work?' 
echo "">> exploits
echo "">> exploits

echo "">> exploits
echo 'Python...' | grep --color 'Python' 
echo "">> exploits
echo "">> exploits
python -V>> exploits
echo "">> exploits
echo "">> exploits
echo 'Perl...' | grep --color 'Perl' 
echo "">> exploits
echo "">> exploits
perl -v>> exploits
echo "">> exploits
echo "">> exploits

echo 'gcc...' | grep --color 'gcc' 
echo "">> exploits
echo "">> exploits
gcc -v>> exploits
echo "">> exploits
echo "">> exploits
echo 'cc...' | grep --color 'cc' 
echo "">> exploits
echo "">> exploits
cc -v>> exploits
echo "">> exploits


echo "">> network
echo 'Network Information...' | grep --color 'Network Information' 
echo "">> network
echo "">> network
/sbin/ifconfig -a >> network

echo "">> network
echo 'Network Interfaces:' | grep --color 'Network Interfaces:' 
echo "">> network
echo "">> network
cat /etc/network/interfaces >> network
echo "" >> network

echo "">> network
echo "/etc/sysconfig/network:	 ">> network
echo "">> network
cat /etc/sysconfig/network >>network
echo "" >> network

echo "">> network
echo "/etc/resolv.conf:	 ">> network
echo "">> network
cat /etc/resolv.conf>> network
echo "" >>network

echo "">> network
echo 'IPTABLES: ' | grep --color 'IPTABLES: ' 
echo "">> network
echo "">> network

iptables -L
echo "" >> network

echo "">> network
echo 'Hosts communicating with: ' | grep --color 'Hosts communicating with' 
echo "">> network
echo "">> network

lsof -i >> network
echo "" >> network

echo 'Netstat O/p:	 ' | grep --color 'Netstat O/p:	' 
echo " " >> network
echo "">> network

netstat -antup
echo ""

echo 'Route Information...' | grep --color 'Route Information' 
echo "">> network
route >> network
echo "">> network



