#!/bin/bash
#Enumerat1on script
#Created By: Lucifer-HR #original author 
#Greetz to team : joinse7en..
#Working with linux x86 all systems Enumeration tool 
# 

#some color here to make the magic ;) 
RED=$(tput setaf 1 && tput bold)
GREEN=$(tput setaf 2 && tput bold)
STAND=$(tput sgr0)
BLUE=$(tput setaf 6 && tput bold)
WHITE=$(tput setaf 7)
BLACK=$(tput setaf 0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
MAGENTA=$(tput setaf 9)
ORANGE=$(tput setaf 3)
PURPLE=$(tput setaf 1)

#
#
#Creat Banner... 
cat <<"EOT"

                                                                 
                         771488888889477                         
                    78888888888888888888888887                   
                     888888861788897288888888                    
                      67       8887       787                    
                               8887                              
          9887          77488888888888847           7887         
        7888887      288888888888888888888867      988888        
       988887     788888888817777 7771888888889     7888887      
      88888     788888847                78888888     188887     
     88884     8888887                      7888883    788882    
    88888847 788888                      7    388888  74888887   
   888888888888883  38888887          68888887  88888888888888   
  78888   7888887  8888888887        8888888886  8888867  38888  
  88887    88887  88888888888       18888888888   88887    88887 
 78888    88880   88888888888       78888888888    8888    78888 
 48883   78888     8888888887   77   4888888887    18888    8888 
         88884      7888887    8888    188887       8888         
         8888                   77                  8888         
         888817333337777777373777773337777773333323788887        
         888888888888888888888888888888888888888888888887        
         88888777888877774888277777738883777788807778888         
 08883   78888   8888     888        888     8887  78888    8888 
 18888    88884  8888    7888        888     8887  88887   18888 
  88887    88887 6888    7888        888     888  88883    88887 
  18888   788888 4888    78887       888     88874888807  28888  
   888888888888888888     888        888     88888888888888888   
    88888817 78888886     8887       888     8888888  38888887   
    788880     888888     888        888    7888881     88881    
      88888     78888881  888        888 78888888     788883     
       888881     788888888887      78888888888      888887      
        1888887      188888888888888888888887      688888        
          88887         73888888888888897           1887         
           33                  6888                              
                      77       7888       78                     
                     788888817788887188888888                    
                     888888888888888888888888                    
                          7773313233777                          

                                         
EOT
##
#
#Title tool :)
echo 'Enumerat1on' | grep --color 'Enumerat1on' 
echo '.....by Alexcerus-HR' | grep --color 'by Alexcerus-HR'
#Grep here used for coloring only ...
echo ""
#strips out username uid & gid values 
usrsinfo=`cat /etc/passwd | cut -d ":" -f 1,2,3,4 2>/dev/null`
if [ "$usrsinfo" ]; then
echo -e 'all users and uid & gid info...' | grep --color -i 'all users and uid & gid info'
  echo -e "\n$usrsinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi
#
#lists all id's and respective group(s)
grpinfo=`for i in $(cat /etc/passwd 2>/dev/null| cut -d":" -f1 2>/dev/null);do id $i;done 2>/dev/null`
if [ "$grpinfo" ]; then
echo -e 'Enum Group memberships...' | grep --color -i 'Enum Group memberships'
  echo -e "\n$grpinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

echo 'Screen session found :' $(screen -ls) | grep --color 'Screen session found'
echo ''
#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\n$hashesinpasswd" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#Possible Local Tools for use...
echo 'Possible Local Tools for use: ' | grep --color 'Possible Local Tools for use'
which gcc nc nmap ncat lynx curl wget php perl python ruby /etc/valiases | grep --color -i -E '/usr/bin|/etc/valiases|/bin'
echo ''

#locate custom user accounts with some 'known default' uids
readpasswd=`grep -v "^#" /etc/passwd | awk -F: '$3 == 0 || $3 == 500 || $3 == 501 || $3 == 502 || $3 == 1000 || $3 == 1001 || $3 == 1002 || $3 == 2000 || $3 == 2001 || $3 == 2002 { print }'`
if [ "$readpasswd" ]; then
#Sample entires from /etc/passwd 
echo -e 'Searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002' | grep --color -i 'Searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002'
  echo -e "\n$readpasswd" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi


#Grabbing Local Tools Version Info (Test 1)
echo 'Grabbing Local Tools Version Info (Test 1): ' | grep --color 'Grabbing Local Tools Version Info (Test 1)'
gcc --version | grep --color 'gcc'
mysql --version | grep --color -i -E 'mysql||Ver'
perl -v | grep --color -i -E 'This is perl|version|subversion|built for'
python --version | grep --color -i 'Python' 2> /dev/null
php --version | grep --color -i -E 'PHP||Zend Engine||Copyright' 2> /dev/null
java -version | grep --color 'java version' 2> /dev/null
echo ''
#
if [ "$export" ] && [ "$readpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
else 
  :
fi

#Users list test 2 :
echo 'User List: ' | grep --color 'User List'
cat /etc/passwd | cut -d: -f1 
echo ''

#Check file shadow..
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
echo -e 'Reading the shadow files...' | grep --color -i 'Reading the shadow files'
  echo -e "\n$readshadow" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#Host file ENum :
echo 'Hosts File Enumeration: ' | grep --color 'Hosts File Enumeration'
cat /etc/hosts
echo ''
#
if [ "$export" ] && [ "$readshadow" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/shadow $format/etc-export/shadow 2>/dev/null
else 
  :
fi

#Open port check ...
echo 'Open Ports on Host: ' | grep --color 'Open Ports on Host'
netstat -an | yellow-grep 'listen|listening' && echo 


#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
echo -e 'We can read the master.passwd file !' | grep --color -i 'We can read the master.passwd file !'
  echo -e "\n$readmasterpasswd" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#Find writable directories
echo 'Looking for all writable folders:' | grep --color 'Looking for all writable folders'
find / -type d -perm -2 -ls 2> /dev/null | grep --color -i -E 'root||/etc||/bin||/vaar/www||/home||/vhosts'
echo ''

#
if [ "$export" ] && [ "$readmasterpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
else 
  :
fi

#
echo ''
echo 'Check and see if your luckiest man alive...' | grep --color 'Check and see if your luckiest man alive'
echo 'Looking for config files in current directory...' | grep --color 'Looking for config files in current directory'
find . -type f -name 'config'*'.'*'' 2> /dev/null | grep --color -i -E 'config.php||configuration.php||config.inc.php||wp-config.php'
echo ''
echo 'Looking for config.php...' | grep --color 'Looking for config.php'
find / -type f -name config.php 2> /dev/null | grep --color -i 'config.php'
echo ''
echo 'Looking for config.inc.php...' | grep --color 'Looking for config.inc.php'
find / -type f -name config.inc.php 2> /dev/null | grep --color -i 'config.inc.php'
echo ''
echo 'Looking for wp-config.php...' | grep --color 'Looking for wp-config.php'
find / -type f -name wp-config.php 2> /dev/null | grep --color -i 'wp-config.php'
echo ''
echo 'Looking for db.php...' | grep --color 'Looking for db.php'
find / -type f -name db.php 2> /dev/null | grep --color -i 'db.php'
echo ''
echo 'Looking for db-conn.php...' | grep --color 'Looking for db-conn.php'
find / -type f -name db-conn.php 2> /dev/null | grep --color -i 'db-conn.php'
echo ''
echo 'Looking for sql.php...' | grep --color 'Looking for sql.php'
find / -type f -name sql.php 2> /dev/null | grep --color -i 'sql.php'
echo ''
echo 'Looking for security.php...' | grep --color 'Looking for security.php'
find / -type f -name security.php 2> /dev/null | grep --color -i 'security.php'
echo ''
echo 'Looking for service.pwd files...' | grep --color 'Looking for service.pwd files'
find / -type f -name service.pwd 2> /dev/null | grep --color -i 'service.pwd'
echo ''
echo 'Looking for .htpasswd files...' | grep --color 'Looking for .htpasswd files'
find / -type f -name .htpasswd 2> /dev/null | grep --color -i '.htpasswd'
echo ''
echo 'Looking for .bash_history files...' | grep --color 'Looking for .bash_history files'
find / -type f -name .bash_history 2> /dev/null | grep --color -i '.bash_history'
echo ''
echo 'Looking for any possible config files...' | grep --color 'Looking for any possible config files' 
find / -type f -name 'config*' 2> /dev/null | grep --color -i -E 'config||configuration'
echo ''
echo 'Checking for readable Shadow File...' | grep --color 'Checking for readable Shadow File'
echo '/etc/shadow...' | grep --color '/etc/shadow'
cat /etc/shadow 2> /dev/null
echo '/etc/master.passwd...' | grep --color '/etc/master.passwd'
cat /etc/master.passwd 2> /dev/null
echo '/etc/gshadow...' | grep --color '/etc/gshadow'
cat /etc/gshadow 2> /dev/null
echo ''

echo 'File system information' | grep --color 'File system information' 
df -a
echo -e 'Time & date' | grep --color -i 'Time & date'
date
echo ""
echo -e 'Process Management' | grep --color -i 'Process Management'
echo ""
w | grep --color -E '|USER||TTY||FROM||LOGIN@||IDLE||JCPU||PCPU||WHAT'
sleep 1
ls -lh| grep --color -E '|root||total||'
sleep 03
ls -a| grep --color -E '|root||total||'
TFILE="/root/Desktop/$(basename $0).$$.txt"
ls > $TFILE
sleep 03
echo 'Scaning files all format...' | grep --color 'Scaning files all format'
echo ""
du -ah | grep --color -E '|rb||sh||py||png||jpg||mp3||doc||txt'
sleep 03
du -sh| grep --color -E '|rb||sh||py||png||jpg||mp3||doc||txt'
pwd
trap Static-process-list INT
trap Static-process-list INT
trap Static-process-list INT
trap Static-process-list INT
bashtrap(){
echo ''
echo ''
echo 'CTRL+C has been detected!.....shutting down now' | grep --color '.....shutting down now'
#remove any partial report file to avoid confusion ...
if [ -f Enumeration.txt ]; then
	rm -f Enumerat1on.txt
fi
#exit entire script
exit 0
}
#
#process report ;)
ps -ejH > process-repo.txt

#all root accounts (uid 0)
echo 'Super user account :' | grep --color 'Super user account :' 
echo -e "" | tee -a $report 2>/dev/null; grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

#pull out vital sudoers info
sudoers=`cat /etc/sudoers 2>/dev/null | grep -v -e '^$'|grep -v "#"`
if [ "$sudoers" ]; then
echo 'Sudoers configuration (condensed):' | grep --color 'Sudoers configuration (condensed):' 
  echo -e "$sudoers" | tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$sudoers" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
else 
  :
fi

#SSH scan & check ..
echo 'Checking SSH...' | grep --color 'Checking SSH'
echo '/home/*/.ssh/authorized_keys' | grep --color '/home/*/.ssh/authorized_keys' && cat /home/*/.ssh/authorized_keys
echo '/home/*/.ssh/known_hosts' | grep --color '/home/*/.ssh/known_hosts' && cat /home/*/.ssh/known_hosts
echo ''

#Sudo...
sudoperms=`echo '' | sudo -S -l 2>/dev/null`
if [ "$sudoperms" ]; then
echo 'sudo without supplying a password....' | grep --color 'sudo without supplying a password' 
  echo -e "\n$sudoperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi
#
sudopwnage=`echo '' | sudo -S -l 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb' | xargs -r ls -la 2>/dev/null`
if [ "$sudopwnage" ]; then
echo 'Sudo PWNAGE....' | grep --color 'Sudo PWNAGE....' 
  echo -e "\n$sudopwnage" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#checks to see if roots home directory is accessible
rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
echo -e 'read roots home directory....' | grep --color -i 'read roots home directory'
  echo -e "\n$rthmdir" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
echo -e 'Are permissions on /home directories lax:...' | grep --color -i 'Are permissions on /home directories lax:'
  echo -e "\n$homedirperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
	if [ "$wrfileshm" ]; then
		echo -e "\n$wrfileshm" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wrfileshm" ]; then
		mkdir $format/wr-files/ 2>/dev/null
		for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#lists current user's home directory contents
if [ "$thorough" = "1" ]; then
homedircontents=`ls -ahl ~ 2>/dev/null`
	if [ "$homedircontents" ] ; then
		echo -e "\n$homedircontents" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
sshfiles=`find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls`
	if [ "$sshfiles" ]; then
		echo -e "\n$sshfiles" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
  :
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$sshfiles" ]; then
		mkdir $format/ssh-files/ 2>/dev/null
		for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#is root permitted to login via ssh
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$sshrootlogin" = "yes" ]; then
echo 'Root is allowed to login via SSH:' | grep --color 'Root is allowed to login via SSH:' 
  echo -e "" |tee -a $report 2>/dev/null; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi
#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
echo 'Path information:' | grep --color 'RPath information:' 
  echo -e "\n$pathinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#lists available shells
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
echo 'Available shells' | grep --color 'Available shells' 
  echo -e "\n$shellinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#current umask value with both octal and symbolic output
umask=`umask -S 2>/dev/null & umask 2>/dev/null`
if [ "$umask" ]; then
echo 'Current umask value...' | grep --color 'Current umask value...' 
  echo -e "\n$umask" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#umask value as in /etc/login.defs
umaskdef=`cat /etc/login.defs 2>/dev/null |grep -i UMASK 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$umaskdef" ]; then
echo 'mumask value as specified in /etc/login.defs...' | grep --color 'mumask value as specified in /etc/login.defs...' 
  echo -e "\n$umaskdef" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#password policy information as stored in /etc/login.defs
logindefs=`cat /etc/login.defs 2>/dev/null | grep "PASS_MAX_DAYS\|PASS_MIN_DAYS\|PASS_WARN_AGE\|ENCRYPT_METHOD" 2>/dev/null | grep -v "#" 2>/dev/null`
if [ "$logindefs" ]; then
  echo -e "\n$logindefs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$logindefs" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
else 
  :
fi


#are there any cron jobs configured
cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
echo 'Cron jobs...' | grep --color 'Cron jobs...' 
  echo -e "\n$cronjobs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
echo 'World-writable cron jobs and file contents...' | grep --color 'World-writable cron jobs and file contents...' 
  echo -e "\n$cronjobwwperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#contab contents
crontab=`cat /etc/crontab 2>/dev/null`
if [ "$crontab" ]; then
echo 'Crontab contents...' | grep --color 'Crontab contents' 
  echo -e "\n$crontab" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
echo 'Anything interesting in /var/spool/cron/crontabs...' | grep --color 'Anything interesting in /var/spool/cron/crontabs' 
  echo -e "\n$crontabvar" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
echo 'Anacron jobs and associated file permissions:' | grep --color 'Anacron jobs and associated file permissions:' 
  echo -e "" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
echo 'When were jobs last executed (/var/spool/anacron contents):' | grep --color 'When were jobs last executed (/var/spool/anacron contents):' 
  echo -e "" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cat /etc/passwd | cut -d ":" -f 1 | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
echo 'Jobs held by all users:' | grep --color 'Jobs held by all users:' 
  echo -e "\n$cronother" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi


#Network & IP info:
nicinfo=`/sbin/ifconfig -a 2>/dev/null`
if [ "$nicinfo" ]; then
echo 'Network & IP info:' | grep --color 'Network & IP info:' 
  echo -e "\n$nicinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

##another simple code to see Network settings ..
#echo 'Graphique net' | grep --color 'Graphique net'
#echo ''
#ifconfig | grep --color -E '|lo||eth0'
#trap Static-process-list INT
#trap Static-process-list INT


#dns settings
nsinfo=`cat /etc/resolv.conf 2>/dev/null | grep "nameserver"`
if [ "$nsinfo" ]; then
echo 'Nameserver(s):' | grep --color 'Nameserver(s):' 
  echo -e "\n$nsinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#default route configuration
defroute=`route 2>/dev/null | grep default`
if [ "$defroute" ]; then
echo 'Default route:' | grep --color 'Default route:' 
  echo -e "\n$defroute" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#listening TCP
tcpservs=`netstat -antp 2>/dev/null`
if [ "$tcpservs" ]; then
echo 'Listening TCP:' | grep --color 'Listening TCP:' 
  echo -e "\n$tcpservs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#listening UDP
udpservs=`netstat -anup 2>/dev/null`
if [ "$udpservs" ]; then
echo 'Listening UDP:' | grep --color 'Listening UDP:' 
  echo -e "\n$udpservs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#running processes
psaux=`ps aux 2>/dev/null`
if [ "$psaux" ]; then
echo 'Running processes:' | grep --color 'Running processes:' 
  echo -e "\n$psaux" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#lookup process binary path and permissisons
procperm=`ps aux | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++'`
if [ "$procperm" ]; then
echo 'Process binaries & associated permissions (from above list):' | grep --color 'Process binaries & associated permissions (from above list):' 
  echo -e "\n$procperm" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$procperm" ]; then
procpermbase=`ps aux | awk '{print $11}'|xargs -r ls 2>/dev/null |awk '!x[$0]++'`
  mkdir $format/ps-export/ 2>/dev/null
  for i in $procpermbase; do cp --parents $i $format/ps-export/; done 2>/dev/null
else 
  :
fi

#anything 'useful' in inetd.conf
inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$inetdread" ]; then
echo 'Contents of /etc/inetd.conf:' | grep --color 'Contents of /etc/inetd.conf:' 
  echo -e "\n$inetdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$inetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
else 
  :
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`cat /etc/inetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$inetdbinperms" ]; then
echo 'The related inetd binary permissions:' | grep --color 'The related inetd binary permissions:' 
  echo -e "\n$inetdbinperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdread" ]; then
echo 'Contents of /etc/xinetd.conf:' | grep --color 'Contents of /etc/xinetd.conf:' 
  echo -e "\n$xinetdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$xinetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
else 
  :
fi

xinetdincd=`cat /etc/xinetd.conf 2>/dev/null |grep "/etc/xinetd.d" 2>/dev/null`
if [ "$xinetdincd" ]; then
echo '/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:' | grep --color '/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:' 
  echo -e "" ls -la /etc/xinetd.d 2>/dev/null |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`cat /etc/xinetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
echo 'The related xinetd binary permissions:' | grep --color 'The related xinetd binary permissions:' 
  echo -e "\n$xinetdbinperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

initdread=`ls -la /etc/init.d 2>/dev/null`
if [ "$initdread" ]; then
echo '/etc/init.d/ binary permissions' | grep --color '/etc/init.d/ binary permissions' 
  echo -e "\n$initdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi  

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initdperms" ]; then
echo '/etc/init.d/ files not belonging to root (uid 0):' | grep --color '/etc/init.d/ files not belonging to root (uid 0):' 
  echo -e "\n$initdperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
if [ "$rcdread" ]; then
echo '/etc/rc.d/init.d binary permissions:' | grep --color '/etc/rc.d/init.d binary permissions:' 
  echo -e "\n$rcdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$rcdperms" ]; then
echo '/etc/rc.d/init.d files not belonging to root (uid 0):' | grep --color '/etc/rc.d/init.d files not belonging to root (uid 0):' 
  echo -e "\n$rcdperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$usrrcdread" ]; then
echo '/usr/local/etc/rc.d binary permissions:' | grep --color '/usr/local/etc/rc.d binary permissions:' 
  echo -e "\n$usrrcdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$usrrcdperms" ]; then
echo '/usr/local/etc/rc.d files not belonging to root (uid 0):' | grep --color '/usr/local/etc/rc.d files not belonging to root (uid 0):' 
  echo -e "\n$usrrcdperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
echo 'Sudo version:' | grep --color 'Sudo version:' 
  echo -e "\n$sudover" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#mysql details - if installed
mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
echo 'MYSQL version:' | grep --color 'MYSQL version:' 
  echo -e "\n$mysqlver" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
if [ "$mysqlconnect" ]; then
echo 'connect to the local MYSQL service with default root/root credentials' | grep --color 'connect to the local MYSQL service with default root/root credentials' 
  echo -e "\n$mysqlconnect" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#mysql version details
mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
echo 'connect to the local MYSQL service as 'root' and without a password' | grep --color 'connect to the local MYSQL service as 'root' and without a password' 
  echo -e "\n$mysqlconnectnopass" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#postgres details - if installed
postgver=`psql -V 2>/dev/null`
if [ "$postgver" ]; then
echo 'Postgres version:' | grep --color 'Postgres version:' 
  echo -e "\n$postgver" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
postcon1=`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon1" ]; then
echo 'connect to Postgres DB 'template0' as user 'postgres' with no password' | grep --color 'connect to Postgres DB 'template0' as user 'postgres' with no password' 
  echo -e "\n$postcon1" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

postcon11=`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon11" ]; then
echo 'connect to Postgres DB 'template1' as user postgres with no password...' | grep --color 'connect to Postgres DB 'template1' as user postgres with no password' 
  echo -e "\n$postcon11" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

postcon2=`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon2" ]; then
  echo -e "\n$postcon2" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon22" ]; then
  echo -e "\n$postcon22" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#apache details - if installed
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
echo 'Apache version:' | grep --color 'Apache version:' 
  echo -e "\n$apachever" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#what account is apache running under
apacheusr=`cat /etc/apache2/envvars 2>/dev/null |grep -i 'user\|group' |awk '{sub(/.*\export /,"")}1'`
if [ "$apacheusr" ]; then
echo 'Apache user configuration:' | grep --color 'Apache user configuration:' 
  echo -e "\n$apacheusr" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$apacheusr" ]; then
  mkdir --parents $format/etc-export/apache2/ 2>/dev/null
  cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
else 
  :
fi


#checks to see if various files are installed
echo 'Useful file locations:' | grep --color 'Useful file locations:' 
echo -e "" |tee -a $report 2>/dev/null; which nc 2>/dev/null |tee -a $report 2>/dev/null; which netcat 2>/dev/null |tee -a $report 2>/dev/null; which wget 2>/dev/null |tee -a $report 2>/dev/null; which nmap 2>/dev/null |tee -a $report 2>/dev/null; which gcc 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

#limited search for installed compilers
compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`
if [ "$compiler" ]; then
echo 'Installed compilers:' | grep --color 'Installed compilers:' 
  echo -e "\n$compiler" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
 else 
  :
fi

#manual check - lists out sensitive files, can we read/modify etc.
echo 'read/write sensitive files:' | grep --color 'read/write sensitive files:' 
echo -e "" |tee -a $report 2>/dev/null; ls -la /etc/passwd 2>/dev/null |tee -a $report 2>/dev/null; ls -la /etc/group 2>/dev/null |tee -a $report 2>/dev/null; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null |tee -a $report 2>/dev/null; ls -la /etc/master.passwd 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

#search for suid files - this can take some time so is only 'activated' with thorough scanning switch (as are all suid scans below)
if [ "$thorough" = "1" ]; then
findsuid=`find / -perm -4000 -type f 2>/dev/null`
	if [ "$findsuid" ]; then
echo 'SUID files:' | grep --color 'SUID files:' 
		echo -e "\n$findsuid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$findsuid" ]; then
		mkdir $format/suid-files/ 2>/dev/null
		for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#list of 'interesting' suid files - feel free to make additions
if [ "$thorough" = "1" ]; then
intsuid=`find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la` 2>/dev/null
	if [ "$intsuid" ]; then
echo 'interesting SUID files:' | grep --color 'interesting SUID files:' 
		echo -e "\n$intsuid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#lists word-writable suid files
if [ "$thorough" = "1" ]; then
wwsuid=`find / -perm -4007 -type f 2>/dev/null`
	if [ "$wwsuid" ]; then
echo 'World-writable SUID files:' | grep --color 'World-writable SUID files:' 
		echo -e "\n$wwsuid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#lists world-writable suid files owned by root
if [ "$thorough" = "1" ]; then
wwsuidrt=`find / -uid 0 -perm -4007 -type f 2>/dev/null`
	if [ "$wwsuidrt" ]; then
echo 'World-writable SUID files owned by root:' | grep --color 'World-writable SUID files owned by root:' 
		echo -e "\n$wwsuidrt" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#search for guid files - this can take some time so is only 'activated' with thorough scanning switch (as are all guid scans below)
if [ "$thorough" = "1" ]; then
findguid=`find / -perm -2000 -type f 2>/dev/null`
	if [ "$findguid" ]; then
echo 'GUID files:' | grep --color 'GUID files:' 
		echo -e "\n$findguid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$findguid" ]; then
		mkdir $format/guid-files/ 2>/dev/null
		for i in $findguid; do cp $i $format/guid-files/; done 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#list of 'interesting' guid files - feel free to make additions
if [ "$thorough" = "1" ]; then
intguid=`find / -perm -2000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la`
	if [ "$intguid" ]; then
echo 'interesting GUID files:' | grep --color 'interesting GUID files:' 
		echo -e "\n$intguid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#lists world-writable guid files
if [ "$thorough" = "1" ]; then
wwguid=`find / -perm -2007 -type f 2>/dev/null`
	if [ "$wwguid" ]; then
echo 'World-writable GUID files:' | grep --color 'World-writable GUID files:' 
		echo -e "\n$wwguid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#lists world-writable guid files owned by root
if [ "$thorough" = "1" ]; then
wwguidrt=`find / -uid 0 -perm -2007 -type f 2>/dev/null`
	if [ "$wwguidrt" ]; then
echo 'AWorld-writable GUID files owned by root:' | grep --color 'AWorld-writable GUID files owned by root:' 
		echo -e "\n$wwguidrt" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#list all world-writable files excluding /proc
if [ "$thorough" = "1" ]; then
wwfiles=`find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null`
	if [ "$wwfiles" ]; then
echo 'World-writable files (excluding /proc):' | grep --color 'World-writable files (excluding /proc):' 
		echo -e "\n$wwfiles" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else 
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wwfiles" ]; then
		mkdir $format/ww-files/ 2>/dev/null
		for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
	else 
		:
	fi
  else
	:
fi

#are any .plan files accessible in /home (could contain useful information)
usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$usrplan" ]; then
echo 'Plan file permissions and contents:' | grep --color 'Plan file permissions and contents:' 
  echo -e "\n$usrplan" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$usrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $usrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
else 
  :
fi

bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$bsdusrplan" ]; then
echo 'Plan file permissions and contents:' | grep --color 'Plan file permissions and contents:' 
  echo -e "\n$bsdusrplan" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$bsdusrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $bsdusrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
else 
  :
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
echo 'rhost config file(s) and file contents:' | grep --color 'rhost config file(s) and file contents:' 
  echo -e "\n$rhostsusr" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$rhostsusr" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
else 
  :
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$bsdrhostsusr" ]; then
echo 'rhost config file(s) and file contents:' | grep --color 'rhost config file(s) and file contents:' 
  echo -e "\n$bsdrhostsusr" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$bsdrhostsusr" ]; then
  mkdir $format/rhosts 2>/dev/null
  for i in $bsdrhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
else 
  :
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostssys" ]; then
echo 'Hosts.equiv file details and file contents: ' | grep --color 'Hosts.equiv file details and file contents: ' 
  echo -e "\n$rhostssys" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
  else 
  :
fi

if [ "$export" ] && [ "$rhostssys" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostssys; do cp --parents $i $format/rhosts/; done 2>/dev/null
else 
  :
fi

#list nfs shares/permisisons etc.
nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$nfsexports" ]; then
echo 'NFS config details:' | grep --color 'NFS config details:' 
  echo -e "\n$nfsexports" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
  else 
  :
fi

if [ "$export" ] && [ "$nfsexports" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/exports $format/etc-export/exports 2>/dev/null
else 
  :
fi

#looking for credentials in /etc/fstab
fstab=`cat /etc/fstab 2>/dev/null |grep username |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1'| xargs -r echo username:; cat /etc/fstab 2>/dev/null |grep password |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1'| xargs -r echo password:; cat /etc/fstab 2>/dev/null |grep domain |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1'| xargs -r echo domain:`
if [ "$fstab" ]; then
echo 'There are credentials in /etc/fstab' | grep --color 'There are credentials in /etc/fstab!' 
  echo -e "\n$fstab" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
  else 
  :
fi

if [ "$export" ] && [ "$fstab" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
else 
  :
fi

fstabcred=`cat /etc/fstab 2>/dev/null |grep cred |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1'| xargs -I{} sh -c 'ls -la {}; cat {}'`
if [ "$fstabcred" ]; then
echo '/etc/fstab contains a credentials file!' | grep --color '/etc/fstab contains a credentials file!' 
    echo -e "\n$fstabcred" |tee -a $report 2>/dev/null
    echo -e "\n" |tee -a $report 2>/dev/null
    else
    :
fi

if [ "$export" ] && [ "$fstabcred" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
else 
  :
fi

#use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
echo 'Cant search *.conf files as no keyword was entered' | grep --color 'Cant search *.conf files as no keyword was entered' 
  echo -e "\n" |tee -a $report 2>/dev/null
  else
    confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$confkey" ]; then
echo 'Find keyword ' | grep --color 'Find keyword ' 
      echo -e "\e[00;31m($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$confkey" |tee -a $report 2>/dev/null
      echo -e "\n" |tee -a $report 2>/dev/null
     else 
	echo -e "\e[00;31m($keyword) in .conf files (recursive 4 levels):\e[00m" |tee -a $report 2>/dev/null
	echo -e "'$keyword' not found in any .conf files" |tee -a $report 2>/dev/null
	echo -e "\n" |tee -a $report 2>/dev/null
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$confkey" ]; then
	  confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
      for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
    else 
      :
  fi
fi

#use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
echo 'Can t search *.log files as no keyword was entered' | grep --color 'Can t search *.log files as no keyword was entered' 
  echo -e "\n" |tee -a $report 2>/dev/null
  else
    logkey=`find / -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$logkey" ]; then
echo 'Find keyword ' | grep --color 'Find keyword ' 
      echo -e "\e[00;31m($keyword) in .log files (output format filepath:identified line number where keyword appears):\e[00m\n$logkey" |tee -a $report 2>/dev/null
      echo -e "\n" |tee -a $report 2>/dev/null
     else 
	echo -e "\e[00;31m($keyword) in .log files (recursive 2 levels):\e[00m" |tee -a $report 2>/dev/null
	echo -e "'$keyword' not found in any .log files"
	echo -e "\n" |tee -a $report 2>/dev/null
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$logkey" ]; then
      logkeyfile=`find / -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
	  mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
      for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
    else 
      :
  fi
fi

#use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "Can't search *.ini files as no keyword was entered\n" |tee -a $report 2>/dev/null
  else
    inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$inikey" ]; then
      echo -e "\e[00;31mFind keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$inikey" |tee -a $report 2>/dev/null
      echo -e "\n" |tee -a $report 2>/dev/null
     else 
	echo -e "\e[00;31mFind keyword ($keyword) in .ini files (recursive 2 levels):\e[00m" |tee -a $report 2>/dev/null
	echo -e "'$keyword' not found in any .ini files" |tee -a $report 2>/dev/null
	echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$inikey" ]; then
	  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
      for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
    else 
      :
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
if [ "$allconf" ]; then
echo 'All *.conf files in /etc (recursive 1 level):' | grep --color 'All *.conf files in /etc (recursive 1 level):' 
  echo -e "\e[00;31m\e[00m\n$allconf" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$allconf" ]; then
  mkdir $format/conf-files/ 2>/dev/null
  for i in $allconf; do cp --parents $i $format/conf-files/; done 2>/dev/null
else 
  :
fi

#extract any user history files that are accessible
usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$usrhist" ]; then

# Current user's history files....
echo 'Current users history files:' | grep --color 'Current users history files:' 
  echo -e "\e[00;31m\e[00m\n$usrhist" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$usrhist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  for i in $usrhist; do cp --parents $i $format/history_files/; done 2>/dev/null
 else 
  :
fi

#can we read roots *_history files - could be passwords stored etc.
roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
echo 'Root history files are accessible' | grep --color 'Root history files are accessible' 
  echo -e "\e[00;33m\e[00m\n$roothist" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$roothist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  cp $roothist $format/history_files/ 2>/dev/null
else 
  :
fi

#is there any mail accessible
readmail=`ls -la /var/mail 2>/dev/null`
if [ "$readmail" ]; then
echo 'Any interesting mail in /var/mail:' | grep --color 'Any interesting mail in /var/mail:' 
  echo -e "\e[00;31m\e[00m\n$readmail" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  echo -e "\e[00;33m***We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else 
  :
fi

if [ "$export" ] && [ "$readmailroot" ]; then
  mkdir $format/mail-from-root/ 2>/dev/null
  cp $readmailroot $format/mail-from-root/ 2>/dev/null
else 
  :
fi

#TO-DO :
#If something wrong you need check the source or edit it with second code ..
#
