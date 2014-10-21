# setup for iam ansible install
# all as root

# bail on any error
set -e

# sanity check for proper system
case `id -nu` in
 root)
          ;;
 *) echo "This script must run as root"
    exit 1
    ;;
esac
[[ -d /etc/daemons && -d /usr/local/apache && -d /usr/local/tomcat && -d /usr/local/ssl ]] || {
  echo "This doesn't look like a proper iam host."
  exit 1
}



iamgrp="iam-dev"

# setup something with iam-grp write permissions

# arg is existing file
function iamwfile {
  [[ -f $1 ]] || {
     echo "not a regular file: $1"
     exit 1
  }
  chgrp $iamgrp $1
  chmod g+w $1
}

# arg is directory 
function iamwdir {
  dir=$1
  [[ -d $dir ]] || mkdir $dir
  chgrp $iamgrp $dir
  chmod g+w $dir
}


# setup local and ansible-comand
mkdir /data/local
mkdir /data/local/src
mkdir /data/local/bin
mkdir /data/local/etc
# chgrp -R iam-dev  /data/local/
cd /data/local/src
wget https://iam-tools.u.washington.edu/iam-ansible/host-tools.tar.gz
tar xf host-tools.tar.gz
rm host-tools.tar.gz
cd host-tools
make install

# setup apache
iamwdir /data/conf/
iamwdir /data/conf/apache-http.d/
iamwdir /data/conf/apache-https.d/

iamwdir /www/js
iamwdir /www/css

# setup tomcat
iamwdir /data/webapps
iamwfile /data/tomcatsettings/startup

# for certservice
mkdir /logs/cs
chown nobody /logs/cs
iamwdir /data/local/cs

# for spreg
mkdir /logs/spreg
chown nobody /logs/spreg

iamwdir /data/local/spreg

