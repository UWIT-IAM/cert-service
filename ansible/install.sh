#!/bin/bash

# certservice ansible installation script

function usage {
  echo "usage: $0 [-p playbook (install.yml)] [-v] [-l limit_host] target "
  echo "       $0 -H  target (shows hostnames)"
  exit 1
}

# get the base path
dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
base=${dir%/ansible}

cd $dir
playbook=install.yml
list_hosts=0
verb=0
target=
limit=
gettools=1

# limited args to playbook
OPTIND=1
while getopts 'h?p:l:Hv' opt; do
  case "$opt" in
    h) usage
       ;;
    \?) usage
       ;;
    p) playbook=$OPTARG
       ;;
    l) limit=$OPTARG
       ;;
    H) listhosts=1
       ;;
    v) verb=1
       ;;
    q) gettools=0
       ;;
  esac
done

eval target="\${$OPTIND}"
[[ -z $target ]] && usage
echo $target

# get ansible-tools
[[ -d ansible-tools ]] || {
   echo "installing ansible-tools tools"
   git clone ssh://git@git.s.uw.edu/iam/ansible-tools.git
   gettools=0
}
(( getools>0 )) && {
      cd ansible-tools
      git pull origin master
      cd ..
}

export ANSIBLE_LIBRARY=ansible-tools/modules:/usr/share/ansible

((listhosts>0)) && {
   ansible-playbook ${playbook} --list-hosts -i ansible-tools/hosts  --extra-vars "target=${target}"
   exit 0
}

# make sure the war file was generated
[[ -f ../target/cs.war ]] || {
   echo "use 'mvn clean package' to make the war file first"
   exit 1
}

# make sure the war file is up-to-date
[[ -z $force ]] && {
   mod="`find ../src -newer ../target/cs.war`"
   [[ -n $mod ]] && {
      echo "cs war file appears out of date"
      echo "use 'mvn clean package' to update the war file first"
      exit 1
   }
}


# run the installer 

vars=
(( verb>0 )) && vars="$vars -v "
[[ -n $limit ]] && vars="$vars -l $limit "
echo ansible-playbook ${playbook} $vars -i ansible-tools/hosts  --extra-vars "target=${target}"
ansible-playbook ${playbook} $vars -i ansible-tools/hosts  --extra-vars "target=${target}"

