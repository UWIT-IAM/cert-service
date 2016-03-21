#!/bin/bash

# certservice ansible installation script

function usage {
  echo "usage: $0 [-c local_config] [-v] [-p playbook] [-t] target "
  exit 1
}

# get the base path
dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
base=${dir%/ansible}

cd $dir

target=
verbose=
playbook=install.yml

# generic parser
prefix=""
key=""
value=""
inventory=""
for keyValue in "$@"
do
  case "${prefix}${keyValue}" in
    -p=*|--playbook=*)  key="-p";     value="${keyValue#*=}";; 
    -t=*|--target=*)  key="-t";     value="${keyValue#*=}";; 
    -i=*|--inventory=*)  key="-i";     value="${keyValue#*=}";; 
    -n*|--no_update)      key="-n";    value="";;
    -v*|--verbose)      key="-v";    value="";;
    -d*|--debug)      key="-d";    value="";;
    -f*|--force)      key="-f";    value="";;
    *)       value=$keyValue;;
  esac
  case $key in
    -p) playbook=${value}; echo "p=$playbook";  prefix=""; key="";;
    -t) target="${value}";          prefix=""; key="";;
    -i) inventory="${value}";          prefix=""; key="";;
    -v) verbose="-v";           prefix=""; key="";;
    -d) verbose="-vvvv";           prefix=""; key="";;
    -n) TEST=1;           prefix=""; key="";;
    -f) force="f";           prefix=""; key="";;
    *)  prefix="${keyValue}=";;
  esac
done

[[ -z $target ]] && target=$value
[[ -n "$target" ]] || usage

# get ansible-tools

[[ -d ansible-tools ]] || {
   echo "installing ansible-tools tools"
   git clone ssh://git@git.s.uw.edu/iam/ansible-tools.git
   quick="notneeded"
}
[[ -z $quick ]] && {
      cd ansible-tools
      git pull origin master
      cd ..
}

export ANSIBLE_LIBRARY=ansible-tools/modules:/usr/share/ansible

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

vars="target=${target} "
ansible-playbook ${playbook} $verbose  -i ansible-tools/hosts  --extra-vars "${vars}"

