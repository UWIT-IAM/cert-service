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
    *)       value=$keyValue;;
  esac
  case $key in
    -p) playbook=${value}; echo "p=$playbook";  prefix=""; key="";;
    -t) target="${value}";          prefix=""; key="";;
    -i) inventory="${value}";          prefix=""; key="";;
    -v) verbose="-v";           prefix=""; key="";;
    -d) verbose="-vvvv";           prefix=""; key="";;
    -n) TEST=1;           prefix=""; key="";;
    *)  prefix="${keyValue}=";;
  esac
done

[[ -z $target ]] && target=$value
[[ -n "$target" ]] || usage

# get iam-ansible location

. ./install.properties
[[ -z $iam_ansible/hosts ]] && {
   echo "iam_ansible installation directory is missing from install.properties"
   exit 1
}

[[ -L tasks ]] || {
  echo "creating tasks link"
  ln -s ${iam_ansible}/tasks .
}
export ANSIBLE_LIBRARY=${iam_ansible}/modules:/usr/share/ansible

# make sure the war file was generated
[[ -f ../target/cs.war ]] || {
   echo "use 'mvn clean package' to make the war file first"
   exit 1
}

# run the installer 

vars="target=${target} "
ansible-playbook ${playbook} $verbose  -i ${iam_ansible}/hosts  --extra-vars "${vars}"

