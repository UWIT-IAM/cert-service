#!/bin/bash

# certservice ansible installation script

function usage {
  echo "
    usage:  $0 [options] product target
            options:     [-v]            ( verbose )
                         [-d]            ( very verbose )
                         [-l hostname]   ( limit install to 'hostname' )
                         [-H]            ( list hosts in the cluster )
            product: app | util
            target: eval | prod

            target help: $0 targets
    "
    exit 1
}

function targets {
  echo "
     eval                       Installs to eval hosts (iamtools-test11)
     prod                       Installs to prod hosts (iamtools21, 22)
  "
  exit 1
}

# get the base path
dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
base=${dir%/ansible}

cd $dir
playbook=
listhosts=0
verb=0
debug=0
target=
limit=
gettools=1

# limited args to playbook
OPTIND=1
while getopts 'h?l:Hvd' opt; do
  case "$opt" in
    h) usage
       ;;
    \?) usage
       ;;
    l) limit=$OPTARG
       ;;
    H) listhosts=1
       ;;
    v) verb=1
       ;;
    d) debug=1
       ;;
    q) gettools=0
       ;;
  esac
done

eval product="\${$OPTIND}"
[[ -z $product ]] && usage
[[ $product == 'targets' ]] && targets
[[ $product == "app" || $product == "util" ]] || usage
(( OPTIND += 1 ))
eval target="\${$OPTIND}"
[[ -z $target ]] && usage
echo "Installing $product to $target"
playbook="install-${product}.yml"

((listhosts>0)) && {
   ansible-playbook ${playbook} --list-hosts -i ./hosts  --extra-vars "target=${target}"
   exit 0
}

# make sure the war file was generated
[[ $product = "app" &&  ! -f ../target/cs.war ]] && {
   echo "use 'mvn clean package' to make the war file first"
   exit 1
}

# make sure the war file is up-to-date
[[  $product = "app" && -z $force ]] && {

   echo $product
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
(( debug>0 )) && vars="$vars -vvvv "
[[ -n $limit ]] && vars="$vars -l $limit "
ansible-playbook ${playbook} $vars -i ./hosts  --extra-vars "target=${target}"

