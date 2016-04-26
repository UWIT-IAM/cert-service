This is the ansible certservice installer

prerequisites
-------------

On your build host:

1) Ansible

   see: http://docs.ansible.com/

   via git:  git clone https://github.com/ansible/ansible.git

2) iam-ansible tools

   git clone ssh://git@git.s.uw.edu/iam/ansibletools.git

3) echo "iam_ansible=<your ansibletools install path>" > install.properties

4) httest

   see: http://htt.sourceforge.net/cgi-bin/cwiki/bin/public



On the target:

1) Ansible 'as-root' controller

   /data/local/bin/ansible_command

   see: iam-ansible tools / host-tools


2) Directories to be chgrp to 'iam-dev' and chmod g+w

   /etc/daemons/tomcat
   /data/local/sp-registry
   /data/webapps
   /data/conf
   /data/conf/apache-http.d/
   /data/conf/apache-https.d/
   /logs/spreg (writeable by tomcat)

3) If python
   (as user)
   $ cd /data/local
   $ virtualenv iam-env

---------------------

Install
--------

1) Be sure there is a spreg.properties.xxx file for the type of host
   you're installing.  xxx = prod | eval | dev
   
2) Make the package.  In base product directory: 

   $ mvn clean package

3) Run installer.  In this directory:

   $ ./install.sh <host_type>

   host_type = tools_dev | tools_eval | tools_prod


