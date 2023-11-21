openssl req -new -newkey rsa:2048 -nodes -out secrets/daily.csr -keyout secrets/daily.key \
    -subj "/C=US/ST=Washington/L=dsg/O=University of Washington/OU=dsg/CN=iam-tools.u.washington.edu"
