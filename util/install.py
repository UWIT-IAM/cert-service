# install pythons to bin dir

import py_compile
import sys

sources = ['certs_warn.py', 'certs_util_lib.py']
for s in sources:
   py_compile.compile(s, '/data/local/bin/' + s + 'c')
