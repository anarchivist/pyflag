""" A program demonstrating the automation of flag using the Flag Shell and python.

We extract all the files with type like image into the /tmp/ directory"""

## Provides access to the pyflag shell
import pyflag.pyflagsh as pyflagsh

## First we load the filesystem in:
pyflagsh.shell_execv('load','demo.test1')

for i in pyflagsh.shell_execv_iter('find_dict','/'):
    print i
