""" A program demonstrating the automation of flag using the Flag Shell and python.

We extract all the files with type like image into the /tmp/ directory"""

## Provides access to the pyflag shell
import pyflag.pyflagsh as pyflagsh

## First we load the filesystem in:
pyflagsh.shell_execv('load','demo.test')

#Do a big find over the filesystem to recover all the files
for file in pyflagsh.shell_execv_iter('find_dict','/'):
    # Use file to check their magic
    t = pyflagsh.shell_execv('file',"%s%s" % (file['path'],file['name']))
    try:
        if t and t['type'].index('image'):
            ## Create this file in the /tmp/ directory
            new_filename = "/tmp/results/%s" % file['name']
            if not new_filename.endswith('.jpg'): new_filename+='.jpg'
            print "created file %s magic %s" % (new_filename,t['type'])
            
            fd = open(new_filename,'w')
            for data in pyflagsh.shell_execv_iter('cat',"%s%s" % (file['path'],file['name'])):
                fd.write(data)
            fd.close()
    except ValueError:
        pass
