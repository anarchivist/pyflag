#!/usr/bin/python
# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************
#
# Version 0.1 Aaron Iles

# This is a rewrite of the program 'examine.pl' authored by Michael Cohen and
# Eddie Cornejo in python using the pyflag architecture. It is designed to dig
# through a hard disk for graphic images.

import pyflag.FlagFramework as FlagFramework
import pyflag.IO as IO
import pyflag.Exgrep as Exgrep
import pyflag.conf
config=pyflag.conf.ConfObject()

#Set the log level to show informational message:
config.LOG_LEVEL=5
import sys,os,stat,getopt
from os.path import join
from pyflag.logging import *
import tempfile

# Defaults
max_num_images = 150
max_collection_size = 61953024
min_image_size = 2000
extracted_length = 0
zgv_cmd = 'xzgv'

# show images function
def show_images(tmp_dir):
    """ This function is responsible for launching the appropriate viewer.

    @arg tmp_dir: A temporary directory to launch the viewer in
    """
    #We try and spawn the users requested viewer if its not there, we try with zgv:
    if os.spawnlp(os.P_WAIT,zgv_cmd, zgv_cmd,tmp_dir)>0:
        if os.spawnlp(os.P_WAIT,'zgv','zgv',tmp_dir) >0:
            log(ERRORS,"Unable to launch zgv or %s, bailing" % zgv_cmd)
            sys.exit(1)

optlist, arglist = getopt.gnu_getopt(sys.argv[1:],"i:s:f:z:S:")
for opt, arg in optlist:
    if opt == '-i':
        max_num_images = int(arg)
    elif opt == '-s':
        max_collection_size = int(arg)
    elif opt == '-S':
        extracted_length=int(arg)
    elif opt == '-f':
        min_image_size = int(arg)
    elif opt == '-z':
        zgv_cmd = 'zgv'

if len(arglist) == 0:
    print """Usage: %s filename [opts] filename.
    Opts are:
       -i num    : Maximum number of images to display per phase
       -S num  : Size of image extracted from the raw image
       -s size   : Maximum size (in kb) that all images may take before displaying them
       -f size   : Minimum size for images to display
       -z viewer : Viewer program to launch - default xzgv """ % (sys.argv[0],)
    sys.exit(0)
else:
    target = arglist[0]
    log(INFO,"%s: target %s." % (sys.argv[0],target,))
    log(INFO,"%s: max num images %s." % (sys.argv[0],max_num_images,))
    log(INFO,"%s: max storage size %s." % (sys.argv[0],max_collection_size,))
    log(INFO,"%s: min image size %s." % (sys.argv[0],min_image_size,))

tmp_dir=tempfile.mkdtemp()
tmp_image_filename = tempfile.mkstemp('.jpg','image',tmp_dir)[1]
image_fix_cmd = "%s/bin/djpeg %s 2>/dev/null | %s/bin/cjpeg >" % \
                (config.PYFLAGDIR,tmp_image_filename,config.PYFLAGDIR)

def clean_up_tmp_directory(tmp_dir):
    #Recursively remove the tmp directory
    for root, dirs, files in os.walk(tmp_dir, topdown=False):
        for name in files:
            os.remove(join(root, name))
        for name in dirs:
            os.rmdir(join(root, name))
            
# set up flag io subsystem 
query_target = FlagFramework.query_type(())
query_target['subsys'] = 'standard'
query_target['io_filename'] = target
io_target = IO.IOFactory(query_target)
io_source = IO.IOFactory(query_target)

#iterate file copying
image_count = 0
total_image_count = 0
collection_size = 0
for image in Exgrep.process(None,io_target,("jpg")):
    io_source.seek( image['offset'] )
    tmp_image = open(tmp_image_filename, 'w')
    if extracted_length>0:
        tmp_image.write( io_source.read( extracted_length * 1024) )
    else:
        tmp_image.write( io_source.read( image['length'] ) )
        
    tmp_image.close()
    
    new_image = tmp_dir + '/' + str(image['offset']) + '.jpg'
    if os.system( image_fix_cmd + new_image )>0:
        pass
#        raise(os.error,"Spawn command returned with error code")

    ## Get the new images size and add to tally
    new_image_size = os.stat( new_image )[stat.ST_SIZE]
    ## If its too small for us to worry about, we remove it
    if new_image_size < min_image_size:
        os.remove( new_image )
    else:
        image_count = image_count + 1
        total_image_count = total_image_count + 1
        collection_size = collection_size + new_image_size
        log(INFO,'%s: Found image at offset %d.' % (sys.argv[0],image['offset']))
        log(INFO,'%s: Page count %d. Total count %d.' % (sys.argv[0],image_count,total_image_count))

    if image_count >= max_num_images or collection_size > max_collection_size:
        log(INFO,'%s: Disk usage %d File count %d' % (sys.argv[0],collection_size,image_count))
        log(WARNINGS,'%s: Close all zgv windows to continue' % (sys.argv[0],))
        show_images(tmp_dir)
        clean_up_tmp_directory(tmp_dir)
        image_count = 0;
        collection_size = 0;
## End exgrep loop

#We get here after we have done the entire disk.
if image_count > 0:
    log(INFO,'%s: Disk usage %d File count %d' % (sys.argv[0],collection_size,image_count))
    log(WARNINGS,'%s: Close all zgv windows to continue' % (sys.argv[0],))
    show_images(tmp_dir)
    clean_up_tmp_directory(tmp_dir)
