#!/usr/bin/env python
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Name:  $ $Date: 2004/10/26 01:07:53 $
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
import optparse,os,sys

def getPermutations(a):
    if len(a)==1:
        yield a
    else:
        for i in range(len(a)):
            this = [a[i],]
            rest = list(a[:i]) + list(a[i+1:])
            for p in getPermutations(rest):
                yield this + list(p)

if __name__=="__main__":
    parser = optparse.OptionParser(usage = "Guess RAID configuration by permuting through RAID parameters\nUsage: %prog [options] disk1 disk2 disk3 ... ",version = "%prog version 0.1")
    parser.add_option("-c","--command",
                      default="./bin/fls -r -f linux-ext2 foo",
                      help="Command to invoke for testing the raid configuration")
    parser.add_option("-o","--offset",
                      default=0,help="Offset to the start of the partition")
    parser.add_option("-b",'--blocksize',
                      default='4k',help="Blocksize to try")
    parser.add_option("-s","--slots",
                      default=0,help="number of slots to try (by default all slots")
    parser.add_option("-H",'--header',
                      default='0',help="Constant header for each disk")
    
    (options, args) = parser.parse_args()

    ## This variable holds possible maps that I have seen. If you find more maps in practice, please submit a patch.
    maps = [
        ## The format of this is:
        ## (disks, slots, map)
        ## These are simple diagonal maps:
        ## 0.1.P
        ## 2.P.3
        ## P.4.5
        (3,3, '0.1.P.2.P.3.P.4.5'),
        (4,4, '0.1.2.P.3.4.P.5.6.P.7.8.P.9.10.11'),
        (5,5, '0.1.2.3.P.4.5.6.P.7.8.9.P.10.11.12.P.13.14.15.P.16.17.18.19'),
        (6,6, '0.1.2.3.4.P.5.6.7.8.P.9.10.11.12.P.13.14.15.16.P.17.18.19.20.P.21.22.23.24.P.25.26.27.28.29'),
        (7,7, '0.1.2.3.4.5.P.6.7.8.9.10.P.11.12.13.14.15.P.16.17.18.19.20.P.21.22.23.24.25.P.26.27.28.29.30.P.31.32.33.34.35.P.36.37.38.39.40.41'),

        ## More diagonal maps:
        ## P.0.1
        ## 2.P.3
        ## 4.5.P
        (3,3,'P.0.1.2.P.3.4.5.P'),
        (4,4,'P.0.1.2.3.P.4.5.6.7.P.8.9.10.11.P'),
        (5,5,'P.0.1.2.3.4.P.5.6.7.8.9.P.10.11.12.13.14.P.15.16.17.18.19.P'),
        (6,6,'P.0.1.2.3.4.5.P.6.7.8.9.10.11.P.12.13.14.15.16.17.P.18.19.20.21.22.23.P.24.25.26.27.28.29.P'),
        (7,7,'P.0.1.2.3.4.5.6.P.7.8.9.10.11.12.13.P.14.15.16.17.18.19.20.P.21.22.23.24.25.26.27.P.28.29.30.31.32.33.34.P.35.36.37.38.39.40.41.P'),

        ## These are some more maps:
        ## 0.1.P
        ## P.2.3
        ## 5.P.4
        (3,3, '0.1.P.P.2.3.5.P.4'),
        (4,4, '0.1.2.P.P.3.4.5.8.P.6.7.10.11.P.9'),
        (5,5, '0.1.2.3.P.P.4.5.6.7.11.P.8.9.10.14.15.P.12.13.17.18.19.P.16'),
        (6,6, '0.1.2.3.4.P.P.5.6.7.8.9.14.P.10.11.12.13.18.19.P.15.16.17.22.23.24.P.20.21.26.27.28.29.P.25'),
        (7,7,'0.1.2.3.4.5.P.P.6.7.8.9.10.11.17.P.12.13.14.15.16.22.23.P.18.19.20.21.27.28.29.P.24.25.26.32.33.34.35.P.30.31.37.38.39.40.41.P.36'),

        ## Some weird maps I have seen with HP controllers:
        (3, 6, '0.1.P.2.3.P.4.P.5.6.P.7.P.8.9.P.10.11'),
        (3, 6, '0.1.P.3.2.P.4.P.5.7.P.6.P.8.9.P.11.10'),
        ]


    ##Some really huge Raid controller seen on Compaq smart array 3200
    def gen_smartarray(disknumber):
        pos=disknumber-1
        count=0
        str=[]

        while pos>=0:
            for i in range(0,16):
                for j in range(0,disknumber):
                    if j==pos:
                        str.append('P')
                    else:
                        str.append('%s'%count)
                        count+=1
            pos-=1

        return '.'.join(str)

    maps.append((6,6*16,gen_smartarray(6)))

    best_s=''
    best_len=0

    for disk,slots,map in maps:
        if int(options.slots)!=slots: continue
        
        if disk==len(args):
            print """
------------------------------------------------------
Trying map %s with %s slots
------------------------------------------------------""" % (map,slots)
            for permutation in getPermutations(args):
                s="./bin/iowrapper -i raid -header %(header)s -blocksize %(block)s -slots %(slots)s -map %(map)s -offset %(offset)s -filenames %(filename)s -- %(command)s" % {
                    'command':options.command,
                    'slots':slots,
                    'header':options.header,
                    'offset':options.offset,
                    'map':map,
                    'filename':' '.join(permutation),
                    'block':options.blocksize
                    }
                print "Running %s:" % s
                (stdin,stdout,stderr)=os.popen3(s)
                stdin.close()
                stderr.close()
                data=[]
                for line in stdout.readlines():
                    data.append(line)
                    sys.stdout.write( line)

                print "- produced %s lines of data:\n"% len(data)
                if len(data)>best_len:
                    best_len=len(data)
                    best_s=s
                ## We find another array thats just as good
                elif len(data)==best_len:
                    best_s+="\nAnd\n"+s
                    
                stdout.close()

    print "**********************************************\nBest result produced %s lines with command line:\n%s\n**********************************************" % (best_len,best_s)
