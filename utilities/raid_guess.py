#!/usr/bin/env python
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

    (options, args) = parser.parse_args()

    ## This variable holds possible maps that I have seen. If you find more maps in practice, please submit a patch.
    maps = (
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
        )

    best_s=''
    best_len=0

    for disk,slots,map in maps:
        if disk==len(args):
            print """
------------------------------------------------------
Trying map %s with %s slots
------------------------------------------------------""" % (map,slots)
            for permutation in getPermutations(args):
                s="./bin/iowrapper -i raid -o blocksize=%(block)s,slots=%(slots)s,map=%(map)s,offset=%(offset)s,%(filename)s %(command)s" % {
                    'command':options.command,
                    'slots':slots,
                    'offset':options.offset,
                    'map':map,
                    'filename':','.join(["filename=%s" % f for f in permutation]),
                    'block':options.blocksize
                    }
                (stdin,stdout,stderr)=os.popen3(s)
                stdin.close()
                stderr.close()
                data = stdout.readlines()
                print "Running %s produced %s lines of data:\n%s"% (s,len(data),''.join(data))
                if len(data)>best_len:
                    best_len=len(data)
                    best_s=s
                stdout.close()

    print "**********************************************\nBest result produced %s lines with command line:\n%s\n**********************************************" % (best_len,best_s)
