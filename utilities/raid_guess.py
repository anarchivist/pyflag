#!/usr/bin/env python
import optparse,os

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
    parser = optparse.OptionParser()
    parser.add_option("-c","--command",
                      default="./bin/fls -r -f linux-ext2 foo",
                      help="Command to invoke for testing the raid configuration")
    parser.add_option("-o","--offset",
                      default=0,help="Offset to the start of the partition")
    parser.add_option("-b",'--blocksize',
                      default='4k',help="Blocksize to try")

    (options, args) = parser.parse_args()

    slots=len(args)
    map =[]
    k=0
    min=0
    max=slots-1
    for i in range(0,slots):
        map.append([str(i) for i in range(min,min+k) ] +['P',] + [str(i) for i in range(min+k,max) ])
        k+=1
        min=max
        max+=slots-1

    map='.'.join( ['.'.join(i) for i in map ])

    for permutation in getPermutations(args):
        print permutation
        s="./bin/iowrapper -i raid -o blocksize=%(block)s,slots=%(slots)s,map=%(map)s,offset=%(offset)s,%(filename)s %(command)s" % {
            'command':options.command,
            'slots':slots,
            'offset':options.offset,
            'map':map,
            'filename':','.join(["filename=%s" % f for f in permutation]),
            'block':options.blocksize
            }
        result=os.system(s)
        print s,result
