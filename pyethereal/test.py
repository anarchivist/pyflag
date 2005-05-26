import pyethereal,sys, gc

FILENAME="/tmp/test.pcap"
f=pyethereal.open_file(FILENAME)

def output(message):
    print "\n\n%s\n-------------------------------------------"  % message

count=0
for i in range(0,1000):
    n=pyethereal.ReadPacket(f)
    output( "Print the top level nodes:")
    for i in n.get_child():
        print i
        
    try:
        output( "Find and print the tcp node:")
        v=n['tcp.srcport'].value()
        print v,type(v)
    except:
        pass

#    n.__del__()
#    print "Read packet %s" % count
    count+=1

gc.set_debug(gc.DEBUG_LEAK)
gc.collect()
sys.exit(0)

output("Testing buffer dissection: Frame 10")
fd=open(FILENAME)
fd.seek(40)
data=fd.read(74)
n=pyethereal.Packet(data,10)
output( "Print the content of frame: (We allow n to go out of scope here to test reference count)")
n=n['udp']
print n
for i in n.get_child():
    print i

