import pyethereal
FILENAME="/tmp/test.pcap"
f=pyethereal.open_file(FILENAME)
n=pyethereal.ReadPacket(f)

def output(message):
    print "\n\n%s\n-------------------------------------------"  % message

output( "Print the top level nodes:")
for i in n.get_child():
    print i

#output( "Find and print the tcp node:")
v=n['udp'].value()
print v,type(v)

output("Testing buffer dissection: Frame 10")
fd=open(FILENAME)
fd.seek(40)
data=fd.read(74)
n=pyethereal.Packet(data,10)
output( "Print the content of frame: (We allow n to go out of scope here to test reference count)")
n=n['frame']
print n
for i in n.get_child():
    print i

