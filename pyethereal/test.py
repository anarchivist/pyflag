import pyethereal
f=pyethereal.open_file("/tmp/test.pcap")
n=pyethereal.ReadPacket(f)

def output(message):
    print "\n\n%s\n-------------------------------------------"  % message

output( "Print the top level nodes:")
for i in n.get_child():
    print i

output( "Find and print the tcp node:")
print n['tcp']
