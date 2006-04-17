import reassembler
import DB

hnd = reassembler.init()

print hnd

def Callback(stream):
    print stream
#    raise IOError
#    print "%s: %s" % (stream['con_id'], stream)

reassembler.set_tcp_callback(hnd, Callback)

filename = "/var/tmp/demo/stdcapture_0.2.pcap"
fd=open(filename)
dbh = DB.DBO("demo")

dbh.execute("select * from pcap")
for row in dbh:
    fd.seek(row['offset'])
    data = fd.read(row['length'])
    try:
        reassembler.process_tcp(hnd, data, row['id'], row['link_type'])
    except RuntimeError:
        pass

reassembler.clear_stream_buffers(hnd)
