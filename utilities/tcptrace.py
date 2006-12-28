# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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

""" This is a reimplementation of TCPTrace. It is primarily written as
an example as to how to use the stream reassembler within an external
program.

Invoke like this:
tcptrace.py pcap_file ... pcap_file

Files will be written to the current directory one file per stream.
"""
from optparse import OptionParser
import FileFormats.PCAP as PCAP
from format import Buffer
import pyflag.pyflaglog as pyflaglog
import reassembler, _dissect
import socket, struct
import pyflag.conf
config=pyflag.conf.ConfObject()

parser = OptionParser(usage = """%prog [options] pcap_file ... pcap_file

Will reassemble all TCP streams in pcap_files into seperate files
written to the current directory.""",
                      version="Version: %prog PyFlag "+config.VERSION)

parser.add_option("-p", "--prefix", default="",
                  help = "The prefix which will be appended to all stream files. (This can be used to place them in a different directory)")

parser.add_option("-s","--stats", default=None,
                  help = "If set allows detailed stats to be written to the specified file")

parser.add_option("-v", "--verbose", default=5, type='int',
                  help = "Level of verbosity")

(options, args) = parser.parse_args()

## Hush up a bit
pyflaglog.config.LOG_LEVEL=options.verbose
if options.stats:
    stats_fd = open(options.stats,'w')
    stats_fd.write("""## Stats for streams in the following format:
## stream name: (packet_id, offselt, length) ....
""")

def tcp_callback(s):
    l =0
    for i in s['length']:
        l+=i
    print "%sS%s->%sS%s (%s stream) %s:%s -> %s:%s Length %s" % (
        options.prefix,s['con_id'],options.prefix,
        s['reverse'], s['direction'],
        socket.inet_ntoa(struct.pack(">L",s['src_ip'])), s['src_port'],
        socket.inet_ntoa(struct.pack(">L",s['dest_ip'])), s['dest_port'], l)

    if options.stats:
        tmp=[]
        stats_fd.write("S%s: " % s['con_id'])
        for i in range(len(s['packets'])):
            tmp.append("%s" % ((s['packets'][i], s['offset'][i], s['length'][i]),))

        stats_fd.write("%s\n" % ','.join(tmp))

hashtbl = reassembler.init(options.prefix,0)
reassembler.set_tcp_callback(hashtbl, tcp_callback)

count = 0
for f in args:
    fd = open(f,'r')
    buffer = Buffer(fd=fd)
    header = PCAP.FileHeader(buffer)
    for p in header:
        data = p.payload()
        d = _dissect.dissect(data,header['linktype'], count)
        count+=1
        try:
            reassembler.process_packet(hashtbl, d)
        except Exception,e:
            pyflaglog.log(pyflaglog.DEBUG, "%s" % e)

# Finish it up
reassembler.clear_stream_buffers(hashtbl);
