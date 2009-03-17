# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
import reassembler
import socket, struct
import pypcap
import pyflag.conf
config=pyflag.conf.ConfObject()
from pyflag.CacheManager import CachedWriter
import pyflag.FlagFramework as FlagFramework

parser = OptionParser(usage = """%prog [options] pcap_file ... pcap_file

Will reassemble all TCP streams in pcap_files into seperate files
written to the current directory.""",
                      version="Version: %%prog PyFlag %s " % config.VERSION)

parser.add_option("-p", "--prefix", default="",
                  help = "The prefix which will be appended to all stream files. (This can be used to place them in a different directory)")

parser.add_option("-s","--stats", default=None,
                  help = "If set allows detailed stats to be written to the specified file")

parser.add_option("-v", "--verbose", default=5, type='int',
                  help = "Level of verbosity")

(options, args) = parser.parse_args()

if options.stats:
    stats_fd = open(options.stats,'wb')
    stats_fd.write("""## Stats for streams in the following format:
## stream name: (packet_id, offset, length) ....
""")
    stats_fd.close()

CONS = 0

def Callback(mode, packet, connection, options = None):
    global CONS
    import socket, struct, time

    if mode=='est':
        if not connection.has_key('con_id'):
            connection['con_id'] = CONS
            connection['ts_sec'] = packet.ts_sec
            CONS +=1
            connection['reverse']['con_id'] = CONS
            CONS +=1

            connection['data'] = CachedWriter("%s/S%s" % (options.prefix, connection['con_id']))
            connection['reverse']['data'] = CachedWriter("%s/S%s" % (options.prefix, connection['reverse']['con_id']))

        ip = packet.find_type("IP")
        connection['src_ip'] = ip.src
        connection['dest_ip'] = ip.dest
        connection['l'] = 0
        connection['packets'] = []

        tcp = packet.find_type("TCP")
        connection['src_port'] = tcp.source
        connection['dest_port'] = tcp.dest
        if tcp.data_len > 0:
            Callback('data', packet, connection)
            
    if mode=='data':
        tcp = packet.find_type("TCP")
        data = tcp.data
        fd = connection['data']
        connection['packets'].append(dict(offset = packet.offset,
                                          length = len(data)))
        connection['l'] += len(data)
        if data: fd.write(data)

    if mode=='destroy':
        try:
            fd = connection['data']
            fd.write_to_file()
        except KeyError: pass

        try:
            fd = connection['reverse']['data']
            fd.write_to_file()
        except KeyError: pass

        stat = "%s: %sS%s->%sS%s %s:%s -> %s:%s Length %s\n" % (
            time.ctime(connection['ts_sec']),
            options.prefix,connection['con_id'],options.prefix,
            connection['reverse']['con_id'],
            socket.inet_ntoa(struct.pack(">L",connection['src_ip'])), connection['src_port'],
            socket.inet_ntoa(struct.pack(">L",connection['dest_ip'])), connection['dest_port'],
            connection['l'])

        if options.stats:
            stats_fd = open(options.stats,'ab')
            stats_fd.write(stat)
            stats_fd.close()
            #for i in range(len(connection['packets'])):
            #    tmp.append("%s" % ((connection['packets'][i], connection['offset'][i],
            #                        connection['length'][i]),))
                
            #stats_fd.write("%s\n" % ','.join(tmp))

processor = reassembler.Reassembler(packet_callback = FlagFramework.Curry(Callback, options=options))
for f in args:
    try:
        pcap_file = pypcap.PyPCAP(open(f,"rb"))
    except IOError:
        continue
    
    while 1:
        try:
            packet = pcap_file.dissect()
            processor.process(packet)
        except StopIteration: break


