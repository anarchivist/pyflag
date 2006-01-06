import _dissect
import pyflag.conf
config=pyflag.conf.ConfObject()

class empty_dissector:
    """ A do nothing dissector object which a network scanner starts with """
    def __getitem__(self, item):
        raise KeyError

    def is_protocol_to_server(self, proto):
        return False
    
    def is_protocol(self, proto):
        return False
    
class dissector:
    def __init__(self, data, link_type):
        self.d = _dissect.dissect(data,link_type);

    def __getitem__(self, item):
        return _dissect.get_field(self.d, item)

    def is_protocol_to_server(self,proto):
        """ Check if the dest port is one of the ones we are looking for """
        ports = fix_ports(proto)
        try:
            if self['tcp.dest_port'] in ports:
                return True
        except KeyError:
            pass

        return False
        
    def is_protocol(self, proto):
        """ Check if either the dest port or src port is one of the ones we are looking for """
        ports = fix_ports(proto)
        try:
            if (self['tcp.src_port'] in ports
                or self['tcp.dest_port'] in ports):
                return True
        except KeyError:
            pass
        
        return False
    
def fix_ports(proto):
    """ Retrieve the ports from the config as a list """
    ports = getattr(config,proto+"_PORTS")
    try:
        ports[0]
    except:
        ports=[ports]

    return ports
