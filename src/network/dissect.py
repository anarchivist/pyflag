import _dissect
import pyflag.conf
config=pyflag.conf.ConfObject()

class empty_dissector:
    """ A do nothing dissector object which a network scanner starts with

    Useful to trip it up with exceptions if anyone tries to use it.
    """
    def __getitem__(self, item):
        raise KeyError

    def is_protocol_to_server(self, proto):
        return False
    
    def is_protocol(self, proto):
        return False

class base_dissector:
    """ A base dissector which can be initialised directly from an
    existing PyCObject.
    """
    def __init__(self, name, dissector_PyCObject):
        self.d = dissector_PyCObject
        self.name = name

    def __getitem__(self, item):
        ## If the item refers to another object we return a new
        ## dissector object. Otherwise we just return the value itself
        result = _dissect.get_field(self.d, item)
        try:
            name=_dissect.get_name(result)

            return base_dissector(name,result)
        except:
            return  result

    def list_fields(self):
        return _dissect.list_fields(self.d)

    def is_node(self,field):
        """ Returns true if field is another node. False if its
        not. KeyError if there is no field.
        """
        f = self.__getitem__(field)
        try:
            f.d
            return True
        except:
            return False

    def get_range(self,field=''):
        """ Returns the range (start,length) where the field was
        derived. If field does not exist in this node, raise KeyError.
        """
        return _dissect.get_range(self.d, field)

class dissector(base_dissector):
    def __init__(self, data, link_type, packet_id, packet_offset):
        self.d = _dissect.dissect(data,link_type,packet_id, packet_offset);
        self.name = _dissect.get_name(self.d)
    
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
