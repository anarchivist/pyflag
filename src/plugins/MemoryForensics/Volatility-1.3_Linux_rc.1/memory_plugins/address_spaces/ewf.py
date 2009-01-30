""" This Address Space allows us to open ewf files """
import standard

try:
    ## We must have this module or we dont activate ourselves
    import pyewf
    
    class EWFAddressSpace(standard.FileAddressSpace):
        """ An EWF capable address space.

        In order for us to work we need:
        1) There must be a base AS.
        2) The first 6 bytes must be 45 56 46 09 0D 0A (EVF header)
        """
        order = 20
        def __init__(self, base, opts):
            assert(base)
            assert(base.read(0,6) == "\x45\x56\x46\x09\x0D\x0A")
            self.name = self.fname = opts['filename']
            self.fhandle = pyewf.open([self.name])
            self.mode = 'rb'
            self.fhandle.seek(0,2)
            self.fsize = self.fhandle.tell()
            self.fhandle.seek(0)
            
        def is_valid_address(self, addr):
            return True
        
except ImportError:
    pass

