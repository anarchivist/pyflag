#!/usr/bin/python

#### TODO ####
#### Check for memory leaks in the pypst module calls

import pypst
import re

class Pstfile:
    """ higher level shadow class for libpst
    impliments an filesystem-like interface into pst files
    for use in pyflag """

    class Item:
        """ Base class to represent pst items (email, contact, journal, appointment, folder)
        These will allow access to all the members of the corresponding C structs
        In addition, they have a 'read' method which should return something sensible
        for use in scanning etc. These keep a reference to the item and must be deleted to free memory
        """
        def __init__(self, pst, ptr, item):
            self.pst = pst
            self.id = ptr.id
            self._item = item
            self._read() # must fill in self.data
            self.size = len(self.data)

        def free(self):
            pypst._pst_freeItem(self._item)

        def __del__(self):
            """ Object destructor, frees memory in the C module
            I hope we can rely on this, it does seem to get called appropriately """
            if self._item:
                self.free()

        def __str__(self):
            return self.read()

        def read(self):
            return self.data
            #return "I am a %s" % self.__class__

        def _read(self):
            self.data = ''

        def __getattr__(self, name):
            """ access to data structures """
            try:
                if isinstance(self, Pstfile.Email):
                    return self._item.email.__getattr__(name)
                elif isinstance(self, Pstfile.Contact):
                    return self._item.contact.__getattr__(name)
                elif isinstance(self, Pstfile.Journal):
                    return self._item.journal.__getattr__(name)
                elif isinstance(self, Pstfile.Appointment):
                    return self._item.appointment.__getattr__(name)
                else:
                    return self._item.__getattr__(name)
            except AttributeError:
                return self._item.__getattr__(name)

    class Email(Item):
        """ email item """
        import base64
        
        class Attachment:
            """ Email attachment """
            def __init__(self, pst, ref):
                self.pst = pst
                self.mimetype = ref.mimetype
                self.filename1 = ref.filename1
                self.filename2 = ref.filename2
                self.data = self.pst.get_attach_data(ref)
                self.size = len(self.data)
                
            def read(self):
                return self.data
            
        def getattach(self, num):
            attach = self._item.attach
            count = 0
            while attach:
                if count == num:
                    return Pstfile.Email.Attachment(self.pst, attach)
                attach = attach.next
                count += 1
            raise IndexError, "No attachment: %i last is: %i" % (num, count)

        def attach(self):
            """ iterate through attachments """
            attach = self._item.attach
            while attach:
                yield Pstfile.Email.Attachment(self.pst, attach)
                attach = attach.next
        
        def _read(self):
            email = self._item.email
            base64enc = False
            self.data = ''
            if email.header:
                self.data = email.header.replace('\r','')
                m = re.search('Content-Transfer-Encoding:\s+base64',self.data,re.IGNORECASE)
                if m:
                    base64enc = True
            if email.body:
                if base64enc:
                    self.data += base64.decodestring(email.body)
                else:
                    self.data += email.body.replace('\r','')
            if email.htmlbody:
                if base64enc:
                    self.data += base64.decodestring(email.htmlbody)
                else:
                    self.data += email.htmlbody.replace('\r','')
            if email.rtf_compressed:
                #### WARNING: MEMORY LEAK ####
                #retstr += pypst.rtf_decompress(email.rtf_compressed)
                self.data += "Libpst: RTF compressed body found, not currently suppored\n"
            if email.encrypted_body or email.encrypted_htmlbody:
                self.data += "Libpst: Encrypted body found, not currenlty supported\n"


    class Contact(Item):
        """ contact item """
        def _read(self):
            self.data = ''
            contact = self._item.contact
            for name in contact.__swig_getmethods__:
                val = contact.__getattr__(name)
                if val:
                    self.data += "%s: %s\n" % (name.title(), val)
        
    class Journal(Contact):
        """ contact item """
        def _read(self):
            self.data = ''
            journal = self._item.journal
            for name in journal.__swig_getmethods__:
                val = journal.__getattr__(name)
                if val:
                    self.data += "%s: %s\n" % (name.title(), val)

    class Appointment(Contact):
        """ appointment item """
        def _read(self):
            self.data = ''
            appt = self._item.appointment
            for name in appt.__swig_getmethods__:
                val = appt.__getattr__(name)
                if val:
                    self.data += "%s: %s\n" % (name.title(), val)
                    
    class Folder(Item):
        """ folder item """
        def __str__(self):
            return "Folder %s" % self._item.file_as
        
    def __init__(self, filename):
        self.pst = pypst.pst_file()
        if self.pst.open(filename) == -1:
            raise IOError, "Pstfile: Can't open file"
        if self.pst.load_index() == -1:
            raise IOError, "Pstfile: Can't load index"
        if self.pst.load_extended_attributes() == -1:
            raise IOError, "Pstfile: Can't load extended attributes"
        item = self.pst.get_item(self.pst.d_head)
        ptr = self.pst.getTopOfFolders(item)
        self.rootid = ptr.id
        self.name = item.file_as
        pypst._pst_freeItem(item)

    def close(self):
        """ close pst file """
        self.pst.close()
        
    def walk(self, id, topdown=True):
        """ emulate the os.walk directory tree generator
        It has some peculiarities: The input arg is an (id, path) 2-tuple, where path
        can be empty in which case the results will be rooted there (it becomes ('/')).
        It yields a three-tuple (path, dirs, non-dirs) where each of these is itself
        a two-tuple (id, path) (for path) or list of two-tuples (for dirs, non-dirs).
        This makes sense at the moment, but it is late...
        The reason is that it is difficult/expensive to optain a path from an id and vice-versa
        Therefore we will do both here since we're retrieving items anyway, and you wont have to
        do any further lookups with the result.
        The names or nondirs are of the form Class:id eg. Email:123456, Contact:654321 etc
        @arg id: a two-tuple (id, path) where path may be an empty string or None
        @arg topdown: specifies the output order, default True"""

        def pjoin(a, b):
            if a.endswith('/'):
                a = a[:-1]
            if b.startswith('/'):
                b = b[1:]
            return "%s/%s" % (a, b)

        if not id[1]:
            id = (id[0], '/')

        dirs, nondirs = self.listitems(id)
                
        if topdown:
            yield id, dirs, nondirs

        for mydir in dirs:
            tmp = (mydir[0], pjoin(id[1], mydir[1]))
            for x in self.walk(tmp, topdown):
                yield x

        if not topdown:
            yield id, dirs, nondirs
    
    def listitems(self, id):
        """ return a tuple of lists of tuples (dirs, nondirs) of all the items in this folder """
        dirs, nondirs = [], []
        ptr = self.pst.get_ptr(id[0])
        ptr = ptr.child
        while(ptr):
            item = self.getitem(ptr.id)
            if item:
                if isinstance(item, Pstfile.Folder):
                    dirs.append((ptr.id, item.file_as))
                else:
                    nondirs.append((ptr.id, "%s:%i" % (item.__class__.__name__,ptr.id)))
            ptr = ptr.next
        return (dirs, nondirs)

    def getitem(self, id):
        """ item dispatcher, returns an allocated item (consumes memory) """
        ptr = self.pst.get_ptr(id)
        item = self.pst.get_item(ptr)
        if(item):
            if item.folder:
                ret = self.Folder(self.pst, ptr, item)
            elif item.contact:
                ret = self.Contact(self.pst, ptr, item)
            elif ( item.email and item.type == pypst.PST_TYPE_NOTE or item.type == pypst.PST_TYPE_REPORT ):
                ret = self.Email(self.pst, ptr, item)
            elif item.type == pypst.PST_TYPE_JOURNAL:
                ret = self.Journal(self.pst, ptr, item)
            elif item.type == pypst.PST_TYPE_APPOINTMENT:
                ret = self.Appointment(self.pst, ptr, item)
            else:
                ret = None
            return ret
        else:
            return None

    def open(self, id):
        """ return a file-like item or attachment
        Email attachments can be opened directly using the id syntax itemid:attach_number eg. 1234:1
        The attachment '0' is actually the email header and main body(part1)"""
        parts = id.split(':')
        item = self.getitem(int(parts[0]))
        if len(parts) > 1:
            if parts[1] != '0':
                return item.getattach(int(parts[1])-1)
        return item