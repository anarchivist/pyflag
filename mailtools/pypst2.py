#!/usr/bin/python

#### TODO ####
#### Check for memory leaks in the pypst module calls

import pypst
import re

class Pstfile:
    """ higher level shadow class for libpst
    impliments an filesystem-like interface into pst files
    for use in flag """

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
            
        def free(self):
            pypst._pst_freeItem(self._item)

        def __del__(self):
            if self._item:
                self.free()

        def __str__(self):
            return self.read()

        def read(self):
            return "I am a %s" % self.__class__

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
                
            def read(self):
                return self.data
        
        def attach(self):
            """ iterate through attachments """
            attach = self._item.attach
            while attach:
                yield Pstfile.Email.Attachment(self.pst, attach)
                attach = attach.next
            
        def read(self):
            email = self._item.email
            base64enc = False
            retstr = ''
            if email.header:
                retstr = email.header.replace('\r','')
                m = re.search('Content-Transfer-Encoding:\s+base64',retstr,re.IGNORECASE)
                if m:
                    base64enc = True
            if email.body:
                if base64enc:
                    retstr += base64.decodestring(email.body)
                else:
                    retstr += email.body.replace('\r','')
            if email.htmlbody:
                if base64enc:
                    retstr += base64.decodestring(email.htmlbody)
                else:
                    retstr += email.htmlbody.replace('\r','')
            if email.rtf_compressed:
                #### WARNING: MEMORY LEAK ####
                #retstr += pypst.rtf_decompress(email.rtf_compressed)
                retstr += "Libpst: RTF compressed body found, not currently suppored\n"
            if email.encrypted_body or email.encrypted_htmlbody:
                retstr += "Libpst: Encrypted body found, not currenlty supported\n"

            for a in self.attach():
                retstr += "Got Attachment: %s\n" % a.filename1
                #fd = open('/tmp/attachment_%s' % a.filename1, 'w')
                #fd.write(a.data)
                #fd.close()
                #retstr += a.data

            return retstr

    class Contact(Item):
        """ contact item """
        ### FIXME, theres heaps more stuff to stick in here...
        # is there a way to cycle through all these without knowing them by name?
        fields = ('fullname','surname','first_name','middle_name',
                  'display_name_prefix','suffix','nickname','address1',
                  'address2','address3','birthday')

        def read(self):
            retstr = ''
            contact = self._item.contact
            for field in Pstfile.Contact.fields:
                val = contact.__getattr__(field)
                if val:
                    retstr += "%s: %s\n" % (field.title(), val)
            return retstr
        
    class Journal(Item):
        """ contact item """

    class Appointment(Item):
        """ appointment item """

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
        ptr = self.pst.getTopOfFolders(self.pst.get_item(self.pst.d_head))
        self.rootid = ptr.id

    def close(self):
        """ close pst file """
        self.pst.close()
        
    def walk(self, id, topdown=True):
        """ emulate the os.walk directory tree generator, uses item ids, NOT strings """
        if not id:
            print "WTF happened"

        dirs, nondirs = self.listitems(id)
                
        if topdown:
            yield id, dirs, nondirs

        for mydir in dirs:
            for x in self.walk(mydir, topdown):
                yield x

        if not topdown:
            yield id, dirs, nondirs

    def listitems(self, id):
        """ return a tuple of tuples (dirs, nondirs) of all the items in this folder """
        dirs, nondirs = [], []
        ptr = self.pst.get_ptr(id)
        ptr = ptr.child
        while(ptr):
            item = self.pst.get_item(ptr)
            if item:
                if item.folder:
                    dirs.append(ptr.id)
                elif (item.contact
                      or ( item.email and item.type == pypst.PST_TYPE_NOTE or item.type == pypst.PST_TYPE_REPORT )
                      or item.type == pypst.PST_TYPE_JOURNAL
                      or item.type == pypst.PST_TYPE_APPOINTMENT ):
                    nondirs.append(ptr.id)
                else:
                    # found something we cant deal with
                    pass
            pypst._pst_freeItem(item)
            ptr = ptr.next
        return (tuple(dirs), tuple(nondirs))
    
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
        """ return a file-like item """
        return self.getitem(id)
