#!/usr/bin/python

#### TODO ####
#### Check for memory leaks in the pypst module calls

import pypst

class Pstfile:
    """ shadow class for libpst, impliments an filesystem-like interface into pst files """

    class Item:
        """ Base class to represent pst items (email, contact, journal, appointment, attachment, folder)
        These will allow access to all the member of the corresponding C structs
        In addition, they have a 'read' method which should return something sensible
        for use in scanning etc. Do NOT keep references to 'ptr' and 'item' they will
        be free'd, classes must grab everything they want inside the constructor.
        """
        def __init__(self, ptr, item):
            self.id = ptr.id
            
        def __str__(self):
            return "I am a %s" % self.__class__

        def read(self):
            pass

    class Email(Item):
        """ email item """

    class Contact(Item):
        """ contact item """

    class Journal(Item):
        """ contact item """

    class Appointment(Item):
        """ appointment item """

    class Folder(Item):
        """ folder item """
        def __init__(self, ptr, item):
           Pstfile.Item.__init__(self, ptr, item)
           self.name = item.file_as

        def __str__(self):
            return self.name
        
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
        #get a list of id's in this dir(chain)
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
            item.free()
            ptr = ptr.next
        return (tuple(dirs), tuple(nondirs))
    
    def getitem(self, id):
        """ item dispatcher """
        ptr = self.pst.get_ptr(id)
        item = self.pst.get_item(ptr)
        if(item):
            if item.folder:
                ret = self.Folder(ptr, item)
            elif item.contact:
                ret = self.Contact(ptr, item)
            elif ( item.email and item.type == pypst.PST_TYPE_NOTE or item.type == pypst.PST_TYPE_REPORT ):
                ret = self.Email(ptr, item)
            elif item.type == pypst.PST_TYPE_JOURNAL:
                ret = self.Journal(ptr, item)
            elif item.type == pypst.PST_TYPE_APPOINTMENT:
                ret = self.Appointment(ptr, item)
            else:
                ret = None
            item.free()
            return ret
        else:
            return None

    def open(self, id):
        """ return a file-like item """
        return self.getitem(id)
