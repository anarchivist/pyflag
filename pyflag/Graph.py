# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG 0.4 (12-02-2004)
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

""" Graph UI implementations.

The Abstract base class must be extended for implementation of graph drawing. Reports may call this class in order to draw a graph. By calling the UI's graph method this graph may be installed properly within the UI """

import pyflag.conf
config=pyflag.conf.ConfObject()

import os,pipes

class GraphException(Exception): pass

class Image:
    """ Class defining the Image Interface.

    Note that this class implements a very simple image interface. The only requirements on this interface is that there are the following methods:

    >>>  def GetContentType(self)
    >>>  def SetFormat(self,format)
    >>>  def display(self)
    """
    out_format = 'png'

    def __init__(self,data):
        self.data=data

    def GetContentType(self):
        """ This should produce the proper mime-type for this image class.

        The default implementation uses magic to determine the content type. This is sufficiently intelligent for most applications. The only reason you might want to override this is if the extra overhead of displaying the image twice is too prohibitive.
        """
        import pyflag.FlagFramework as FlagFramework

        magic = FlagFramework.Magic(mode='mime')
        return magic.buffer(self.display())
    
    def SetFormat(self,format):
        """ A function used to set the output format.

        The caller specifies the format the image is requested in. If the implementation can not produce output in this format, the best format prefered by the implementation is returned, otherwise the requested format is returned.
        
        @arg format: Requested format.
        @return: Best format prefered by the implementation, or the requested format if available """
        self.out_format = format
        return format
        
    def display(self):
        """ Displays the image in the format specified in out_format if possible.

        @return: A binary string representing the image in its requested format.
        """
        return self.data

class GenericGraph(Image):
    """ Abstract class defining the graph interface.

    @cvar out_format: The output format to use. Currently all these could be SVG, PNG, X11 but not all derived classes implement all of those. This class variable may be set by the relevant UI backend.
    """
    out_format = 'svg'
    
    def __init__(self,**opts):
        """ A constructor with options.

        The following options are supported:
        """
        
class Ploticus(GenericGraph):
    """ Graph implementation using the ploticus plotting package """
    def __init__(self,**opts):
        import conf,os

        os.environ['PLOTICUS_PREFABS'] = config.PLOTICUS_PREFABS

    def hist(self,x,y,**opts):
        """ Draw a Histogram.

        @arg x: A list of x values to use
        @arg y: A list of y values to use
        @arg opts: The currently supported options are:
             - xlabels (list): specifies that the x list should be treated as labels
        """
        cmd = " -prefab vbars data=stdin x=1 y=2 delim=csv "
        options = [ "%s=%r" % (k,v) for k,v in opts.items() ]
        self.cmd = cmd + " ".join(options)
        self.input = ''
        ## Now work out the input:
        for i,j in zip(x,y):
            self.input += '"%s","%s"\n' % (i,j)

    def pie(self,lables,values,**opts):
        """ Draw a Pie Chart.

        @arg lables: A list of labels
        @arg values: A list of y values to use
        @arg opts: Options
        """
        #Array with all the colors in it:
        colors="red orange green purple yellow blue magenta tan1 coral tan2 claret pink brightgreen brightblue limegreen yellowgreen lavender powderblue redorange lightorange".split(" ")

        try:
            colors = opts['colors'].split(" ")
            del opts['colors']
        except KeyError:
            pass
        
        cmd = " -prefab pie data=stdin labels=1 values=2 colorfld=3 delim=csv "
        options = [ "%s=%s" % (k,v) for k,v in opts.items() ]
        self.cmd = cmd + " ".join(options)
        self.input = ''

        while len(colors) < len(values):
            colors += colors
        
        ## Now work out the input:
        for i,j,k in zip(lables,values,colors):
            self.input += '"%s","%s",%s\n' % (i,j,k)
        
    def line(self,x,y,**opts):
        """ Draws a line plot.

        @arg x: A list of x values to use
        @arg y: A list of y values to use
        @arg opts: The currently supported options are:
             - xlabels (list): specifies that the x list should be treated as labels

        """
        ## Here we just need to work out the command line:
        cmd = " -prefab lines data=stdin x=1 y=2 delim=csv "
        if opts.has_key("xlabels"):
            cmd += " cats=yes "

        self.cmd = cmd

        self.input = ''
        ## Now work out the input:
        for i,j in zip(x,y):
            self.input += '"%s","%s"\n' % (i,j)

    def display(self):
        import popen2

        p = popen2.Popen3("%s  -%s -o stdout  %s " % (config.PLOTICUS,self.out_format,self.cmd))
        p.tochild.write(self.input)
        p.tochild.close()
        data=p.fromchild.read()
        return data

Graph = Ploticus

class Thumbnailer(Image):
    """ An image class to display thumbnails files.
    
    Users of this class need to implement the Extract method, and an appropriate initialiser.
    This object is derived from the Image class, and knows how to create thumbnails of itself.
    Any type of object may be stored here and used in the UI.image method. The content type will be deduced automatically using magic.

    If you want to teach this object how to create more thumbnails, add more methods and update the dispatcher accordingly.

    @cvar dispatcher: A dictionary that manages access to the different thumbnail creation routines. The keys should be the relevant mime type, while the values are the string name of the method.
    """
    def Extract(self):
        """ Returns the original file as a binary string
        @note: This function is a generator yielding a small amount on each call.
        """

    def Extract_size(self,size):
        """ Calls Extract until it obtains at least size bytes. """
        result=''
        for i in self.Extract():
            result+=i
            if len(result)>size:
                break

        return result

    def set_image(self,name):
        """ Sets the thumbnail to a constant image """
        fd = open("%s/%s" % (config.IMAGEDIR,name))
        result = fd.read()
        fd.close()
        self.content_type='image/png'
        return result

    def Unknown(self):
        """ Default handler """
        return self.set_image("unknown.png")

    def PDFHandler(self):
        """ Handle PDF Documents """
        return self.set_image("pdf.png")
    
    def MSOffice(self):
        """ Handle MSOffice Documents """
        return self.set_image("msoffice.png")

    def MpegHandler(self):
        """ Perform Video Thumbnailing with mplayer """

        # try to create thumbnail
        try:
            mplayer = os.popen('cd /tmp; mplayer -vo png -ao null -frames 1 -', 'w')
            mplayer.write(self.Extract_size(1000000))
            mplayer.close()
        except IOError:
            pass

        try:
            # see if the thumb was created
            fd = open('/tmp/00000001.png')
            result = fd.read()
            fd.close()
            try:
                import glob
                for i in glob.glob('/tmp/000*.png'):
                    os.remove(i)
            except OSError, e:
                pass
            self.content_type='image/png'
            return result
        except (IOError,OSError), e:
            return self.set_image("broken.png")
        
    def JpegHandler(self):
        """ Handles Jpeg thumbnails

        @arg data: binary string representing the image
        """
        try:
            os.mkdir("%s/%s/" %(config.RESULTDIR,self.tempdir))
        except OSError:
            pass
        
        #First try to see if the file is already there from last time.
        try:
            reader=open("%s/%s/%s.jpg" % (config.RESULTDIR,self.tempdir,self.temp_name),'r')
            result = reader.read()
            reader.close()
            print "Read file from  cache %s/%s/%s.jpg" % (config.RESULTDIR,self.tempdir,self.temp_name)
            return result
        except IOError:
            result=self.Extract_size(1000000)

        #If the file is not there, make it.
        try:
            t = pipes.Template()
            t.append("%s/djpeg -scale 1/2" % config.FLAG_BIN,'--')
            t.append("%s/cjpeg" % config.FLAG_BIN,'--')
            writer = t.open("%s/%s/%s.jpg" % (config.RESULTDIR,self.tempdir,self.temp_name),'w')
            writer.write(result)
            writer.close()
            print "Made file %s/%s/%s.jpg" % (config.RESULTDIR,self.tempdir,self.temp_name)
        except IOError:
            pass

        #Now try to open it again
        try:
            reader=open("%s/%s/%s.jpg" % (config.RESULTDIR,self.tempdir,self.temp_name),'r')
            result = reader.read()
            reader.close()
        except IOError:
            pass        

        #If that failed, just return the original file.
        return result

    def Null(self):
        """ A do nothing method that just returns the original image as its thumbnail. """
        return self.Extract_size(1000000)
        
    dispatcher ={"image/jpg":"JpegHandler","image/jpeg":"JpegHandler",
                 "image/png":"Null","image/gif":"Null",
# commented out mplayer stuff cos its kinda slow, cool but...
#                 "video/mpeg":"MpegHandler","video/x-msvideo":"MpegHandler",
#                 "video/x-ms-asf":"MpegHandler",
                 "application/pdf":"PDFHandler",
#                 "video/quicktime":"MpegHandler",
                 "application/msword":"MSOffice",
		 "application/msaccess":"MSOffice",
                 }    
    def __init__(self,tempdir,temp_name):
        """ A do nothing constructor. Derived classes will want to extend this as they see fit. """
        self.tempdir=tempdir
        self.temp_name=temp_name
 
    def display(self):
        generator=self.Extract()
        try:
            self.data=generator.next()
        except AttributeError:
            self.data=generator
            generator=()
        except StopIteration:
            self.data=''
            generator=()
            
        import pyflag.FlagFramework as FlagFramework
            
        magic=FlagFramework.Magic(mode='mime')
        self.content_type=magic.buffer(self.data)
        magic=FlagFramework.Magic()
        self.magic=magic.buffer(self.data)

        ## Use the content type to access the thumbnail
        try:
            method=getattr(self,self.dispatcher[self.content_type])
            return method()
        except KeyError:
            return self.Unknown()

    def GetMagic(self):
        try:
            return self.magic
        except AttributeError:
            #We call our display method so that the content type gets set
            self.display()
            return self.magic

    def GetContentType(self):
        try:
            return self.content_type
        except AttributeError:
            #We call our display method so that the content type gets set
            self.display()
            return self.content_type

    def SetFormat(self,format):
        """ We only support jpeg here """
        return 'jpeg'

class FileThumb(Thumbnailer):
    """ Simple thumbnailer for file-like objects. """
    def Extract(self):
        self.fd.seek(0)
        while 1:
            f=self.fd.read(self.limit)
            if not f: return
            yield f

    def __init__(self,fd,limit=1024*1024):
        Thumbnailer.__init__(self,"case_%s" % (fd.case),"%s_%s" % (fd.table,fd.inode))
        self.fd = fd
        self.limit=limit

class FileDump(FileThumb):
    """ This simply returns the file with an appropriate mime type"""
    ## We dont want to produce any thumbnails
    dispatcher = {}

    def __init__(self,fd,limit=None):
        FileThumb.__init__(self,fd,limit)
        self.fd = fd
        self.limit = limit

    ## Copy the binary data out as is.
    def Unknown(self):
        result=''
        for r in self.Extract():
            result+=r
            if self.limit and len(result)>self.limit:
                break

        return result
