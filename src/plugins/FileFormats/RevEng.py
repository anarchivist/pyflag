import pyflag.Reports as Reports
import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework
import pyflag.format as format
import pyflag.DB as DB
import pyflag.HTMLUI as HTMLUI
from plugins.FileFormats.BasicFormats import *

class DynamicStruct(SimpleStruct):
    def init(self):
        self.fields=[]

class AlignedOffset(format.DataType):
    visible = True
    def __init__(self, buffer, parameters, *args, **kwargs):
        self.buffer = buffer
        self.parameters = parameters
##        try:
##            if buffer.offset % int(parameters['alignment']):
##                raise IOError("Not aligned: offset is %s - alignment is %s" % (buffer.offset, parameters['alignment']))
##        except KeyError:
##            pass

    def size(self):
        """ This consumes as many bytes until the next alignment boundary """
	align = self.parameters['alignment']

	### Allow alignment to be entered in dec or hex (0x)
	if align.find('0x') == 0:
	    align = int(align[2:],16)
	else:
	    align = int(align)

	if self.buffer.offset % align == 0:
	    size = 0
	else:
	    size = align - (self.buffer.offset % align)

        return size 

    def __str__(self):
        return "Aligned to %s\nat 0x%08X" % (self.parameters['alignment'],
                                        self.buffer.offset + self.size())

    def form(self,prefix, query,result):
        result.textfield("Alignment boundary",prefix+"alignment")

class HexDump(STRING):
    sql_type = "text"
    
    def display(self, result):
        h=FlagFramework.HexDump(self.__str__(),result)
        h.dump()

    def get_value(self):
        tmp = HTMLUI.HTMLUI(None)
        self.display(tmp)
        return tmp

class RevEng_GUI(Reports.report):
    """ Allows us to manipulate data structures in reverse engineering efforts """
    name = "DAFT"
    family = "Misc"
    description = "Data Analysis Facilitation Tool (Reverse Engineering)"
##    parameters = { "foo": "any"}

#    def analyse(self, query,result):
#        fd=open("/var/tmp/SEReveng/SE_T630_351295000248246_23Apr05.bin")
#        fd.seek(8*1024*1024)

    def display(self, query, result):
        result.start_form(query)
        try:
            result.heading("Data Analysis Facilitation Tool")
            dbh=DB.DBO(query['case'])
            result.start_form(query)

            result.textfield("Starting Offset","StartOffset",size=20)
            result.end_table()
          
            def popup_cb(query, ui, column_number = None):
                print "I am here"
                ui.decoration = "naked"
                
                try:
                    if query['finish'] and query['name_%s' % column_number]:
                        del query['finish']
                        del query['submit']
                        
                        ui.refresh(0,query,parent=1)
                except KeyError:
                    pass
                
                ui.start_form(query)
                ui.start_table()
                ui.heading("Column number %s" % column_number)
                names = [ x.__name__ for x in Registry.FILEFORMATS.classes if x.visible ]

                ui.textfield("Name for this field", "name_%s" % column_number)
                ui.const_selector("Data Type", 'data_type_%s' % column_number, names, names)
                try:
                    temp = Registry.FILEFORMATS[query['data_type_%s' % column_number]]("",None)
                    ui.row("Description", temp.__doc__)

                    temp.form("parameter_%s_" % column_number, query,ui)
                except KeyError,e:
                    pass
                
                ui.checkbox("Visible","visible_%s" % column_number, "yes", checked=True)
                ui.checkbox("Click here to finish", "finish","yes");
                ui.end_table()
                ui.end_form()
                return ui

            fd=open("/var/tmp/SEReveng/SE_T630_351295000248246_23Apr05.bin")
            ## Build a struct to work from:
            try:
                startoffset = query['StartOffset']
                if startoffset.find('0x') == 0:
                    startoffset = int(startoffset[2:],16)
                else:
                    startoffset = int(startoffset)
                
            except KeyError:
                startoffset = 0
            buf = format.Buffer(fd=fd)[startoffset:]


            while 1:
                try:
                    struct = DynamicStruct(buf)

                    count = 0
                    parameters={}
                    while 1:
                        try:
                            parameters[count]={}
                            for k in query.keys():
                                key = 'parameter_%s_' % count
                                if k.startswith(key):
                                    parameters[count][k[len(key):]] = query[k]

                            print parameters
                            struct.fields.append((Registry.FILEFORMATS[query['data_type_%s' % count]],
                                                  parameters[count],
                                                  query['name_%s' % count]
                                                  ))
                        except KeyError:
                            break

                        count+=1 

                    popup_row = []
                    headings = []
                    data = []
                    row_data = {}
                    row_data_names = []
                    row_data_types = []
                    row_view = []
                    row_htmls = []
                    for i in range(count+1):
                        tmp = result.__class__(result)
                        tmp.popup(FlagFramework.Curry(popup_cb, column_number = i)
                                  ,"Edit", icon="red-plus.png")
                        popup_row.append(tmp)

                    

                    struct.read(buf)

                    print struct.fields

                    for i in range(count):
                        tmp = result.__class__(result)
                        tmp.text(query['name_%s' % i], color="red", font="bold")
                        headings.append(tmp)

                        tmp = result.__class__(result)
                        struct.data[query['name_%s' % i]].display(tmp)
                        row_view.append( tmp)

                        try:
                            name = query['name_%s' % i]
                            value = struct.data[name].get_value()
                            row_data_types.append(struct.data[name].sql_type)

                            if(isinstance(value, result.__class__)):
                                row_htmls.append(name)
                            
                            row_data[name]=value
                            row_data_names.append(name)
                            
                        except AttributeError:
                            pass

                    result.row(*popup_row)
                    result.row(*headings)
                    result.row(*row_view)
                except IOError:
                    buf = buf[1:]

                dbh.execute("drop table if exists reveng")
                dbh.execute("""create table reveng  ("""+
                            ",".join(
                    ["`%s` %s" % (row_data_names[i],row_data_types[i])
                     for i in range(len(row_data_names))]
                    )+
                            ")")
                
                dbh.set_meta("reveng_HTML", ",".join(row_htmls))
                dbh.mass_insert_start("reveng")
                dbh.mass_insert(**row_data)
                dbh.mass_insert_commit()

                ###########################################

                def render_HTMLUI(data):
                    tmp = result.__class__(result)
                    tmp.result = data
                    return tmp

                row_htmls = dbh.get_meta("reveng_HTML").split(",")
                cb={}
                count=0
                names=[]
                try:
                    while 1:
                        name = query['name_%s' % count]
                        names.append(name)
                        if name in row_htmls:
                            cb[name] = render_HTMLUI

                        count+=1
                except KeyError:
                    pass
                
                result.table(
                    names= names,
                    columns = names,
                    callbacks = cb,
                    table = "reveng",
                    case = query['case']
                    )

                if len(buf)==0:
                    break
                
                break

        except KeyError,e:
            result.case_selector()
            print "%r%s%s" %(e,e,FlagFramework.get_bt_string(e))


    def reset(self, query):
        dbh = self.DBO(query['case'])
        dbh.execute("drop table daft")
