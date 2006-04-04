import pyflag.Reports as Reports
import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework
import pyflag.format as format
import pyflag.DB as DB
import pyflag.HTMLUI as HTMLUI
import plugins.FileFormats.BasicFormats as BasicFormats

def numeric(num_str):
    try:
        if num_str.find('0x') == 0:
            result = int(num_str[2:],16)
        else:
            result = int(num_str)
    except TypeError:
        result = 0

    return result

class DynamicStruct(BasicFormats.SimpleStruct):
    def init(self):
        self.fields=[]

class AlignedOffset(format.DataType):
    visible = True
    def __init__(self, buffer, parameters, *args, **kwargs):
        self.buffer = buffer
        self.parameters = parameters

    def size(self):
        """ This consumes as many bytes until the next alignment boundary """
	align = numeric(self.parameters['alignment'])

	if self.buffer.offset % align == 0:
	    size = 0
	else:
	    size = align - (self.buffer.offset % align)

        return size 

    def __str__(self):
        return "Offset %X Aligned to %s\nat 0x%08X (%X consumed)" % (self.buffer.offset, self.parameters['alignment'],
                                        self.buffer.offset + self.size(), self.size())

    def form(self,prefix, query,result):
        result.textfield("Alignment boundary",prefix+"alignment")

class SearchFor(format.DataType):
    visible = True
    def __init__(self, buffer, parameters, *args, **kwargs):
        self.buffer = buffer
        self.parameters = parameters

    def size(self):
        """This consumes as many bytes until the search string is found """
        strbuffer = buffer.read(0, int(self.parameters['within']))
        size = strbuffer.find(self.parameters['search'])
        if size == -1:
            raise NotFound
            
        return size

    def __str__(self):
        return "Search for %s" % self.parameters['search']

    def form(self, prefix, query, result):
        result.textfield("Search string",prefix+"search")
        result.textfield("within n bytes",prefix+"within")
        
class HexDump(BasicFormats.STRING):
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
#    parameters = { "foo": "any"}


    def analyse(self, query):
        pass
##        fd=open("/home/michael/dev/SERevEng/T630/SE_T630_351295000248246_23Apr05.bin")
##        fd.seek(8*1024*1024)

#    def analyse(self, query,result):
#        fd=open("/var/tmp/SEReveng/SE_T630_351295000248246_23Apr05.bin")
#        fd.seek(8*1024*1024)


    def display(self, query, result):
        
        def popup_cb(query, ui, column_number = None):
            """Popup for defining column attributes"""
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

        def render_HTMLUI(data):
            """Callback to render mysql stored data in HTML"""
            tmp = result.__class__(result)
            tmp.result = data
            return tmp

        ##### Display starts here
        
        try:
            result.heading("Data Analysis Facilitation Tool")
            dbh=DB.DBO(query['case'])
            result.start_form(query)

            result.textfield("Starting Offset","StartOffset",size=20)
            result.textfield("Maximum Rows","MaxRows")
            result.end_table()
          

            fd=open("/home/michael/dev/SERevEng/T630/SE_T630_351295000248246_23Apr05.bin")

            ## Build a struct to work from:
            try:
                startoffset = numeric(query['StartOffset'])
            except KeyError:
                startoffset = 0

            try:
                maxrows = numeric(query['MaxRows'])
            except KeyError:
                maxrows = 10
                
            buf = format.Buffer(fd=fd)[startoffset:]

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

##                    print parameters
                    struct.fields.append((Registry.FILEFORMATS[query['data_type_%s' % count]],
                                          parameters[count],
                                          query['name_%s' % count]
                                          ))
                    count+=1
                    
                except KeyError:
                    break

            popup_row = ['']
            headings = ['']
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

            result.row(*popup_row)


            struct.read(buf)

            print struct.fields

            for i in range(count):
                tmp = result.__class__(result)
                tmp.text(query['name_%s' % i], color="red", font="bold")
                headings.append(tmp)

            result.row(*headings)

            for i in range(count):
                tmp = result.__class__(result)
                struct.data[query['name_%s' % i]].display(tmp)
                row_view.append( tmp)

##            result.row(*row_view)

            ######## Attempting multiple table rows here
            rc = 0
            offset = 0
            while 1:
                for i in range(count):
                    try:
                        name = query['name_%s' % i]
                        value = struct.data[name].get_value()
                        row_data_types.append(struct.data[name].sql_type)

                        if rc == 0:
                            if(isinstance(value, result.__class__)):
                                row_htmls.append(name)

                        row_data[name]=value
                        row_data_names.append(name)

                    except AttributeError:
                        pass


                #### DBH can't create a table when there are no fields
                if len(row_data_names) == 0:
                    break;

                if rc == 0:
                    dbh.execute("drop table if exists reveng")
                    dbh.execute("""create table reveng  (`Row` int,"""+
                                ",".join(
                        ["`%s` %s" % (row_data_names[i],row_data_types[i])
                         for i in range(len(row_data_names))]
                        )+
                                ")")

                dbh.mass_insert_start("reveng")
                row_data['Row'] = rc
                dbh.mass_insert( **row_data)
                dbh.mass_insert_commit()

                print struct.size()
                offset += struct.size()
                buf = buf[offset:]
                struct.read(buf)
                rc += 1

                if rc > maxrows:
                    break

            dbh.set_meta("reveng_HTML", ",".join(row_htmls))


            ###########################################


            row_htmls = dbh.get_meta("reveng_HTML").split(",")
            cb={}
            count=0
            names=['Row']
            try:
                while 1:
                    name = "`%s`" % query['name_%s' % count]
                    names.append(name)
                    if name in row_htmls:
                        cb[name] = render_HTMLUI

                    count+=1
            except KeyError:
                pass

            try:
                result.table(
                    names= names,
                    columns = names,
                    callbacks = cb,
                    table = "reveng",
                    case = query['case']
                    )
            except IndexError:
                pass

                            
            result.end_form()

        except KeyError,e:
            result.case_selector()
            print "%r%s%s" %(e,e,FlagFramework.get_bt_string(e))



    def reset(self, query):
        dbh = self.DBO(query['case'])
        dbh.execute("drop table daft")
