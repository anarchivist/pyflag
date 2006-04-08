import pyflag.Reports as Reports
import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework
import pyflag.format as format
import pyflag.DB as DB
import pyflag.HTMLUI as HTMLUI
import plugins.FileFormats.DAFTFormats as DAFTFormats

class RevEng_GUI(Reports.report):
    """ Allows us to manipulate data structures in reverse engineering efforts """
    name = "DAFT"
    family = "Misc"
    description = "Data Analysis Facilitation Tool (Reverse Engineering)"
#    parameters = { "foo": "any"}


    def analyse(self, query):
        pass

    def display(self, query, result):
        
        def popup_cb(query, ui, column_number = None, mode = ''):
            """Popup for defining column attributes"""
            print "I am here"
            ui.decoration = "naked"

            if mode == 'insert':
                pre = 'insert_'
            else:
                pre = ''
            try:
                if query['finish'] and query['%sname_%s' % (pre, column_number)]:
                    del query['finish']
                    del query['submit']

                    ui.refresh(0,query,parent=1)
            except KeyError:
                pass

            ui.start_form(query)
            ui.start_table()
            if mode == 'insert':
                ui.heading("Inserting Column number %s" % column_number)
            else:
                ui.heading("Column number %s" % column_number)
            names = [ x.__name__ for x in Registry.FILEFORMATS.classes if x.visible ]

            ui.textfield("Name for this field", "%sname_%s" % (pre, column_number))
            ui.const_selector("Data Type", '%sdata_type_%s' % (pre, column_number),
                              names, names)
            try:
                temp = Registry.FILEFORMATS[query['%sdata_type_%s' % (pre,
                              column_number)]]("",None)
                ui.row("Description", temp.__doc__)

                temp.form("%sparameter_%s_" % (pre, column_number), query,ui)
            except KeyError,e:
                pass

            ui.checkbox("Visible","%svisible_%s" % (pre, column_number), "yes",
                        checked=True)
            ui.checkbox("Click here to finish", "finish","yes");
            ui.end_table()
            ui.end_form()
            return ui

        def delete_col_cb(query, ui, column_number = None):
            """Popup to confirm deletion of column"""
            ui.decoration = "naked"
            ui.heading("Delete column number %s?" % column_number)
            try:
                if query['submit']:
                    del query['submit']
                    ui.refresh(0,query,parent=1)
            except KeyError:
                pass

            ui.start_form(query)
            ui.checkbox("Click here to delete", "delete_%s" % column_number, "yes")
            ui.end_form()
            return ui

        def processquery(query):
            delcol = -1
            insvalues={}
            
            for k in query.keys():
                if k.startswith('delete_'):
                    delcol = int(k[7:])
                    del query[k]
                    break
                elif k.startswith('insert_'):
                    insvalues[k[7:]] = query[k]
                    if k.startswith('insert_name_'):
                        inscol = int(k[12:])
                    del query[k]
                    continue
                    ### other stuff for ins col parameters
            
            if delcol >= 0:
                count = delcol
                while 1:
                    try:
                        query['name_%s' % count]
                        count += 1
                    except KeyError:
                        break
                for i in range(delcol+1, count):
                    del query['name_%s' % (i-1)]
                    del query['data_type_%s' % (i-1)]
                    del query['visible_%s' % (i-1)]
                    params = [k for k in query.keys() if
                              k.startswith('parameters_%s_' % (i-1))]
                    for parameter in params:
                        del query[parameter]

                    query['name_%s' % (i-1)] = query['name_%s' % i]
                    query['data_type_%s' % (i-1)] = query['data_type_%s' % i]
                    query['visible_%s' % (i-1)] = query['visible_%s' % i]
                    key = 'parameter_'
                    params = [k[11+len('%s'%i):] for k in query.keys() if
                              k.startswith('%s%s_' % (key,i))]
                    for parameter in params:
                        query['%s%s_%s'%(key, (i-1), parameter)] = query['%s%s_%s'%(key, i, parameter)]
                    
                del query['name_%s' % (count-1)]
                del query['data_type_%s' % (count-1)]
                del query['visible_%s' % (count-1)]
                params = [k for k in query.keys() if
                          k.startswith('parameter_%s_' % (count-1))]
                for parameter in params:
                    del query[params]
            elif len(insvalues) > 0:
                count = inscol
                while 1:
                    try:
                        query['name_%s' % count]
                        count +=1
                    except KeyError:
                        break
                for i in range(count, inscol, -1):
                    query['name_%s' % i] = query['name_%s' % (i-1)]
                    query['data_type_%s' % i] = query['data_type_%s' % (i-1)]
                    query['visible_%s' % i] = query['visible_%s' % (i-1)]
                    key = 'parameter_'
                    params = [k[11+len('%s'%(i-1)):] for k in query.keys() if
                              k.startswith('%s%s_' % (key,(i-1)))]
                    for parameter in params:
                        query['%s%s_%s'%(key, i, parameter)] = query['%s%s_%s'%(key, (i-1), parameter)]
                    del query['name_%s' % (i-1)]
                    del query['data_type_%s' % (i-1)]
                    del query['visible_%s' % (i-1)]
                    params = [k for k in query.keys() if
                              k.startswith('parameter_%s_' % (i-1))]
                    for parameter in params:
                        del query[parameter]
                for k in insvalues.keys():
                    query[k] = insvalues[k]

            
        def render_HTMLUI(data):
            """Callback to render mysql stored data in HTML"""
            tmp = result.__class__(result)
            tmp.result = data
            return tmp

        ##### Display starts here
        
        try:
            result.heading("Data Analysis Facilitation Tool")
            dbh=DB.DBO(query['case'])

            processquery(query)
            result.start_form(query)

            result.textfield("Starting Offset","StartOffset",size=20)
            result.textfield("Maximum Rows","MaxRows")
            result.end_table()
          

            fd=open("/home/michael/dev/SERevEng/T630/SE_T630_351295000248246_23Apr05.bin")

            ## Build a struct to work from:
            try:
                startoffset = DAFTFormats.numeric(query['StartOffset'])
            except KeyError:
                startoffset = 0

            try:
                maxrows = DAFTFormats.numeric(query['MaxRows'])
            except KeyError:
                maxrows = 10
                
            buf = format.Buffer(fd=fd)[startoffset:]

            struct = DAFTFormats.DynamicStruct(buf)
            struct.create_fields(query, 'parameter_')
            
#            result.row(*popup_row)

            struct.read(buf)
            popup_row = {}
            for i in range(struct.count):
                tmp = result.__class__(result)
                tmp.popup(FlagFramework.Curry(popup_cb, column_number = i,
                          mode='insert'), "Insert column", icon="insert.png")
                tmp.popup(FlagFramework.Curry(popup_cb, column_number = i)
                          ,"Edit column", icon="edit.png")
                tmp.popup(FlagFramework.Curry(delete_col_cb, column_number = i)
                          ,"Delete column", icon="delete.png")
                popup_row[query['name_%s' % i]]=tmp

            result.popup(FlagFramework.Curry(popup_cb, column_number = struct.count)
                          ,"Add new column", icon="red-plus.png")

                    
            ######## Creating table rows here
            data = []
            row_data = {}
            row_data_names = []
            row_data_types = []
            row_htmls = []

            rowcount = 0
            while 1:
                for i in range(struct.count):
                    try:
                        name = query['name_%s' % i]
                        value = struct.data[name].get_value()
                        row_data_types.append(struct.data[name].sql_type)

                        if rowcount == 0:
                            if(isinstance(value, result.__class__)):
                                row_htmls.append(name)

                        row_data[name]=value
                        row_data_names.append(name)

                    except AttributeError:
                        pass
                    except IOError:
                        break


                #### DBH can't create a table when there are no fields
                if len(row_data_names) == 0:
                    break;

                if rowcount == 0:
                    dbh.execute("drop table if exists reveng")
                    dbh.execute("""create table reveng  (`Row` int,"""+
                                ",".join(
                        ["`%s` %s" % (row_data_names[i],row_data_types[i])
                         for i in range(len(row_data_names))])+")")

                dbh.mass_insert_start("reveng")
                row_data['Row'] = rowcount
                dbh.mass_insert( **row_data)
                dbh.mass_insert_commit()

                if rowcount >= maxrows - 1:
                    break

                buf = buf[struct.size():]
##                print "buffer length: %d, struct size: %d" % (len(buf), struct.size())
##                if len(buf) == 0:
##                    print "eof"
##                    break
                struct.read(buf)
                rowcount += 1


            print row_htmls
            dbh.set_meta("reveng_HTML", ",".join(row_htmls))
            ###########################################
            # Display table
            row_htmls = dbh.get_meta("reveng_HTML").split(",")
            cb={}
            count=0
            names=['Row']
            try:
                while 1:
                    name = "%s" % query['name_%s' % count]
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
                    headers=popup_row,
                    case = query['case'],
                    valign="top"
                    )
            except IndexError, e:
                print "Index Error: %s" % e
            except DB.DBError, e:
                print "DB Error: %s" % e
                            
            result.end_form()

        except KeyError,e:
            result.case_selector()
            print "%r%s%s" %(e,e,FlagFramework.get_bt_string(e))



    def reset(self, query):
        dbh = self.DBO(query['case'])
        dbh.execute("drop table reveng")
