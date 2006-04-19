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
        result.start_form(query)

        def settings_cb(query, ui):
            ui.decoration = "naked"

            try:
                if query['finish'] and query['MaxRows'] and query['StartOffset']:
                    del query['finish']
                    del query['submit']
                    ui.refresh(0,query,parent=1)
            except KeyError:
                pass

            ui.start_form(query)
            ui.start_table()
            ui.textfield("Starting Offset","StartOffset",size=20)
            ui.textfield("Maximum Rows","MaxRows")
            ui.checkbox("Click here to finish", "finish", "yes")
            ui.end_table()
            ui.end_form()
            return ui
            
        def popup_cb(query, ui, column_number = None, mode = ''):
            """Popup for defining column attributes"""
##            print "I am here"
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
                print 'KeyError: %s' %e

            ui.checkbox("Visible","%svisible_%s" % (pre, column_number), "yes",
                        checked=True)
            ui.checkbox("Click here to finish", "finish","yes")
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
                elif k.startswith('savenow'):
                    savelayout(query)
                    del query[k]
                    break
                elif k.startswith('loadlayout'):
                    openlayout(query)
                    del query[k]
                    
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

        def open_cb(query, ui):
            """Popup for loading a layout"""
            ui.decoration = "naked"
            dbh = self.DBO(query['case'])
            
            try:
                if query['finish']:
                    del query['finish']
                    del query['submit']
                    ui.refresh(0,query,parent=1)
            except KeyError:
                pass

            ui.start_form(query)
            ui.start_table()
            ui.heading("Load a saved layout")

            try:
                dbh.execute('select name from DAFTLayouts')
                rows = []
                for row in dbh:
                    rows.append(row['name'])
                ui.const_selector("Layout Name", "loadlayout", rows, rows)
                
                
            except DB.DBError:
                dbh.execute('create table DAFTLayouts (`name` text, `layout` text)')
                ui.const_selector("Layout Name", "loadlayout", [''], [''])

            ui.checkbox("Click here to finish", "finish", "yes")
            ui.end_table()
            ui.end_form()
            return ui
            ### Create a list of saved layouts

        def openlayout(query):
            dbh = self.DBO(query['case'])
            keylist = ['name_', 'data_type_', 'visible_', 'parameter_', 'fileselect',
                       'MaxRows', 'StartOffset', 'savelayout']
            try:
                dbh.execute("select layout from DAFTLayouts where name='%s'" % query['loadlayout'])
            except DB.DBError:
                pass

            rows=[]
            oldkeys=[]
            for row in dbh:
                rows.append(row)
            try:
                if len(rows)<1:
                    raise ValueError
                for k in keylist:
                    oldkeys = [x for x in query.keys() if x.startswith(k)]
                for key in oldkeys:
                    del query[key]

                for kvpair in rows[0]['layout'].split(','):
                    key, value = kvpair.split('=')
                    query[key] = value
                    
            except ValueError:
                pass

        
        def save_cb(query, ui):
            """Popup for saving layout"""
            ui.decoration = "naked"

            try:
                if query['finish'] and query['savelayout']:
                    query['savenow'] = 'yes'
                    del query['finish']
                    del query['submit']

                    ui.refresh(0,query,parent=1)
            except KeyError:
                pass

            ui.start_form(query)
            ui.start_table()
            ui.heading("Save current layout")

            ui.textfield("Layout name", "savelayout")
            
            ui.checkbox("Click here to finish", "finish","yes")
            ui.end_table()
            ui.end_form()
            return ui

        def savelayout(query):
            """Saves the current layout into the DAFTLayouts table"""
            dbh = self.DBO(query['case'])
            keylist = ['name_', 'data_type_', 'visible_', 'parameter_', 'fileselect',
                       'MaxRows', 'StartOffset', 'savelayout']
            try:
                dbh.execute("select name, layout from DAFTLayouts where name='%s'" % query['savelayout'])
            except DB.DBError:
                dbh.execute("create table DAFTLayouts (`name` text, `layout` text)")
                dbh.execute("select name, layout from DAFTLayouts where name='%s'" % query['savelayout'])
        
            rows = []
            keys = []
            for row in dbh:
                rows.append(row)
            for k in keylist:
                keys = keys + [x for x in query.keys() if x.startswith(k)]
                value = ','.join('%s=%s'%(x, query[x]) for x in keys)
            if rows == []:
                dbh.execute("insert into DAFTLayouts set name='%s', layout='%s'" %(query['savelayout'],
                            value))
            else:
                dbh.execute("update DAFTLayouts set layout='%s' where name='%s'" %(value,
                             query['savelayout']))

        def filelist_cb(query, ui):
            """Popup to select files to analyse"""
            ui.decoration = "naked"

            try:
                if query['finish'] and query['fileselect']:
                    del query['finish']
                    del query['submit']

                    ui.refresh(0, query, parent=1)
            except KeyError:
                pass

            ui.start_form(query)
            ui.start_table()
            ui.heading("Select files")

            values = []
            keys = []
            dbh.execute("select name, path, inode from file where inode != ''")
            for row in dbh:
                values.append('%s%s' % (row['path'], row['name']))
                keys.append(row['inode'])
            ui.const_selector("File", "fileselect", keys, values)

            ui.checkbox("Click here to finish", "finish", "yes")
            ui.end_table()
            ui.end_form()
        
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

            ## Build a struct to work from:
            try:
                startoffset = DAFTFormats.numeric(query['StartOffset'])
            except KeyError:
                startoffset = 0

            try:
                maxrows = DAFTFormats.numeric(query['MaxRows'])
            except KeyError:
                maxrows = 10

            fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"])
            try:
                fd = fsfd.open(inode=query['fileselect'])
                fdsize = fsfd.istat(inode=query['fileselect'])
                fd.block_size = dbh.get_meta('block_size')
                buf = format.Buffer(fd=fd)[startoffset:]
            except IOError, e:
                print 'IOError: %s' % e
                fd = None
                fdsize = 0
                s = '\x00'*1024
                buf = format.Buffer(string=s)
            except KeyError, e:
                print 'KeyError: %s' %e
                s = '\x00'*1024
                buf = format.Buffer(string=s)
                fd = None
                fdsize = 0

##            print 'File Size %s' % fdsize

               
            struct = DAFTFormats.DynamicStruct(buf)
            struct.create_fields(query, 'parameter_')
            
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

            result.popup(settings_cb, "Change settings", icon="page.png")
            result.popup(FlagFramework.Curry(popup_cb, column_number = struct.count)
                          ,"Add new column", icon="red-plus.png")
            result.popup(filelist_cb, "Select files to use", icon="find.png")
            result.popup(open_cb, "Open a saved layout", icon="fileopen.png")
            result.popup(save_cb, "Save the current layout", icon="filesave.png")
                    
            ######## Creating table rows here
            data = []
            row_data = {}
            row_data_names = []
            row_data_types = []
            row_htmls = []

            rowcount = 0
            done = False
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

                    except AttributeError,e:
                        pass
                    except IOError,e:
                        print e
                        done = True
                        break

                if done: break
                

                #### DBH can't create a table when there are no fields
                if len(row_data_names) == 0:
                    break

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
                struct.read(buf)
                rowcount += 1


##            print row_htmls
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

        except KeyError,e:
            result.case_selector()
            print "%r%s%s" %(e,e,FlagFramework.get_bt_string(e))

        result.end_form()
        
    def reset(self, query):
        dbh = self.DBO(query['case'])
        dbh.execute("drop table reveng")
