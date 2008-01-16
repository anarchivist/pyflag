import pyflag.FlagFramework as FlagFramework
import pyflag.Registry as Registry
import pyflag.Reports as Reports

class GenericReport(Reports.report):
    name = "Generic Report"
    family = "Disk Forensics"
    parameters = { 'case':'flag_db',
                   'columns': 'any' }

    def form(self, query, result):
        result.heading("Select columns to display")
        for t in Registry.CASE_TABLES.classes:
            result.row("Table %s" % t.__doc__)
            columns = t.columns + t.extras
            
            for i in range(len(columns)):
                columns_cls, args = columns[i]
                c = columns_cls(**args)
                result.checkbox(c.name,'columns', '%s:%s' % (t.name, i))
            
    def interpolate_query(self, table, args, query):
        for k,v in args.items():
            if k=='table':
                args[k] = table.name
            elif v==None:
                args[k] = query[k]
            if k=='column':
                args[k] = "%s.%s" % (table.name,v)

    def display(self, query,result):
        elements = []
        tables = []
        for c in query.getarray('columns'):
            t, i = c.split(':')
            t = Registry.CASE_TABLES.dispatch(t)
            i = int(i)

            if not t.name in tables: tables.append(t.name)
            columns = t.columns + t.extras
            columns_cls, args = columns[i]
            args = args.copy()
            self.interpolate_query(t,args,query)
            
            elements.append( columns_cls(**args))

        table = ",".join(tables)
        ## Calculate the cross join conditions:
        conditions = []
        for x in tables:
            for y in tables:
                if x>=y: continue
                conditions.append("`%s`.inode_id = `%s`.inode_id" % (x,y))

        where = " and ".join(conditions)

        result.table(
            elements = elements,
            table = table,
            where = where,
            case = query['case'],
            )
