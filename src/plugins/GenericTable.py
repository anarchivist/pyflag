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
            result.row("&nbsp;")
            result.row(t.__doc__, **{'class':'explain', 'colspan':4})
            columns = t.columns + t.extras
            
            for i in range(len(columns)):
                columns_cls = columns[i][0]
                args = columns[i][1]
                c = columns_cls(**args)
                result.checkbox(c.name,'columns', '%s:%s' % (t.name, i), reverse=True, **{'class': 'explain'})
            
    def interpolate_query(self, table, args, query):
        for k,v in args.items():
            if k=='table':
                args[k] = table.name
            elif v==None:
                args[k] = query[k]

    def display(self, query,result):
        elements = []
        for c in query.getarray('columns'):
            t, i = c.split(':')
            t = Registry.CASE_TABLES.dispatch(t)
            i = int(i)
            
            columns = t.columns + t.extras
            columns_cls, args = columns[i][:2]
            args = args.copy()
            args['case'] = query['case']
            args['table'] = t.name
            elements.append( columns_cls(**args))
            
        result.table(
            elements = elements,
            case = query['case'],
            )
