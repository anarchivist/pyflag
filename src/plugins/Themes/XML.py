""" A basic XML Theme support files """

import pyflag.Reports as Reports
import pyflag.Registry as Registry

class Schema(Reports.report):
    name = "List"
    family = "Introspection"
    hidden = True
    parameters = {'object':'any'}

    def display(self, query, result):
        obj  = query['object']
        if obj=='report families':
            for f in Registry.REPORTS.get_families():
                result.row(f)
