""" This module identifies VOIP streams by performing traffic analysis
"""
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType

active = False

class VOIPTable(FlagFramework.CaseTable):
    """ Store information about VOIP streams """
    name = 'voip'
    columns = [ [ InodeIDType, {} ],
                [ StringType, dict(name = 'Service', column = 'service')],
                [ TimestampType, dict(name = 'Start Time', column='start')],
                [ TimestampType, dict(name = 'End Time', column='end')],
                [ InodeIDType, dict(name = "Decoded", column = 'decoded')]
                ]

import pyflag.Reports as Reports

class VOIPSessions(Reports.PreCannedCaseTableReports):
    """ View voip sessions detected """
    family = 'Network Forensics'
    description = 'View VOIP sessions'
    name = "/Network Forensics/Communications/VOIP/Sessions"
    default_table = 'voip'
    columns = [ 'Inode', 'ConnectionDetailsTable.Source IP',
                'ConnectionDetailsTable.Destination IP',
                'Start Time', 'End Time', 'Service', 'Decoded' ]
