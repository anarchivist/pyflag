""" This table renderer produces a bundle (a tar file) of a set of
html pages from the table. The bundle can be viewed as a stand alone
product (i.e. all html pages are self referential and static) - you do
not need pyflag to view them, just a web browser.

This is a good way of delivering a report.
"""

import pyflag.UI as UI
import csv, cStringIO
import pyflag.DB as DB

class HTMLRenderer(CSVRenderer):
    exportable = True
    name = "HTML Bundle"
