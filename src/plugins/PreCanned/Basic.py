""" These are PreCanned Reports.

PreCanned Reports are the PyFlag equivalent of the google 'Im Feeling
Lucky' feature - we basically just dump out some simple queries which
are used to get you started.
"""

import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry

class ImFeelingLucky(Reports.report):
    """
    'Im Feeling Lucky' is a report which does basic analysis to get
    you started on the case. Select which kind of analysis you want to
    do.
    """
    name = "Im Feeling Lucky"
    family = "Case Management"

    def display(self, query, result):
        for cls in Registry.PRECANNED.classes:
            cls().display(query, result)


class Images(Registry.PreCanned):
    args = {'filter':' "Thumbnail"  has_magic image and  "Size"  > 20000 ',
            'order': 4, 'direction':1}
    family = "Disk Forensics"
    report = "Browse Types"
    description = "View all images bigger than 20kb "

class HTMLPages(Registry.PreCanned):
    args = {'filter': '"Content Type" contains html',
            '_hidden':[1,3,5] }
    report='Browse HTTP Requests'
    family='Network Forensics'
    description = 'View all HTML pages'
