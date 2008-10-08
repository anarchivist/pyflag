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
    family = "Disk Forensics"

    def get_names(self, cls):
        if type(cls.name)==str:
            names = [cls.name,]
        else:
            names = cls.name
                    
        return names

    def display(self, query, result):
        def left_pane_cb(path):
            ## We expect a directory here:
            if not path.endswith('/'): path=path+'/'

            seen = []
            result = []
            for cls in Registry.PRECANNED.classes:
                if not cls.name: continue
                
                for name in self.get_names(cls):
                    if name.startswith(path):
                        branches = name[len(path):].split('/')
                        branch = branches[0]
                        if branch not in seen:
                            seen.append(branch)
                            if len(branches)>1:
                                result.append((branch, branch, "branch"))
                            else:
                                result.append((branch, branch, "leaf"))

            return result
            
        def right_pane_cb(path, result):
            for cls in Registry.PRECANNED.classes:
                for name in self.get_names(cls):
                    if name == path:
                        query.set("open_tree",path)
                        cls().display(query, result)
                        return

            result.heading("Precanned Analysis")
            result.para("Select the type of automated analysis required. You can use this to get you started, and then drive the analysis further.")

        result.tree(tree_cb = left_pane_cb, pane_cb = right_pane_cb)

class Images(Reports.PreCannedCaseTableReoports):
    """ Display a preview of images """
    args = {'filter':' "Thumbnail"  has_magic image and  "Size"  > 20000 ',
            'order': 1, 'direction':0}
    family = "Disk Forensics"
    description = "View all images bigger than 20kb "
    name = "/Disk Forensics/Multimedia/Graphics"
    columns = ['TypeCaseTable.Thumbnail', 'InodeTable.Size','FileTable.Filename']

class HTMLPages(Registry.PreCanned):
    args = {'filter':' "Thumbnail"  has_magic HTML ',
            'order': 4, 'direction':1}
    family = "Disk Forensics"
    report = "Browse Types"
    description = "View all HTML Pages "
    name = "/Disk Forensics/Multimedia/HTML Pages"

class HTMLURLs(Registry.PreCanned):
    args = {'filter': '"Content Type" contains html',
            '_hidden':[1,3,5] }
    report='Browse HTTP Requests'
    family='Network Forensics'
    description = 'View all HTML URLs'
    name = [ "/Network Forensics/Web Applications/HTML URLs" ]

