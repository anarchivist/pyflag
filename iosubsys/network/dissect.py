import _dissect

class dissector:
    def __init__(self, data, link_type):
        self.d = _dissect.dissect(data,link_type);

    def __getitem__(self, item):
        print "asked to get field %s" % item
        return _dissect.get_field(self.d, item)
