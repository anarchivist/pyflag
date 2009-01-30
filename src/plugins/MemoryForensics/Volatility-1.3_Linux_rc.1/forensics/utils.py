import forensics.registry as registry

def load_as(opts):
    base_as = None
    while 1:
        found = False
        for cls in  registry.AS_CLASSES.classes:
            print "Trying %s " % cls
            try:
                base_as = cls(base_as, opts.__dict__)
                print "Succeeded instantiating %s" % base_as
                found = True
                break
            except AssertionError,e:
                continue

        ## A full iteration through all the classes without anyone
        ## selecting us means we are done:
        if not found: break
        
    return base_as

    
