import pyflag.Registry as Registry

def draw_scanners(query,result):
    result.row("Choose Scanners to run:","",bgcolor='pink')
    scanner_desc = [ i.__doc__.splitlines()[0] for i in Registry.SCANNERS.classes]
    for i in range(len(scanner_desc)):
        scanner_name = Registry.SCANNERS.scanners[i]
        scanner_factory = Registry.SCANNERS.classes[i]
        ## should the checkbox be ticked by default?
        if scanner_name not in query.getarray('scan') and scanner_factory.default:
            query['scan']=scanner_name

        result.checkbox(scanner_desc[i],"scan",scanner_name )
    
