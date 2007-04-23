import pst

f = pst.PstFile("/tmp/outlook.pst")

def print_item(root=None):
    for x in f.listitems(root):
        print x, x.properties()
        print_item(x)


print_item()
