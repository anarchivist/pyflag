from forensics.object2 import *
from forensics.object import get_obj_offset

def list_entry(vm, types, profile, head, objname,
               offset=-1, fieldname=None, forward=True):
    """Traverse a _LIST_ENTRY.

    Traverses a _LIST_ENTRY starting at virtual address head made up of
    objects of type objname. The value of offset should be set to the
    offset of the _LIST_ENTRY within the desired object."""
    
    seen = set()

    if fieldname:
        offset,typ = get_obj_offset(types, [objname,fieldname])
        if typ != "_LIST_ENTRY":
            print ("WARN: given field is not a LIST_ENTRY, attempting to "
                   "continue anyway.")

    lst = NewObject("_LIST_ENTRY", head, vm, profile=profile)
    seen.add(lst)
    if not lst.is_valid(): return
    while True:
        if forward:
            lst = lst.Flink.dereference()
        else:
            lst = lst.Blink.dereference()
        
        if not lst.is_valid(): return
        
        if lst in seen: break
        else: seen.add(lst)
        obj = NewObject(objname, lst.offset - offset, vm, profile=profile)
        yield obj
