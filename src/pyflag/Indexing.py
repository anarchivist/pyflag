""" This module implements the indexing facilities in PyFlag.

It has now become a core feature because many other plugins depend on
it.
"""
import index
import pyflag.DB as DB
import time

def inode_upto_date(case, inode_id):
    """ Checks to see if the inode_id is ready (i.e. is up to
    date). Return True if its up to date, False otherwise.
    """
    dbh = DB.DBO(case)
    try:
        dbh.execute("select version, desired_version from inode where inode_id = %r limit 1" ,inode_id)
    except DB.DBError:
        dbh.execute("alter table inode add column desired_version int")

    row = dbh.fetch()

    return row['version'] >= row['desired_version']

## These are some useful facilities
def schedule_index(case, inode_ids, word, word_type):
    """ This function schedules an indexing job on the inode specified with the word and index type specified.

    We check to see if the index is already in the dictionary and if
    said inode is up to the relevant dictionary version.
    """
    pdbh = DB.DBO()
    try:
        dict_version = int(pdbh.get_meta('dict_version'))
    except:
        dict_version = 1

    ## Is the word in the dictionary?
    pdbh.execute("select * from dictionary where word = %r and type = %r",
                 word, word_type)
    row = pdbh.fetch()
    if not row:
        ## The word is not in the dictionary - add it
        pdbh.insert('dictionary',
                    word = word,
                    type = word_type,
                    _fast = True)
        
        ## Increment the dictionary version
        dict_version += 1
        pdbh.set_meta('dict_version', dict_version)

        ## Tell all workers the dictionary has changed
        pdbh.insert('jobs',
                    command = "ReIndex",
                    state = "broadcast",
                    _fast = True
                    )

    if type(inode_ids)!=type(list):
        inode_ids = (inode_ids,)
        
    for inode_id in inode_ids:
        ## Now check the inode to see if its out dated
        dbh = DB.DBO(case)
        dbh.execute("select version from inode where inode_id = %r limit 1" ,inode_id)
        row = dbh.fetch()
        inode_dict_version = row['version']

        ## Do we need to rescan it?
        if inode_dict_version < dict_version:
            dbh.update('inode',
                       where = "inode_id = %s" % inode_id,
                       desired_version = dict_version)
            
            pdbh.insert('jobs',
                        cookie = time.time(),
                        command = 'Index',
                        arg1 = case,
                        arg2 = inode_id)
        
