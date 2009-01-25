""" This module implements the indexing facilities in PyFlag.

It has now become a core feature because many other plugins depend on
it.

PyFlag maintains two types of indexs:
1) Unique index stores the first hit of each key word in each inode.
2) Detailed index stores all hits of each word within each inode.

For initial scanning unique indexes are made - this reduces database
traffic to a minimum because in the first instance we only want to see
those inodes which match the keyword at all. For those inodes of
interest, we re-run the indexer with a detailed flag to get all hits.

Inodes are scanned on demand and the indexing dictionary is
dynamic. This means that a new word can be added to the dictionary at
any time, without affecting previous indexes. This is achieved through
the concept of dictionary versioning.

When a new word is added to the dictionary, the dictionary version is
incremented - and the version is assigned for this word. When an inode
is indexed, the inode table maintains versioning information within
the version column. This keeps a current view of the level of indexing
applied to the inode.

The version number is an unsigned int (32 bits). Bit 30 (MSB) is 0 if
the index is unique and 1 if a detailed index was performed on the
inode.

The following API is designed to simplify access to the indexing
framework:

inode_upto_date(case, inode_id, unique):

This function returns True if the inode has completed
scanning. Because indexing is distributed, the indexing of particular
inodes may happen at any time (when a worker gets to it). Callers need
to specify which type of index they are interested in.

schedule_index(case, inode_id, word, word_type, unique):

This function schedules an indexing job on the specified inode. We
ensure that the specified word is also added to the dictionary if not
there already.

So to make sure the inode is indexed with a given word, clients should
call schedule_index first and then periodically check with
inode_upto_date() to see when the indexing job has been completed.

"""
import index
import pyflag.DB as DB
import time
import pyflag.Farm as Farm

def inode_upto_date(case, inode_id, unique = False):
    return inode_upto_date_sql(case, "inode_id = '%s'" % inode_id, unique)

def inode_upto_date_sql(case, sql, unique = False):
    """ Checks to see if the inode_id is ready (i.e. is up to
    date). Return True if its up to date, False otherwise.
    """
    dbh = DB.DBO(case)
    try:
        dbh.execute("select version, desired_version from inode where %s limit 1" ,sql)
    except DB.DBError:
        ## Check for older schemas
        dbh.execute("alter table inode add column desired_version int")

    row = dbh.fetch()
    
    return row['version'] >= row['desired_version']

def get_dict_version(word_id = None):
    pdbh = DB.DBO()
    if word_id == None:
        try:
            pdbh.execute("select max(id) as version from dictionary")
            row = pdbh.fetch()
            return row['version'] or 1
        except:
            return 1
    else:
        return word_id
    
def is_word_in_dict(word):
    pdbh = DB.DBO()
    pdbh.execute("select * from dictionary where word=%r", word)
    row = pdbh.fetch()
    return row

def insert_dictionary_word(word, word_type, classification='', binary=False):
    pdbh = DB.DBO()
    ## This guarantees that only we can manipulate the dictionary
    ## right now otherwise we can get races and duplicates
    pdbh.execute("lock table dictionary write")
    try:
        ## Is the word in the dictionary?
        if word_type == 'word':
            sql = "select * from dictionary where word = %r and type = %r"
            prefix =''
            ## Other types are stored in binary:
        else:
            prefix = '__'
            sql = "select * from dictionary where word = %b and type = %r"

        pdbh.execute(sql,
                     word, word_type)
        row = pdbh.fetch()

        if not row:
            ## The word is not in the dictionary - add it and increment
            ## the dictionary version
            pdbh.insert('dictionary',
                        **{'__word': word,
                           'type': word_type,
                           'class': classification or "English",
                           ## Cant be fast here - cache must be updated
                           ##'_fast': True,
                           })

            pdbh.execute("unlock tables")
            
            word_id = pdbh.autoincrement()
            ## Tell all workers the dictionary has changed
            pdbh.insert('jobs',
                        command = "ReIndex",
                        state = "broadcast",
                        cookie = 0,
                        _fast = True
                        )
        else:
            word_id = row['id']
            
    finally:
        pdbh.execute("unlock tables")
        
    return word_id

## These are some useful facilities
def schedule_index(case, inode_ids, word, word_type, unique=True):
    """ This function schedules an indexing job on the inode specified with the word and index type specified.

    We check to see if the index is already in the dictionary and if
    said inode is up to the relevant dictionary version.

    unique requests the indexer to produce a single hit for each inode
    (i.e. it only shows unique hits). If unique is False the indexer
    will generate offsets for all hits in this inode.
    """
    word_id = insert_dictionary_word(word, word_type)

    if type(inode_ids)!=type(list):
        inode_ids = (inode_ids,)
        
    for inode_id in inode_ids:
        schedule_inode_index(case, inode_id, word_id)
        
    ## Wake the workers:
    Farm.wake_workers()

def count_outdated_inodes(case, sql, word_id=None, unique=True):
    """ This function counts the number of inodes outstanding to be scanned.

    sql is a subquery which is expected to return a list of inode_ids.

    word_id is the word which we count the outdated inodes with
    respect to. If word_id is None, or omitted we simply count all
    inodes in the sql provided.
    
    unique is the type of index (a unique index of a detailed index).
    """
    dbh = DB.DBO(case)

    print "Checking word_id %s,%s" % (word_id,sql)

    if word_id==None:
        dbh.execute("select count(*) as c, sum(inode.size) as s %s",sql)
    else:
        ## The dict_version is relative to the word searched (i.e. the
        ## version the dictionary was in at the time the word was added).
        dict_version = get_dict_version(word_id)

        ## If we want detailed scan we want to set bit 30 of the dict_version
        if not unique:
            desired_version = dict_version | 2**30
        else:
            desired_version = dict_version

        ## Now check the inode to see if its out dated
        dbh.execute("select count(*) as c, sum(inode.size) as s "
                    " from inode where (inode.version < %r or "
                    " (inode.version & (pow(2,30) -1)) < %r ) "
                    " and (inode.inode_id in (select inode.inode_id %s))" ,
                    dict_version, desired_version, sql)

    row=dbh.fetch()
    print row
    
    return row['c'], row['s']

def schedule_inode_index_sql(case, sql, word_id, cookie='', unique=True):
    dict_version = get_dict_version()

    ## If we want detailed scan we want to set bit 30 of the dict_version
    if not unique:
        desired_version = dict_version | 2**30
    else:
        desired_version = dict_version

    ## Now check the inode to see if its out dated
    dbh = DB.DBO(case)
    dbh2 = DB.DBO(case)
    pdbh = DB.DBO()
    dbh.execute("select inode_id from "
                " inode where (inode.version < %r or "
                " (inode.version & (pow(2,30) -1)) < %r ) "
                " and (inode_id in (%s))" ,
                dict_version, desired_version, sql)
    
    for row in dbh:
        dbh2.update('inode',
                   where = "inode_id = %s" % row['inode_id'],
                   desired_version = desired_version,
                   _fast=True)

        pdbh.insert('jobs',
                    cookie = cookie,
                    command = 'Index',
                    _fast = True,
                    arg1 = case,
                    arg2 = row['inode_id'],
                    arg3 = desired_version) # The desired version we
                                            # want to be in
    ## Wake the workers:
    Farm.wake_workers()

def list_hits(case, inode_id, word, start=None, end=None):
    """ Returns a generator of hits of the word within the inode
    between offset start and end (these are inode offsets."""
    dbh = DB.DBO(case)
    pdbh = DB.DBO()
    pdbh.execute("select id from dictionary where word = %r limit 1" , word)
    row = pdbh.fetch()
    if not row:
        raise RuntimeError("Word queried (%s) is not in the dictionary???" % word)

    ranges = ''
    if start!=None:
        ranges += DB.expand("and offset >= %r",(start,))

    if end!=None:
        ranges += DB.expand("and offset < %r", (end,))
        
    id = row['id']
    dbh.execute("select offset,length from LogicalIndexOffsets where "
                "inode_id = %r and word_id = %r %s order by offset", inode_id, id, ranges)

    return dbh
