#!/usr/bin/env python
# ******************************************************
# Copyright 2006
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

""" A distributed processing framework for PyFlag.

= Why do we want distributed capability? =

PyFlag was originally designed to be a single threaded, single process
application. As the application grew in capabilities, it became more
desired to be able to spread the load between CPUs on a single machine,
as well as spread the load to many machines simultaneously.

The typical PyFlag analysis process consists of the following steps:
 1. A disk image or network capture is loaded into the VFS.

 2. The files in the VFS are scanned by scanners

 3. The results of the various scanners are then reviewed by the
 Analyst by executing various reports.

The initial loading of the VFS is typically quite fast because VFS
nodes are simply created corresponding to entities in the original
evidence material. This typically only involves reading metadata about
the filesystem, or reassembling TCP streams. Due to the nature of this
process it is difficult to distribute the work, while gains would be
limited (for example loading a HDD image takes about 20-30 seconds,
while reassembling a 2G capture file might only take on the order of 5
minutes - while scanning a large filesystem can take several hours).

In the current implementation, the second step - i.e. the scanning of
the VFS is most time consuming and most attractive for
distributing. Running other analysis methods (e.g. NSRL hash
comparisons) are also candidates for distribution, but are not done at
present.

Finally the presentation of material to the analyst is typically very
quick because the reports should cache infomation in the database in
the most efficient way during the analysis phase.

= How Distribution is done in PyFlag? =

When designing distributed applications, there are two aspect that
need to be addressed:

 1. The problem needs to lend itself to division - i.e. The large task
 must be able to be broken to smaller tasks that are run independantly
 of other tasks.
 
 2. Each processing thread needs to be able to communicate its results
 and draw its problem set from other threads. (In this discussion we
 use the word thread to denote an independant processing entity which
 may or may not run on the same machine). This requirement specifies a
 communication medium in effect which faciliates IPC between threads.

PyFlag's solution is simplistic at present addressing the above
requirements in the following ways:

 1. PyFlag only distributes scanning of VFS nodes at present. Scanning
 of VFS nodes can be done independantly with no knowledge of other
 nodes at all. In other VFS nodes are created during processing, they
 are scanned by the same thread at present.

 2. PyFlag requires all threads to operate on the same data set. The
 PyFlag data set is confined to the two directories, which should be
 shared by all threads in some way (for example NFS is ideal for
 sharing between machines, but AOE (ATA over Ethernet) is also
 attractive):

    - The UPLOAD directory - contains the images PyFlag operates
    on. This is a read only directory.
 
    - The RESULTDIR directory - This directory contains cached and
    temporary data which may need to be shared by all threads. This
    directory should be shared read/write among all threads.

  So long as all threads have a common view of the above directories,
  all threads can obtain tasks from each other.

  The second part of thread IPC is the database. All threads
  continually communicate with the database and use it as a general
  purpose IPC facilitator as well as a place to store results, and
  obtain new tasks. This does create a bottleneck at the database end,
  but there are a number of ways to deal with that (e.g. MySQL
  distribution etc). At present all threads must be connected to the
  same database.

== Database model ==
  
Threads periodically poll the `jobs` table in FLAGDB to see if new
jobs are available. When jobs are scheduled, they are inserted into
that table by the scheduling thread. All other threads will pick up
jobs from that table, deleting them as they are completed.

== Scanners ==

This is a brief recap of the scanner architecture and how this fits
into the distribution model.

Scanner Factories are classes which inherit from the GenScanFactory
class. Factories are responsible for instantiating an object for
each new file scanned using their Scan inner class (which may
inherit from a number of base classes performing different Scanning
functionality).

The following phases are typical:

1. The Factory is instantiated by a thread and stored. This is an
opportunity for the thread to initialise itself - for example the
VirusScanner factory loads virus signatures etc. This operation may
be time consuming. The factory may be stored for a long time by the
thread and reused frequently - so this time cost is amortised over
the length of the threads life.

2. The thread fetches a task from the jobs queue and opens the VFS
inode. The inode is then used to instantiate the factory's inner
Scan class.

3. The inode is read in chunks and fed into the Scan.process
method. When the inode is finished the Scan.finish method is called
giving the scanner an opportunity to finalise the results for the
specific inode.

Note that factories are instantiated on demand by each thread, and
are kept for an indefinite period of time. Also note that each
factory relates to a single case only (because it is instantiated
with a vfs arguement which is unique to each case). After a period
of disuse or under memory pressure, the factory may be destroyed by
the thread.

== Conclusions ==

This model is very simplistic but adequate to distribute the
scanning operations either across a number of threads on the same
machine or seperate threads on many machines. The upside is that
since threads join voluntarily at any time, it is possible for a
thread to quit and be restarted without affecting the overall
progress. This in an imporant reliability advantage guaranteeing the
scanning task can continue even after a crash or memory leak caused a
thread to die.

Since all threads are equal this is a peer to peer model. Any thread
may be used to issue jobs as well as service jobs. By default when
starting up the GUI WORKERS working threads are also created (default
1 although on an SMP machine you might want to increase
this). Starting up any number of GUIs will result in many threads
being created. Hence there is no special setup or configuration
required to manage working threads (other than ensuring the UPLOAD and
RESULTDIR are synctonised).

""" 
import sys,os,select

sys.path.append(os.path.join(os.path.dirname(__file__),"pyflag"))
sys.path.append(os.path.join(os.path.dirname(__file__),".."))

import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog
import atexit,os,signal,time
import pyflag.DB as DB
import pyflag.Registry as Registry
import pyflag.Store as Store

## This stores the pids of working threads - we kill those when the
## main thread exits
children = []
def child_exist():
    pyflaglog.log(pyflaglog.INFO, "Child Existed")

## Windows uses events for IPCs
try:
    import win32event
    
    TerminateEvent = win32event.CreateEvent(None, 0, 0, "PyFlagTerminateEvent")
    SyncEvent      = win32event.CreateEvent(None, 0, 0, "PyFlagSyncEvent")
except ImportError:
    win32event = None
    
def terminate_children():
    try:
        for pid in children:
            win32event.PulseEvent(TerminateEvent)

        return
    except AttributeError:
        pass
    
    for pid in children:
        try:
            #print "Terminating child %s" % pid
            os.kill(pid, signal.SIGINT)
        except: pass

config.add_option("MAXIMUM_WORKER_MEMORY", default=0, type='int',
                  help='Maximum amount of memory (Mb) the worker is allowed to consume (0=unlimited,default)')

def check_mem(cb, *args, **kwargs):
    """ Checks for our current memory usage - if it exceeds the limit
    we exit and let the nanny restart us.
    """
    if config.MAXIMUM_WORKER_MEMORY > 0:
        mem = open("/proc/%s/statm" % os.getpid()).read().split()
        if int(mem[1])*4096/1024/1024 > config.MAXIMUM_WORKER_MEMORY:
            pyflaglog.log(pyflaglog.WARNING, "Process resident memory exceeds threshold. Exiting")
            cb(*args, **kwargs)

class Task:
    """ All distributed tasks need to extend this subclass """

## There are two types of messages we listen for, the pending messages
## and broadcast messages. Pending jobs are those which we take
## ownership of (i.e. we guarantee that no one else is doing the same
## job at the same time). A broadcast job is sent to all workers at
## once - and should be responded to by all workers. Note that there
## is no guaratees on when a worker will get around to responding to
## the broadcast, so the Task handling the broadcast needs to check
## that its still relevant.

## Typically pending jobs are things like scanning inodes, cracking
## keys etc. While broadcasts are drop case messages, which require
## all workers to free resources allocated to the case.

config.add_option("WORKERS", default=2, type='int',
                  help='Number of workers to start up')

config.add_option("JOB_QUEUE", default=10, type='int',
                  help='Number of jobs to take on at once')

config.add_option("JOB_QUEUE_POLL", default=10, type='int',
                  help='Number of seconds to wait between worker queue polls')

config.add_option("DISABLE_NANNY", default=False,
                  action = 'store_true',
                  help = "Disables the use of a nanny. Useful for debugging")

def nanny(cb, keepalive=None, *args, **kwargs):
    """ Runs cb in another process persistently. If the child process
    quits we restart it.
    """
    if config.DISABLE_NANNY:
        cb(*args, **kwargs)
        
    atexit.register(terminate_children)
    signal.signal(signal.SIGABRT, handler)
    signal.signal(signal.SIGUSR1, handler)
    signal.signal(signal.SIGINT, handler)
    global children
    
    children = []
    while 1:
        try:
            ## create a socket pair for communications
            r, w = os.pipe()
            pid = os.fork()
        except AttributeError:
            ## For windows we just call directly
            cb(*args, **kwargs)

        ## Parent
        if pid:
            os.close(w)
            children.append(pid)
            while 1:
                ## Check that our parent is still around
                fds = select.select([keepalive],[],[], 0)
                if fds[0]:
                    data = os.read(fds[0][0],1024)
                    if len(data)==0:
                        pyflaglog.log(pyflaglog.INFO, "Main process disappeared - closing children")
                        ## Parent quit - kill our child
                        os.kill(pid,signal.SIGABRT)
                        os._exit(0)

                time.sleep(1)
                try:
                    data = os.read(r,1024)
                    if len(data)==0:
                        ## Other end is closed:
                        os.close(r)
                        
                        ## Try to read its pid so it doesnt become a
                        ## zombie:
                        os.waitpid(pid,0)
                        children.pop(children.index(pid))
                        break
                except OSError:
                    pass
            
        ## Child
        else:
            os.close(r)
            cb(keepalive=w, *args, **kwargs)
            os._exit(0)

def worker_run(keepalive=None):
     """ The main loop of the worker """
     ## It is an error to fork with db connections
     ## established... they can not be shared:
     if DB.db_connections > 0:
         ## We try to fix it by making the child get new
         ## handlers. Note that the child still needs to hold the
         ## handles or they will get closed on the parent as well
         ## - this seems like a hack
         DB.DBO.DBH_old = DB.DBO.DBH
         DB.DBO.DBH = Store.Store(max_size=10)
         DB.db_connections = 0

     ## These are all the methods we support
     jobs = []

     ## This is the last broadcast message we handled. We will
     ## only handle broadcasts newer than this.
     broadcast_id = 0
     try:
         dbh=DB.DBO()
         dbh.execute("select max(id) as max from jobs")
         row = dbh.fetch()
         broadcast_id = row['max'] or 0
     except: pass

     while 1:
         ## Ping the parent
         try:
             if keepalive:
                 os.write(keepalive,"Checking")
         except Exception, e:
             print e
             pyflaglog.log(pyflaglog.WARNING,"Our nanny died - quitting")
             os._exit(1)

         ## Check for memory usage
         check_mem(os._exit,0)
         ## Check for new tasks:
         if not jobs:
             try:
                 r = win32event.WaitForMultipleObjects([SyncEvent, TerminateEvent], False, 10000)
                 if r==1:
                     ## TerminateEvent signaled
                     sys.exit(0)
                 
             except (NameError,AttributeError),e:
                 time.sleep(config.JOB_QUEUE_POLL)

         dbh = None
         try:
             dbh = DB.DBO()
             try:
                 dbh.execute("lock tables jobs write")
                 ## Higher priority jobs take precendence over lower
                 ## priority jobs. We only want jobs which are valid
                 ## now (jobs can be set in the future). We assume
                 ## that we actually can process all jobs (all workers
                 ## must have all the same plugins).
                 dbh.execute("select * from jobs where when_valid <= now() "
                             " and ((state='pending') or (state='broadcast' and "
                             " id>%r)) order by id asc, priority desc limit %s",
                             (broadcast_id, config.JOB_QUEUE))
                 jobs = [ row for row in dbh ]

                 if not jobs:
                     continue

                 ## Ensure the jobs are marked as processing so other jobs dont touch them:
                 for row in jobs:
                     if row['state'] == 'pending':
                         dbh.execute("update jobs set state='processing' where id=%r", row['id'])
                     elif row['state'] == 'broadcast':
                         broadcast_id = row['id']
             finally:
                 if dbh:
                     dbh.execute("unlock tables")
         except:
             continue

         ## Now do the jobs
         for row in jobs:
             try:
                 try:
                     task = Registry.TASKS.dispatch(row['command'])
                 except:
                     pyflaglog.log(pyflaglog.DEBUG, "Dont know how to process job %s" % row['command'])
                     continue

                 try:
                     task = task()
                     task.run(row['arg1'], row['arg2'], row['arg3'])
                 except Exception,e:
                     pyflaglog.log(pyflaglog.ERRORS, "Error %s(%s,%s,%s) %s" % (task.__class__.__name__,row['arg1'], row['arg2'],row['arg3'],e))

             finally:
                 try:
                     if keepalive:
                         os.write(keepalive, " ".join(row))
                 except:
                     pyflaglog.log(pyflaglog.WARNING,"Our nanny died - quitting")
                     os._exit(1)
                 if row['state'] != 'broadcast':
                     dbh.execute("delete from jobs where id=%r", row['id'])


def start_workers():
    if config.FLUSH:
        dbh = DB.DBO()
        pyflaglog.log(pyflaglog.WARNING,"Deleting job queue and killing workers")
        #dbh.execute("select max(id) as max from jobs")
        #row = dbh.fetch()
        #broadcast_id = row['max'] or 0
        dbh.execute("delete from jobs")
        #dbh.insert("jobs", _fast=True,
        #           command='Exit', state='broadcast',
        #           )

    if config.WORKERS == 0:
        return

    for i in range(config.WORKERS):
       try:
           r,w = os.pipe()
           pid = os.fork()
       except AttributeError:
           ## When running under windows we can not fork...  We must
           ## launch this module by itself instead - this is very
           ## suboptimal because we will be performing all startup
           ## code (registry parsing etc) for each worker. If you want
           ## performance you would not choose windows anyway,
           ## though. The following is windows specific:
           ## First find the name of the interpreter:
           import ctypes, sys

           name = ctypes.create_string_buffer(255)
           length = ctypes.windll.kernel32.GetModuleFileNameA(None, name, 255)
           interpreter = name.raw[:length]

           ## This encloses at least the file path in quotes just in
           ## case we are installed to somewhere with spaces - It
           ## seems that on windows argvs are not processed correctly
           ## because the below array ends up as a single command line
           ## string WTF? This is very dodgy...
           os.spawnv(os.P_NOWAIT, interpreter, ['"%s"' % interpreter,
                                                '"%s"' % __file__] + sys.argv[1:])
           pid = 1
       
       ## Parents:
       if pid:
           os.close(r)
           children.append(pid)
       else:
           os.close(w)
           nanny(worker_run, keepalive=r)
           
    atexit.register(terminate_children)

    ## The parent now calls the startup method on each of the events:
    for event in Registry.EVENT_HANDLERS.classes:
        try:
            event().startup()
        except Exception,e:
            pyflaglog.log(pyflaglog.WARNING, "Error: %s" % e)
        
def handler(sig, frame):
    if sig==signal.SIGABRT or sig==signal.SIGUSR1:
        ## Pass these signals directly to our children
        for pid in children:
            try:
                os.kill(pid, sig)
            except Exception,e:
                pass

    if sig!=signal.SIGUSR1:
        os._exit(0)

## Is this a dangerous thing to do? If a signal comes when we dont
## expect it we may lose sync with the db. Seems to work for now, but
## Im dubious.
## FIXME: Use select on unix domain sockets instead of time.sleep
try:
    signal.signal(signal.SIGUSR1, handler)
    signal.signal(signal.SIGABRT, handler)
    signal.signal(signal.SIGINT, handler)
except AttributeError:
    ## This fails on windows (no signals)
    pass

def wake_workers():
    """ Try to wake workers if possible. If we fail we must wait until
    the worker polls next, so its not a big deal.
    """
    print "Waking workers %s" % (children,)
    try:
        for i in range(config.WORKERS):
            win32event.PulseEvent(SyncEvent)

        return
    except AttributeError,e:
        pass

    ## A Signal should interrupt the children's sleep
    for pid in children:
        try:
            os.kill(pid, signal.SIGUSR1)
        except AttributeError: pass

config.add_option("FLUSH", default=False, action='store_true',
                  help='There are no workers currently processing, flush job queue.')

atexit.register(terminate_children)

if __name__ == "__main__":
    import pyflag.Registry as Registry
    import pyflag.conf
    config=pyflag.conf.ConfObject()

    config.set_usage(usage = "PyFlag Worker")

    Registry.Init()

    #config.parse_options()
    
    pyflaglog.log(pyflaglog.INFO,"Starting PyFlag worker")
    nanny(worker_run)
