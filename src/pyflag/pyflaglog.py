# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
""" Implement a simple logger wrapper.

logging verbosity is controlled through the configuration variable LOG_LEVEL
"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import sys,traceback,time,threading,os

## These are predefined logging levels:
ERRORS=1
ERROR=1
WARNINGS=3
WARNING=3
INFO=5
DEBUG=7
VERBOSE_DEBUG=12
RING_BUFFER_SIZE=20
ring_buffer = []

lookup = {
    ERRORS: "Critical Error",
    WARNINGS: "Warning",
    INFO:"Infomation",
    DEBUG:"Debug",
    VERBOSE_DEBUG: "Debug++",
    }

from Queue import Queue, Full, Empty

LOG_QUEUE = Queue(100)

class LoggingThread(threading.Thread):
    def run(self):
        import pyflag.DB as DB

        log(INFO, "Log thread starting in thread %s, pid %s" % (threading.currentThread().getName(), os.getpid()))
        dbh = DB.DBO(None)
        dbh.cursor.ignore_warnings = True
        ## We get some weird thread related dead locks if we use the
        ## timeout feature here.
        dbh.cursor.timeout = 0
        dbh.mass_insert_start("logs")
        while 1:
            try:
                level, message = LOG_QUEUE.get(block=True)
                ## Terminate the thread
                if level==0:
                    break
                dbh.mass_insert(level=level, message=message)
    #            dbh.insert('logs', level=level, message=message)
            except Exception,e:
                sys.stdout.write( "Logging service: %s" % e)
                sys.stdout.flush()
                time.sleep(1)

def start_log_thread():
    """ This needs to be called to start the log thread.

    NOTE: It is very important to start this _after_ any forking that
    will be done in the main process. We do not want the db handled
    here to be shared between processes or we will get dead locks.
    """
    def kill_logging_thread():
        LOG_QUEUE.put((0,None))

    t = LoggingThread()
    t.start()

    import atexit

    atexit.register(kill_logging_thread)

def log(level,message):
    """ Prints the message out only if the configured verbosity is higher than the message's level."""
    try:
        string = "%s: %s" % (lookup[level],message)
    except:
        string = message

    if config.LOG_LEVEL>=level:
        ## Pass the message to the logger queue:
        try:
            LOG_QUEUE.put((level,message), False)
        except Full:
            pass
        
        print string
        sys.stdout.flush()
        
    if level<=ERRORS:
        print string
        print traceback.print_tb(sys.exc_info()[2])
        sys.stdout.flush()
