#!/usr/bin/env python
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
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
""" Implement a simple logger wrapper.

logging verbosity is controlled through the configuration variable LOG_LEVEL
"""
import pyflag.conf
config = pyflag.conf.ConfObject()

import sys,traceback,time,threading,os

## Declare the parameters we need:
config.add_option("LOG_LEVEL", default=10, type='int', short_option='v',
                  help="Logging level")

config.add_option("LOGFILE", default="/dev/stderr",
                  help="Send log messages to this file")

## These are predefined logging levels:
ERRORS=1
ERROR=1
WARNINGS=3
WARNING=3
INFO=5
DEBUG=7
VERBOSE_DEBUG=12

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
    def try_to_connect(self):
        import pyflag.DB as DB

        dbh = DB.DBO(None)
        dbh.cursor.ignore_warnings = True
        ## We get some weird thread related dead locks if we use the
        ## timeout feature here.
        dbh.cursor.timeout = 0
        dbh.cursor.logged  = False
        
        return dbh
        
    def run(self):
        log(INFO, "Log thread starting in thread %s, pid %s" % (threading.currentThread().getName(), os.getpid()))
        try:
            dbh = self.try_to_connect()
        except:
            dbh = None
            
        while 1:
            try:
                level, message = LOG_QUEUE.get(block=True)
                ## Terminate the thread
                if level==0:
                    break
                ## dbh.mass_insert(level=level, message=message)
                if not dbh:
                    dbh = self.try_to_connect()
                    
                #if dbh:
                #    dbh.insert('logs', level=level, message=message[:250], _fast=True)
            except Exception,e:
                sys.stdout.write( "Logging service: %s\nIf PyFlag is not configured yet just connect to its URL. (http://%s:%s/)\n" % (e,config.HTTPSERVER_BINDIF, config.HTTPSERVER_PORT))
                sys.stdout.flush()
                time.sleep(10)

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

def log(level,message, *args):
    """ Prints the message out only if the configured verbosity is higher than the message's level."""
    if config.LOG_LEVEL >= level:
        try:
            log_fd = open(config.LOGFILE,"ab")
        except Exception,e:
            log_fd = sys.stderr

        import pyflag.DB as DB

        try:
            string = DB.expand("%s(%s): %s" % (os.getpid(),lookup[level],message), args)
        except Exception,e:
            log_fd.write("%s\n" % e)
            string = message

        ## Pass the message to the logger queue:
        try:
            LOG_QUEUE.put((level,message), False)
        except Full:
            pass
        import pyflag.FlagFramework as FlagFramework
        
        log_fd.write(FlagFramework.smart_str(string) + "\n")
        log_fd.flush()
        
    if level<=ERRORS and level>0:
        log_fd.write("%s\n" % string)
        log_fd.write("%s\n" % traceback.print_tb(sys.exc_info()[2]))
        log_fd.flush()

def render_system_messages(result):
    result.row("System messages:")
    import pyflag.DB as DB
    
    dbh = DB.DBO()
    dbh.execute("select count(*) as size from logs")
    size = dbh.fetch()['size']
    pagesize=20
    dbh.execute("select timestamp,level,message from logs limit %s, %s", (max(size-pagesize,0), pagesize))
    data = '\n'.join(["%(timestamp)s(%(level)s): %(message)s" % row for row in dbh])
    tmp=result.__class__(result)
    tmp.text(data,font='typewriter',style="red")
    result.row(tmp)
