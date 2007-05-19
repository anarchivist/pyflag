# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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
""" An interactive shell for examining file systems loaded into flag """
try:
    import readline

    readline.parse_and_bind("tab: complete")
except ImportError:
    pass

import sys
import pyflag.DB as DB
import pyflag.IO as IO
import shlex,os,os.path,re,fnmatch
import getopt
import pyflag.FlagFramework as FlagFramework
import pyflag.TEXTUI as TEXTUI
import pyflag.Registry as Registry
import pyflag.conf
config = pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem

class ParserException(Exception):
    """ Exception thrown by the parser when we cant parse the line """
    pass

class environment:
    """ A class representing the environment """
    def __init__(self, case=None):
        self._flag=FlagFramework.Flag()
        self._FS = None
        self.CWD='/'
        self._CASE = case

class command:
    """ Base class for each command """
    optlist=""
    long_opts = []
    def __init__(self,args,env=None):
        """ Constructor uses args as an initialiser. Parses args uses self.getopts """
        self.parse(args)
        if env:
            self.environment=env
        else:
            self.environment=environment()

    def glob_files(self, args):
        ## Glob the path if possible:
        files = {}
        for arg in args:
            ## Add the implied CWD:
            if not arg.startswith("/"): arg=FlagFramework.normpath(self.environment.CWD+"/"+arg)
            for path in FileSystem.glob(arg, case=self.environment._CASE):
                files[path]=True

        ## This is used to collate files which may appear in multiple globs
        files = files.keys()
        files.sort()

        return files

    def help(self):
        """ Help function to print when the user asked for help """
        raise ParserException("No help available")

    def parse(self,args):
        """ This method parses the args storing the option args in self.opts and non-option args in self.args.

        Note that we expect to have self.optlist as the getopt string for this command.
        """
        opts,self.args=getopt.gnu_getopt(args,self.optlist,self.long_opts)
        self.opts=FlagFramework.query_type(opts)

    def complete(self,text,state):
        """ Method used to complete the command. """

    def complete_from_list(self, text, state, array):
        """ Does the right thing of returning what complete() needs
        given a list of possibilities
        """
        for i in range(state, len(array)):
            if array[i].startswith(text):
                return array[i]

    def execute(self):
        """ Executes the command. This generator yields each line of output """

class command_parse:
    def __init__(self,environment):
        self.environment=environment

    def parse(self,args):
        try:
            ## Create an instance of this command:
            command=Registry.SHELL_COMMANDS[args[0]](args[1:],env=self.environment)
            return command.execute()
        except KeyError:
            raise ParserException("No such command %s" % args[0])

def escape(string):
    """ Escapes spaces in the string """
    return string.replace(' ','\\ ')

def completer(text,state):
    """ This function gets called each time the user types tab to complete.

    Note that this function works around a severe bug in the readline library: When completing a term with delimeters in it (eg spaces), the completer function received text=the last word in the term, despite the term having its delimeters properly escaped. In other words it seems that the completer functionality does not understand escaping properly. This results in problems when completing terms with spaces in them.

    This workaround recalculates text from a proper shlex parse of the line.
    """
    t=text
    line = readline.get_line_buffer()
    args=shlex.split(line)
##    if line[-1] in readline.get_completer_delims():
##        text=''
##    else:
##        text=args[-1]

    # We are trying to complete the primary command:
    if not len(args) or len(args)==1 and text:
        commands=[ x for x in Registry.SHELL_COMMANDS.commands.keys() if x.startswith(text)]
        try:
            return commands[state]
        except IndexError:
            return None
    else:
        c=Registry.SHELL_COMMANDS[args[0]](args,env)
        try:
            result=c.complete(text,state)
            return(escape(result[len(text)-len(t):]))
        except Exception,e:
            return None

class Asker:
    """ Class asks the user for parameters to fill into flash scripts """
    cache={}
    def  __getitem__(self,data):
        try:
            return self.cache[data]
        except KeyError:
            input=raw_input("Please enter a value for %s: " % data)
            self.cache[data]=input
            return input

def process_line(line):
    try:
        args=shlex.split(line)

        if args and args[0][0]!='#':
            lines = []
            for result in parser.parse(args):
                ## If we get a dict we enumerate it nicely
                try:
                    for k,v in result.items():
                        lines.append( "%s : %s" % (k,v))
                    lines.append("-------------")
                except AttributeError:
                    lines.extend(result.splitlines())

            ## If the output is short enough to fit on the screen,
            ## just print it there, otherwise pipe it to less.
            if len(lines)<20:
                print "\n".join(lines)
            else:
                ## FIXME: we should set a config parameter for pager.
                pipe=os.popen("less","w")
                pipe.write("\n".join(lines))
                pipe.close()

    except (ParserException,getopt.GetoptError,DB.DBError,TypeError),e:
        print "Error: %s" % e
        raise
    except IOError,e:
        print "IOError: %s" % e
    except ValueError,e:
        print "ValueError: %s" %e
    except Exception,e:
        raise

def shell_execv_iter(env=None,command=None, argv=[]):
    """ A helper routine to execute a shell command.

    This command will usually yield its results. Often the result will be a dict.
    """
    if not command: raise RuntimeError("No command provided")
    if not env: env=environment()
    
    ## This ensures the registry was initialised
    Registry.Init()
    try:
        command = Registry.SHELL_COMMANDS[command]
    except:
        raise RuntimeError("Command %s not found in registry" % command)
    
    command = command(argv, env=env)
        
    return command.execute()

def shell_execv(env=None,command=None, argv=[]):
    """ returns the data returned by the iterator in one object """
    string = None
    for i in shell_execv_iter(env=env, command=command, argv=argv):
        if i:
            if string == None:
                string = i
            else:
                string += i

    return string

if __name__ == "__main__":
    # Parse commandline args:
    config.set_usage(usage="PyFlash the pyflag interactive shell",
                     version=config.VERSION)
    
    config.optparser.add_option("-c", "--commands", dest="command_file",
                                help="execute flash script from FILE", metavar="FILE")

    config.optparser.add_option("-p", "--params", dest="params", 
                                help="comma seperated list of KEY:VALUE for flash scripts",
                                metavar="PARAMS")

    config.parse_options()

    ## Make sure the registry is properly initialised
    Registry.Init()

    import pyflag.UI as UI
    
    UI.UI = TEXTUI.TEXTUI

    ## Handle a history file
    histfile = os.path.join(os.environ["HOME"], ".flashhist")
    try:
        readline.read_history_file(histfile)
    except IOError:
        pass
    import atexit

    atexit.register(readline.write_history_file, histfile)
    atexit.register(FlagFramework.post_event, 'exit', config.FLAGDB)
    
    readline.set_completer(completer)
    readline.set_completer_delims(' \t\n/=+\'"')
    
    env=environment()
    parser=command_parse(env)
    print "Welcome to the Flag shell. Type help for help"
    
    ## Create a worker thread:
    import pyflag.Farm as Farm
    Farm.start_workers()

    if config.command_file != None:
      asker=Asker()
      fd=open(config.filename)
      file = fd.read()
      
      #Initialise variable cache from parameters (if they are provided)
      if config.params != None:
        params = config.params.split(",")
        for keypair in params:
          keyvalue = keypair.split(":")
          asker.cache[keyvalue[0]] = keyvalue[1]
      
      # Ask the user to fill in variables in the file
      file=file % asker
      for f in file.split('\n'):
          print "# %s" % f
          try:
              process_line(f)
          except Exception,e:
              print "Unknown error: %r %s" % (e,e)
              print FlagFramework.get_bt_string(e)
                  
    else:
        while 1:
            try:
                input = raw_input("Flag Shell: %s>" % env.CWD)
                process_line(input)
            except RuntimeError,e:
                print e
            except (EOFError, SystemExit):
                print "Bibi Then - Have a nice day."
                sys.exit(0)
            except KeyboardInterrupt:
                print "\nInterrupted"
            except Exception,e:
                print isinstance(e,ParserException)
                print "Unknown error: %r %s" % (e,e)
                print FlagFramework.get_bt_string(e)
