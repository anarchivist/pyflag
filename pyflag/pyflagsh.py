#!/usr/bin/python2.3
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
import pyflag.UI as UI
import pyflag.Registry as Registry

## Make sure the registry is properly initialised
#Registry.Init()

class ParserException(Exception):
    """ Exception thrown by the parser when we cant parse the line """
    pass

class environment:
    """ A class representing the environment """
    _flag=None
    _DBO=None
    _FS = None
    _IOSOURCE = None
    _CASE = None
    
    def __init__(self):
        environment.CWD='/'
        if not environment._flag:
            environment._flag=FlagFramework.Flag()
            environment._DBO=DB.DBO
            environment._flag.ui=UI.GenericUI

class command:
    """ Base class for each command """
    optlist=""
    long_opts = []
    def __init__(self,args,e=None):
        """ Constructor uses args as an initialiser. Parses args uses self.getopts """
        self.parse(args)
        if e:
            self.environment=e
        else:
            self.environment=environment()

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

    def execute(self):
        """ Executes the command. This generator yields each line of output """

class command_parse:
    def glob_list(self,args):
        """ Implement globbing of the args array to produce a new args array.
        This implementation is based on the standard library's glob module
        """
        newargs=[]
        for pathname in args:
            newargs.extend(self.glob(pathname))
        return newargs

    def glob(self,pathname):
        """ Globs the pathname against the image by recursively resolving glob directories """
        if not self.has_magic(pathname):
            return [pathname]

        dirname, basename = os.path.split(pathname)
        if not dirname:
            return self.glob1(self.environment.CWD, basename)
        elif self.has_magic(dirname):
            list = glob(dirname)
        else:
            list = [dirname]
        if not self.has_magic(basename):
            result = []
            for dirname in list:
                if basename or self.environment._FS.isdir(dirname):
                    name = os.path.join(dirname, basename)
                    if self.environment._FS.exists(name):
                        result.append(name)
        else:
            result = []
            for dirname in list:
                sublist = self.glob1(dirname, basename)
                for name in sublist:
                    result.append(os.path.join(dirname, name))
        return result

    def glob1(self,dirname, pattern):
        if not dirname: dirname = self.environment.CWD
        try:
            names = self.environment._FS.ls(dirname)
        except os.error:
            return []
        if pattern[0]!='.':
            names=filter(lambda x: x[0]!='.',names)
        return fnmatch.filter(names,pattern)

    magic_check = re.compile('[*?[]')
    def has_magic(self,s):
        return self.magic_check.search(s) is not None

    def __init__(self,environment):
        self.environment=environment

    def parse(self,args):
        try:
            ## Create an instance of this command:
            command=Registry.SHELL_COMMANDS[args[0]](args,self.environment)
            return command.execute()
        except KeyError:
            raise ParserException("No such command %s" % args[0])

def escape(string):
    """ Escapes spaces in the string """
    return string.replace(' ','\\ ')

def completer(text,state):
    args=shlex.split(readline.get_line_buffer())
    # We are trying to complete the primary command:
    commands=Registry.SHELL_COMMANDS.commands.keys()
    if not len(args) or len(args)==1 and text:
        for i in range(state,len(commands)):
            if commands[i].startswith(text):
                return commands[i]
    else:
        c=Registry.SHELL_COMMANDS[args[0]](args,env)
        return(escape(c.complete(text,state)))

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
        #Implement globbing of filenames
        try:
            args=parser.glob_list(args)
        except AttributeError:
            pass

        if args and args[0][0]!='#':
            for result in parser.parse(args):
                ## If we get a dict we enumerate it nicely
                try:
                    for k,v in result.items():
                        print "%s : %s" % (k,v)
                    print "-------------"
                except AttributeError:
                    print result

    except (ParserException,getopt.GetoptError,DB.DBError,TypeError),e:
        print "Error: %s" % e
    except IOError,e:
        print "IOError: %s" % e
    except ValueError,e:
        print "ValueError: %s" %e
    except Exception,e:
        print "Unknown error: %r %s" % (e,e)

def shell_execv_iter(*argv):
    """ A helper routine to execute a shell command.

    This command will usually yield its results. Often the result will be a dict.
    """
    ## This ensures the registry was initialised
    Registry.Init()
    command = Registry.SHELL_COMMANDS[argv[0]](argv)
    return command.execute()

def shell_execv(*argv):
    """ returns the data returned by the iterator in one object """
    string = None
    for i in shell_execv_iter(*argv):
        if i:
            if string == None:
                string = i
            else:
                string += i

    return string

if __name__ == "__main__":
    readline.set_completer(completer)
    env=environment()
    parser=command_parse(env)
    print "Welcome to the Flag shell. Type help for help"
    ## Parse commandline args:
    opts,args=getopt.gnu_getopt(sys.argv,"c:")
    opts=FlagFramework.query_type(opts)

    if opts.has_key("-c"):
        asker=Asker()
        fd=open(opts['-c'])
        file=fd.read()
        
        ## Ask the user to fill in variables in the file
        file=file % asker
        for f in file.split('\n'):
            print "# %s" % f
            process_line(f)
            
    else:
        while(1):
            try:
                input = raw_input("Flag Shell: %s>" % env.CWD)
                process_line(readline.get_line_buffer())
            except (EOFError):
                print "\nBibi Then - Have a nice day."
                sys.exit(0)
            except KeyboardInterrupt:
                print "\nInterrupted"

