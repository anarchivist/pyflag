#!/usr/bin/python2.3
""" An interactive shell for examining file systems loaded into flag """

import readline,sys
import pyflag.Sleuthkit as Sleuthkit
import pyflag.DB as DB
import pyflag.IO as IO
import shlex,os,os.path,re,fnmatch
import getopt
import pyflag.FlagFramework as FlagFramework
import pyflag.UI as UI
import pyflag.FileSystem as FileSystem
import time

readline.parse_and_bind("tab: complete")

class ParserException(Exception):
    """ Exception thrown by the parser when we cant parse the line """
    pass

class environment:
    """ A class representing the environment """

class command:
    """ Base class for each command """
    optlist=""
    def __init__(self,args,environment):
        """ Constructor uses args as an initialiser. Parses args uses self.getopts """
        self.parse(args)
        self.environment=environment

    def help(self):
        """ Help function to print when the user asked for help """
        return "No help Available, sorry :( "

    def parse(self,args):
        """ This method parses the args storing the option args in self.opts and non-option args in self.args.

        Note that we expect to have self.optlist as the getopt string for this command.
        """
        opts,self.args=getopt.gnu_getopt(args,self.optlist)
        self.opts=FlagFramework.query_type(opts)

    def complete(self,text,state):
        """ Method used to complete the command. """

    def execute(self):
        """ Executes the command. This generator yields each line of output """

class load(command):
    def help(self):
        return  "load case.iosource: loads the iosource within case into the shell."
    
    def execute(self):
        args=self.args
        text=''
        try:
            text=args[1]
            try:
                case=text[:text.index(".")]
                dbh = self.environment._DBO(case)
                sourcename=text[text.index(".")+1:]
            except ValueError:
                raise ParserException("Load has the following format: case.tag")
            iofd=IO.open(case,sourcename)
            self.environment._FS=FileSystem.FS_Factory(case,sourcename,iofd)
            yield "Loaded Filesystem tag %r in case %r" %(sourcename,case)
        except Exception,e:
            raise ParserException("Unable to open filesystem %s (%s)" %(text,e))

    def complete(self,text,state):
        """ Completes the command for the different filesystems """
        #If the text does not have . in it, list the cases, other wise assume the thing before the first . is the case name and list the filesystems in it
        args=self.args
        try:
            case=text[:text.index(".")]
            iosource=text[text.index(".")+1:]
            dbh=self.environment._DBO(case)
            dbh.execute("select value from meta where property =%r","iosource")
            iosources=[ row['value'] for row in dbh ]
            for i in range(state,len(iosources)):
                if iosources[i].startswith(iosource):
                    return case+"."+iosources[i]
            
        except ValueError:
            # No case was given yet
            dbh=self.environment._DBO(None)
            dbh.execute("select value from meta where property=%r","flag_db")
            cases=[ row['value'] for row in dbh ]
            for i in range(state,len(cases)):
                if cases[i].startswith(text):
                    return cases[i]

class ls(command):
    """ Implement the ls command. """
    optlist="lR"
    def help(self):
        return "ls [dir]:  lists the files in the current directory (if dir not specified) or in dir."

    def execute(self):
        args=self.args
        if len(args)==1:
            args.append(self.environment.CWD)
                
        for path in args[1:]:
            return self.list(path)
            
    def list(self,path):
        """ List the files in a particular path """
        path=os.path.abspath(os.path.join(self.environment.CWD,path))
        try:
            if self.environment._FS.isdir(path):
                if not path.endswith('/'):
                    path=path+'/'

                if self.opts.has_key('-l'):
                    for dir in self.environment._FS.longls(path=path):
                        yield "%s %s %s" % (dir['mode'],dir['inode'],dir['name'])
                        
                else:
                    for dir in self.environment._FS.ls(path=path,dirs=1):
                        yield "[%s]"%dir
                        
                    for file in self.environment._FS.ls(path=path,dirs=0):
                        yield " %s " % file

                ## Do we need to recurse?
                if self.opts.has_key('-R'):
                    for dir in self.environment._FS.ls(path=path,dirs=1):
                        print "Directory %s:" % (path+dir)
                        for file in self.list(path+dir):
                            yield file

            else:
                yield ''

        except AttributeError:
            raise ParserException("No Filesystem loaded, do you need to load a filesystem first?")

    def complete(self,text,state):
        args=self.args
        if len(args)==1: args.append('.')
        path,name=os.path.split(args[-1])
        path=os.path.abspath(os.path.join(self.environment.CWD,path))
        if not path.endswith('/'):
            path=path+'/'

        ## This does an ls of the current directory
        files=[ file for file in self.environment._FS.ls(path=path,dirs=1)]
        files.extend([ file for file in self.environment._FS.ls(path=path,dirs=0)])
        for i in range(state,len(files)):
            if files[i].startswith(text):
                return files[i]

class cd(ls):
    def help(self):
        return  "cd [dir]: changes directory to root (if dir not specified) or to dir."
    
    def execute(self):
        args=self.args
        try:
            path=args[1]
        except IndexError:
            path="/"

        new_path=os.path.abspath(os.path.join(self.environment.CWD,path))
        if not new_path.endswith('/'):
            new_path+='/'

        #Now check if the new path actually exists (There is an edge case here with / does have an inode):
        if not self.environment._FS.isdir(new_path):
            raise ParserException("No such directory: %s" % new_path)
        
        self.environment.CWD=new_path
        yield 'current working directory %s' % self.environment.CWD

    def complete(self,text,state):
        args=self.args
        if len(args)==1: args.append('.')
        path,name=os.path.split(args[-1])
        path=os.path.abspath(os.path.join(self.environment.CWD,path))
        if not path.endswith('/'):
            path=path+'/'

        ## This does an ls of the current directory only for directories.
        files=[ file for file in self.environment._FS.ls(path=path,dirs=1)]
        for i in range(state,len(files)):
            if files[i].startswith(text):
                return files[i]

class less(ls):
        """ Pipes the content of the file to less """
        def help(self):
            return "Pipe files to less pager "
        
        def execute(self):
            args=self.args
            for arg in args[1:]:
                path=os.path.abspath(os.path.join(self.environment.CWD,arg))
                fd=self.environment._FS.open(path)
                f=fd.read()
                fd.close()
                pipe=os.popen("less","w")
                pipe.write(f)
                pipe.close()
                yield 'Viewing of %s with less successful' % path

class cp(ls):
    """ Copies files from the filesystem to the directory specified as the last arg """
    def help(self):
        return "cp files dest: copies files (which could use globs) to destination directory (on the real system).\n(note: This will not overwrite a file!)"
    
    def execute(self):
        args=self.args
        target=args[-1]
        #Check to see if the target is a valid directory:
        if not os.path.isdir(target):
            raise IOError("Target %s is not a directory. (Note: Target must exist on the host filesystem)")
        for file in args[1:-1]:
            path=os.path.abspath(os.path.join(self.environment.CWD,file))
            target_path=os.path.abspath(os.path.join(target,file))
            outfd=open(target_path,"w")
            try:
                fd=self.environment._FS.open(path)
                while 1:
                    f=fd.read(1000000)
                    if not f: break
                    outfd.write(f)

                fd.close()
                outfd.close()
                yield "Copied %s in image to %s on host" % (path,target_path)
            except IOError,e:
                yield "Unable to copy %s: %s" %(path,e)

class help(command):
    def help(self):
        return("""PyFlag shell allows direct access to the filesystems. Command line expansion is supported. The following commands are defined, type help command to find out more:
%s
""" % functions.keys())
    
    def execute(self):
        args=self.args
        if len(args)==1:
            args.append('help')

        for i in args[1:]:
            command=sys.modules['__main__'].__dict__[i]([],environment)
            yield(command.help())

class pwd(command):
    def execute(self):
        yield "Current directory is %s" % self.environment.CWD

class set(command):
    """ Sets and reads different values in the environment """
    def execute(self):
        args=self.args
        if len(args)==1:
            for i in dir(self.environment):
                if not i.startswith('_'):
                    try:
                        yield "%s = %s" %(i,self.environment.__dict__[i])
                    except KeyError:
                        pass
        else:
            for i in args[1:]:
                try:
                    index=i.index("=")
                    self.environment.__dict__[i[:index]]=i[index+1:]
                except ValueError:
                    yield self.environment.__dict__[i]

class exit(command):
    """ Exits the shell"""
    def execute(self):
        raise EOFError

class istat(command):
    """ stats an inode in the filesystem """
    def help(self):
        return "istat: Stats an inode in the file system returning statistics"

    def execute(self):
        args=self.args
        for arg in args[1:]:
            yield "Status for inode %s (%s)" % (arg,self.environment._FS.lookup(inode=arg))
            status=self.environment._FS.istat(inode=arg)
            if not status:
                raise ParserException("No status available for %s" % arg)
            for k,v in status.items():
                yield "%s: %s" % (k,v)

class execute(command):
    """ Executes a report's analysis method with the required parameters """
    def help(self):
        return """
        This command executes a flag report giving it the arguments given. The general format of this command is:

        execute Family.ReportName arg1=value arg2=value

        Note that environment values are automatically included into the set of args. So you may use set to set args that are commonly used.
        Note also that command line completion is enabled for this, and so may be used liberally to assist with both the selection of reports and the args needed
        """
    def __init__(self,args,environment):
        self.args=args
        self.environment=environment
        try:
            self.environment._flag
        except AttributeError:
            self.environment._flag=FlagFramework.Flag()
            
        self.reports={}
        for key in self.environment._flag.dispatch.family.keys():
            for report in self.environment._flag.dispatch.family[key].values():
                self.reports["%s" % report.__class__]=report

    def complete(self,text,state):
        args=self.args
        if not text: args.append('')
        
        if len(args)<=2:
            items=self.reports.keys()
        else:
            report=self.reports[args[1]]
            items=report.parameters.keys()
            items.append('case')
        
        for i in range(state,len(items)):
            if items[i].startswith(text):
                return items[i]

    def execute(self):
        start_time=time.time()
        args=self.args
        try:
            report=self.reports[args[1]]
        except KeyError:
            raise ParserException("Unknown report %s" % args[1])
        
        query=FlagFramework.query_type(())

        for arg in args[2:]:
            try:
                del query[arg[:arg.index('=')]]
                query[arg[:arg.index('=')]]=arg[arg.index('=')+1:]
            except ValueError:
                raise ParserException("Argument should be of the form key=value, got %s" % arg)

        ## Include environment variables in the query:
        for arg in dir(self.environment):
            if not arg.startswith('_'):
                try:
                    query[arg]=self.environment.__dict__[arg]
                except KeyError:
                    pass

        ## Include the report and family:
        query['family'],query['report']=args[1].split('.')

        print "Checking meta cache"
        if self.environment._flag.is_cached(query):
            yield "Report previously run... You need to reset it first."
            return
            
        ## Execute the report:
        try:
            report.analyse(query)
            dbh = self.environment._DBO(query['case'])
            canonical_query = self.environment._flag.canonicalise(query)
            dbh.execute("insert into meta set property=%r,value=%r",('report_executed',canonical_query))
            yield "Execution of %s successful in %s sec" % (args[1],time.time()-start_time)
        except Exception,e:
            import traceback
            print traceback.print_tb(sys.exc_info()[2])
            raise ParserException("%s: %s after %s sec" %  (sys.exc_info()[0],sys.exc_info()[1]),time.time()-start_time)

class reset(execute):
    """ Resets the given report """
    def help(self):
        return """
        This command resets a flag report. After running this command the state of the database should be returned to what it was before the report was executed.
        """
    def execute(self):
        start_time=time.time()
        args=self.args
        try:
            report=self.reports[args[1]]
        except KeyError:
            raise ParserException("Unknown report %s" % args[1])
        
        query=FlagFramework.query_type(())
        
        for arg in args[2:]:
            try:
                del query[arg[:arg.index('=')]]
                query[arg[:arg.index('=')]]=arg[arg.index('=')+1:]
            except ValueError:
                raise ParserException("Argument should be of the form key=value, got %s" % arg)

        ## Include environment variables in the query:
        for arg in dir(self.environment):
            if not arg.startswith('_'):
                try:
                    query[arg]=self.environment.__dict__[arg]
                except KeyError:
                    pass

        ## Include the report and family:
        query['family'],query['report']=args[1].split('.')

        ## Execute the report:
        try:
            report.do_reset(query)
            yield "Resetting of %s successful in %s sec" % (args[1],time.time()-start_time)
            
        except Exception,e:
            import traceback
            print traceback.print_tb(sys.exc_info()[2])
            raise ParserException("%s: %s after %s sec" %  (sys.exc_info()[0],sys.exc_info()[1]),time.time()-start_time)

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
            command=functions[args[0]](args,self.environment)
            return command.execute()
        except KeyError:
            raise ParserException("No such command %s" % args[0])

env=environment()
parser=command_parse(env)
functions={}

## This fills in the function dispatcher through instrospection. This means that the only thing you need to do to add a new command is to create a new class, subclassing the command class.
for i in dir(sys.modules['__main__']):
    try:
        if issubclass(sys.modules['__main__'].__dict__[i],command):
            functions[i]=sys.modules['__main__'].__dict__[i]
    except TypeError:
        pass


def escape(string):
    """ Escapes spaces in the string """
    return string.replace(' ','\\ ')

def completer(text,state):
    args=shlex.split(readline.get_line_buffer())
    # We are trying to complete the primary command:
    commands=functions.keys()
    if not len(args) or len(args)==1 and text:
        for i in range(state,len(commands)):
            if commands[i].startswith(text):
                return commands[i]
    else:
        c=functions[args[0]](args,env)
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

readline.set_completer(completer)
env.CWD='/'
env._FS=None
env._flag=FlagFramework.Flag()
env._DBO=DB.DBO
env._flag.ui=UI.GenericUI

def process_line(line):
    try:
        args=shlex.split(line)
        #Implement globbing of filenames
        try:
            args=parser.glob_list(args)
        except AttributeError:
            pass

        if args and args[0][0]!='#':
            for i in parser.parse(args):
                print i

    except (ParserException,getopt.GetoptError,DB.DBError,TypeError),e:
        print "Error: %s" % e
    except IOError,e:
        print "IOError: %s" % e
    except ValueError,e:
        print "ValueError: %s" %e

if __name__ == "__main__":
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
            print f
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

