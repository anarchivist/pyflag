
""" These are basic flash commnads for the flag shell """
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
import pyflag.pyflagsh as pyflagsh
import sys,os
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FileSystem as FileSystem
import time
import pyflag.Registry as Registry
import pyflag.logging as logging
import pyflag.conf
config=pyflag.conf.ConfObject()
import fnmatch
import pyflag.TEXTUI as TEXTUI

class load(pyflagsh.command):
    def help(self):
        return  "load case.iosource: loads the iosource within case into the shell."
    
    def execute(self):
        args=self.args
        text=''
        try:
            case=args[1]
            dbh = self.environment._DBO(case)
##            try:
##                case=text[:text.index(".")]
##                dbh = self.environment._DBO(case)
##            except ValueError:
##                raise ParserException("Load has the following format: case.tag")

            self.environment.__class__._FS=Registry.FILESYSTEMS.fs['DBFS'](case)
            self.environment.__class__._CASE = case
            yield "Loaded case %r" %(case)
        except Exception,e:
            raise RuntimeError("Unable to open filesystem %s (%s)" %(text,e))

    def complete(self,text,state):
        """ Completes the command for the different filesystems """
        args=self.args
        dbh=self.environment._DBO(None)
        dbh.execute("select value from meta where property=%r","flag_db")
        cases=[ row['value'] for row in dbh ]
        for i in range(state,len(cases)):
            if cases[i].startswith(text):
                return cases[i]

class ls(pyflagsh.command):
    """ Implement the ls command. """
    optlist="lR"
    def help(self):
        return "ls [dir]:  lists the files in the current directory (if dir not specified) or in dir."

    def execute(self):
        args=self.args[1:]
        if len(args)==0:
            args.append(self.environment.CWD)

        print args
        ## Glob the path if possible:
        files = {}
        for arg in args:
            ## Add the implied CWD:
            if not arg.startswith("/"): arg=FlagFramework.normpath(self.environment.CWD+"/"+arg)
            for path in FileSystem.glob(arg, case=self.environment._CASE):
                f=FlagFramework.joinpath(path)
                files[f]=True

        ## This is used to collate files which may appear in multiple globs
        files = files.keys()
        files.sort()

        for path in files:
            for f in self.list(path):
                yield f
            
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

        except AttributeError:
            raise RuntimeError("No Filesystem loaded, do you need to load a filesystem first?")

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

        path=FlagFramework.normpath(new_path)
        if new_path!='/':
        ## Now check if the new path actually exists (There is an edge case here with / does have an inode):
            if not self.environment._FS.isdir(new_path):
                raise RuntimeError("No such directory: %s" % new_path)
        
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

class cat(ls):
    """ Dumps the content of the file """
    def execute(self):
        for arg in self.args[1:]:
            path=os.path.abspath(os.path.join(self.environment.CWD,arg))
            fd=self.environment._FS.open(path)
            while 1:
                f=fd.read(1000000)
                if len(f)>0:
                    yield f
                else: break

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

class help(pyflagsh.command):
    def help(self):
        return("""PyFlag shell allows direct access to the filesystems. Command line expansion is supported. The following commands are defined, type help command to find out more:
%s
""" % Registry.SHELL_COMMANDS.commands.keys())
    
    def complete(self,text,state):
        commands = Registry.SHELL_COMMANDS.commands.keys()
        for i in range(state,len(commands)):
            if commands[i].startswith(text):
                return commands[i]
            
    def execute(self):
        args=self.args
        if len(args)==1:
            args.append('help')

        for i in args[1:]:
            command=Registry.SHELL_COMMANDS[i]([],self.environment)
            try:
                yield(command.help())
            except pyflagsh.ParserException:
                yield(command.__doc__)

class pwd(pyflagsh.command):
    def execute(self):
        yield "Current directory is %s" % self.environment.CWD

class set(pyflagsh.command):
    """ Sets and reads different values in the environment """
    def complete(self,text,state):
        env = [ i for i in dir(self.environment) if not i.startswith('_') ]
        for i in range(state,len(env)):
            if env[i].startswith(text):
                return env[i]
            
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

class exit(pyflagsh.command):
    """ Exits the shell"""
    def help(self):
        return "exit: Exits the PyFlag shell"
    
    def execute(self):
        sys.exit()

class istat(pyflagsh.command):
    """ stats an inode in the filesystem """
    def help(self):
        return "istat: Stats an inode in the file system returning statistics"

    def execute(self):
        args=self.args
        for arg in args[1:]:
            filename = self.environment._FS.lookup(inode=arg)
            status=self.environment._FS.istat(inode=arg)
            if not status:
                raise RuntimeError("No status available for %s" % arg)

            status['filename'] = filename
            yield status

class execute(pyflagsh.command):
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

    def complete(self,text,state):
        args=self.args

        possibilities=[]
        allreports=[]
        families = Registry.REPORTS.get_families()
        for family in families:
            reports=Registry.REPORTS.family[family]
            for report in reports:
                possibilities.append("%s.%s" % (family,report.name))
                allreports.append(report)
        
        if len(args)<2 or len(args)==2 and text:
            for i in range(state,len(possibilities)):
                if possibilities[i].startswith(text):
                    return possibilities[i]
        else:
            for i in range(0,len(possibilities)):
                if possibilities[i] == args[1]:
                    r = allreports[i]
                    params = r.parameters.keys()
                    params.append('case')
                    for i in range(state,len(params)):
                        if params[i].startswith(text):
                            return params[i]

    def prepare(self):
        """ Returns a report, query all ready from the current args """
        args=self.args
        query=FlagFramework.query_type(())
 
        try:
            query['family'],query['report']=args[1].split('.')
        except:
            raise RuntimeError("Unable to parse %s as a family.report" % args[1])
        
        report = Registry.REPORTS.dispatch(query['family'],query['report'])
        ## Include the report and family:

        for arg in args[2:]:
            try:
#                del query[arg[:arg.index('=')]]
                query[arg[:arg.index('=')]]=arg[arg.index('=')+1:]
            except ValueError:
                raise RuntimeError("Argument should be of the form key=value, got %s" % arg)

        ## Include environment variables in the query:
        for arg in dir(self.environment):
            if not arg.startswith('_') and not query.has_key(arg):
                try:
                    query[arg]=self.environment.__dict__[arg]
                except KeyError:
                    pass

#        if not query.has_key('case'): query['case']=config.FLAGDB
        return report,query

    def execute(self):
        start_time=time.time()
        report,query = self.prepare()

        logging.log(logging.DEBUG, "Will execute the following query %s" % query)

        ## Instantiate the report
        report=report(self.environment._flag)
        if self.environment._flag.is_cached(query):
            print query
            
            ## Run the display method
            result=TEXTUI.TEXTUI(query=query)
            report.display(query,result)           
            print result
#            yield "Report previously run... You need to reset it first."
            return
            
        ## Execute the report:
        try:
            report.analyse(query)
            try:
                dbh = DB.DBO(query['case'])
            except KeyError:
                dbh = DB.DBO()
                
            canonical_query = FlagFramework.canonicalise(query)
            dbh.execute("insert into meta set property=%r,value=%r",('report_executed',canonical_query))

            ## We call the display method just in case this report
            ## does something in the display
            result=TEXTUI.TEXTUI(query=query)
            report.display(query,result)
            print result.display()
            yield "Execution of %s successful in %s sec" % (self.args[1],time.time()-start_time)
        except Exception,e:
            import traceback
            print traceback.print_tb(sys.exc_info()[2])
            raise RuntimeError("%s: %s after %s sec" %  (sys.exc_info()[0],sys.exc_info()[1],time.time()-start_time))

class reset(execute):
    """ Resets the given report """
    def help(self):
        return """
        This command resets a flag report. After running this command the state of the database should be returned to what it was before the report was executed.
        """
    def execute(self):
        start_time=time.time()
        report,query = self.prepare()

        ## Instantiate the report:
        report=report(self.environment._flag)
        
        ## Execute the report:
        try:
            report.do_reset(query)
            yield "Resetting of %s successful in %s sec" % (self.args[1],time.time()-start_time)            
        except Exception,e:
            import traceback
            print traceback.print_tb(sys.exc_info()[2])
            raise RuntimeError("%s: %s after %s sec" %  (sys.exc_info()[0],sys.exc_info()[1]),time.time()-start_time)

class find(ls):
    """ A command to find files in the filesystem """
    long_opts = [ "name=", "type=" ]
    
    def execute(self):
        for path in self.args[1:]:
            for file in self.list(path):
                yield os.path.normpath( "/////%s/%s" % (file['path'],file['name']))
        
    def list(self,path):
        """ List the files in a particular path """
        path=os.path.abspath(os.path.join(self.environment.CWD,path))
        try:
            if self.environment._FS.isdir(path):
                if not path.endswith('/'):
                    path=path+'/'

                for dir in self.environment._FS.longls(path=path, dirs=0):
                    yield dir

                for dir in self.environment._FS.longls(path=path, dirs=1):
                    yield dir
                    for file in self.list(path+dir['name']):
                        yield file

#            else:
#                yield {'name':path, 'path':''}

        except AttributeError:
            raise RuntimeError("No Filesystem loaded, do you need to load a filesystem first?")

class find_dict(find):
    """ This command returns a full dict of information for each file returned """
    def execute(self):
        for path in self.args[1:]:
            return self.list(path)

class file(ls):
    """ Returns the file magic of args """
    def execute(self):
        dbh=self.environment._DBO(self.environment._CASE)
        #Find the inode of the file:
        
        for path in self.args[1:]:
            inode = self.environment._FS.lookup(path=path)
            dbh.execute("select mime,type from type where inode =%r",(inode))
            yield dbh.fetch()

