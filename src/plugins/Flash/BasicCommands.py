
""" These are basic flash commnads for the flag shell """
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
import pyflag.pyflagsh as pyflagsh
import sys,os,posixpath
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FileSystem as FileSystem
import time
import pyflag.Registry as Registry
import pyflag.pyflaglog as pyflaglog
import pyflag.conf
config=pyflag.conf.ConfObject()
import fnmatch
import pyflag.TEXTUI as TEXTUI

class load(pyflagsh.command):
    """ Assigns a current case for use in the shell """
    def help(self):
        return  "load case.iosource: loads the case into the shell."
    
    def execute(self):
        args=self.args
        text=''
        try:
            case=args[0]
            dbh = DB.DBO(case)

            self.environment._FS=FileSystem.DBFS(case)
            self.environment._CASE = case
            yield "Loaded case %r" %(case)
        except Exception,e:
            raise RuntimeError("Unable to open filesystem %s (%s)" %(text,e))

    def complete(self,text,state):
        """ Completes the command for the different filesystems """
        args=self.args
        dbh=DB.DBO()
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
        args=self.args
        if len(args)==0:
            args.append(self.environment.CWD)

        for path in self.glob_files(args):
            for f in self.list(path):
                yield f
            
    def list(self,path):
        """ List the files in a particular path """
        path=posixpath.abspath(posixpath.join(self.environment.CWD,path))
        try:
            if self.environment._FS.isdir(path):
                if not path.endswith('/'):
                    path=path+'/'

            if self.opts.has_key('-l'):
                for dir in self.environment._FS.longls(path=path):
                    if dir['name']:
                        yield "%s\t%s\t%s\t%s" % (dir['mode'],
                                                  dir.get('size','-'),
                                                  dir['inode'],
                                                  dir['name'])

            else:
                for dir in self.environment._FS.ls(path=path,dirs=1):
                    ## Remove the current dir from path:
                    if path.startswith(self.environment.CWD):
                        new_path=path[len(self.environment.CWD):]
                    else: new_path=path
                    
                    if dir:
                        yield "[%s%s]" % (new_path,dir)

                for dent in self.environment._FS.longls(path=path,dirs=0):
                    if dent:
                        yield " %s%s " % (dent['path'],dent['name'])

            ## Do we need to recurse?
            if self.opts.has_key('-R'):
                for dir in self.environment._FS.longls(path=path,dirs=1):
                    if dir['name']:
                        new_path = path + dir['name']
                        yield "Directory %s:" % (new_path)
                        for file in self.list(new_path):
                            yield file

        except AttributeError:
            raise RuntimeError("No Filesystem loaded, do you need to load a filesystem first?")

    def complete(self,text,state):
        args=self.args
        if len(args)==1: args.append('.')
        path,name=posixpath.split(args[-1])
        path=posixpath.abspath(posixpath.join(self.environment.CWD,path))
        if not path.endswith('/'):
            path=path+'/'

        ## This does an ls of the current directory
        files=[ file for file in self.environment._FS.ls(path=path,dirs=1)]
        files.extend([ file for file in self.environment._FS.ls(path=path,dirs=0)])
        for i in range(state,len(files)):
            if files[i].startswith(text):
                return files[i]

class cd(ls):
    """ Change working directory """
    def help(self):
        return  "cd [dir]: changes directory to root (if dir not specified) or to dir."
    
    def execute(self):
        args=self.args
        try:
            path=args[0]
        except IndexError:
            path="/"

        new_path=posixpath.abspath(posixpath.join(self.environment.CWD,path))
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
        path,name=posixpath.split(args[-1])
        path=posixpath.abspath(posixpath.join(self.environment.CWD,path))
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
        args = self.args
        
        for arg in self.glob_files(args):
            fd=self.environment._FS.open(arg)
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
            glob_files=self.glob_files(args)
            if not glob_files:
                yield "Error: No such file"
                
            for arg in glob_files:
                fd=self.environment._FS.open(arg)
                pipe=os.popen("less","w")
                while 1:
                    data=fd.read(10000)
                    if not data: break
                    pipe.write(data)
                    
                pipe.close()
                yield 'Viewing of %s with less successful' % arg


class cp(ls):
    """ Copies files from the filesystem to the directory specified as the last arg """
    def help(self):
        return "cp files dest: copies files (which could use globs) to destination directory (on the real system).\n(note: This will not overwrite a file!)"
    
    def execute(self):
        args=self.args
        target=args[-1]
        #Check to see if the target is a valid directory:
        if not posixpath.isdir(target):
            raise IOError("Target %s is not a directory. (Note: Target must exist on the host filesystem)")
        
        for arg in self.glob_files(args[:-1]):
            ## FIXME: implement a -R switch
            #target_path=target + '/' + arg[len(self.environment.CWD):]
            target_path=target + '/' + posixpath.basename(arg)
            outfd=open(target_path,"w")
            try:
                fd=self.environment._FS.open(arg)
                while 1:
                    f=fd.read(1000000)
                    if not f: break
                    outfd.write(f)

                yield "Copied %s in image to %s on host" % (arg,target_path)
            except IOError,e:
                yield "Unable to copy %s: %s" %(arg,e)

class help(pyflagsh.command):
    """ Print some help about a command (try help help) """
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
        if len(args)==0:
            args.append('help')

        for i in args:
            command=Registry.SHELL_COMMANDS[i]([],self.environment)
            try:
                yield(command.help())
            except pyflagsh.ParserException:
                yield(command.__doc__)

class pwd(pyflagsh.command):
    """ Print the current working directory """
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
        if len(args)==0:
            for i in dir(self.environment):
                if not i.startswith('_'):
                    try:
                        yield "%s = %s" %(i,self.environment.__dict__[i])
                    except KeyError:
                        pass
        else:
            for i in args:
                try:
                    index=i.index("=")
                    self.environment.__dict__[i[:index]]=i[index+1:]
                except ValueError:
                    yield self.environment.__dict__[i]
class quit(pyflagsh.command):
    """ Exits the shell"""
    def help(self):
        return "quit: Exits the PyFlag shell"

    def execute(self):
        sys.exit()
        
class exit(pyflagsh.command):
    """ Exits the shell"""
    def help(self):
        return "exit: Exits the PyFlag shell"
    
    def execute(self):
        sys.exit()

class istat(pyflagsh.command):
    """ stats an inode in the filesystem """
    def help(self):
        return "istat: Stats an inode in the file system returning statistics. Arg can be a regex which will match inodes (e.g. /Itest|K0.*/)"

    def execute(self):
        args=self.args
        for arg in args:
            ## Glob the inodes:
            dbh = DB.DBO(self.environment._CASE)
            if arg[0]=='/':
                dbh.execute("select inode from inode where inode rlike %r", arg[1:-1])
            else:
                dbh.execute("select inode from inode where inode like %r", arg)

            for row in dbh:
                inode = row['inode']                
                filename, inode, inode_id = self.environment._FS.lookup(inode=inode)
                status=self.environment._FS.istat(inode=inode)
                if not status:
                    raise RuntimeError("No status available for %s" % arg)
                
                status['filename'] = filename
                yield status

class iless(istat):
    """ Pipes the content of an inode to less """
    def help(self):
        return "Pipe inodes to less pager "
        
    def execute(self):
        for inode in self.args:
            fd=self.environment._FS.open(inode=inode)
            pipe=os.popen("less","w")
            while 1:
                data=fd.read(10000)
                if not data: break
                pipe.write(data)
                
            pipe.close()
            yield 'Viewing of %s with less successful' % inode

class iiless(iless):
    def help(self):
        return """ Dump the value of an inode_id (inode ids are internal db ids for the inodes, this is probably not generally useful for anyone other than developers) """
    
    def execute(self):
        dbh = DB.DBO(self.environment._CASE)
        for inode_id in self.args:
            dbh.execute("select inode from inode where inode_id = %r ", inode_id)
            row = dbh.fetch()
            if not row['inode']: continue

            fd=self.environment._FS.open(inode=row['inode'])
            pipe=os.popen("less","w")
            while 1:
                data=fd.read(10000)
                if not data: break
                pipe.write(data)
                
            pipe.close()
            yield 'Viewing of %s with less successful' % row['inode']


    
class icp(iless):
    """ Copy Inodes from the VFS to the file system """
    def execute(self):
        ## check that last arg is a dir
        mode = "file"
        if len(self.args)>2 and not os.isdir(self.args[-1]):
            raise RuntimeError("Last argument must be a directory for multiple files")
        else:
            mode = "directory"
        
        for inode in self.args[:-1]:
            fd=self.environment._FS.open(inode=inode)
            if mode =='directory':
                output_filename = inode.replace("/","_")
                outfd = open("%s/%s" % (self.args[-1], output_filename),'w')
            else:
                outfd = open(self.args[-1],'w')
                
            while 1:
                data=fd.read(10000)
                if not data: break
                outfd.write(data)
                    
            outfd.close()
            yield 'Copying of %s into %s successful' % (inode,self.args[-1])

    
class iicp(iless):
    """ Copy Inodes from the VFS to the file system """
    def execute(self):
        ## check that last arg is a dir
        mode = "file"
        if len(self.args)>2 and not os.isdir(self.args[-1]):
            raise RuntimeError("Last argument must be a directory for multiple files")
        else:
            mode = "directory"
        
        for inode_id in self.args[:-1]:
            fd=self.environment._FS.open(inode_id=inode_id)
            if mode =='directory':
                output_filename = inode_id
                outfd = open("%s/%s" % (self.args[-1], output_filename),'w')
            else:
                outfd = open(self.args[-1],'w')
                
            while 1:
                data=fd.read(10000)
                if not data: break
                outfd.write(data)
                    
            outfd.close()
            yield 'Copying of %s into %s successful' % (inode_id,self.args[-1])

class stat(ls):
    """ stats a list of files in the filesystem """
    def help(self):
        return "stat: Stats a list of files in the file system. Files can consist of any glob pattern"

    def execute(self):
        args=self.args
        for arg in self.glob_files(args):
            try:
                path,inode,inode_id = self.environment._FS.lookup(arg)
                status=self.environment._FS.istat(inode=inode)
                if not status:
                    raise RuntimeError("No status available for %s" % arg)

                status['filename'] = arg
                yield status
            except IOError:
                pass
            
class execute(pyflagsh.command):
    """ Executes a report's analysis method with the required parameters """
    def help(self):
        return """
        This command executes a flag report giving it the arguments given. The general format of this command is:

        execute Family.ReportName arg1=value arg2=value

        Note that environment values are automatically included into the set of args. So you may use set to set args that are commonly used.
        Note also that command line completion is enabled for this, and so may be used liberally to assist with both the selection of reports and the args needed
        """
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
            query['family'],query['report']=args[0].split('.')
        except:
            raise RuntimeError("Unable to parse %s as a family.report" % args[0])
        
        report = Registry.REPORTS.dispatch(query['family'],query['report'])
        ## Include the report and family:

        for arg in args[1:]:
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

        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Flash will execute the following query: %s" % query)

        ## Instantiate the report
        report=report(self.environment._flag)
        if self.environment._flag.is_cached(query):
            ## Run the display method
            result=TEXTUI.TEXTUI(query=query)
            report.display(query,result)
            yield result.display()
            return
        
        ## Execute the report:
        try:
            report.analyse(query)
            try:
                dbh = DB.DBO(query['case'])
            except KeyError:
                dbh = DB.DBO()
                
            canonical_query = FlagFramework.canonicalise(query)
            ## We call the display method just in case this report
            ## does something in the display
            result=TEXTUI.TEXTUI(query=query)
            report.display(query,result)
            yield result.display()
            dbh.execute("insert into meta set property=%r,value=%r",('report_executed',canonical_query))
            yield "Execution of %s successful in %s sec" % (self.args[1],time.time()-start_time)
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Flash successfully ran the following query: %s" % query)
        except Exception,e:
            pyflaglog.log(pyflaglog.WARNING, "Flash encountered the following error: %s when running query: %s" % (e,query))
            print FlagFramework.get_bt_string(e)
            raise RuntimeError("%s: %s after %s sec" %  (sys.exc_info()[0],sys.exc_info()[1],time.time()-start_time))

class reset(execute):
    """ Resets the given report """
    def help(self):
        return """
        reset report: This command resets a flag report. After running this command the state of the database should be returned to what it was before the report was executed.
        """
    def execute(self):
        if len(self.args) < 1:
            yield self.help()
            return      

        start_time=time.time()
        report,query = self.prepare()

        ## Instantiate the report:
        report=report(self.environment._flag)
        
        ## Execute the report:
        try:
            report.do_reset(query)
            yield "Resetting of %s successful in %s sec" % (self.args[0],time.time()-start_time)            
        except Exception,e:
            import traceback
            print traceback.print_tb(sys.exc_info()[2])
            raise RuntimeError("%s: %s after %s sec" %  (sys.exc_info()[0],sys.exc_info()[1]),time.time()-start_time)

class find(ls):
    """ A command to find files in the filesystem """
    long_opts = [ "name=", "type=" ]
    
    def execute(self):
        for path in self.args:
            for file in self.list(path):
                yield posixpath.normpath( "/////%s/%s" % (file['path'],file['name']))
        
    def list(self,path):
        """ List the files in a particular path """
        path=posixpath.abspath(posixpath.join(self.environment.CWD,path))
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
        dbh=DB.DBO(self.environment._CASE)
        #Find the inode of the file:
        
        for path in self.glob_files(self.args):
            path,inode, inode_id = self.environment._FS.lookup(path=path)
            dbh.execute("select type.inode_id,name, mime,type from type,file where file.inode_id =%r and file.inode_id=type.inode_id",(inode_id))
            row = dbh.fetch()
            if row:
                yield row

class delete_case(load):
    """ Drop a case and delete all its data """
    
    def help(self):
        return """Delete the specified case and all data within it. E.g. 'delete_case foobar'"""

    def execute(self):
        try:
            case=self.args[0]
            dbh = DB.DBO(case)
            FlagFramework.delete_case(case)
            yield "Deleted case %r" %(case)
        except Exception,e:
            ## Should we just return here or report an error?
            return
            raise RuntimeError("Unable to delete case %s (%s)" %(case,e))

#class create_iosource(load):
#    def help(self):
#        return "create_iosource CaseName iosource_name URL. Creates the named IOSource in the specified case using the URL "
#
##    def execute(self):
##        case = self.args[0]
##        name = self.args[1]
##        url = self.args[2]
        

class create_case(load):
    """ Create a new PyFlag case """
    
    def help(self):
        return """Create a new empty case with specified name. E.g. 'create_case foobar'"""

    def execute(self):
        dbh = DB.DBO(None)
        case = self.args[0]
        dbh.cursor.ignore_warnings = True
        try:
           dbh.execute("Create database `%s` default character set utf8",(case))
        except DB.DBError, e:
           raise RuntimeError("Unable to create case %s, does the database "\
                              "already have a table with this name? Cowardly"\
                              " refusing to replace it. "\
                              " Error was %s" % (case, e))
           
        dbh.execute("select * from meta where property='flag_db' and value=%r",case)
        if not dbh.fetch():
            dbh.insert('meta',
                       property='flag_db',
                       value=case)

            ## Post the create event on the case
            FlagFramework.post_event('create', case)

            ## set any case parameters that were provided
            params = dict([arg.split("=",1) for arg in self.args[1:] if "=" in arg])

            ## add a default TZ if not present
            if not params.has_key("TZ"):
            	params["TZ"] = "SYSTEM"

            case_dbh  = DB.DBO(case)
            for p in params:
                case_dbh.insert("meta", property = p, value = params[p])
            
        yield "Created Case %s" % case
        
## Unit tests:
import unittest
from hashlib import md5
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class BasicCommandTests(pyflag.tests.ScannerTest):
    """ Test PyFlash commands """
    test_case = "PyFlag Test Case"
    test_file = "pyflag_stdimage_0.4.e01"
    subsystem = 'EWF'
    offset = "16128s"

    def test01ls(self):
        """ Test the ls command """
        self.env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=self.env, command="load",
                             argv=[self.test_case,])

        ## Check we can list default directory
        lines = [ l for l in pyflagsh.shell_execv_iter(env=self.env, command="ls",
                                                       argv=[])]
        self.assertEqual(len(lines),18)

        ## Check we can list directories
        lines = [ l for l in pyflagsh.shell_execv_iter(env=self.env, command="ls",
                                                       argv=["docs"])]
        self.assert_(len(lines)>=3)

        ## Check that we can glob files:
        lines = [ l for l in pyflagsh.shell_execv_iter(env=self.env, command="ls",
                                                       argv=["*.jpg"])]
        self.assertEqual(len(lines),5)
        
        ## Check that we can glob directories:
        lines = [ l for l in pyflagsh.shell_execv_iter(env=self.env, command="ls",
                                                       argv=["do*"])]
        self.assert_(len(lines)>3)

    def test02catTests(self):
        """ Test the cat command """
        self.env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=self.env, command="load",
                             argv=[self.test_case,])

        self.fsfd = FileSystem.DBFS(self.test_case)
        fd = self.fsfd.open("/dscf1080.jpg")
        data1=fd.read()        
        fd = self.fsfd.open("/dscf1081.jpg")
        data2=fd.read()
        fd = self.fsfd.open("/dscf1082.jpg")
        data3=fd.read()

        result = ''
        for l in pyflagsh.shell_execv_iter(env=self.env, command="cat",
                                           argv=["/dscf1081.jpg"]):
            result+=l
        self.assertEqual(result,data2)

        result = ''
        for l in pyflagsh.shell_execv_iter(env=self.env, command="cat",
                                           argv=["/dscf108*"]):
            result+=l

        self.assertEqual(len(result),len(data1)+len(data2)+len(data3))
        self.assert_(result==data1+data2+data3)

    def test03cpTests(self):
        """ Test the cp (copy) command """
        self.env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=self.env, command="load",
                             argv=[self.test_case,])

        ## Make a directory for the files:
        tmpname = os.tmpnam()
        os.mkdir(tmpname)

        pyflagsh.shell_execv(env=self.env, command="cp",
                             argv=["/dscf108*", tmpname])

        ## Now verify the copy worked:
        fd = open(tmpname+"/dscf1080.jpg",'r')
        data = fd.read()
        md5sum = md5.new()
        md5sum.update(data)
        self.assertEqual(md5sum.hexdigest(),'9e03e022404a945575b813ffb56fd841')

        ## Clean up:
        for file in os.listdir(tmpname):
            os.unlink(tmpname+'/'+file)
            
        os.rmdir(tmpname)
