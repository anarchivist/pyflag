""" This is an implementation of the remote IO Source.
"""
import plugins.Images as Images
## This currently does not work.
active = False

class Remote(Images.Advanced):
    """ This IO Source provides for remote access """
    mandatory_parameters = ['host','device']
    def form(self, query, result):
        ## Fill the query with some defaults:
        query.default('port','3533')
        
        result.textfield("Host",'host')
        result.textfield("Port",'port')
        result.textfield("Raw Device",'device')
        
        query['host']
        
        self.calculate_partition_offset(query, result)

    def create(self, name, case, query):
        import remote
        offset = self.calculate_offset_suffix(query.get('offset','0'))
        
        io = remote.remote(host = query['host'],
                           port = int(query.get('port', 3533)),
                           device = query['device'],
                           offset = offset)

        return io
    
import os, unittest,time
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflagsh as pyflagsh

class RemoteIOSourceTests(unittest.TestCase):
    """ Test the Remote IO source implementation """
    level = 10
    active = False
    def setUp(self):
        time.sleep(1)
        ## Start the remote server on the localhost
        slave_pid = os.spawnl(os.P_NOWAIT, config.FLAG_BIN + "/remote_server", "remote_server", "-s")

        print "slave run with pid %u" % slave_pid
        ## Try to avoid the race
        time.sleep(1)
        
    def test02RemoteIOSource(self):
        """ Test the remote iosource implementation """
        io1 = iosubsys.iosource([['subsys','advanced'],
                                 ['filename','%s/pyflag_stdimage_0.4.dd' % config.UPLOADDIR]])
        
        ## get the remote fd:
        import remote

        r = remote.remote("127.0.0.1", config.UPLOADDIR + self.test_file)

        ## Test the remote source
        IO.test_read_random(io1,r, io1.size, 1000000, 100)

    test_case = "PyFlagTestCase"
    test_file = "/pyflag_stdimage_0.4.dd"
    fstype = "Sleuthkit"
    
    def test01LoadingFD(self):
        """ Try to load a filesystem using the Remote source """
        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Remove case",'remove_case=%s' % self.test_case])

        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Create new case",'create_case=%s' % self.test_case])

        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load IO Data Source",'case=%s' % self.test_case,
                                   "iosource=test",
                                   "subsys=Remote",
                                   "filename=%s" % (self.test_file),
                                   ])
        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load Filesystem image",'case=%s' % self.test_case,
                                   "iosource=test",
                                   "fstype=%s" % self.fstype,
                                   "mount_point=/"])
