""" This is a test which loads the dfrws2008 forensic challenge. """
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class DFRWS2008Test(pyflag.tests.ScannerTest):
    """ Test the DFRWS2008 Forensics Challenge """
    test_case = "dfrws2008 test"
    test_file = "dfrws2008-challenge.zip"
    subsystem = "Standard"
    fstype = "Raw"
    TZ = "US/Eastern"

    def test01ScanFS(self):
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'ZipScan'])
        ## Carve Memory
        pyflagsh.shell_execv(env=env, command='load',
                             argv=[self.test_case])
        pyflagsh.shell_execv(env=env, command="scan_file",
                             argv=['/raw_filesystem/response_data/challenge.mem', 'ScriptCarver', 'IECarver'])

        ## Load the PCAP file in
        pyflagsh.shell_execv(env=env, command="execute",
                             argv=["Load Data.Load IO Data Source",'case=%s' % self.test_case,
                                   "iosource=n",
                                   "subsys=Standard",
                                   "filename=vfs://%s/raw_filesystem/response_data/suspect.pcap" % self.test_case,
                                   "offset=0",
                                   "TZ=%s" % self.TZ
                                   ])

        pyflagsh.shell_execv(env=env, command='load_and_scan',
                             argv=['n', '/net/', 'PCAP Filesystem', 'SquirrelMailScan',
                                   'YahooMailScan','YahooScanner', 'POPScanner',
                                   'MSNScanner', 'GmailScanner', 'HTTPScanner',
                                   'HotmailScanner' ,'FTPScanner', 'GoogleDocs'])

        ## Load the memory image in
        pyflagsh.shell_execv(env=env, command="execute",
                             argv=["Load Data.Load IO Data Source",'case=%s' % self.test_case,
                                   "iosource=m",
                                   "subsys=Standard",
                                   "filename=vfs://%s/raw_filesystem/response_data/challenge.mem" % self.test_case,
                                   "offset=0",
                                   "TZ=%s" % self.TZ
                                   ])
        pyflagsh.shell_execv(env=env, command='load_and_scan',
                             argv =['m','/mem/', 'Linux Memory', 'profile=2_6_18-8_1_15_el5',
                                    'map=System.map-2.6.18-8.1.15.el5.map'])
