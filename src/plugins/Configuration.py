import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import os
import DB

class Configure(Reports.report):
    """ Configures pyflag """
    name = "Pyflag Configuration"
    family = "Configuration"
    hidden = True
    
    def __init__(self,flag,ui=None):
        self.parameters = {}
        ## Initialise our missing args
        for k,v in config.__class__.__dict__.items():
            if v=='':
                self.parameters['PYFLAG_' + k] = 'any'

        Reports.report.__init__(self,flag,ui=None)

    def form(self,query, result):
        result.para("Fill in values for the following mandatory parameters. Optional parameters can be overridden in ~/.pyflagrc")

        parameters = self.parameters.keys()
        parameters.sort()
        
        for parameter in parameters:
            result.textfield(parameter,parameter)

    def display(self,query,result):
        ## Do some checks to ensure the parameters seem right
        for k,v in dict(RESULTDIR=os.X_OK | os.R_OK | os.W_OK,
                        UPLOADDIR=os.X_OK | os.R_OK
                        ).items():
            if not os.access(config.__class__.__dict__[k], v):
                result.heading("Access denied to %s" % k)
                result.para("We do not seem to have enough privileges to access %s, or the path (%s) does not exist" %(k,config.__class__.__dict__[k]))
                return

        fd=open(os.environ['HOME'] + '/.pyflagrc', 'a+')
        result.para("Writing new $HOME/.pyflagrc")

        result.start_table(border=1)
        for parameter in query.keys():
            if parameter.startswith('PYFLAG_'):
                result.row(parameter, query[parameter])
                fd.write('\n%s="%s"\n' % (parameter, query[parameter]))

        fd.close()
        result.end_table()
        
        result.para("Done. You may edit your personalised configuration by overriding the system configuration at %s/pyflagrc" % config.PREFIX)
        result.refresh(5,query.__class__())

class InitDB(Reports.report):
    """ Initialises the database """
    name = "Initialise Database"
    family = "Configuration"
    hidden = True
    parameters = {'final':'any'}

    def form(self,query, result):
        result.para("Pyflag is able to connect to the database server (so credentials seem ok), but we receive the following error when trying to use the pyflag database.")

        result.text("%s\n\n" % query['error'], color='red')
        
        result.text("This may be because the pyflag database (%s) is not properly initialised. Tick the button below to allow Pyflag to attempt to re-create and initialise the database.\n\n" % config.FLAGDB, color="black")

        result.text("Note that doing this will delete all data in pyflag. Initialising Pyflag should only need to be done after initial installation.", color='red', font='bold')
            
        result.checkbox("Attempt to create database", 'final','ok')

    def display(self,query,result):
        ## Connect to the mysql database
        dbh = DB.DBO('mysql')
        dbh.execute("create database if not exists %s" % config.FLAGDB)
        
        dbh = DB.DBO(None)
        dbh.MySQLHarness("/bin/cat %s/db.setup" % config.DATADIR)

        try:
            dbh.execute("desc meta")
        except:
            result.heading("Failed")
            result.para("Unable to create database properly. Try to create it manually")
            return

        result.heading("Success")
        result.para("Attempt to create initial database succeeded. Pyflag will start in a few seconds.")
        
        result.refresh(5,query.__class__())
