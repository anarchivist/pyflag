""" Implement a simple logger wrapper.

logging verbosity is controlled through the configuration variable LOG_LEVEL
"""
import pyflag.conf
config=pyflag.conf.ConfObject()

## These are predefined logging levels:
ERRORS=1
WARNINGS=2
INFO=3
DEBUG=7

lookup = { ERRORS: "Critical Error", WARNINGS: "Warning", INFO:"Infomation",DEBUG:"Debug"}

def log(level,message):
    """ Prints the message out only if the configured verbosity is higher than the message's level."""
    if config.LOG_LEVEL>=level:
        print "%s: %s" % (lookup[level],message)
