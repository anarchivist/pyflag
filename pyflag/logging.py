""" Implement a simple logger wrapper.

logging verbosity is controlled through the configuration variable LOG_LEVEL
"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import sys,traceback

## These are predefined logging levels:
ERRORS=1
WARNINGS=2
INFO=3
DEBUG=7
RING_BUFFER_SIZE=20

ring_buffer = []

lookup = { ERRORS: "Critical Error", WARNINGS: "Warning", INFO:"Infomation",DEBUG:"Debug"}

def log(level,message):
    """ Prints the message out only if the configured verbosity is higher than the message's level."""
    global ring_buffer
    string = "%s: %s" % (lookup[level],message)
    
    if config.LOG_LEVEL>=level:
        print string
        ring_buffer.append(string)

        if len(ring_buffer)>RING_BUFFER_SIZE:
            ring_buffer=ring_buffer[-RING_BUFFER_SIZE:]
        
    if level<=ERRORS:
        print traceback.print_tb(sys.exc_info()[2])
