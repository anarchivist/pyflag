#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
pyclamd.py - v0.1.1 - 2006.07.15

Author : Alexandre Norman - norman@xael.org
Licence : GPL

Usage :


    # Init the connexion to clamd, either :
    # Network
    pyclamd.init_network_socket('localhost', 3310)
    # Unix local socket 
    #pyclamd.init_unix_socket('/var/run/clamd')

    # Get Clamscan version
    print pyclamd.version()

    # Scan a buffer
    print pyclamd.scan_stream(pyclamd.EICAR)

    # Scan a file
    print pyclamd.scan_file('/tmp/test.vir')


Test strings :
^^^^^^^^^^^^
>>> try:
...     init_unix_socket('/var/run/clamd')
... except ScanError:
...     init_network_socket('localhost', 3310)
... 
>>> ping()
True
>>> version()[:6]=='ClamAV'
True
>>> scan_stream(EICAR)
{'stream': 'Eicar-Test-Signature FOUND'}
>>> open('/tmp/EICAR','w').write(EICAR)
>>> scan_file('/tmp/EICAR')
{'/tmp/EICAR': 'Eicar-Test-Signature'}
>>> contscan_file('/tmp/EICAR')
{'/tmp/EICAR': 'Eicar-Test-Signature'}
>>> import os
>>> os.remove('/tmp/EICAR')

"""

############################################################################


# Module defined Exceptions
global BufferTooLong
global ScanError
BufferTooLong = 'BufferTooLong'
ScanError = 'ScanError'


# Some global variables
global use_socket
global clamd_HOST
global clamd_PORT
global clamd_SOCKET
global EICAR

# Default values for globals
use_socket = None
clamd_SOCKET = "/var/run/clamd"
clamd_HOST='127.0.0.1'
clamd_PORT=3310

# Eicar test string (encoded for skipping virus scanners)
EICAR = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5E'.decode('base64') \
        +'QVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n'.decode('base64')


############################################################################

import socket
import types
import string
            
############################################################################

def init_unix_socket(filename="/var/run/clamd"):
    """
    Init pyclamd to use clamd unix local socket 
    
    filename (string) : clamd file for local unix socket
    
    return : Nothing

    May raise :
      - TypeError : if filename is not a string
      - ValueError : if filename does not allow to ping the server
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET

    if type(filename)!=types.StringType:
        raise TypeError, 'filename should be a string not "%s"' % filename 
    
    use_socket = "UNIX"
    clamd_SOCKET = filename

    ping()
    return

############################################################################

def init_network_socket(host='127.0.0.1', port=3310):
    """
    Init pyclamd to use clamd network socket 
    
    host (string) : clamd server adresse
    port (int) : clamd server port
    
    return : Nothing

    May raise :
      - TypeError : if host is not a string or port is not an int
      - ValueError : if the server can not be pingged
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET
    

    if type(host)!=types.StringType:
        raise TypeError, 'host should be a string not "%s"' % host

    if type(port)!=types.IntType:
        raise TypeError, 'port should be an integer not "%s"' % port

    use_socket = "NET"
    clamd_HOST = host
    clamd_PORT = port

    ping()
    return

############################################################################

def ping():
    """
    Send a PING to the clamav server, which should reply
    by a PONG.
    
    return : True if the server replies to PING
    
    May raise :
      - ScanError : if the server do not reply by PONG
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET

    global ScanError

    s = __init_socket__()

    try:
        s.send('PING')
        result = s.recv(20000)
        s.close()
    except:
        raise ScanError, 'Could not ping clamd server'
        
    
    if result=='PONG\n':
        return True
    else:
        raise ScanError, 'Could not ping clamd server'


############################################################################

def version():
    """
    Get Clamscan version

    return : (string) clamscan version
    
    May raise :
      - ScanError : in case of communication problem
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET
    
    s = __init_socket__()

    s.send('VERSION')
    result = s.recv(20000).strip()
    s.close()
    return result

############################################################################

def reload():
    """
    Force Clamd to reload signature database

    return : (string) "RELOADING"
    
    May raise :
      - ScanError : in case of communication problem
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET
    
    s = __init_socket__()

    s.send('RELOAD')
    result = s.recv(20000).strip()
    s.close()
    return result

############################################################################

def shutdown():
    """
    Force Clamd to shutdown and exit

    return : nothing
    
    May raise :
      - ScanError : in case of communication problem
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET
    
    s = __init_socket__()

    s.send('SHUTDOWN')
    result = s.recv(20000)
    s.close()
    return


############################################################################

def scan_file(file):
    """
    Scan a file or directory given by filename and stop on virus

    file (string) : filename or directory (MUST BE ABSOLUTE PATH !)

    return either :
      - (dict) : {filename1: "virusname"}
      - None if no virus found
    
    May raise :
      - ScanError : in case of communication problem
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET
    
    global ScanError

    s = __init_socket__()

    s.send('SCAN %s' % file)
    result='...'
    dr={}
    while result!='':
        result = s.recv(20000)
        if len(result)>0:
            filenm = string.join(result.strip().split(':')[:-1])
            virusname = result.strip().split(':')[-1].strip()
            if virusname[-5:]=='ERROR':
                raise ScanError, virusname
            elif virusname[-5:]=='FOUND':
                dr[filenm]=virusname[:-6]
    s.close()
    if dr=={}:
        return None
    else:
        return dr

############################################################################

def contscan_file(file):
    """
    Scan a file or directory given by filename

    file (string) : filename or directory (MUST BE ABSOLUTE PATH !)

    return either :
      - (dict) : {filename1: "virusname", filename2: "virusname"}
      - None if no virus found

    May raise :
      - ScanError : in case of communication problem
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET

    global ScanError

    s = __init_socket__()

    s.send('CONTSCAN %s' % file)
    result='...'
    dr={}
    while result!='':
        result = s.recv(20000)
        if len(result)>0:
            filenm = string.join(result.strip().split(':')[:-1])
            virusname = result.strip().split(':')[-1].strip()
            if virusname[-5:]=='ERROR':
                raise ScanError, virusname
            elif virusname[-5:]=='FOUND':
                dr[filenm]=virusname[:-6]
    s.close()
    if dr=={}:
        return None
    else:
        return dr

############################################################################

def scan_stream(buffer):
    """
    Scan a buffer

    buffer (string) : buffer to scan

    return either :
      - (dict) : {filename1: "virusname"}
      - None if no virus found

    May raise :
      - BufferTooLong : if the buffer size exceeds clamd limits
      - ScanError : in case of communication problem
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET


    global BufferTooLong
    global ScanError


    s = __init_socket__()

    s.send('STREAM')
    port = int(s.recv(200).strip().split(' ')[1])
    n=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    n.connect((clamd_HOST, port))
    
    sended = n.send(buffer)
    n.close()
    
    if sended<len(buffer):
        raise BufferTooLong
        
    result='...'
    dr={}
    while result!='':
        result = s.recv(20000)
        if len(result)>0:
            filenm = result.strip().split(':')[0]
            virusname = result.strip().split(':')[1].strip()
            if virusname[-5:]=='ERROR':
                raise ScanError, virusname
            elif virusname!='OK':
                dr[filenm]=virusname
    s.close()
    if dr=={}:
        return None
    else:
        return dr



############################################################################

def __init_socket__():
    """
    This is for internal use
    """
    global use_socket
    global clamd_HOST
    global clamd_PORT
    global clamd_SOCKET

    global ScanError


    if use_socket=="UNIX":
        s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(clamd_SOCKET)
        except socket.error:
            raise ScanError, 'Could not reach clamd using unix socket (%s)' % (clamd_SOCKET)
    elif use_socket=="NET":
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((clamd_HOST, clamd_PORT))
        except socket.error:
            raise ScanError, 'Could not reach clamd using network (%s, %s)' % (clamd_HOST, clamd_PORT)
    else:
        raise ScanError, 'Could not reach clamd : connexion not initialised'

    return s


############################################################################

def __non_regression_test__():
    """
    This is for internal use
    """
    import doctest
    doctest.testmod()
    return
    

############################################################################


# MAIN -------------------
if __name__ == '__main__':


    __non_regression_test__()

    import os
    import sys

##     import doctest
##     doctest.testmod()
    sys.exit(0)

    
    # Print autodoc
    if sys.argv[0].find(os.path.sep)==-1:
        os.system("pydoc ./"+sys.argv[0])
    else:
        os.system("pydoc "+sys.argv[0])
    sys.exit(0)



#<EOF>######################################################################
