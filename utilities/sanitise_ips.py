## gregsfdev@users.sourceforge.net

## Use this to randomise IPs in a text file.

## Usage: python sanitise_ips.py input_file output_file

import re,sys,random

try:

    f=open(sys.argv[1], 'r')
    
except Exception,e:
    print "Error opening for reading: %s.  Exception: %s" % (sys.argv[1],e)

try:

    out=open(sys.argv[2], 'w')
    
except Exception,e:
    print "Error opening file for writing: %s.  Exception: %s" % (sys.argv[2],e)

iplist={}
for line in f:
    #print "original: %s" % line

    #find all the IPs
    ips = re.finditer(r"(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})",line)
    
    for ip in ips:

        #For each new Ip we see, generate a random IP with exactly the same length.
        #If we have seen this IP before, just look it up in the dictionary.
        #This approach could be bad if you have heaps and heaps of unique IPs....

        try:
            line=line.replace(ip.group(),iplist[ip.group()])
            
        except KeyError:
            
            #This must be an IP we haven't seen before
            newip=""
            for octet in ip.groups():

                if len(octet)==1:
                    newip=newip + str(random.randint(1,9))
                elif len(octet)==2:
                    newip=newip + str(random.randint(10,99))
                elif len(octet)==3:
                    newip=newip + str(random.randint(100,255))
                if octet!=ip.group(4):
                    newip=newip + "."
                
            iplist[ip.group()]=newip
            line=line.replace(ip.group(),iplist[ip.group()])
            
        except Exception,e:
            print "Exception: %s" % (e)

    #Other strings that should be replaced
    #These have been left here as examples
    
    #ascii_replacement="abcdeFGHIJKLMNopqrstuv12345678910"

    #Change hostname in "inside:hostname/"
    #def rem_hostnames(matchline):
    #    return matchline.group('direction') + ":" + ascii_replacement[:len(matchline.group('host'))] + "/"
    #    
    #line=re.sub(r"(?P<direction>inside|outside)\:(?P<host>\w+)\/",rem_hostnames,line)

    #Change filename in "Stored 192.168.0.1:filename.ext"
    #def rem_stored(matchline):
    #    return matchline.group('static') + "somefilename1.txt"
    #
    #line=re.sub(r"(?P<static>Stored\ \d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}\:)(?P<filename>[\w\-\.]+)",rem_stored,line)

    #line=line.replace("somestring","anotherstring")

    out.write(line)

    #print "sanitised: %s" % line
        
f.close()
out.close()
    
    
