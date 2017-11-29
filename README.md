
FULCROM
=====

Fulcrom is a specialized web shell designed specifically for tunneling traffic through a compromised web server by wrapping it in HTTP traffic. 

v0.1 (Alpha)

```
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
```

### Disclaimers

This tool is designed for authorized penetration tests or research purposes only. Do not use this tool to perform illegal activities.

Although efforts have been made to try and clean up sockets, it is possible that unforseen errors could create sockets that are stuck open on the server which could eventually lead to a DoS condition. Please consider this proof-of-concept code at this stage and use caution on any production systems.

## Summary

A web shell is a script that when uploaded to a web server and executed, allows an attacker to remotely administer the server. This can include the ability to add, delete, modify, and execute files, as well as the ability to run operating system commands. They are typically installed by an attacker after a web server is compromised to provide a persistent backdoor into the server.

While standard web shells are powerful, certain types of lateral movement are difficult to execute with them. For example, it is quite simple to map a share on a neighboring system and access it using a standard web shell, but connecting via RDP is not possible. Using the web shell to spawn a traditional TCP / HTTPS reverse shell (such as a meterpreter shell) is one option, but firewall rules, network defenses, or concerns over stealth often eliminate this as a possibility.

Fulcrom provides a means to leverage a compromised web server as a pivot point to move farther into the network. Currently, there are two modes of operation: Port Forward and HTTP proxy.

### Port Forward

With port forward, one of your local ports is mapped to the python client. Any data sent to this port will be tunneled over HTTP to the server module, which will relay it to a destination host/port you specify.
```
<Your RDP Client> -> [LocalPort]<Fulcrom Python Client> -> [INTERNET] -> [Web Port]<Victim Webserver> -> [TargetPort]<TargetHost>
```
From the perspective of your RDP client (or Database client, or whatever other software you wish to tunnel) the tunneling process is completely transparent.

### HTTP Proxy

HTTP Proxy mode is specifically designed to proxy web traffic through the compromised host for the purpose of gaining access to internal websites that would otherwise be inaccessible, or perhaps simply routing a separate attack through the victim to obfuscate the true source.

One of your local ports is mapped to the python client, at which time it can be used like any other HTTP proxy. Configure your browser to use the local port as its HTTP proxy and traffic will be transparently tunneled to the victim. An intercepting proxy (such as BURPSUITE) can be intruduced, either as an upstream proxy to fulcrom, or placed in front of fulcrom accepting traffic straight from the browser before forwarding it to fulcrom.

## Background
Fulcrom is a fork/rewrite of Tunna, a tool created by Nikos Vassakis (secforce.com) - https://github.com/SECFORCE/Tunna/

It was created to address certain shortcomings with Tunna that made it unsuitable for penetration testing in some environments.

-Commands were being sent in plain text in GET parameters allowing for easy detection for network defenders

-There was no password / IP filtering protection. This meant installing it on a webserver created a new vulnerability that was undefended and open to the world.

-No Support for HTTPS

Aside from these security concerns, the functionality of the tool was incredibly useful. Thus, the project was forked and these features (any many more later) were added. It should be noted that the author of TUNNA has made significant changes since this project was forked to it, some of which address some of the initial concerns.

### Installation

Client: Place fulcrom.py, socks.py, and socksipyhandler.py in the same directory. Ensure python 2.X is installed, along with the netaddr module.

Server: Place server web shell in an executable directory on the web server. Change the Allowed IPs and password to reflect the IP you intend to connect from and your password. Insert the SHA1 hash of these values.

### Upgrades / Differences from TUNNA:

-The Server now has an allowedIPs list. It will NOT accept connections from any source not in the IP list. The list is generated before deployment and the IPs are added in the form of sha1 hashes, so they are difficult to reverse if discovered by a defender.

-The server requires a password to be sent by the client during the connection negotiation phase. This password is added to the server in the form of an SHA1 hash. It is entered into the client at run-time and therefore exists in memory only.

-All commands have been moved from GET parameters to POST parameters. This will keep the commands out of the web logs, which is a concern for many pentesting scenarios.

-They have additionally been base64 encoded. This will help prevent signature-based tools (likely not human analysts) from detecting or interpreting the traffic. 
Although in most cases the victim website will be behind HTTPS, making the base64 encoding redundant, this is not always the case and defense-in-depth is never a bad thing.

-The HTTP mode is entirely new

-A whitelist for destination addresses. Used in HTTP mode to prevent forcing the victim to make out-of-scope requests.

-User-agent customization

-Basic Authentication support

-Ability to use a pre-defined authentication cookie

### Architecture

##### Multi-threading

Fulcrom is multi-threaded on the python client side. In the case of port forwarding, there are two threads: One to listen to the local port for new data base sent out, and another to continually query the server to see if any data is ready to be retrieved.

For HTTP mode, the multi-threading is more complex. There is a main thread which listens for local connections. There is a "receive" thread, responsible for cycling through the list of all currently open sockets. When it finds a socket it needs to check, it spawns a new child thread specifically used for that request and then torn down called the "individual" thread. This dramatically improves performance for websites which load lots of auxilliary content over dozens of requests, as each of these requests can operate in its own thread independently without blocking occuring.

###### Command Headers

Each request includes a header which lets the server know what action is being performed, whether it is to check and see if data is available, or to set up an upcoming connection on the server-side. These commands are located in the body (POST DATA) of the request, and are base64 encoded. Raw data is sent in the same section, but separately base64 encoded first (to prevent possible oddities when parsing the header data) and separated with three pipes "|||", before the entire package is base64 encoded.

### Usage

python fulcrom.py -u <remoteurl> -l <localport> -r <remote_service_port> (for PortFwd mode) -p <password> -m PORTFWD|HTTP [options]"

-u (URL of the remote webshell, REQUIRED)

    The full URL of the server web shell you previously installed
	
-l (Local port to listen on, REQUIRED)

    The local port to open, to which data sent will be tunneled to the server
	
-p (password, REQUIRED)

	The password to the web shell, defined on the web shell as a SHA1 hash
	
-r (Remote Port, REQUIRED FOR PORTFWD MODE)

    The remote port to forward traffic to when using portfwd mode. If no address (-a) parameter is provided, this will be a localport on the victim server
	
-m (Mode of operation, REQUIRED)

    Current modes are HTTP or PORTFWD
	
-q (Webshell pinging thread interval. Affects portfwd functionality only, OPTIONAL)

    Optional paremeter that changes the frequency with which the portfwd "pinging thread" polls for new data
	
-a (Address for victim server to connect to, OPTIONAL - default is 127.0.0.1)

-b (HTTP request size. OPTIONAL - default is 4096)

   In rare circumstances you may wish to modify this to change network performance
   
-s (Start pinging thread first - affects PORTFWD mode only, OPTIONAL)

    Some services perform better if the pinging thread is started before the initial request

-v (Werbose Mode, OPTIONAL)

    Turns on many more debug messages in the console
	
-h (Help, OPTIONAL)

    Display the usage menu in the console
	
-w (HTTP Destination whitelist, applied to HTTP mode only, OPTIONAL)

    Sets a whitelist for allowed destinations in HTTP mode, preventing accidental out of scope connections from being made
	Format is comma separated list. CIDR addresses are accepted (for example: 127.0.0.1,10.10.10.0/24,172.16.0.0/16)

-g (User-agent, OPTIONAL)

    Sets a custom user-agent to be used with all outgoing HTTP requests. Applied only to HTTP mode. Default user agent is:
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"

-z (Basic Auth, OPTIONAL)

    Sets a basic auth header to include with all requests
	
-x (Upstream SOCKS Proxy, OPTIONAL)

    Forward all outgoing traffic through the specified SOCKS proxy
	
-x (Upstream HTTP Proxy, OPTIONAL)

    Forward all outgoing traffic through the specified HTTP proxy
```
    Usage: python proxy.py -u <remoteurl> -l <localport> -p <password> -m <mode>[options]
        -u:          url of the remote webshell
        -l:          local port of webshell
        -p:          Password for the web shell
        -r:          Remote port of service for the webshell to connect to when using PORTFWD mode
        -m:          The mode of operation. (PORTFWD, or HTTP)
        -q:          webshell pinging thread interval (default = 0.5)
        -a:          address for remote webshell to connect to (default = 127.0.0.1)
        -b:          HTTP request size (some webshels have limitations on the size)
        -s:          start the pinging thread first - some services send data first (SSH)
        -v:          Verbose (outputs packet size)
        -c:          use predefined authentication cookie (cookiename=cookievalue)
        -h:          Help page
        -w:          Sets a whitelist of allowed destination IP addresses
        -g:          Set a custom user-agent string for use in requests
        -z:          {basic auth string} include this basic auth string in requests
        -x:          Upstream SOCKS Proxy
        -y:          Upstream HTTP Proxy
```	
	
### Dependencies

-Python netaddr module

-Included python files socksipyhandler.py and socks.py, used for upstream SOCKS mode

### Known Bugs

###### asp.net version

If your victim is using .net version 3.5 or lower it will not work at all. If demand is high I enough, I could create a special version that would be compatible with 3.5, but I have no idea how prevelant 3.5 still is and whether it is worth the effort.

### To-Do list

-Create more server versions. JSP is the top priority. Others will include PHP and Cold Fusion.

-Add a third SOCKS mode


### Copyright
Fulcrom - Web shell for internal pivoting
Paul Mueller
Copyright (C) 2017 Paul Mueller

Fork/Rewite of:

Tunna, TCP Tunneling Over HTTP
Nikos Vassakis
Copyright (C) 2014 SECFORCE.

This tool is for legal purposes only.

This program is free software: you can redistribute it and/or modify it 
under the terms of the GNU General Public License as published by the 
Free Software Foundation, either version 3 of the License, or (at your 
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General 
Public License for more details.

You should have received a copy of the GNU General Public License along 
with this program. If not, see <http://www.gnu.org/licenses/>.



