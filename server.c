import logging
import re
import socket
import sys
import ssl
from urllib.parse import urlparse

# Constants
RECV_BYTES = 4096 # The number of bytes to try to read for every call to recv.

# Configure logging
# Comment/Uncomment to chose your desired logging level.  Changing this could
# also be made programmable if needed.
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
# logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
hw2_logger = logging.getLogger('cs450-hw2')


def parse_url(url):
    """A function to parse a url and return the hostname, port, and path.

    Args:
        url (str): The url to be parsed.

    Returns:
        A tuple of (scheme (str), hostname (str), port (int), path (str)) that
        is parsed from the URL or None if an error is encoutnered.

    Notes:
        You are welcome to use the urlpasrse function to parse the url in an
        RFC compliant manner.  However, you will then need to validate the
        output and set default values if they were not specified.  For example,
            - You should assume a scheme of http if none is specified.
            - If no port is specified, you should assume a port of 80 for HTTP
              and a port of 443 for HTTPS.
            - If the port is invalid, this is an error
    """
    # Assign default vaules to the returns
    scheme, hostname, port, path = 'http', None, None, '/'

    # ============ YOUR CODE STARTS HERE ============
    try:
    # Call into the urlparse library (already imported) to parse the URL
        output = urlparse(url)
        if(output.scheme != ""):
            scheme = output.scheme
        port = output.port
        hostname = output.hostname
        path = output.path
        if(hostname == None):
            hostname = path
            path = ""
    # Scheme error checking and getting
    
    # Hostname error checking and getting
    
    # Port error checking and getting
        if(port == None or port < 0 or port > 65353):
            if(scheme == 'https'):
                port = 443
            if(scheme == 'http'):
                port = 80
    except Exception as e:
        return None
    # Hint: Reading the port attribute will raise a ValueError if an invalid port is specified in the URL.
    #       If no port number is specified, use the default port according to the scheme (http or https).

    # Path getting

    # Return the tuple, or return None if one or more errors occured, like:
    return (scheme, hostname, port, path)

    # ============ YOUR CODE ENDS HERE ============


def open_connection(hostname, port):
    """A function to connect to a hostname on a port and return the
    socket.

    Args:
        hostname (str): The hostname to connect to.
        port (int): The port to connect to.

    Returns:
        An open socket to the server or None if an error is encountered.

    Notes:
        To correctly support both IPv4 and IPv6 addresses, you must use the
        socket.getaddrinfo() function.  Importantly, although simpler, the
        socket.gethostbyname() function is deprecated because it only
        supports IPv4.

        socket.getaddrinfo() returns an address info list.  Every entry in the
            list is a family, socktype, proto, canonname, sockaddr tuple.
            Importantly, socket.socket() accepts a family, socktype, and proto
            as its arguments, and the connect() function of a socket object
            accepts a sockaddr as its arguments.

        Given a list of addresses, you should try to connect to all of them in
        order until success is achieved.
    """
    # Initialize the socket to None
    s = None
    
    # ============ YOUR CODE STARTS HERE ============ 
    # Get the address to connect to (support both IPv4 and IPv6) using socket.getaddrinfo, catch exceptions if any
    
    # Try to connect to the returned addresses (hint: traverse the returned addresses)
    try:
        address = socket.getaddrinfo(hostname, port)
        s = socket.socket(address[0][0], address[0][1], address[0][2])
        for i in range (0,len(address[0][4]) - 1):
            try:
                #print("trying")
                ad = (address[0][4][i],address[0][4][i+1])
                print(ad)
                s.connect(ad)
            except OSError as e:
                s.close()
                s = None
                continue
            #print("Success")
            break
    except Exception as e:
        #print("Other error")
        return s    
    # ============ YOUR CODE ENDS HERE ============
    
    return s


def wrap_socket_ssl(s, hostname):
    """A function to wrap a socket to use SSL.

    Args:
        s (socket): The socket to wrap.
        hostname (str): The hostname to validate

    Returns:
        A wrapped socket (socket) on success.  None on error.

    Notes:
        - See the documentation for the python ssl library
          (https://docs.python.org/3/library/ssl.html)
        - Create an SSLContext (ssl.SSLContext)
          (https://docs.python.org/3/library/ssl.html#ssl.SSLContext)
            - Require TLS
        - Require certificates (ssl.CERT_REQUIRED)
        - Check the hostname
        - Use default certificates (load_default_certs())
        - Use the SSLContext to eventually wrap the socket
    """

    # ============ YOUR CODE STARTS HERE ============
    #print("Before try statement")
    try:
    # Create the SSL context
        #print("first line")
        context = ssl.create_default_context()
        #print("Create context")
    # Set the conext to verify certificates (ssl.CERT_REQUIRED)
        context.verify_mode = ssl.CERT_REQUIRED
    # Check the hostname
        context.check_hostname = True
    # Wrap the socket
        ws = context.wrap_socket(s, server_hostname=hostname)
    # Get and check the certificate (getpeercert)
        cert = ws.getpeercert(binary_form = False)
    # Handle exceptions (e.g., invalid hostnames, invalid certificates, or other general SSL errors)
        if(len(cert) == 0):
            return None
    except Exception as w:
        #print("Wrap socket error")
        return None
    # Return the wrapped socket
    #print("Worked")
    return ws
    # ============ YOUR CODE ENDS HERE ============


def gen_http_req(hostname, port, path):
    """A function to generate an HTTP request

    Args:
        hostname (str): The hostname to connect to.
        port (int): The port to connect to.
        path (str): The path of the HTTP request.

    Returns:
        A valid HTTP 1.1 request (bytes).

    Notes:
        The request should be a HTTP/1.1 request, and it should include at
        least the following headers:
            - Host:
            - 'Connection: close'
    """
    req = ''

    # ============ YOUR CODE STARTS HERE ============
    
    # Create the request string (please strictly following the http/1.1 specification)
    Request_string = "GET " + path + ' HTTP/1.1\r\n'  #Method SP Request-URI SP HTTP-Version CRLF  
    Host = 'Host: ' + hostname + ':' + str(port) +'\r\n' #Host = "Host" ":" host [ ":" port ] ; Section 3.2.2
    Connection = 'Connection: close\r\n\r\n'
    req += Request_string + Host + Connection
    # ============ YOUR CODE ENDS HERE ============
    
    # Encode the message for transmission over the socket (str -> bytes)
    req = req.encode()

    return req


def send_req(s, req):
    """Send a request on a socket

    Args:
        s (socket): The socket to send on
        req (bytes): The request to send

    Returns:
        bool: True on success.  False on error.

    Notes:
        It is recommended to use sendall as part of this function.  See this
        note on Python's sendall function from Stack Overflow:
        https://stackoverflow.com/questions/34252273/what-is-the-difference-between-socket-send-and-socket-sendall
    """

    # ============ YOUR CODE STARTS HERE ============

    # Send the entire request (remember to catch socket errors if any)
    try:
        s.sendall(req)
    # Return the required bool value (True on sending successfully, False on error)
    except Exception as e:
        return False
    # Return the required bool value (True on sending successfully, False on error)
    return True
    # ============ YOUR CODE ENDS HERE ============


def parse_headers(headers):
    """Parses an HTTP Header and gets the field names and value.

    Args:
        headers (bytes): The bytes in the HTTP header

    Returns:
        A list with a first entry of Status-Line (str)
        and following entries of (field_name (str), field_value (str)) pairs.
        None on error.

    Notes:
        - From 2.2 in the RFC: "HTTP/1.1 header field values can be folded onto
          multiple lines if the continuation line begins with a space or
          horizontal tab. All linear white space, including folding, has the
          same semantics as SP." -> This implies that every SP can be replaced
          with folding for field values, and you are expected to correctly
          handle folded field values.  However,
        - The Status-Line must still be on a single line -> "The first line of
          a Response message is the Status-Line"
        - Case-insensitive: (4.2 Message Headers) says that field names are
          case-insensitive.
    """
    parsed_headers = []

    # ============ YOUR CODE STARTS HERE ============
    try:
    # Split the headers into decoded lines
        headers = headers.decode()
        print(headers)
    # Get the Status-Line
        header_list = re.split('\r\n', headers, flags=re.IGNORECASE)  
        #print(len(header_list))
    # Get the header field names and values
        #print("Status-line: ",header_list[0])
        parsed_headers.append(header_list[0])
        #print("After parsed headers")
        for i in range(1,len(header_list)):
            #print("Before split")
            sentence = re.split(':', header_list[i],2, flags=re.IGNORECASE)
            #print("After split")
            name = sentence[0].replace(" ","")
            value = sentence[1].replace(" ","")
            print("Name:",name)
            print("Value:",value)
            parsed_headers.append((name,value)) 
    # Find the name and value
        #for x in range(0,len(parsed_headers)):
         #   print((parsed_headers[i]))
    # Handle extended header fields
        
    # Add the parsed field name and value to the list
    
    except Exception as e:
        print("Parsing Error")
        return None
    return parsed_headers 
    # ============ YOUR CODE ENDS HERE ============

def check_status_line(line):
    """Checks if the status line is good (True) or bad (False).

    Args:
        line (bytes): The bytes in status line

    Returns:
        bool: If the status line is ok, return True. Otherwise, return False.

    Notes:
        - Unless stated otherwise, the text is case-insensitive.
        - SP can be any number of spaces
    """
    # ============ YOUR CODE STARTS HERE ============
    #line = line.decode()
    # Split the line on whitespace
    #print(line)
    words = []
    words = line.split()
    # Check if the status line has enough fields
    if(len(words) < 2):
        return False;
    # Check the HTTP version (note: only 1.1 is accepted)
    if(words[0] != 'HTTP/1.1'):
        return False;
    # Check the status (note: only status 200 is accepted)
    if('200' not in words):
        return False;
    # Return the checking result
    return True;
    # ============ YOUR CODE ENDS HERE ============


def get_body_len_info(headers):
    """Gets information needed to determine the length and format of the HTTP
    response body.

    Args:
        headers (list): The parsed and cleaned headers to search

    Returns:
        A dictionary of {'content_len: (int), chunked: (bool)} based on the
        vaule of the headers.  Returns None if the headers needed to determine
        the content length are not available.

    Notes:
        - If present, the "Content-Length" field contains the length of the
          body.
        - If the "Transfer-Encoding" field is "chunked", then no
          "Content-Length" field is required, and the body will be encoded in
          chunks.
        - If no "Content-Length" is specified, and the "Transfer-Encoding"
          field is not chunked, this is still not necessarily an error.
    """
    content_len = None
    chunked = False

    # ============ YOUR CODE STARTS HERE ============
    
    # Check the headers for either content-length or a chunked transfer-encoding
    check1 = "Content-Length"
    check2 = "Transfer-Encoding"
    check3 = "chunked"
    for i in range(0,len(headers)):
        print("Header ",i,":",headers[i])
        if(check1.casefold() in headers[i][0].casefold()):
            content_len = int(headers[i][1])
            break
        if(check2.casefold() in headers[i][0].casefold() and check3.casefold() in headers[i][1].casefold()):
            chunked = True
            break
    # ============ YOUR CODE ENDS HERE ============

    if content_len == None and chunked == False:
        hw2_logger.warning('Neither Content-Length nor Chunked found!')
        return None
    #print(content_len)
    return {'content_len': content_len, 'chunked': chunked}


def get_body_content_len(s, body_start, content_len):
    """Gets the body of an HTTP response given a body_start that has already
    been received and a total length of the content to read.

    Args:
        body_start (bytes): The start of the body that has already been
            received
        content_len (int): The total length of the content to read.

    Returns:
        The complete body (bytes).

    Notes:
        recv() is allowed to return less than the requested amount of bytes
        (including 0).  As a result, you should call recv until you have
        received all of the bytes specified by the protocol.
    """

    # ============ YOUR CODE STARTS HERE ============

    # While recv has not returned enough bytes, continue to call recv
    print("Content-len: ",content_len) 
    body_start += s.recv(content_len)
    #print("Received: ", int.from_bytes(body_start,"big"))
    while(int.from_bytes(body_start,"big") < content_len):
        try:
            body_start += s.recv(content_len)
            print("Received: ", body_start)
        except Exception as e:
            print("Recv Error: ",sys.exc_info())
            break
    return body_start
    # ============ YOUR CODE ENDS HERE ============

def get_body_chunked(s, body_start):
    """Parses an HTTP Body formatted in the chunked transfer-encoding

    Args:
        s (socket): The socket to read from
        body_start (bytes): The start of the body that has already been
            received

    Returns:
        The complete body (bytes).

    Notes:
        A process for decoding the "chunked" transfer-coding (section 3.6)
        can be represented in pseudo-code as:

        length := 0
        read chunk-size, chunk-extension (if any) and CRLF
        while (chunk-size > 0) {
           read chunk-data and CRLF
           append chunk-data to entity-body
           length := length + chunk-size
           read chunk-size and CRLF
        }
        read entity-header
        while (entity-header not empty) {
           append entity-header to existing header fields
           read entity-header
        }
        Content-Length := length
        Remove "chunked" from Transfer-Encoding
    """

    # ============ YOUR CODE STARTS HERE ============

    # Initialize loop variables (if needed)
    #print(body_start)
    #body = body_start.decode()
    #chunk_size = re.split('\r\n',body)
    #print(chunk_size)
    # Start the loop
    body_start += s.recv(1200)
    # While the last chunk has not been seen
        # Verify and get the next chunk header

        # Verify and get the length of the next chunk

        # Get the chunk.
        # Note: recv must be called as many times as needed to get all of the
        # bytes!

        # Add the chunk to the decoded body

        # Each chunk has a newline at the end.  Verify that it is there

        # Move to the start of the new chunk header

    # Return the complete body in bytes
    return body_start
    # ============ YOUR CODE ENDS HERE ============


"""
Note: You do not need to modify the following functions
"""

def read_resp(s):
    """Read an HTTP response from the server

    Args:
        s (socket): The socket to read from.

    Returns:
        The response on success, None on error.
    """

    response = b""

    # Get at least the header of the response. While we have not received the full header, recv more bytes
    while b"\r\n\r\n" not in response:
        try:
            recv = s.recv(RECV_BYTES)
            if not recv:
                break
        except Exception as e:
            break
        response += recv

    # Find the end of the headers/start of the body and save pointers to them
    tmp = response.split(b"\r\n\r\n", 1)
    if len(tmp) == 2:
        body_start = tmp[1] # Case 1: Already meet CRLF, Some body contents are read
    else:
        body_start = b"" # Case 2: No body contents are read

    raw_headers = tmp[0]

    # Parse the headers
    headers = parse_headers(raw_headers)
    if headers == None:
        return None
    hw2_logger.info('Parsed Headers: {}'.format(headers))

    # Validate the headers
    if not check_status_line(headers[0]):
        hw2_logger.warning('Invalid Headers: {}'.format(headers))
        return None

    # Get information about the both length
    body_info = get_body_len_info(headers)
    hw2_logger.debug('Response body_info: {}'.format(body_info))

    # Get the body
    if body_info['chunked']:
        body = get_body_chunked(s, body_start)
    else:
        body = get_body_content_len(s, body_start, body_info['content_len'])
        #hw2_logger.info("Body: ", body)
    return body


def retrieve_url(url):
    """Read an HTTP response from the server at URL

    Args:
        url (str): The URL to request

    Returns:
        The response on success, None on error.
    """
    # Log the URL that is being fetched
    hw2_logger.info('Retrieving URL: {}'.format(url))

    # Parse the URL.
    parsed_url = parse_url(url)
    if parsed_url != None:
        scheme, hostname, port, path = parsed_url
    else:
        hw2_logger.warning('Invalid URL: {}'.format(url))
        return None
    hw2_logger.info('Parsed URL, got scheme: {}, hostname: {}, port: {}, '
        'path: {}'.format(scheme, hostname, port, path))

    # Open the connection to the server.
    s = open_connection(hostname, port)
    if s == None:
        hw2_logger.warning('Unable to open connection to: ({}, {})'.format(
            hostname, port))
        return None
    hw2_logger.info('Opened connection to: ({}, {})'.format(hostname, port))

    # Use SSL if requested
    if scheme == 'https':
        s = wrap_socket_ssl(s, hostname)
        if s == None:
            hw2_logger.warning('Unable to wrap socket and validate SSL')
            return None
        hw2_logger.info('Wrapped socket and validated SSL (HTTPS)')
    
    # Generate the request. Cannot fail.
    req = gen_http_req(hostname, port, path)
    hw2_logger.info('Generated the following request to send: {}'.format(req))
    
    # Send the request
    success = send_req(s, req)
    if success != True:
        hw2_logger.warning('Unable to send request')
        return None
    hw2_logger.info('Request sent successfully')

    # Read the response
    resp = read_resp(s)
    if resp == None:
        hw2_logger.warning('Unable to read response')

    # Close the socket for garbage collection
    s.close()
    print(resp)
    return resp

