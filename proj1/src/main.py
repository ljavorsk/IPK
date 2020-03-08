import socketserver, socket, sys, signal, re
from urllib.parse import parse_qsl, urlparse

# Possible answers
ErrNotFound = " 404 Not Found\r\n\r\n"
ErrBadRequest = " 400 Bad Request\r\n\r\n"
ErrInvalidMethod = " 405 Method Not Allowed\r\n\r\n"
ErrInternal = " 500 Internal Server Error\r\n\r\n"
Success = " 200 OK\r\n"

# Handles the CTRL+C interupt
def signal_handler(sig, frame):
    sys.exit(0)

def isItUrl(url):
    regex_dom_nam = r'(([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,})))'
    if (re.match(regex_dom_nam, url) is not None):
        return True
    else:
        return False

class MyTCPHandler(socketserver.BaseRequestHandler):
    signal.signal(signal.SIGINT, signal_handler)

    def encodeAndSend(self, message):
        message = message.encode()
        self.request.sendall(message)

    def handle(self):
        self.data = self.request.recv(1024)
        decData = self.data.decode()
        data_array = decData.split()
        header = "HTTP/1.1"
        end_of_header = "\r\n\r\n"
        content_type = "Content-type: text/plain\r\n"
        if (data_array[0] == 'GET'):            # GET
            if (urlparse(data_array[1]).path != '/resolve'):
                result = header + ErrBadRequest
                self.encodeAndSend(result)
            else:              # /resolve is correct
                query = urlparse(data_array[1]).query
                query = parse_qsl(query)
                bad_request = not_found = False
                try:
                    if (query[0][0] != 'name' or query[1][0] != 'type'):
                        bad_request = True
                    else:
                        hostname = (query[0][1]).replace("\\","")
                        typeOfReq = query[1][1]
                        if (typeOfReq == 'A' and isItUrl(hostname)):        # Type is A and the input is valid url
                            try:
                                ip = socket.gethostbyname(hostname)
                                if (ip == hostname):
                                        bad_request = True
                                body = (hostname + ":" + typeOfReq + "=" + ip + "\n")
                            except:
                                not_found = True
                        elif (typeOfReq == 'PTR'):

                            try:
                                socket.inet_aton(hostname)      # Is it real IP adress?
                                try:
                                    url = socket.gethostbyaddr(hostname)
                                    body = (hostname + ":" + typeOfReq + "=" + url[0] + "\n")
                                except:
                                    not_found = True
                            except socket.error:
                                bad_request = True
                        else:
                            bad_request = True
                except:
                    bad_request = True
                
                # FINAL SEND
                if (bad_request == True or not_found == True):
                    if (bad_request == True):
                        result = header + ErrBadRequest
                    else:
                        result = header + ErrNotFound
                else:
                    content_length = ("Content-lenght: " + str(len(body.encode())))
                    result = header + Success + content_type + content_length + end_of_header + body
                self.encodeAndSend(result)

        elif (data_array[0] == 'POST'):             # POST
            if (urlparse(data_array[1]).path != '/dns-query'):
                result = header + ErrBadRequest
                self.encodeAndSend(result)
            else:                   # dns-query is correct
                try:
                    body_of_request = decData.split("\r\n\r\n")[1]
                    body_of_request = body_of_request.splitlines()
                    result = header + Success + content_type   # First the result have only header 200 OK
                    initial_body = body = ""
                    bad_type = empty_line = not_found = False        # Bad type of request and not found flag
                    i = 0
                    while i < len(body_of_request):
                        if (body_of_request[i] == ''):     # Empty lines are bad input unless it's last char
                            empty_line = True
                            i += 1
                            break
                        else:
                            typeOfReq = body_of_request[i].split(':')[1]
                            hostname = body_of_request[i].split(':')[0]
                            if (typeOfReq == 'A' and isItUrl(hostname)):
                                try:
                                    ip = socket.gethostbyname(hostname)
                                    if (ip == hostname):
                                        bad_type = True
                                        i += 1
                                        continue
                                    body += (hostname + ":" + typeOfReq + "=" + ip + "\n")
                                    #result += body
                                except:
                                    not_found = True
                                    i += 1
                                    continue
                            elif (typeOfReq == 'PTR'):
                                try:
                                    socket.inet_aton(hostname)      # Is the input real IP adress?
                                    try:
                                        url = socket.gethostbyaddr(hostname)
                                        body += (hostname + ":" + typeOfReq + "=" + url[0] + "\n")
                                        #result += body
                                    except:
                                        not_found = True
                                        i += 1
                                        continue
                                except socket.error:
                                    bad_type = True
                                    i += 1
                                    continue
                            else:           # Nor A or PTR type
                                bad_type = True
                                i += 1
                                continue
                        i += 1
                    if (empty_line or initial_body == body):      # Nothing was appended or empty line
                        if (not_found == True and bad_type != True and empty_line != True):     # Wasn't found
                            result = header + ErrNotFound
                        else:               # Empty line or bad type of request
                            result = header + ErrBadRequest
                        self.encodeAndSend(result)
                    else:       # Everything is valid
                        content_length = ("Content-lenght: " + str(len(body.encode())))
                        result += content_length + end_of_header + body
                        self.encodeAndSend(result)
                except:
                    result = header + ErrBadRequest
                    self.encodeAndSend(result)
        else:
            result = header + ErrInvalidMethod
            self.encodeAndSend(result)      

if __name__ == "__main__":
    if (len(sys.argv) != 2):
       sys.exit("You need to define PORT you want the server listen to\n")

    UINT16_MAX_LIMIT = "65535"
    UINT16_MIN_LIMIT = "0"
    if ( sys.argv[1] > UINT16_MAX_LIMIT or sys.argv[1] < UINT16_MIN_LIMIT):
       sys.exit("Invalid PORT number\n")

    HOST = '127.0.0.1'  # (localhost)
    PORT = int(sys.argv[1])    # Port defined by user

    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)
    server.serve_forever()