## HTTP Resolver
### About
This server results the TCP/IP request from client writen in Python.
You need to have `python3` installed for this server.    
There are only two types of methods that are allowed:  
`POST` and `GET`

### Run
If you want to run the server just type `make run PORT=<port>`  
`<port>` is number of port where you want the server listen to.  
The range of port numbers are <0, 65535>.  

### Types of requests
There are two types of requests allowed from client.  
Type `A` is made for Domain name tobe translated to IP adress.  
Type `PTR` need IP adress in input and translates it to Domain name.  
Any other request is marked as Bad Request.

### Responses
Server does reply with various of responses.  
These are the headers of possible replies:  
`200 OK` = The translate was successful
`400 Bad Request` = There is some sort of problem in request  
`404 Not Found` = The IP or Domain name couldn't be found  
`500 Internal Error` = Something went wrong on the server side  