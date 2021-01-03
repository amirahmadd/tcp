#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
//#include <time.h>
using namespace std;
//Client side
int main(int argc, char *argv[])
{
    //we need 3 things: ip address and port number and count of packet, in that order
    if(argc != 4)
    {
        cerr << "Usage: ip_address port count" << endl; exit(0); 
    } //grab the IP address and port number 
    char *serverIp = argv[1]; int port = atoi(argv[2]); 
    //create a message buffer 
    char msg[1500]; 
    //setup a socket and connection tools 
    struct hostent* host = gethostbyname(serverIp); 
    sockaddr_in sendSockAddr;   
    bzero((char*)&sendSockAddr, sizeof(sendSockAddr)); 
    sendSockAddr.sin_family = AF_INET; 
    sendSockAddr.sin_addr.s_addr = 
        inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
    sendSockAddr.sin_port = htons(port);
    int clientSd = socket(AF_INET, SOCK_STREAM, 0);
    //try to connect...
    int status = connect(clientSd,
                         (sockaddr*) &sendSockAddr, sizeof(sendSockAddr));
    if(status < 0)
    {
        cout<<"Error connecting to socket!"<<endl;// break;
    }
    cout << "Connected to the server!" << endl;
    int bytesRead, bytesWritten = 0;
    
    cout << "write sth to send to server "<< argv[3]<< " times" << endl;
    clock_t difference ;
    clock_t finish_time ;
    clock_t start_time  ;
    while(1){

        cout << ">";
        string data;
        getline(cin, data);
        memset(&msg, 0, sizeof(msg));//clear the buffer
        strcpy(msg, data.c_str());
        if(data == "exit")
        {   
            send(clientSd, (char*)&msg, strlen(msg), 0);
            break;
        }
        start_time = clock();
        for(int i =0 ;i<= atoi(argv[3]);i++){
            bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
            
        }
        //
        finish_time = clock();
        clock_t difference = finish_time - start_time ;
        int msec = difference * 1000 / CLOCKS_PER_SEC;
        printf("time : %d ms \n",msec);
        //
        cout << "Bytes written: " << bytesWritten << endl;
        cout << "write exit to enable chat system" << endl;
    }
    while(1)
    {
        cout << ">";
        string data;
        getline(cin, data);
        memset(&msg, 0, sizeof(msg));//clear the buffer
        strcpy(msg, data.c_str());
        if(data == "exit")
        {   
            send(clientSd, (char*)&msg, strlen(msg), 0);
            break;
        }

        bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
       
        cout << "Awaiting server response..." << endl;
        memset(&msg, 0, sizeof(msg));//clear the buffer
        bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
        if(!strcmp(msg, "exit"))
        {
            cout << "Server has quit the session" << endl;
            break;
        }
        cout << "Server: " << msg << endl;
    }
    close(clientSd);
    cout << "********Session********" << endl;
    cout << "Bytes written: " << bytesWritten << 
    " Bytes read: " << bytesRead << endl;
    cout << "Connection closed" << endl;
    return 0;    
}
