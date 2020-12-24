#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>

using namespace std;

int main()
{
    // create a socket
    int sock = socket(AF_INET, SOCK_STREAM , 0);
    if (sock == -1){
        return 1;
    }

    // create a hint structure for the server we're connecting with
    int port = 54001;
    string ipAddress = "127.0.0.1";
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(port);
    inet_pton(AF_INET, ipAddress.c_str(), &hint.sin_addr);

    // connect to the server on the socket
    int connectResult = connect(sock, (sockaddr*)&hint, sizeof(hint));
    if ( connectResult == -1 ){
    return 1 ;
    }

    // while loop :
    char buf[4096];
    string userInput ;

     do{
        // enter lines of text
        cout << "> ";
        getline(cin, userInput);

        // send to server
        int sendRes = send(sock, userInput.c_str(), userInput.size()+1,0);
        if(sendRes ==-1){
            cout << "did not send to server ! \r\n";
            continue ;
        }
        // wait for response
        memset(buf ,0 , 4096);
        int byteReceived = recv(sock , buf , 4096 , 0);
        if (byteReceived == -1){
            cout << "there was an error getting response from sever\r\n";
        }else{
            // display response
            cout << "SERVER > " << string(buf,byteReceived)<<"\r\n";
        }


     }while(true);

    //close the socket
    close(sock);




    return 0;
}
