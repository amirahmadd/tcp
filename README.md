# tcp
#### computer Network
tcp protocol using Raw socket

## ToDO

## client (sender)
[ ] three-way handshake \
[ ] create buffer with certain size \
[ ] get data & put it on buffer \
[ ] create tcp segment \
[ ] set tcp headers \
[ ] read buffer data and put in tcp body \
[ ] create ip packet \
[ ] put tcp segment in ip packet \
[ ] send packet \
[ ] waiting for ack \
[ ] manage time out
### on ACK receive
[ ] double window size \
[ ] send next packets
## on ACK error (not received or time out)
[ ] reduce window size \
[ ] send current packet
## close connection
[ ] send FIN

## server (Receiver)
[ ] three-way handshake \
[ ] create buffer with certain size \
[ ] get received data from connection \
[ ] put the received data in to buffer \
[ ] read buffer data \
[ ] manage connection time out
### on data received 
[ ] error detection (checksum)
#### correct data
[ ] send ACK
#### data problem
[ ] send RST
