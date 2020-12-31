/**
 * FILE: main.c
 * SEND DATA VIA TCP/IP USING RAW SOCKETS IN C

 * Prevent the kernel from sending RST-packets:
 * $ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
 *
 * Drop the rule:
 * $ sudo iptables -F
 *
 * usage: sudo ./rawsock <Src-IP> <Src-Port> <Dst-IP> <Dst-Port>
 * example: sudo ./rawsock 192.168.2.109 4243 192.168.2.100 4242
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <pthread.h>
#include "bsc_ext.h"
#include "packet.h"

/* Recevive data and write to buffer */
int receive_packet(int sockfd, char *buf, size_t len, struct sockaddr_in *dst);

/* Listening to incoming packets*/
void listening(void *vargp);

/*
 * Global window size
 * This will change after listening thread or timeout
 * default value is 1
*/
int w_size = 5 ;

/*
 * Global window time out
 * This will change after listening thread or timeout
 * default value is 0.25s
*/
unsigned short w_timeOut = 0.25 ;

// for thread controlling
unsigned short should_exit = 0 ;

/* number of  rcvd ACK packets
 * on each window
 */
unsigned int ACK_COUNT = 0 ;

/*window buffer , store all window packets*/
char* win_buf;
int win_buflen;

/*ack buffer , store all received window acks*/
char* ack_buf;
int ack_buflen;

int j =0;

int main(int argc, char **argv)
{

    int sockfd;
    int sent;
    int	one  = 1;
    short sSendPacket = 0;

    /* listening thread for incoming packets*/
    pthread_t listening_t;
    /* listening thread args struct */
    struct thread_data *args;

    /* The IP-addresses of both maschines in the connections */
    struct sockaddr_in srcaddr;
    struct sockaddr_in dstaddr;

    /* The buffer containing the raw datagram, both when it is */
    /* received and send. */
    char* pckbuf;
    int pckbuflen;

    /* The buffer filled with the information to create the packet. */
    /* The buffer will be filled like that: Seq + Ack [ + Payload ] */
    /* So by default without the payload, it is 8 bytes long. */
    char* databuf;
    int databuflen = 0;

    /* Both numbers used to identify the send packets */
    uint32_t seqnum;
    uint32_t acknum;

    /* The payload contained in the packet */
    char* pld;
    int pldlen;

    /* Buffers used when taking apart the received datagrams */
    struct iphdr ip_hdr;
    struct tcphdr tcp_hdr;
    char data_arr [10][20]= {"firstt data","second element","other data", "sth else", "annd more","first data1","second element2","other data3", "sth else4", "and more5"};
    int data_len = sizeof(data_arr)/20;
    int sent_count = 0;
    int len_arr [100] ={0};

//    data_arr = malloc(DATAGRAM_LEN * w_size);
//    memset(data_arr,0,DATAGRAM_LEN*w_size);
//    printf("%d\n", data_len);

    /* Check if all necessary parameters have been set by the user */
    if (argc < 5)
    {
        printf("usage: %s <src-ip> <src-port> <dest-ip> <dest-port>\n", argv[0]);
        exit (1);
    }

//    if (argc > 5)
//    {
//        // FILE *fopen(argv[5], 'r');
//    }

    /* Reserve memory for the datagram */
    pckbuf = calloc(DATAGRAM_LEN, sizeof(char));


    /* Initialize the data-buffer */
    databuf = malloc(520);

    /* Set the payload intended to be send using the connection */
    pld = malloc(512);
//    strcpy(pld, data_arr[i]);
//    pldlen = (strlen(pld) / sizeof(char));

    /* listening thread args initialization*/
    args = malloc(sizeof *args);
    args->sockfd = &sockfd;
    args->buf = &pckbuf;
    args->len = DATAGRAM_LEN;
    args->dst = &srcaddr;
    //int sockfd, char *buf, size_t len, struct sockaddr_in *dst //sockfd, pckbuf, DATAGRAM_LEN, &srcaddr


    /* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
    /* SETUP SOCKET                                                  */

    printf("SETUP:\n");

    /* Create a raw socket for communication and store socket-handler */
    printf(" Create raw socket...");
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0)
    {
        printf("failed.\n");
        perror("ERROR:");
        exit (1);
    }
    printf("done.\n");

    /* Configure the destination-IP-address */
    printf(" Configure destination-ip...");
    dstaddr.sin_family = AF_INET;
    dstaddr.sin_port = htons(atoi(argv[4]));
    if (inet_pton(AF_INET, argv[3], &dstaddr.sin_addr) != 1)
    {
        printf("failed.\n");
        perror("Dest-IP invalid:");
        exit (1);
    }
    printf("done.\n");

    /* Configure the source-IP-address */
    printf(" Configure source-ip...");
    srcaddr.sin_family = AF_INET;
    srcaddr.sin_port = htons(atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &srcaddr.sin_addr) != 1)
    {
        printf("failed.\n");
        perror("Src-IP invalid:");
        exit (1);
    }
    printf("done.\n");

    /* Tell the kernel that headers are included in the packet */
    printf(" Configure socket...");
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        printf("failed.\n");
        perror("ERROR:");
        exit (1);
    }
    printf("done.\n");

    printf("\n");
    printf("COMMUNICATION:\n");

    /* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
    /* THE TCP-HANDSHAKE                                             */

    /* Step 1: Send the SYN-packet */
    memset(pckbuf, 0, DATAGRAM_LEN);
    create_raw_datagram(pckbuf, &pckbuflen, SYN_PACKET, &srcaddr, &dstaddr, NULL, 0);
    dump_packet(pckbuf, pckbuflen);
    if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr,
                       sizeof(struct sockaddr))) < 0)
    {
        printf("failed.\n");
    }

    /* Step 2: Wait for the SYN-ACK-packet */
    pckbuflen = receive_packet(sockfd, pckbuf, DATAGRAM_LEN, &srcaddr);
    dump_packet(pckbuf, pckbuflen);
    if (pckbuflen <= 0)
    {
        printf("failed.\n");
        exit(1);
    }

    /* Update seq-number and ack-number */
    update_seq_and_ack(pckbuf, &seqnum, &acknum);

    /* Step 3: Send the ACK-packet, with updated numbers */
    memset(pckbuf, 0, DATAGRAM_LEN);
    gather_packet_data(databuf, &databuflen, seqnum, acknum, NULL, 0);
    create_raw_datagram(pckbuf, &pckbuflen, ACK_PACKET, &srcaddr, &dstaddr, databuf, databuflen);
    dump_packet(pckbuf, pckbuflen);
    if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr,
                       sizeof(struct sockaddr))) < 0)
    {
        printf("failed.\n");
        exit(1);
    }

    free(databuf);


    /* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
    /* SEND DATA USING TCP-SOCKET                                    */

    /* Send data using the established connection */
//    gather_packet_data(databuf, &databuflen, seqnum, acknum, pld, pldlen);
//        create_raw_datagram(pckbuf, &pckbuflen, PSH_PACKET, &srcaddr, &dstaddr, databuf, databuflen);
//        dump_packet(pckbuf, pckbuflen);
//        if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr,
//                           sizeof(struct sockaddr))) < 0)
//        {
//            printf("send failed\n");
//            return(1);
//        }

int i,j = 0;
int skip = 0;

    while(sent_count < data_len)
    {
        // for last data window
        if (w_size+sent_count>data_len)
        {
            printf("chane window size \n");
            w_size = data_len - sent_count;
        }
        // store databuflen in 2i & pckbuflen in 2i+1
        //int len_arr [2*w_size] ;

        // Reserve memory for acks
        ack_buf = malloc(DATAGRAM_LEN * w_size);
        memset(ack_buf, 0, DATAGRAM_LEN * w_size);
        // init & start thread
        pthread_create(&listening_t, NULL, listening, args);

        // Reserve memory for all packets in window
        win_buf = malloc(DATAGRAM_LEN * w_size);
        memset(win_buf,0,DATAGRAM_LEN*w_size);

        /* create all window packets in loop */
        while(i<w_size)
        {
       // printf("in while");

            // Set the payload intended to be send using the connection
            //memset(pld,0,512);
            strcpy(pld, data_arr[i+(w_size*j)]);
            pldlen = (strlen(pld) / sizeof(char));

            // gather last packet data , set seq & ack num & pld in buffer
            gather_packet_data(databuf, &databuflen, seqnum, acknum, pld, pldlen);

            // create raw packets & store in window buffer
//            create_raw_datagram(win_buf + (i*databuflen), &pckbuflen, PSH_PACKET, &srcaddr, &dstaddr, databuf, databuflen);
            create_raw_datagram(win_buf + skip, &pckbuflen, PSH_PACKET, &srcaddr, &dstaddr, databuf, databuflen);

            // Update ack-number and seq-numbers
            update_seq_and_ack(win_buf + skip, &seqnum, &acknum);

            // dump packet
            dump_packet(win_buf + skip, pckbuflen);

            // store packet and data len for sending
            len_arr[2*i+1] = pckbuflen;
            len_arr[2*i] = databuflen;
            skip = skip + pckbuflen +1;
           // printf("data : %d : dalabuf: %d \n pck len : %d , pcklen : %d \n",len_arr[2*i] ,databuflen, len_arr[2*i+1],pckbuflen);

//            if ((sent = sendto(sockfd, win_buf + (i*databuflen), pckbuflen, 0, (struct sockaddr*)&dstaddr,
//                               sizeof(struct sockaddr))) < 0)
//            {
//                printf("send failed\n");
//                return(1);
//            }
            i++;
            //printf("\ni: %d\n w_size: %d\n sent_count: %d\n data_len: %d \n pld:%s\n pckbuflen:%d\n",i,w_size,sent_count,data_len,pld,pckbuflen);
        }

        i=0;
        skip = 0;
        /* sending window packets loop*/
        while(i<w_size){
        // send window buffer packets

            if ((sent = sendto(sockfd, win_buf +skip, len_arr[2*i+1], 0, (struct sockaddr*)&dstaddr,
                                   sizeof(struct sockaddr))) < 0)
                {
                    printf("sendd failed\n");
                    return(1);
                }

        // dump_packet(pckbuf, pckbuflen);
            dump_packet(win_buf + skip , pckbuflen);
            skip = skip + len_arr[2*i+1] +1;
            i++;
        }

        /*end loop*/

        // check for acks

        // if acks received clear the free up memory , update window and timeout , goto next iterate
        // else send window again


//        if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr,
//                           sizeof(struct sockaddr))) < 0)
//        {
//            printf("send failed\n");
//            return(1);
//        }
        memset(win_buf,0,DATAGRAM_LEN*w_size);
        skip = 0;
        j++;
        i=0;
        sent_count=sent_count+w_size;
    }


    printf("\n");

    /* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
    /* CLEAN-UP THE SCRIPT                                           */

    printf("CLEAN-UP:\n");

    /* Close the socket */
    /*gather_packet_data(databuf, &databuflen, seqnum, acknum, NULL, 0);
    create_raw_datagram(pckbuf, &pckbuflen, FIN_PACKET, &srcaddr, &dstaddr, databuf, 8);
    dump_packet(pckbuf, pckbuflen);
    free(databuf);

    if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr,
                       sizeof(struct sockaddr))) < 0)
    {
        printf("send failed\n");
    }*/
    printf(" Close socket...");
    close(sockfd);
    printf("done.\n");
    //fflush(stdout);
    pthread_exit(NULL);
    return (0);
}

/*
 * Recieve a short packet using a given socket and write the data to a buffer.
 *
 * @sockfd: The sockets to receive packets with
 * @buf: A buffer to write to
 * @len: The length of the buffer
 *
 * Returns: The amount of bytes received
 */
int receive_packet(int sockfd, char *buf, size_t len, struct sockaddr_in *dst)
{
    printf("receive_packet\n");
    unsigned short dst_port;
    int recvlen;

    /* Clear the memory used to store the datagram */
    memset(buf, 0, len);

    do
    {
//    printf("do while receive_packet\n");

        recvlen = recvfrom(sockfd, buf, len, 0, NULL, NULL);
        if (recvlen <= 0)
        {
            break;
        }
        memcpy(&dst_port, buf + 22, sizeof(dst_port));
    }
    while (dst_port != dst->sin_port);

    /* Return the amount of recieved bytes */
    return (recvlen);
}

/*
 * listening to incoming packets (acks) from server
 *
 */
void listening(void *targs)
{
    struct thread_data *args = targs;
    //printf("Thread ID: %d",*myid );
    unsigned short dst_port;
    int recvlen;
    //int sockfd, char *buf, size_t len, struct sockaddr_in *dst
    int sockfd = args->sockfd;
    char *buf = args->buf;
    struct sockaddr_in *dst = args->dst;
    size_t len = args->len;
    /* Clear the memory used to store the datagram */
    // memset(buf, 0, len);

    do
    {

//        recvlen = recvfrom(sockfd, buf, len, 0, NULL, NULL);
//        if (recvlen <= 0)
//        {
//            // strip_raw_packet(buf, recvlen, &ip_hdr, &tcp_hdr, pld, &pldlen);
//
//            // get ack w_size time
//            // handle ACK packets
//            //printf("hello from thread/n");
//            break;
//        }

        //memcpy(&dst_port, buf + 22, sizeof(dst_port));
        if(++j>5)
        {
            break;
        }
    }
    while ( should_exit == 0 && ACK_COUNT < w_size );
//dst_port != dst->sin_port
    /* Return the amount of recieved bytes */
    return 0;
}
