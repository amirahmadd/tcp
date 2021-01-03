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
void listening(void *targp);

/* checking incoming packets*/
void pkt_check(void *t_args);

/* checksum function for incoming packets*/
uint16_t cksum_tcp(struct tcphdr *tcp_hdr, u_int32_t src,
		u_int32_t dst, int len);
/*
 * Global window size
 * This will change after listening thread or timeout
 * default value is 1
*/
int w_size = 1 ;

/*
 * Global window time out
 * This will change after listening thread or timeout
 * default value is 30 ms
*/
unsigned short w_timeOut = 30 ;

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

/*seq buffer , store all window packet seq for ack check*/
int* seq_buf;

/*tmp buffer for check packets*/
//char* check_buf;

/*received packet len buffer , store all received window acks len*/
int r_packet_len[500];

int success ; //flag for successful window send

 /* Buffers used when taking apart the received datagrams */
struct iphdr ip_hdr;
struct tcphdr tcp_hdr;

// global socket
int sockfd;


int main(int argc, char **argv)
{
    int sent;
    int	one  = 1;
    short sSendPacket = 0;

    /*
     * listening thread for incoming packets
     * check thread for checksum and packet type
    */
    pthread_t listening_t;
    pthread_t check_t;

    /* listening thread args struct */
    struct thread_data *args;
    struct thread_data *check_args;



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

    clock_t start_time;
    clock_t finish_time;

    /* data to send */
//    char data_arr [20][20]= {
//    "first data","second element","other data", "sth else","and more",
//    "first data1","second element2","other data3", "sth else4", "and more5",
//    "first data6","second element7","other data8", "sth else9", "and more10",
//    "first data11","second element12","other data13", "sth else14", "and more15"};

    /*for more data */
    char data_arr [30000][20];
    for (int c =0 ; c<sizeof(data_arr)/20;c++){
        //my_data[c]="my long data";
        strcpy(data_arr[c], "my long data");
    }

    int data_len = sizeof(data_arr)/20;

    //return 0;
    int sent_count = 0;
    int len_arr [100] ={0};

    // Reserve memory for tmp buffer
   // check_buf= malloc(DATAGRAM_LEN);


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
    args->buf = &ack_buf;
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

    //start timer
    start_time = clock();
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
int last =0;
int sent_skip =0;
while(sent_count < data_len && last == 0)
    {
        // for last data window
        if (w_size+sent_count>data_len)
        {
            printf("last window\n");
            w_size = data_len - sent_count ;
            last =1;
        }
        success =0 ;
        printf("\nwindow size : %d\n",w_size);
        // Reserve memory for acks and packet len
        ack_buf = malloc(DATAGRAM_LEN * w_size);
        memset(ack_buf, 0, DATAGRAM_LEN * w_size);

        // Reserve memory for packets seq
        seq_buf = malloc(w_size * sizeof(int));
        memset(seq_buf, 0, w_size * sizeof(int));

        // set thread arg (ack_buffer len)
        args->len = DATAGRAM_LEN*w_size;


        // init & start thread
        pthread_create(&listening_t, NULL, listening, args);
        pthread_create(&check_t,NULL,pkt_check,NULL);

        // Reserve memory for all packets in window
        win_buf = malloc(DATAGRAM_LEN * w_size);
        memset(win_buf,0,DATAGRAM_LEN*w_size);

        /* create all window packets in loop */
        while(i<w_size)
        {
            // Set the payload intended to be send using the connection
            //memset(pld,0,512);

//            strcpy(pld, data_arr[i+(w_size*j)]);
            strcpy(pld, data_arr[sent_skip]);

            pldlen = (strlen(pld) / sizeof(char));

            // gather last packet data , set seq & ack num & pld in buffer
            gather_packet_data(databuf, &databuflen, seqnum, acknum, pld, pldlen);

            // create raw packets & store in window buffer
//            create_raw_datagram(win_buf + (i*databuflen), &pckbuflen, PSH_PACKET, &srcaddr, &dstaddr, databuf, databuflen);
            create_raw_datagram(win_buf + skip, &pckbuflen, PSH_PACKET, &srcaddr, &dstaddr, databuf, databuflen);

            //store seq of packet in seq_buf for ack checking
            //seq_buf[i] = seqnum;
            // Update ack-number and seq-numbers
            //update_seq_and_ack(win_buf + skip, &seqnum, &acknum);
            update_window_seq_and_ack(win_buf + skip, &seqnum, &acknum);

            // dump packet
            dump_packet(win_buf + skip, pckbuflen);

            // store databuflen in 2i & pckbuflen in 2i+1
            len_arr[2*i+1] = pckbuflen;
            len_arr[2*i] = databuflen;
            skip = skip + pckbuflen +1;
            sent_skip += 1;
            i++;
           // printf("data : %d : dalabuf: %d \n pck len : %d , pcklen : %d \n",len_arr[2*i] ,databuflen, len_arr[2*i+1],pckbuflen);

//            if ((sent = sendto(sockfd, win_buf + (i*databuflen), pckbuflen, 0, (struct sockaddr*)&dstaddr,
//                               sizeof(struct sockaddr))) < 0)
//            {
//                printf("send failed\n");
//                return(1);
//            }
//        if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr,
//                           sizeof(struct sockaddr))) < 0)
//        {
//            printf("send failed\n");
//            return(1);
//        }

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
                    printf("send failed\n");
                    //return(1);
                }

        // dump_packet(pckbuf, pckbuflen);
            //dump_packet(win_buf + skip , pckbuflen);
            skip = skip + len_arr[2*i+1] +1;
            i++;
        }
        /*end loop*/

        //time out
        usleep(w_timeOut*w_size);
        should_exit = 1;

        // check for acks
        // if acks received update window and timeout , goto next iterate

        while(success == 0){
            printf("waiting for packet checking response \n");
        }


        if(success == 1){
            printf("successfull\n");
            sent_count=sent_count+w_size;
            if(w_size < 64){
                w_size *=2;
            }
            //w_size +=2;

           // w_timeOut-=1;
        }else{
            // reduce window size and send window again
            printf("server error , have to send window again\n");
            sent_skip -=w_size;
            if(w_size>1){
                w_size /=2;
            }else{
                printf("connection error , window size < 2\n");
                return 1;
            }
            w_timeOut +=5;
            last=0;
        }
        skip = 0;
        i=0;
        should_exit=0;
        free(ack_buf);
        free(win_buf);
        free(seq_buf);
    }


    printf("\n");

    /* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
    /* CLEAN-UP THE SCRIPT                                           */

    //calculate time
    finish_time = clock();
    clock_t difference = finish_time - start_time ;
    int msec = difference * 1000 / CLOCKS_PER_SEC;
    printf("time : %d ms \n",msec);


    printf("CLEAN-UP:\n");

    /* Close the socket */
    gather_packet_data(databuf, &databuflen, seqnum, acknum, NULL, 0);
    create_raw_datagram(pckbuf, &pckbuflen, FIN_PACKET, &srcaddr, &dstaddr, databuf, 8);
    dump_packet(pckbuf, pckbuflen);
    if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr,
                       sizeof(struct sockaddr))) < 0)
    {
        printf("FIN packet failed\n");
    }

    printf(" Close socket...");
    close(sockfd);
    free(databuf);
    printf("\n%d packets \n",data_len);
    printf("%d sent \n",sent_count);
    printf("done.\n");
    //pthread_exit(NULL);
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
    printf("receive SYN_ACK packet\n");
    unsigned short dst_port;
    int recvlen;

    /* Clear the memory used to store the datagram */
    memset(buf, 0, len);
    do
    {
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
void listening(void *targs){
    struct thread_data *args = targs;
    //printf("Thread ID: %d",*myid );
    //unsigned short dst_port;
    //struct sockaddr_in *dst = args->dst;
    //int sockfd, char *buf, size_t len, struct sockaddr_in *dst
        //dst_port != dst->sin_port
    //int sockfd = args->sockfd;
    //char *buf = args->buf;
    //size_t len = args->len;

    int recvlen;
    int skip=0;
    do
    {
        // get packets
        recvlen = recvfrom(sockfd, ack_buf+skip, args->len, 0, NULL, NULL);
        if (recvlen <= 0)
        {
         continue;
        }
        // store packet len
        r_packet_len[ACK_COUNT]=recvlen;
        //dump_packet(args->buf+skip, recvlen);
        skip += recvlen;
        ACK_COUNT++;
    }
    while ( should_exit == 0 && ACK_COUNT < w_size );
    printf("\nend of listening !\n");
    return 0;
}

void pkt_check(void *t_args){
    success=0;
    printf("checking Recieved packets\n");
    int i=0 ;
    u_int skip = 0;
    char* t_pld = malloc(512);
    memset(t_pld,0,512);
    int t_pldlen;
    int g =0;
    int tcp_cs = 0;
    if(w_size>50){
        printf("fake error !\n");
        ACK_COUNT=0;
        success = 2 ;
        return 0;
    }
    while(1){
        if(i == ACK_COUNT && should_exit ==0 ){
            continue;
        }else if(should_exit != 0 && ACK_COUNT!=w_size){
            // exit and set flag to send window again
            printf("time out !\n");
            ACK_COUNT=0;
            success = 2 ;
            return 0;
        }
        else{
            strip_raw_packet(ack_buf+skip, r_packet_len[i] , &ip_hdr, &tcp_hdr, t_pld, &t_pldlen);
            tcp_cs = cksum_tcp((struct tcphdr *)&tcp_hdr, (u_int32_t)ip_hdr.saddr, (u_int32_t)ip_hdr.daddr, t_pldlen);
            //printf("\ntcp hdr check: %d\nin function tcp hdr check: %d\n",tcp_hdr.check,tcp_cs);
            //if(tcp_cs == tcp_hdr.check){
                //printf("tcp hdr ack: %d\n",tcp_hdr.ack);
                if(t_pldlen > 0) {
                    //hexDump(t_pld, t_pldlen);
                    //printf("Dumped %d bytes.\n", t_pldlen);
                }
                if(tcp_hdr.ack == 1) {
                //printf("\nseq: %d : ack: %d\n\n",ntohl(tcp_hdr.seq),ntohl(tcp_hdr.ack_seq));
               // printf("\nmy seq: %d \n\n",seq_buf+i);
               /* check packet seq & ack number*/
//                printf("\nseq: %d : %d : %d : %d : %d\n",tcp_hdr.seq,ntohl(tcp_hdr.seq),ntohs(tcp_hdr.seq),htonl(tcp_hdr.seq),htons(tcp_hdr.seq));
//                printf("\nack: %d : %d : %d : %d : %d\n",tcp_hdr.ack_seq,ntohl(tcp_hdr.ack_seq),ntohs(tcp_hdr.ack_seq),htonl(tcp_hdr.ack_seq),htons(tcp_hdr.ack_seq));
//                printf("\n mye seq: %d : %d : %d : %d : %d\n",seq_buf+i,ntohl(seq_buf+i),ntohs(seq_buf+i),htonl(seq_buf+i),htons(seq_buf+i));
              // printf("\nseq: %d : ack: %d\n\n",ntohl(tcp_hdr.seq),ntohl(tcp_hdr.ack_seq));
//               for(int j =0 ; j< w_size;j++){
//                if(ntohl(tcp_hdr.seq) == seq_buf+j || ntohl(tcp_hdr.ack_seq) == seq_buf+j){
//                    printf("equal");
//                }
 //              }
                    skip+=r_packet_len[i];
                    i++;
                   // printf("%d : tcp hdr ack number\n",i);
                    if(i == w_size){
//                        break;
                        ACK_COUNT=0;
                        success = 1;
                        return 0;
                    }
                    continue;
                }
                else {
                    // exit and set flag to send window again
                    ACK_COUNT=0;
                    success = 2 ;
                    return 0;
                }
            //}

        }
    }
    // successfull
//    ACK_COUNT=0;
//    success = 1;
//    return 0;
}
// received packets checksum calculation
uint16_t cksum_tcp(struct tcphdr *tcp_hdr, u_int32_t src,
		u_int32_t dst, int len)
{
	/* The pseudoheader used to calculate the checksum */
	struct pseudohdr psh;
	char *psd;
	int psd_sz;

	/* Configure the TCP-Pseudo-Header for checksum calculation */
	psh.source_addr = src;
	psh.dest_addr = dst;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + len);

	/* Paste everything into the pseudogram */
	psd_sz = sizeof(struct pseudohdr) + sizeof(struct tcphdr) + OPT_SIZE + len;
	psd = malloc(psd_sz);
	/* Copy the pseudo-header into the pseudogram */
	memcpy(psd, (char *)&psh, sizeof(struct pseudohdr));
	/* Attach the TCP-header and -content after the pseudo-header */
	memcpy(psd + sizeof(struct pseudohdr), tcp_hdr,
			sizeof(struct tcphdr) + OPT_SIZE + len);

	/* Return the checksum of the TCP-header */
	return(in_cksum((char*)psd, psd_sz));
}
