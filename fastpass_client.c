#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>       
#include <netinet/ip.h>      
#include <netinet/udp.h>     
#include <sys/ioctl.h>        
#include <bits/ioctls.h>      
#include <net/if.h>           
#include <linux/if_ether.h>   
#include <linux/if_packet.h>  
#include <net/ethernet.h>
#include <time.h>
#include <stdlib.h>
#include <semaphore.h>

#define  MTU 		1454
#define  MAXLINE 	80
#define  MAXOPTIONS 	40
#define  ARBITER_IP     "20.0.0.100"
#define  ARBITER_PORT   "5000"
#define  MAXDATASIZE    60

#define MAC_HEADER_LEN 	 18
#define IP_HEADER_LEN 	 20  
#define UDP_HEADER_LEN   8  
#define MAC_ADDR_LEN	 6
#define IP_ADDR_LEN      4
#define PACE		 10


sem_t mutex;
static int pkt_count=0;
struct parsed_options
{
	char		 dest_host[MAXLINE];
	unsigned short	 dest_port;
	int 		 byte;
}parsed_args[MAXOPTIONS];

int record_count;

void command_parser( FILE *fd )
{
	char buffer[MAXLINE];
	char option1[MAXLINE], value1[MAXLINE], option2[MAXLINE], value2[MAXLINE], option3[MAXLINE], value3[MAXLINE];
	int count=0;
	int i;	
	int len;
	while( fgets(buffer, MAXLINE, fd) != NULL)
	{
		if(sscanf(buffer, "%s %s %s %s %s %s", option1, value1, option2,
		value2, option3, value3) == 6)
		{
			switch(option1[1])
			{
				case 'd':
					strcpy(parsed_args[count].dest_host, value1);
					break;
				case 'p': 
					parsed_args[count].dest_port =(short) atoi(value1);
					break;
				case 'n':
 					len = strlen(value1);
					parsed_args[count].byte = atoi(value1);
					if(value1[len-1] == 'K')
						parsed_args[count].byte *= 1000;
					else if(value1[len-1] == 'M')
						parsed_args[count].byte *= 1000000;
					else if(value1[len-1] == 'G')
						parsed_args[count].byte *= 1000000000;
					break;
			}
			
			switch(option2[1])
			{
					case 'd':
							strcpy(parsed_args[count].dest_host, value2);
							break;
					case 'p':
							parsed_args[count].dest_port =(short) atoi(value2);
							break;
					case 'n':
							len = strlen(value2);
							parsed_args[count].byte = atoi(value2);
							if(value2[len-1] == 'K')
                                                		parsed_args[count].byte *= 1000;
                                        		else if(value2[len-1] == 'M')
                                                		parsed_args[count].byte *= 1000000;
                                        		else if(value2[len-1] == 'G')
                                                		parsed_args[count].byte *= 1000000000;
							break;
			}

			switch(option3[1])
			{
					case 'd':
							strcpy(parsed_args[count].dest_host, value3);
							break;
					case 'p':
							parsed_args[count].dest_port =(short) atoi(value3);
							break;
					case 'n':
							len = strlen(value3);
							parsed_args[count].byte = atoi(value3);
							if(value3[len-1] == 'K')
                                                                parsed_args[count].byte *= 1000;
                                                        else if(value3[len-1] == 'M')
                                                                parsed_args[count].byte *= 1000000;
                                                        else if(value3[len-1] == 'G')
                                                                parsed_args[count].byte *= 1000000000;

							break;
			}
			count++;
		}
	}
	record_count = count;
}

/* This function has been referred from www.pdbuchan.com/rawsock/ */
uint16_t checksum (uint16_t *addr, int len)
{
	int count = len;
  	register uint32_t sum = 0;
  	uint16_t answer = 0;

  	// Sum up 2-byte values until none or only one byte left.
  	while (count > 1) 
	{

    		sum += *(addr++);
    		count -= 2;
  	}		

  	// Add left-over byte, if any.
  	if (count > 0) 
	{
    		sum += *(uint8_t *) addr;
  	}

  	// Fold 32-bit sum into 16 bits; we lose information by doing this,
  	// increasing the chances of a collision.
  	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  	while (sum >> 16) 
	{
    		sum = (sum & 0xffff) + (sum >> 16);
  	}

  	// Checksum is one's compliment of sum.
  	answer = ~sum;

  	return (answer);
}

/* This function has been referred from www.pdbuchan.com/rawsock/ */
// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
  	char buf[IP_MAXPACKET];
  	char *ptr;
  	int chksumlen = 0;
  	int i;

  	ptr = &buf[0];  // ptr points to beginning of buffer buf

  	// Copy source IP address into buf (32 bits)
  	memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  	ptr += sizeof (iphdr.ip_src.s_addr);
  	chksumlen += sizeof (iphdr.ip_src.s_addr);

  	// Copy destination IP address into buf (32 bits)
  	memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  	ptr += sizeof (iphdr.ip_dst.s_addr);
  	chksumlen += sizeof (iphdr.ip_dst.s_addr);

  	// Copy zero field to buf (8 bits)
  	*ptr = 0; ptr++;
  	chksumlen += 1;

  	// Copy transport layer protocol to buf (8 bits)
  	memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  	ptr += sizeof (iphdr.ip_p);
  	chksumlen += sizeof (iphdr.ip_p);

  	// Copy UDP length to buf (16 bits)
  	memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  	ptr += sizeof (udphdr.len);
  	chksumlen += sizeof (udphdr.len);

  	// Copy UDP source port to buf (16 bits)
  	memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  	ptr += sizeof (udphdr.source);
  	chksumlen += sizeof (udphdr.source);

  	// Copy UDP destination port to buf (16 bits)
  	memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  	ptr += sizeof (udphdr.dest);
  	chksumlen += sizeof (udphdr.dest);

  	// Copy UDP length again to buf (16 bits)
  	memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  	ptr += sizeof (udphdr.len);
  	chksumlen += sizeof (udphdr.len);

  	// Copy UDP checksum to buf (16 bits)
  	// Zero, since we don't know it yet
  	*ptr = 0; ptr++;
  	*ptr = 0; ptr++;
  	chksumlen += 2;

  	// Copy payload to buf
  	memcpy (ptr, payload, payloadlen);
  	ptr += payloadlen;
  	chksumlen += payloadlen;

  	// Pad to the next 16-bit boundary
  	for (i=0; i<payloadlen%2; i++, ptr++) 
	{
    		*ptr = 0;
    		ptr++;
    		chksumlen++;
 	 }	

  	return checksum ((uint16_t *) buf, chksumlen);
}

void send_packet( unsigned long src_ip, char *dest_ip, unsigned short dest_port, int data_len, unsigned short vlan, int time_slot, int pace)
{
	//static		int pkt_count=0;
	int 	      	raw_sock;	
	int 	      	flags[4];
	int 	      	rv;
	int	      	frame_len;
	int 	      	numbytes;
	int 	      	i;	
	unsigned char 	src_mac[MAC_ADDR_LEN], dest_mac[MAC_ADDR_LEN];
	unsigned char 	*frame;
	unsigned char 	*data;
	char		*interface;
	struct 	      	ip ip_hdr;
  	struct 	      	udphdr udp_hdr;
	struct 	      	sockaddr_ll dev;
	struct 		ifreq ifr;
	char 		*interface_str;
	char 		*source_ip;

	/*sem_wait(&mutex);
	pkt_count++;
	printf("Packet sent: %d\n", pkt_count);
	sem_post(&mutex);*/
	frame = malloc(data_len + MAC_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN);
	data  = malloc(data_len);
	memset(frame, 0, data_len + MAC_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN);
	memset(data, 0, data_len);
	interface = malloc(40);
	memset(interface,0, 40);
	source_ip = malloc(20);
	interface_str = malloc(10);
	//strcpy(interface_str, "h");
	sprintf(interface_str, "h%lu-eth0",src_ip&0x000000FF);
	sprintf(source_ip, "10.0.0.%lu",src_ip&0x000000FF);
	//printf("IP: %s\n", source_ip);
	//printf("Interface: %s\n", interface_str);
        strcpy(interface, interface_str);
	
	for(i=0; i< MAC_ADDR_LEN; i++)	
	{
		//src_mac[i]  = 0xAA;
		dest_mac[i] = 0xBB;
	} 

	if ((raw_sock = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    		perror ("socket() failed to get socket descriptor for using ioctl() ");
		close(raw_sock);	
		free(frame);
		free(interface);
		free(data);
    		return;
  	}	

  	memset (&ifr, 0, sizeof (ifr));
  	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  	if (ioctl (raw_sock, SIOCGIFHWADDR, &ifr) < 0) {
    		perror ("ioctl() failed to get source MAC address ");
    		return;
  	}
  	close (raw_sock);

  	// Copy source MAC address.
  	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	memset (&dev, 0, sizeof (dev));
  	if ((dev.sll_ifindex = if_nametoindex (interface)) == 0) 
	{
    		perror ("if_nametoindex() failed to obtain interface index ");
    		return;
  	}
	
	dev.sll_family = AF_PACKET;
  	memcpy (dev.sll_addr, src_mac, 6 * sizeof (uint8_t));
  	dev.sll_halen = 6;

	/* Build IP header */
	ip_hdr.ip_hl 	= IP_HEADER_LEN / sizeof (uint32_t);
  	ip_hdr.ip_v 	= 4;
  	ip_hdr.ip_tos 	= 0;
	ip_hdr.ip_len 	= htons (IP_HEADER_LEN + UDP_HEADER_LEN + data_len);
	ip_hdr.ip_id 	= htons (0);
  	flags[0] 	= 0;
  	flags[1] 	= 0;
  	flags[2] 	= 0;
	flags[3] 	= 0;
	ip_hdr.ip_off 	= htons ((flags[0] << 15)
                      	     + (flags[1] << 14)
                      	     + (flags[2] << 13)
                      	     +  flags[3]);
	ip_hdr.ip_ttl 	= 255;
  	ip_hdr.ip_p 	= IPPROTO_UDP;
	if ((rv 	= inet_pton (AF_INET, source_ip, &(ip_hdr.ip_src))) != 1) {
    			fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (rv));
    			return;
  	}
	
  	if ((rv 	= inet_pton (AF_INET, dest_ip, &(ip_hdr.ip_dst))) != 1) {
    			fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (rv));
    			return;
  	}
	ip_hdr.ip_sum 	= 0;
  	ip_hdr.ip_sum 	= checksum ((uint16_t *) &ip_hdr, IP_HEADER_LEN);

	/* Build UDP header */
  	udp_hdr.source  = htons (4950);
  	udp_hdr.dest 	= htons (dest_port);
	udp_hdr.len 	= htons (UDP_HEADER_LEN + data_len);
	udp_hdr.check 	= udp4_checksum (ip_hdr, udp_hdr, data, data_len);
	
	/* Build Ethernet Frame */
	if( pace  > 1 )
		frame_len =( 2 * MAC_ADDR_LEN ) + 4 + 2 + IP_HEADER_LEN + UDP_HEADER_LEN + MTU;
	else
		frame_len =( 2 * MAC_ADDR_LEN ) + 4 + 2 + IP_HEADER_LEN + UDP_HEADER_LEN + data_len;
	memcpy (frame, dest_mac, MAC_ADDR_LEN);
  	memcpy (frame + MAC_ADDR_LEN, src_mac, MAC_ADDR_LEN);
	//memcpy (frame + 2*MAC_ADDR_LEN, &type,	2);
	frame[12] = 0x81;
	frame[13] = 0x00;
	memcpy (frame + 2*MAC_ADDR_LEN+2, &vlan,  2);
	//memcpy (frame + 2*MAC_ADDR_LEN+4, &ether_type, 2);
	frame[16] = 0x08;
	frame[17] = 0x00;
	memcpy (frame + MAC_HEADER_LEN, &ip_hdr, IP_HEADER_LEN);
	memcpy (frame + MAC_HEADER_LEN + IP_HEADER_LEN, &udp_hdr, UDP_HEADER_LEN);
	memcpy (frame + MAC_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN, data, data_len);

	//printf("Frame: %s\n", frame);
	if ((raw_sock = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
   		 perror ("socket() failed ");
    		 return;
  	}
	for(i=0; i<pace; i++)
	{
		 if ((numbytes = sendto (raw_sock, frame, frame_len, 0, (struct sockaddr *) &dev, sizeof (dev))) <= 0) {
                        	perror ("sendto() failed");
                        	return;
                }

	}
	//printf("Packet sent to %s\n", dest_ip);
	close(raw_sock);
	free(frame);
	free(data);
	free(interface);
	free(interface_str);
	free(source_ip);
}
	
void *send_receive_demand(void *thread_args)
{
	int 		j, num_chunks, chunks, rem;
	int 		rv;
	int 		sockfd;
	int 		numbytes;
	int 		i;
	int 		data_len;
	int 		timeslot;
	int 		received=0;
	int		len;
	unsigned short  vlan;
	char 		*buf;
	char 		source_host[16];
	struct 		addrinfo hints; 
	struct  	addrinfo *servinfo; 
	struct  	addrinfo *p;
	struct 	  	sockaddr_storage their_addr;
	socklen_t 	addr_len;
	struct 	  	parsed_options *demand =  (struct parsed_options *)thread_args;
	struct 		sockaddr_in srcinfo;
	char   		*dest_ip;
	char 		src_host[10];
	dest_ip = malloc(80);
	memset(dest_ip, 0, 16);
	strcpy(dest_ip, "10.0.0.");
	buf = malloc(60);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(ARBITER_IP, ARBITER_PORT, &hints, &servinfo)) != 0) 
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return;
	}
	
	for(p = servinfo; p != NULL; p = p->ai_next) 
	{
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
		{
			perror("Client: socket\n");
			continue;
		}
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) 
		{
			close(sockfd);
			perror("client: connect\n");
			continue;
		}
		break;
	}

	if (p == NULL) 
	{
		fprintf(stderr, "Client: failed to connect socket\n");
		return;
	}
	freeaddrinfo(servinfo);
	
	len = sizeof(srcinfo);
	rv = getsockname(sockfd, (struct sockaddr *)&srcinfo, &len);

	if(rv == -1)	
	{
		perror("getsockname\n");
		close(sockfd);
		return;
	}
	
	//printf("Src port number %hu and IP address %s\n",ntohs(srcinfo.sin_port), inet_ntoa(srcinfo.sin_addr));
	sprintf(source_host,"h%d",ntohl(srcinfo.sin_addr.s_addr)&0x000000FF);
	memset(buf, 0, MAXDATASIZE);
	sprintf(buf, "%s %hu %u %s", demand->dest_host, demand->dest_port, demand->byte, source_host);
	/*if ((numbytes = send(sockfd, buf, strlen(buf)+1, 0)) == -1) 
	{

		perror("Client: send\n");
		close(sockfd);
		return NULL;
	}*/

	addr_len = sizeof(their_addr);
	/*while(1)
	{
		memset(buf, 0, MAXDATASIZE);
		if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1 , 0)) == -1) 
		{
			error("recv\n");
			return NULL;
		}
		buf[numbytes] = '\0';
		//printf("Received: %s\n",buf);
		sscanf(buf,"%d %d %hu",&data_len, &timeslot, &vlan);
		//printf("%d %d %hu", data_len, timeslot, vlan);
		if ( data_len == -1)
	        {
			close(sockfd);
			free(buf);
			return NULL;
			
			
		}	
		dest_ip[7] = demand->dest_host[1];
		dest_ip[8] = demand->dest_host[2];
		//printf("Received count: %d\n", received++);

		memset(buf, 0, MAXDATASIZE);
        	strcpy(buf, "ACK");
        	if ((numbytes = send(sockfd, buf, strlen(buf)+1, 0)) == -1)
        	{

                	perror("Client: send\n");
                	close(sockfd);
                	return NULL;
        	}

		send_packet(ntohl(srcinfo.sin_addr.s_addr), dest_ip, demand->dest_port,data_len,htons(vlan),timeslot);
	} */
	
	dest_ip[7] = demand->dest_host[1];
	dest_ip[8] = demand->dest_host[2];
	if( demand->byte > MTU)
	{
		num_chunks =(int) demand->byte/MTU;
		for( j=1; j<=num_chunks; j++)
		{
			if( (j%PACE)==0)
			{
				chunks = MTU;
				memset(buf, 0, MAXDATASIZE);
				sprintf(buf, "%s %hu %u %s", demand->dest_host, demand->dest_port, chunks, source_host);
				if ((send(sockfd, buf, strlen(buf)+1, 0)) == -1) 
				{		
					perror("send\n");
					close(sockfd);
					return;
				}
				memset(buf, 0, MAXDATASIZE);
				if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1 , 0)) == -1) 
				{
					error("recv\n");
					return NULL;
				}
				buf[numbytes] = '\0';
				//printf("Received: %s\n",buf);
				sscanf(buf,"%d %d %hu",&data_len, &timeslot, &vlan);
				//dest_ip[7] = demand->dest_host[1];
				//dest_ip[8] = demand->dest_host[2];
				send_packet(ntohl(srcinfo.sin_addr.s_addr), dest_ip, demand->dest_port,data_len,htons(vlan),timeslot, PACE);

			}
			/*else
				send_packet(ntohl(srcinfo.sin_addr.s_addr), dest_ip, demand->dest_port,data_len,htons(vlan),timeslot);*/
		}
		rem = num_chunks%PACE;
		if( rem > 0)
			send_packet(ntohl(srcinfo.sin_addr.s_addr), dest_ip, demand->dest_port, MTU,htons(vlan),timeslot, rem);
		int chunks = demand->byte - num_chunks*MTU ;
		if( chunks > 0)
		{
			memset(buf, 0, MAXDATASIZE);
			sprintf(buf, "%s %hu %u %s", demand->dest_host, demand->dest_port, chunks, source_host);
			if ((send(sockfd, buf, strlen(buf)+1, 0)) == -1) 
			{		
				perror("send\n");
				close(sockfd);
				return;
			}
			memset(buf, 0, MAXDATASIZE);
			if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1 , 0)) == -1) 
			{
				error("recv\n");
				return NULL;
			}
			buf[numbytes] = '\0';
			//printf("Received: %s\n",buf);
			sscanf(buf,"%d %d %hu",&data_len, &timeslot, &vlan);
			//dest_ip[7] = demand->dest_host[1];
			//dest_ip[8] = demand->dest_host[2];
			send_packet(ntohl(srcinfo.sin_addr.s_addr), dest_ip, demand->dest_port,data_len,htons(vlan),timeslot, 1);
		}
	}
	else
	{
		chunks = demand->byte;
		memset(buf, 0, MAXDATASIZE);
		sprintf(buf, "%s %hu %u %s", demand->dest_host, demand->dest_port, chunks, source_host);
		if ((send(sockfd, buf, strlen(buf)+1, 0)) == -1) 
		{		
			perror("send\n");
			close(sockfd);
			return;
		}
		memset(buf, 0, MAXDATASIZE);
		if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1 , 0)) == -1) 
		{
			error("recv\n");
			return NULL;
		}
		buf[numbytes] = '\0';
		//printf("Received: %s\n",buf);
		sscanf(buf,"%d %d %hu",&data_len, &timeslot, &vlan);
		//dest_ip[7] = demand->dest_host[1];
		//dest_ip[8] = demand->dest_host[2];
		send_packet(ntohl(srcinfo.sin_addr.s_addr), dest_ip, demand->dest_port,data_len,htons(vlan),timeslot, 1);
	}
	memset(buf, 0, MAXDATASIZE);
	demand->dest_port = -1;
	chunks = -1;
	sprintf(buf, "%s %hu %u %s", demand->dest_host, demand->dest_port, chunks, source_host);
	if ((send(sockfd, buf, strlen(buf)+1, 0)) == -1) 
	{		
		perror("send\n");
		close(sockfd);
		return;
	}
	close(sockfd);
	free(buf);
	return NULL;
}

void fastpass_agent()
{
	int i, j;
	int demands = 0;
	pthread_t thread_id[MAXOPTIONS];
	int n;
	float val;
	/* Create threads for each demand */
	for( i=0; i <record_count; i++)
	{
		if(pthread_create(&thread_id[i], NULL, send_receive_demand, &parsed_args[i]))
		{
			printf("Error creating thread %d\n", i);
			exit(1);
		}
		//sleep(0.0007);
		/*n = rand()%10;
		val = (float)n/1000000;
		sleep(val);*/
		//send_receive_demand(&parsed_args[i]);
	
	}	
	for( i=0; i<record_count; i++)
	{
		if(pthread_join(thread_id[i], NULL))
        	{
			printf("ERROR joining thread %d\n", i);
                	exit(1);
		}
        }

}

int main(int argc, char * argv[])
{

	if( argc != 2)
	{
		printf("Filename is missing\n");
		return 0;
	}
	FILE *fd = fopen(argv[1], "r");
	if( fd == NULL)
	{
		printf("Error while opening %s\n",argv[1]);
		return 0;
	}
	sem_init(&mutex, 0, 1);
	command_parser(fd);
	fastpass_agent();
	printf("Total packets sent to network:%d\n",pkt_count);
	return 0;
}
