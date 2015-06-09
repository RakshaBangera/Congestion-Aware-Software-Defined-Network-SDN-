#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <pthread.h>
#include <semaphore.h>

#define	 MTU		1454
#define  MAXBUFLEN  	60
#define  ARBITER_IP 	"20.0.0.100"
#define  ARBITER_PORT 	"5000"
#define  BACKLOG	200
#define  MAXHOST	16

sem_t mutex;
static int count = 0;
/* Return the pod number of the host */
int getPod(int host)
{
	if( (host >= 0) && (host <= 3))
		return 1;
	else if ( (host >=4) && (host <= 7))
		return 2;
	else if ( (host >=8) && (host <= 11))
		return 3;
	else if( (host >=12) && (host <= 15))
		return 4;
}

/* Returns the VLAN to be used to transmit frame from host  s to host d */
int getVLAN(int s, int d)
{
	static unsigned short vlan_alloc[MAXHOST][MAXHOST]={-1,};
	//static int count =0;
	//count++;
	//printf("Request count: %d\n", count);
	unsigned short vlan=0;
	sem_wait(&mutex);
	count++;
	printf("Request Processed: %d\n",count);
	if( (s >= 0) && ( s < 16) &&
	    (d >= 0) && (d < 16))
	{
		/* directly connected */
		if( ((s/2)+0.5) == ((d/2)+0.5))
			vlan = (0 <<8)|(s<<4)|d;
		else if( getPod(s) == getPod(d)) /*Same Pod */
		{
			vlan_alloc[s][d]++;
			vlan_alloc[s][d] = vlan_alloc[s][d]%2;
			vlan = (vlan_alloc[s][d]<<8)|(s<<4)|d;
		}
		else
		{
			vlan_alloc[s][d]++;
			vlan_alloc[s][d] = vlan_alloc[s][d]%4;
			vlan = (vlan_alloc[s][d]<<8)|(s<<4)|d;
		}
	}
	sem_post(&mutex);
	/* Wait for 2ms of transmission time */
	//sleep(0.002);
	return vlan;

}

void * connection_handler(void *new_sock)
{
	int new_fd = *(int*)new_sock;
	int    		count=0;
	int 		numbytes;
	int 		chunks;
	int		num_chunks;
	char 		buf[MAXBUFLEN];
	//socklen_t 	addr_len;
	char		dest_host[5], src_host[5];
	unsigned 	short dest_port;
	int		bytes;
	unsigned 	short vlan;
	unsigned 	short host_port;
	unsigned 	int timeslot;
	int 		i, s, d;
	
	
	//printf("s: %d, d:%d\n", s, d);
	/* Break up demand size to fit into the MTU */
	/*if ( bytes > MTU )
	{
		//vlan = getVLAN(s,d);
		num_chunks =(int) bytes/MTU;
		for( i=1; i<=num_chunks; i++)
		{
			if( i == 40)
			{	
			     //int r = rand()%10;
			     sleep(0.6);
			}
			chunks = MTU;
			timeslot = 1;
			vlan = getVLAN(s, d);
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%d %d %hu",chunks, timeslot, vlan);
			//printf("buf: %s\n", buf);
			if ((send(new_fd, buf, strlen(buf), 0)) == -1) 
			{		
				perror("send\n");
				close(new_fd);
				return;
			}
			//printf("Msg_sent: %d\n", msg_sent++);

			memset(buf, 0, sizeof(buf));
					if ((numbytes = recv(new_fd, buf, MAXBUFLEN-1, 0)) == -1)
					{
							perror("recv");
							close(new_fd);
							return;
					}
					buf[numbytes]='\0';
			
					//printf("Received ACK: %s\n", buf);

		}
		int chunks = bytes - num_chunks*MTU ;
		if( chunks > 0)
		{
			timeslot = 1;
							vlan = getVLAN(s, d);
			memset(buf, 0, sizeof(buf));
							sprintf(buf, "%d %d %hu",chunks, timeslot, vlan);
			//printf("buf: %s\n", buf);
							if ((send(new_fd, buf, strlen(buf), 0)) == -1)
							{
									perror("send\n");
									close(new_fd);
									return;
							}
			//printf("Msg_sent: %d\n", msg_sent++);
		
			memset(buf, 0, sizeof(buf));
							if ((numbytes = recv(new_fd, buf, MAXBUFLEN-1, 0)) == -1)
							{
									perror("recv");
									close(new_fd);
									return;
							}
							buf[numbytes]='\0';
							//printf("Received ACK: %s\n", buf);

		}
	}
	else
	{
		chunks = bytes;
		timeslot = 1;
					vlan = getVLAN(s, d);
		memset(buf, 0, sizeof(buf));
					sprintf(buf, "%d %d %hu",chunks, timeslot, vlan);
		//printf("buf: %s\n", buf);
					if ((send(new_fd, buf, strlen(buf), 0)) == -1)
					{
						perror("send\n");
							close(new_fd);
							return;
					}
		//printf("Msg_sent: %d\n", msg_sent++);

		memset(buf, 0, sizeof(buf));
					if ((numbytes = recv(new_fd, buf, MAXBUFLEN-1, 0)) == -1)
					{
						  perror("recv");
						  close(new_fd);
						  return;
					}
					buf[numbytes]='\0';
					//printf("Received ACK: %s\n", buf);		
	}
	/*Indicate end of processing the demand */
	/*memset(buf, 0, MAXBUFLEN);
	chunks = -1;
	timeslot = -1;
	vlan = -1;
	sprintf(buf, "%d %d %hu",chunks, timeslot, vlan);
	//printf("buf: %s\n", buf);
	if ((send(new_fd, buf, strlen(buf), 0)) == -1)
			{
					perror("send\n");
					close(new_fd);
				return;
			}
	//printf("Msg_sent: %d\n", msg_sent++);*/
	while(1)
	{
		count++;
		memset(buf, 0, sizeof(buf));
		if ((numbytes = recv(new_fd, buf, MAXBUFLEN-1, 0)) == -1) 
		{	
			perror("recv");
			close(new_fd);
			return;
		}
		buf[numbytes]='\0';
		//printf("Received: %s\n", buf);
		sscanf(buf,"%s %hu %d %s",dest_host, &dest_port, &bytes, src_host); 
		//memset(buf, 0, sizeof(buf));
		if( count == 1)
		{
			s = atoi(&src_host[1]);
			d = atoi(&dest_host[1]);
			s = s-1;
			d = d-1;
		}
		if( bytes == -1)
			break;
		chunks = bytes;
		timeslot = 1;
		vlan = getVLAN(s, d);
		memset(buf, 0, sizeof(buf));
		sprintf(buf, "%d %d %hu",chunks, timeslot, vlan);
		//printf("buf: %s\n", buf);
		if ((send(new_fd, buf, strlen(buf), 0)) == -1) 
		{		
			perror("send\n");
			close(new_fd);
			return;
		}
	}
	close(new_fd);
	free((int*)new_sock);
}
void handle_requests()
{
	static 	int	msg_sent=0;
	int		i;
	int 		sockfd;
	int 		new_fd;
	int 		rv;
	struct 		sockaddr_storage host_addr;
    	struct 		sockaddr_in *host_ipv4;
	char 		host_ip[INET_ADDRSTRLEN];
	struct          addrinfo hints, *servinfo, *p;	
	pthread_t 	thread;
	int 		*new_sock;
	socklen_t 	addr_len;
	memset(&hints, 0, sizeof hints);
	hints.ai_family 	= AF_INET; 		
	hints.ai_socktype 	= SOCK_STREAM;
 
	if ((rv = getaddrinfo(ARBITER_IP, ARBITER_PORT, &hints, &servinfo)) != 0) 
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return;
	}
	
	for(p = servinfo; p != NULL; p = p->ai_next) 
	{
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
		p->ai_protocol)) == -1) 
		{
			perror("listener: socket\n");
			continue;
		}
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) 
		{
			close(sockfd);
			perror("listener: bind\n");
			continue;
		}
		break;
	}
	if (p == NULL) 
	{
		fprintf(stderr, "listener: failed to bind socket\n\n");
		close(sockfd);
		return;
	}

	if ((listen(sockfd, BACKLOG)) == -1) 
	{
	 	perror("listen\n");
	 	close(sockfd);
	 	return;
	}
	while(1)
	{
		printf("Requests processed:%d\n",count);
		addr_len = sizeof(host_addr);
		new_fd = accept(sockfd, (struct sockaddr *)&host_addr, &addr_len);
		if (new_fd == -1) 
	 	{
		 	perror("accept\n");
		 	continue;
	 	}

		new_sock = malloc(sizeof(int));
        	*new_sock = new_fd;
		
		/*getpeername(new_fd, (struct sockaddr*)&host_addr, &addr_len);
		host_ipv4 = (struct sockaddr_in *)&host_addr;
		host_port = ntohs(host_ipv4->sin_port);
		inet_ntop(AF_INET, &host_ipv4->sin_addr, host_ip, sizeof(host_ip));
		//printf("Host IP:%s\n",host_ip); */
		
		if( pthread_create( &thread , NULL ,  connection_handler , (void*) new_sock) < 0)
        	{
            		perror("could not create thread");
            		continue;
        	}
		//printf("Requests processed:%d\n", count);

		
	}
	close(sockfd);
}

void main()
{
	sem_init(&mutex, 0, 1);
	handle_requests();
}

