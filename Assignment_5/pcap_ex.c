#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <pcap.h>

#include <sys/socket.h>
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>	
#include <netinet/ip.h>	

/* structs */
typedef struct network_flow
{
  char* src_ip;
  char* dst_ip;
  u_int src_port;
  u_int dst_port;
  char* protocol;

  struct network_flow * next;

} n_f;

typedef struct tcp_packet
{
  n_f* p_flow;
  struct tcphdr * tcp;
  int payload;

  struct tcp_packet * next;

} tcp_packet;

/* functions */
void packet_capture(char* fp);
void handler_of_packets(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void print_tcp_info(const u_char * packet, int packet_size);
void print_udp_info(const u_char * packet, int packet_size);


/* initialization */
int total_nfs     = 0; 
int tcp_nfs       = 0; 
int udp_nfs       = 0; 
int total_packets = 0; 
int tcp_packets   = 0; 
int udp_packets   = 0; 
int tcp_bytes     = 0;
int udp_bytes     = 0; 

int main(int argc, char *argv[])
{

   if(argc<=1) 
    {
    printf("You did not feed me arguments, I will die now :(\n");
    exit(1);
    }
 
    int n = 0;
    char* output_file = ""; 

    for (n=1; n<=argc-1; n=n+2) 
    { 
        /* Get output file */
        if (strcmp(argv[n],"-i")==0)
        {
            //monitor_traffic(); 
        }
        /* Get prime number */
        else if (strcmp(argv[n],"-r")==0)
        {
           output_file = argv[n+1];
           packet_capture(output_file); 
        }
        /* Get Primitive Root for previous prime number */ 
        else if (strcmp(argv[n],"-f")==0)
        {
            
        }
        else if (strcmp(argv[n],"-h")==0)
        {
            printf("Options:\n"); 
            printf("\n");
            printf("-i\tNetwork interface name (e.g., eth0)\n");
            printf("-r\tPacket capture file name (e.g., test.pcap)\n");
            printf("-f\tFilter expression (e.g., port 8080)\n");
            printf("-h\tHelp message\n");            
            return 0;
        }
        else
        {
            printf("Invalid arguments.\n"); 
            return 0;
        }
    }
}

void packet_capture(char* fp)
{
    pcap_t *p;

    char errbuf[100];

    p = pcap_open_offline(fp, errbuf);

    if (!p) 
    {
        fprintf(stderr, "Couldn't open file %s: %s\n", fp, errbuf);
        exit(1);
    }

    pcap_loop(p, -1, handler_of_packets, NULL);

    printf("Total Network Flows captured: %d\n", total_nfs);
    printf("TCP Network Flows captured:   %d\n", tcp_nfs);
    printf("UDP Network Flows captured:   %d\n", udp_nfs);
    printf("Total Packets received:       %d\n", total_packets);
    printf("TCP Packets received:         %d\n", tcp_packets);
    printf("UDP packets received:         %d\n", udp_packets); 
    printf("TCP bytes received:           %d\n", tcp_bytes);
    printf("UDP bytes received:           %d\n", udp_bytes);

}

void handler_of_packets(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{

	int packet_size = header->caplen;

	struct iphdr *ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
	
    total_packets = total_packets+1;

	switch (ip_header->protocol) 
	{
		case IPPROTO_TCP: 

			tcp_packets = tcp_packets+1;
			print_tcp_info(packet, packet_size);
			break;
		
		case IPPROTO_UDP: 
			udp_packets = udp_packets+1;
			print_udp_info(packet, packet_size);
			break;

		default: 
			total_packets = total_packets+1;
			break;		
	}

}


void print_tcp_info(const u_char * packet, int packet_size)
{
    // not completed code, this function was so supposed to print tcp info and determine if there's a retransmission
}

void print_udp_info(const u_char * packet, int packet_size)
{
    // not completed code, this function was so supposed to print udp info 

}

