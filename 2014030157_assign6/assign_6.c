#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define ETHERNET_HEADER_LENGTH 14
//Global Variables
pcap_t *handle;
int packs = 0;
int tcps = 0;
int udps = 0;
long tcpBytes = 0;
long udpBytes = 0;
struct Node {
		char *src;
		int src_port;
		char *dst;
		int dst_port;
		char *protocol;
    struct Node *next;
};
struct Node *Head = NULL;
void resetGlobal(){
	packs = 0;
	tcps = 0;
	udps = 0;
	tcpBytes = 0;
	udpBytes = 0;
	return;
}
//Insert new node in list
void insertNode(char *src, int src_port, char *dst, int dst_port, char *protocol) {
  //create a Node
  struct Node *link = (struct Node*) malloc(sizeof(struct Node));
	link->src = src;
	link->src_port = src_port;
	link->dst = dst;
	link->dst_port = dst_port;
	link->protocol = protocol;
  //point it to old Head node
  link->next = Head;
  //point Head to new node
  Head = link;
}
//Check if 5-tuple already in list
void checkList(char *src, int src_port, char *dst, int dst_port, char *protocol) {
  struct Node *ptr = Head;
	int ret = 1;
  //start from the beginning
  while(ptr != NULL) {
  	if (src==ptr->src && src_port==ptr->src_port && dst==ptr->dst && dst_port==ptr->dst_port && protocol==ptr->protocol) {
    	ret = 0;
    }
    ptr = ptr->next;
  }
	if (ret){//if flow doesnt already exist insert it
		insertNode(src, src_port, dst, dst_port, protocol);
	}
	return;
}
//Get #Network Flows by Protocol
int getFlowsByProtocol(char *protocol){
	struct Node *ptr = Head;
	int count = 0;
	while (ptr != NULL) {
		if (protocol == ptr->protocol) {
    	count++;
		}
    ptr = ptr->next;
	}
	return count;
}
//Get #Network Flows
int getAllFlows(){
	struct Node *ptr = Head;
	int count = 0;
	while(ptr != NULL){
		count++;
		ptr = ptr->next;
	}
return count-1;
}
//Print Tool usage
void
usage(void){
	printf(
       "\n"
       "usage:\n"
       "\t./monitor \n"
		   "Options:\n"
		   "-r <device>, Network interface name\n"
		   "-i <filename>, Packet capture file name\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}
//Print UDP packet info
void print_udp(char *src, char *dst, int sport, int dport, int hlen, int len){
	printf("Source IP: %s\n", src);
	printf("Destination IP: %s\n", dst);
	printf("Source Port: %d\n", sport);
	printf("Destination Port: %d\n", dport);
	printf("Protocol: UDP\n");
	printf("Header length: %d\n", hlen);
	printf("Payload length: %d\n", len);
	printf("------------------------\n");
}
//Print TCP packet info
void print_tcp(char *src, char *dst, int sport, int dport,
	int hlen, int len, unsigned int ack, unsigned int seq){
	printf("Source IP: %s\n", src);
 	printf("Destination IP: %s\n", dst);
 	printf("Source Port: %d\n", sport);
 	printf("Destination Port: %d\n", dport);
 	printf("Protocol: TCP\n");
 	printf("Header length: %d\n", hlen);
 	printf("Payload length: %d\n", len);
	printf("Acknowledgement: %u\n", ack);
	printf("Sequence: %u\n", seq);
	printf("------------------------\n");
}
//Prints results for packets captured(called before exit)
void print_result(int flows, int tcpFlows, int udpFlows){
	printf("Total number of network flows captured: %d\n", flows);
	printf("Number of TCP network flows captured: %d\n", tcpFlows);
	printf("Number of UDP network flows captured: %d\n", udpFlows);
	printf("Total number of packets received: %d\n", packs);
	printf("Total number of TCP packets received: %d\n", tcps);
	printf("Total number of UDP packets received: %d\n", udps);
	printf("Total bytes of TCP packets received: %ld\n", tcpBytes);
	printf("Total bytes of UDP packets received: %ld\n", udpBytes);
}
//Called by pcap_loop() each time a packet is captured
void my_packet_handler(u_char *args,const struct pcap_pkthdr *packet_header,const u_char *packet_body){
	struct ip *ipHeader = (struct ip*)(packet_body + ETHERNET_HEADER_LENGTH);
	struct tcphdr *tcpHeader = (struct tcphdr*)(packet_body + ETHERNET_HEADER_LENGTH + 20);
	struct udphdr *udpHeader = (struct udphdr*)(packet_body + ETHERNET_HEADER_LENGTH + 20);
	if(ipHeader->ip_p == 6){//TCP Packet
		print_tcp(inet_ntoa(ipHeader->ip_src),	inet_ntoa(ipHeader->ip_dst),
							ntohs(tcpHeader->th_sport),		ntohs(tcpHeader->th_dport),
							ipHeader->ip_hl, 							ntohs(ipHeader->ip_len),
							ntohl(tcpHeader->th_ack), 		ntohl(tcpHeader->th_seq));
		tcps++;
		tcpBytes += ntohs(ipHeader->ip_len) + ipHeader->ip_hl*4;
		checkList(inet_ntoa(ipHeader->ip_src),	ntohs(tcpHeader->th_sport),
							inet_ntoa(ipHeader->ip_dst),	ntohs(tcpHeader->th_dport),	"TCP");
	}else if (ipHeader->ip_p == 17) {//UDP Packet
		print_udp(inet_ntoa(ipHeader->ip_src),	inet_ntoa(ipHeader->ip_dst),
							ntohs(udpHeader->uh_sport),		ntohs(udpHeader->uh_dport),
							ipHeader->ip_hl,							ntohs(ipHeader->ip_len));
		udps++;
		udpBytes += ntohs(ipHeader->ip_len) + ipHeader->ip_hl*4;
		checkList(inet_ntoa(ipHeader->ip_src),	ntohs(udpHeader->uh_sport),
							inet_ntoa(ipHeader->ip_dst),	ntohs(udpHeader->uh_dport),	"UDP");
	}
	packs++;
  return;
}
//Called when signal is given to terminate pcap_loop()
void terminate_process(int signum){
   pcap_breakloop(handle);
}
//Called by main
void NetworkMonitor(char *device){
  char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
	/* Open device for live capture */
	handle = pcap_open_live(device,BUFSIZ,0,-1,error_buffer);
	if (handle == NULL) {
	   printf("Can't open eth3: %s\n", error_buffer);
	  return ;
	}
	//Reset Global Variables
	resetGlobal();
	Head  = (struct Node*) malloc(sizeof(struct Node));
	signal(SIGINT, terminate_process);
	pcap_loop(handle, -1, my_packet_handler, NULL);
	int tcpFlows = getFlowsByProtocol("TCP");
	int udpFlows = getFlowsByProtocol("UDP");
	int flows = getAllFlows();
	printf("\n");
	print_result(flows,tcpFlows,udpFlows);
	pcap_close(handle);
	free(Head);
	return;
}
//Called by main
void PacketFile(char *filename){
	struct pcap_pkthdr packet_header;
	char error_buffer[PCAP_ERRBUF_SIZE];
	const u_char *packet;
	//Open Pcap file
	handle = pcap_open_offline(filename, error_buffer);
	if (handle == NULL) {
	     printf("Can't open file: %s\n", error_buffer);
	    return ;
	}
	//Reset Global Vaariables
	resetGlobal();
	Head  = (struct Node*) malloc(sizeof(struct Node));
	//Capture all packets
	pcap_loop(handle, 0, my_packet_handler, NULL);
	int tcpFlows = getFlowsByProtocol("TCP");
	int udpFlows = getFlowsByProtocol("UDP");
	int flows = getAllFlows();
	printf("\n");
	print_result(flows,tcpFlows,udpFlows);
	pcap_close(handle);
	free(Head);
	return;
}

int main(int argc, char *argv[]){
	int ch;
	if (argc < 2)
		usage();
	while ((ch = getopt(argc, argv, "hi:r:")) != -1) {
		switch (ch) {
		case 'i':
			NetworkMonitor(optarg);
			break;
		case 'r':
			PacketFile(optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	return 0;
}
