#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>


#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#define ETH_HEADER_SIZE 14

typedef unsigned char u_char;

void print_packet_info(const u_char *packet){
    struct ip *ip_header = (struct ip *)(packet + ETH_HEADER_SIZE);
    u_char *payload = packet + ETH_HEADER_SIZE + (ip_header->ip_hl * 4);
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    
    printf("source ip: %s\n", source_ip);
    printf("dest ip: %s\n", dest_ip);
    printf("size ip header: %d\n", ip_header->ip_hl * 4);
    printf("size total: %d\n", ip_header->ip_len);
    printf("payload:\n");
    for(int i = 0; i < ip_header->ip_len - (ip_header->ip_hl * 4); ++i) {
        printf("%x", (u_char)*(payload + i));
        if(i != 0 && i % 40 == 0) {
            printf("\n");
            if(i > 1000) {
                break;
            }
        }
    }
    printf("\n");

    printf("---\n");
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    printf("dest ip\n");
}

int part_1(size_t packet_len, const u_char *packet) {
    struct pcap_pkthdr hdr;
    hdr.ts.tv_sec = time(NULL); 
    hdr.ts.tv_usec = 0; 
    hdr.caplen = packet_len; 
    hdr.len = packet_len;
    print_packet_info(packet);
}

#define CONDITION 2

#if CONDITION == 1

int main (void)
{
    //  Socket to talk to clients
    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int rc = zmq_bind (responder, "tcp://*:2001");
    assert (rc == 0);


    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *devs;
    const u_char *packet;
     struct pcap_pkthdr packet_header;
    int packet_count_limit = 10;
    int timeout_limit = 10000;

#if 1
  printf("%s:%d\n", __func__, __LINE__);

    pcap_findalldevs(&devs, error_buffer);
    if (devs == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    handle = pcap_open_live(
            devs->name,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );
 printf("%s:%d\n", __func__, __LINE__);

#endif
    
    printf("%s:%d\n", __func__, __LINE__);

    while (1) {
        char buffer [1024];

        pcap_loop(handle, 0, packet_handler, (u_char *)responder);

        printf("%s:%d\n", __func__, __LINE__);

        printf ("Received Hello\n");
        sleep (1);   
        zmq_send (responder, "World", 5, 0);
    }
    return 0;
}
#endif

#if CONDITION == 2


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <zmq.h>



void packet_handler2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    void *socket = args;
    printf("%s:%d\n", __func__, __LINE__);

    print_packet_info(packet);
}

int main() {

    void *context = zmq_ctx_new();
    void *socket = zmq_socket(context, ZMQ_PUSH);
    zmq_bind(socket, "tcp://*:2001");
    printf("%s:%d\n", __func__, __LINE__);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find devices: %s\n", errbuf);
        return 1;
    }
    printf("Доступные интерфейсы:\n");
    for (device = alldevs; device; device = device->next) {
        if(strlen("lo") == strlen(device->name) && !strcmp(device->name, "lo")) {
            break;
        }
    }
    if (device == NULL) {
        fprintf(stderr, "No devices found.\n");
        return 1;
    }
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }
    printf("%s:%d\n", __func__, __LINE__);

    int result = pcap_loop(handle, 0, packet_handler2, (u_char *)socket);
    printf("%s:%d\n", __func__, __LINE__);
    pcap_close(handle);
    zmq_close(socket);
    zmq_ctx_destroy(context);
    pcap_freealldevs(alldevs);

    return (result == -1) ? 1 : 0;
}


#endif
