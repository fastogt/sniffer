// Copyright (c) 2016 Alexandr Topilski. All rights reserved.

#ifdef WIN32
#else
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdlib.h>
#endif

// https://gist.github.com/infinity0/596845b5eea3e1a02a018009b2931a39
// https://stackoverflow.com/questions/4526576/how-do-i-capture-mac-address-of-access-points-and-hosts-connected-to-it

#define MARKER "\r\n"

int main(int argc, char* argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  const char* device = pcap_lookupdev(errbuf);
  if (device == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  pcap_t* pcap = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
  if (!pcap) {
    fprintf(stderr, "error reading pcap file: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  struct pcap_pkthdr header;
  const u_char* packet;
  while ((packet = pcap_next(pcap, &header)) != NULL) {
    bpf_u_int32 packet_len = header.caplen;
    if (packet_len < sizeof(struct ether_header)) {
      pcap_close(pcap);
      return EXIT_FAILURE;
    }

    struct ether_header* ethernet_header = (struct ether_header*)packet;
    uint16_t ht = ntohs(ethernet_header->ether_type);
    if (ht != ETHERTYPE_IP) {  // ETHERTYPE_ARP
      continue;
    }

    const char* dest_mac = ether_ntoa(ethernet_header->ether_dhost);
    const char* src_mac = ether_ntoa(ethernet_header->ether_shost);

    /* Skip over the Ethernet header. (14)*/
    packet += sizeof(struct ether_header);
    packet_len -= sizeof(struct ether_header);

    if (packet_len < sizeof(struct ip)) {
      pcap_close(pcap);
      return EXIT_FAILURE;
    }

    struct iphdr* ip = (struct iphdr*)packet;
    if (!(ip->protocol != IPPROTO_UDP || ip->protocol != IPPROTO_TCP)) {
      continue;
    }

    unsigned int IP_header_length = ip->ihl * 4; /* ip_hl is in 4-byte words */
    if (packet_len < IP_header_length) {         /* didn't capture the full IP header including options */
      pcap_close(pcap);
      return EXIT_FAILURE;
    }

    packet += IP_header_length;
    packet_len -= IP_header_length;

    if (ip->protocol == IPPROTO_UDP) {
      if (packet_len < sizeof(struct udphdr)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
      }

      packet += sizeof(struct udphdr);
      packet_len -= sizeof(struct udphdr);

    } else if (ip->protocol == IPPROTO_TCP) {
      if (packet_len < sizeof(struct tcphdr)) {
        continue;
      }

      struct tcphdr* tcpheader = (struct tcphdr*)packet;
      packet += sizeof(struct tcphdr);
      packet_len -= sizeof(struct tcphdr);
    }
  }

  pcap_close(pcap);
  return EXIT_SUCCESS;
}
