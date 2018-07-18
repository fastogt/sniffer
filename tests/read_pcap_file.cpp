#ifdef WIN32
#else
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#endif

#include "pcap_packages/radiotap_header.h"

#define TEST_PCAP_FILE_NAME "test.sniff"
#define TEST_PCAP_FILE_PATH TEST_FOLDER_PATH TEST_PCAP_FILE_NAME

int main(int argc, char* argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  const char* device = pcap_lookupdev(errbuf);
  if (device == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  pcap_t* pcap = pcap_open_offline_with_tstamp_precision(TEST_PCAP_FILE_PATH, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
  if (!pcap) {
    fprintf(stderr, "error reading pcap file: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  struct pcap_pkthdr header;
  const u_char* packet;
  while ((packet = pcap_next(pcap, &header)) != NULL) {
    bpf_u_int32 packet_len = header.caplen;
    if (packet_len < sizeof(struct radiotap_header)) {
      pcap_close(pcap);
      return EXIT_FAILURE;
    }

    struct radiotap_header* radio = (struct radiotap_header*)packet;
    packet += sizeof(struct radiotap_header);
    packet_len -= sizeof(struct radiotap_header);
    if (packet_len < sizeof(struct ieee80211header)) {
      continue;
    }

    struct ieee80211header* beac = (struct ieee80211header*)packet;
    /*printf("Mac Address1: %s\n", ether_ntoa((struct ether_addr*)beac->addr1));
    printf("Mac Address2: %s\n", ether_ntoa((struct ether_addr*)beac->addr2));
    printf("Mac Address3: %s\n", ether_ntoa((struct ether_addr*)beac->addr3));*/
  }

  pcap_close(pcap);
  return EXIT_SUCCESS;
}
