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

#define TEST_PCAP_FILE_NAME "test.sniff"
#define TEST_PCAP_FILE_PATH TEST_FOLDER_PATH TEST_PCAP_FILE_NAME

#define PACKED_ATTRIBUTE __attribute__((packed))

#include "radiotap.h"

struct PACKED_ATTRIBUTE radiotap_header {
  struct ieee80211_radiotap_header wt_ihdr;
  u_int8_t wt_rate;
  u_int8_t wt_reserved_1;
  u_int16_t wt_chan_freq;
  u_int16_t wt_chan_flags;
  u_int8_t wt_ssi_signal;
  u_int8_t wt_reserved_2;
};

struct PACKED_ATTRIBUTE ieee80211header {
  /** 7.1.3.1 Frame Control Field */
  struct PACKED_ATTRIBUTE fc {
    uint8_t version : 2;
    /** see IEEE802.11-2012 8.2.4.1.3 Type and Subtype fields */
    uint8_t type : 2;
    uint8_t subtype : 4;
    uint8_t tods : 1;
    uint8_t fromds : 1;
    uint8_t morefrag : 1;
    uint8_t retry : 1;
    uint8_t pwrmgt : 1;
    uint8_t moredata : 1;
    uint8_t protectedframe : 1;
    uint8_t order : 1;
  } fc;
  /** 7.1.3.2 Duration/ID field. Content varies with frame type and subtype. */
  uint16_t duration_id;
  /** 7.1.3.3 Address fields. For this program we always assume 3 addresses. */
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  /** 7.1.3.4 Sequence Control Field */
  struct PACKED_ATTRIBUTE sequence {
    uint8_t fragnum : 4;
    uint16_t seqnum : 12;
  } sequence;
};

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
