#pragma once

#include <stdint.h>

#include "radiotap.h"

#define PACKED_ATTRIBUTE __attribute__((packed))

struct PACKED_ATTRIBUTE radiotap_header {
  struct ieee80211_radiotap_header wt_ihdr;
  uint8_t wt_rate;
  uint8_t wt_reserved_1;
  uint16_t wt_chan_freq;
  uint16_t wt_chan_flags;
  uint8_t wt_ssi_signal;
  uint8_t wt_reserved_2;
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
