/*  Copyright (C) 2014-2018 FastoGT. All right reserved.
    This file is part of sniffer.
    sniffer is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    sniffer is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with sniffer.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdint.h>

#include <netinet/ether.h>

#include "pcap_packages/radiotap.h"

#define PACKED_ATTRIBUTE __attribute__((packed))
#define ALIGNED_ATTRIBUTE(X) __attribute__((aligned(X)))
#define PACKED_ALIGNED_ATTRIBUTE(X) PACKED_ATTRIBUTE ALIGNED_ATTRIBUTE(X)

struct PACKED_ATTRIBUTE radiotap_header {
  struct ieee80211_radiotap_header wt_ihdr;
  uint8_t wt_rate;
  uint8_t wt_reserved_1;
  uint16_t wt_chan_freq;
  uint16_t wt_chan_flags;
  uint8_t wt_ssi_signal;
  uint8_t wt_reserved_2;
};

enum TYPE { TYPE_MNGMT = 0, TYPE_CNTRL = 1, TYPE_DATA = 2 };

enum SUBTYPE_MNGMT {
  SUBTYPE_MNGMT_AssociationRequest = 0,
  SUBTYPE_MNGMT_AssociationResponse = 1,
  SUBTYPE_MNGMT_ReassociationRequest = 2,
  SUBTYPE_MNGMT_ReassociationResponse = 3,
  SUBTYPE_MNGMT_ProbeRequest = 4,
  SUBTYPE_MNGMT_ProbeResponse = 5,
  SUBTYPE_MNGMT_TimingAdvertisement = 6,
  SUBTYPE_MNGMT_Beacon = 8,
  SUBTYPE_MNGMT_ATIM = 9,
  SUBTYPE_MNGMT_Disassociation = 10,
  SUBTYPE_MNGMT_Authentication = 11,
  SUBTYPE_MNGMT_Deauthentication = 12,
  SUBTYPE_MNGMT_Action = 13,
  SUBTYPE_MNGMT_ActionNoAck = 14
};

enum SUBTYPE_CNTRL {
  SUBTYPE_CNTRL_ControlWrapper = 7,   // Addr1
  SUBTYPE_CNTRL_BlockAckRequest = 8,  // RA, TA
  SUBTYPE_CNTRL_BlockAck = 9,         // RA, TA
  SUBTYPE_CNTRL_PSPoll = 10,          // RA (BSSID), TA
  SUBTYPE_CNTRL_RTS = 11,             // RA, TA
  SUBTYPE_CNTRL_CTS = 12,             // RA
  SUBTYPE_CNTRL_ACK = 13,             // RA
  SUBTYPE_CNTRL_CFEnd = 14,           // RA, TA (BSSID)
  SUBTYPE_CNTRL_CFEndAck = 15         // RA, TA (BSSID)
};

enum SUBTYPE_DATA {
  SUBTYPE_DATA_DATA = 0,
  SUBTYPE_DATA_DATA_CFAck = 1,
  SUBTYPE_DATA_DATA_CFPoll = 2,
  SUBTYPE_DATA_DATA_CFAckPoll = 3,
  SUBTYPE_DATA_NULL = 4,
  SUBTYPE_DATA_CFAck = 5,
  SUBTYPE_DATA_CFPoll = 6,
  SUBTYPE_DATA_CFAckPoll = 7,
  SUBTYPE_DATA_QOS_DATA = 8,
  SUBTYPE_DATA_QOS_DATA_CFAck = 9,
  SUBTYPE_DATA_QOS_DATA_CFPoll = 10,
  SUBTYPE_DATA_QOS_DATA_CFAckPoll = 11,
  SUBTYPE_DATA_QOS_NULL = 12,
  SUBTYPE_DATA_QOS_CFPoll = 13,
  SUBTYPE_DATA_QOS_CFAckPoll = 14
};

struct PACKED_ATTRIBUTE frame_control {
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
};

struct PACKED_ATTRIBUTE ieee80211header {
  /** 7.1.3.1 Frame Control Field */
  struct frame_control fc;
  /** 7.1.3.2 Duration/ID field. Content varies with frame type and subtype. */
  uint16_t duration_id;
  /** 7.1.3.3 Address fields. For this program we always assume 3 addresses. */
  uint8_t addr1[ETH_ALEN];
  uint8_t addr2[ETH_ALEN];
  uint8_t addr3[ETH_ALEN];
  /** 7.1.3.4 Sequence Control Field */
  struct PACKED_ATTRIBUTE sequence {
    uint8_t fragnum : 4;
    uint16_t seqnum : 12;
  } sequence;
};

static inline bool ieee80211_dataqos(const ieee80211header* hdr) {
  return hdr->fc.type == TYPE_DATA && hdr->fc.subtype >= SUBTYPE_DATA_QOS_DATA &&
         hdr->fc.subtype <= SUBTYPE_DATA_QOS_NULL;
}

static inline bool ieee80211_broadcast_mac(uint8_t mac[ETH_ALEN]) {
  return mac[0] & 0x01;
}

/** 7.1.3.5 QoS Control field. This is not present in all frames, and exact
 * usage of the bits depends on the type/subtype. Here we assume QoS data frame. */
typedef struct PACKED_ATTRIBUTE ieee80211qosheader {
  // 7.1.3.5.1 TID subfield. Allowed values depend on Access Policy (7.3.2.30).
  uint8_t tid : 4;
  uint8_t eosp : 1;
  uint8_t ackpolicy : 2;
  uint8_t reserved : 1;
  uint8_t appsbufferstate;
} ieee80211qosheader;

static inline int ieee80211_hdrlen(const ieee80211header* hdr, int taillen = 0) {
  int pos = sizeof(ieee80211header);
  if (hdr->fc.tods && hdr->fc.fromds)
    pos += 6;
  if (ieee80211_dataqos(hdr))
    pos += sizeof(ieee80211qosheader);
  return pos + taillen;
}

// qos = ieee80211header + ieee80211qosheader
// 4addr = ieee80211header + uint8_t[ETH_ALEN]
