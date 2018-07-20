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

#include "sniffer/live_sniffer.h"

#include <common/sprintf.h>

namespace sniffer {
namespace sniffer {

LiveSniffer::LiveSniffer(ISnifferObserver* observer) : base_class(observer), device_(), stopped_(false) {}

LiveSniffer::~LiveSniffer() {}

common::Error LiveSniffer::Open() {
  DCHECK(!IsValid());

  char errbuf[PCAP_ERRBUF_SIZE];
  const char* device = pcap_lookupdev(errbuf);
  if (device == NULL) {
    return common::make_error(common::MemSPrintf("Couldn't find default device: %s", errbuf));
  }

  pcap_t* pcap = pcap_open_live(device, BUFSIZ, PCAP_TSTAMP_PRECISION_MICRO, -1, errbuf);
  if (!pcap) {
    return common::make_error(common::MemSPrintf("error reading pcap file: %s", errbuf));
  }

  pcap_ = pcap;
  device_ = device;
  return common::Error();
}

void LiveSniffer::Run() {
  DCHECK(IsValid());

  struct pcap_pkthdr* header = NULL;
  const u_char* packet = NULL;
  int res;
  while ((res = pcap_next_ex(pcap_, &header, &packet)) >= 0) {
    HandlePacket(packet, header);

    if (stopped_) {
      break;
    }
  }
}

void LiveSniffer::Stop() {
  stopped_ = true;
}

void LiveSniffer::pcap_handler(u_char* packet, const struct pcap_pkthdr* header, const u_char* user_data) {
  LiveSniffer* sniffer = (LiveSniffer*)(user_data);
  sniffer->HandlePacket(packet, header);
}

std::string LiveSniffer::GetDevice() const {
  return device_;
}
}
}
