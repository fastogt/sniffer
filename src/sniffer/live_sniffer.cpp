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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>

#include <common/sprintf.h>

namespace sniffer {
namespace sniffer {

LiveSniffer::LiveSniffer(const std::string& device, ISnifferObserver* observer, int read_timeout)
    : base_class(observer), device_(device), mac_{0}, read_timeout_(read_timeout), stopped_(false) {}

LiveSniffer::~LiveSniffer() {}

common::Error LiveSniffer::Open() {
  DCHECK(!IsValid());
  if (device_.empty()) {
    return common::make_error_inval();
  }

  const char* device_str = device_.c_str();
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pcap = pcap_open_live(device_str, BUFSIZ, PCAP_TSTAMP_PRECISION_MICRO, read_timeout_, errbuf);
  if (!pcap) {
    return common::make_error(common::MemSPrintf("error reading pcap file: %s", errbuf));
  }

  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  strcpy(s.ifr_name, device_str);
  if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) {
    memcpy(mac_, s.ifr_addr.sa_data, sizeof(mac_));
  }
  pcap_ = pcap;
  return common::Error();
}

void LiveSniffer::Run() {
  DCHECK(IsValid());

  struct pcap_pkthdr* header = NULL;
  const u_char* packet = NULL;
  int res;
  while ((res = pcap_next_ex(pcap_, &header, &packet)) >= 0) {
    if (res == 0) {
    } else if (res == 1) {
      HandlePacket(packet, header);
    }

    if (stopped_) {
      break;
    }
  }

  if (res == -1) {
    ERROR_LOG() << "Reading the packets error: " << pcap_geterr(pcap_);
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

const unsigned char* LiveSniffer::GetRawMacAddress() const {
  DCHECK(IsValid());
  return mac_;
}

std::string LiveSniffer::GetMacAddress() const {
  DCHECK(IsValid());
  return mac2string(mac_);
}

}
}
