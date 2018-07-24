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

#include "isniffer.h"

#include "isniffer_observer.h"

namespace sniffer {
namespace sniffer {

ISniffer::ISniffer(ISnifferObserver* observer) : pcap_(NULL), pos_(0), observer_(observer) {}

ISniffer::~ISniffer() {}

common::Error ISniffer::Close() {
  DCHECK(IsValid());
  if (pcap_) {
    pcap_close(pcap_);
  }
  pcap_ = NULL;
  pos_ = 0;
  return common::Error();
}

bool ISniffer::IsValid() const {
  return pcap_ != NULL;
}

bool ISniffer::IsOpen() const {
  return IsValid();
}

size_t ISniffer::GetCurrentPos() const {
  return pos_;
}

void ISniffer::HandlePacket(const u_char* packet, const struct pcap_pkthdr* header) {
  if (observer_) {
    observer_->HandlePacket(this, packet, header);
  }
  pos_++;
}

int ISniffer::GetLinkHeaderType() const {
  // DLT_PRISM_HEADER
  // DLT_IEEE802_11_RADIO
  // https://github.com/sidak/WiFi-Sniffing-and-Distributed-Computing/blob/master/Wifi%20Computing/packetspammer.c
  return pcap_datalink(pcap_);
}
}
}
