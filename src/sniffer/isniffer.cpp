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

ISniffer::ISniffer(ISnifferObserver* observer) : pcap_(NULL), pos_(0), observer_(observer), stopped_(false) {}

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

void ISniffer::Run() {
  DCHECK(IsValid());

  struct pcap_pkthdr header;
  const unsigned char* packet;
  while ((packet = pcap_next(pcap_, &header)) != NULL) {
    if (observer_) {
      observer_->HandlePacket(this, packet, header);
    }
    pos_++;

    if (stopped_) {
      break;
    }
  }
}

void ISniffer::Stop() {
  stopped_ = true;
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
}
}
