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

#include "pcaper.h"

#include <common/sprintf.h>

namespace sniffer {

Pcaper::Pcaper() : file_path_(), pcap_(NULL) {}

Pcaper::~Pcaper() {}

common::Error Pcaper::Open(const Pcaper::path_type& file_path) {
  if (!file_path.IsValid()) {
    return common::make_error_inval();
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  const char* device = pcap_lookupdev(errbuf);
  if (device == NULL) {
    return common::make_error(common::MemSPrintf("Couldn't find default device: %s", errbuf));
  }

  std::string path = file_path.GetPath();
  pcap_ = pcap_open_offline_with_tstamp_precision(path.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuf);
  if (!pcap_) {
    return common::make_error(common::MemSPrintf("error reading pcap file: %s", errbuf));
  }

  file_path_ = file_path;
  return common::Error();
}

void Pcaper::Parse(pcap_parse_function_t parse_cb) {
  if (!parse_cb) {
    return;
  }

  struct pcap_pkthdr header;
  const unsigned char* packet;
  while ((packet = pcap_next(pcap_, &header)) != NULL) {
    parse_cb(packet, header);
  }
}

common::Error Pcaper::Close() {
  if (pcap_) {
    pcap_close(pcap_);
  }
  pcap_ = NULL;

  file_path_ = path_type();
  return common::Error();
}

Pcaper::path_type Pcaper::GetPath() const {
  return file_path_;
}
}
