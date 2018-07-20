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

#include "sniffer/file_sniffer.h"

#include <common/sprintf.h>

namespace sniffer {
namespace sniffer {

FileSniffer::FileSniffer(const path_type& file_path, ISnifferObserver* observer)
    : base_class(observer), file_path_(file_path) {}

FileSniffer::~FileSniffer() {}

common::Error FileSniffer::Open() {
  DCHECK(!IsValid());
  if (!file_path_.IsValid()) {
    return common::make_error_inval();
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  /*const char* device = pcap_lookupdev(errbuf);
  if (device == NULL) {
    return common::make_error(common::MemSPrintf("Couldn't find default device: %s", errbuf));
  }*/

  std::string path = file_path_.GetPath();
  pcap_t* pcap = pcap_open_offline_with_tstamp_precision(path.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuf);
  if (!pcap) {
    return common::make_error(common::MemSPrintf("error reading pcap file: %s", errbuf));
  }

  pcap_ = pcap;
  return common::Error();
}

void FileSniffer::Run() {
  DCHECK(IsValid());

  struct pcap_pkthdr header;
  const u_char* packet;
  while ((packet = pcap_next(pcap_, &header)) != NULL) {
    HandlePacket(packet, &header);

    if (stopped_) {
      break;
    }
  }
}

void FileSniffer::Stop() {
  stopped_ = true;
}

FileSniffer::path_type FileSniffer::GetPath() const {
  return file_path_;
}
}
}
