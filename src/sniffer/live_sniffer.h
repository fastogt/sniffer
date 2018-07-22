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

#include "sniffer/isniffer.h"

namespace sniffer {
namespace sniffer {

class LiveSniffer : public ISniffer {
 public:
  typedef ISniffer base_class;
  LiveSniffer(const std::string& device, ISnifferObserver* observer);
  virtual ~LiveSniffer();

  virtual common::Error Open() override WARN_UNUSED_RESULT;

  virtual void Run() override;
  virtual void Stop() override;

  std::string GetDevice() const;

  int GetLinkHeaderType() const;

 private:
  static void pcap_handler(u_char* packet, const struct pcap_pkthdr* header, const u_char* user_data);

  std::string device_;
  bool stopped_;
};
}
}
