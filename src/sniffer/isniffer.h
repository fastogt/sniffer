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

#include <pcap.h>

#include <common/error.h>

namespace sniffer {
namespace sniffer {
class ISnifferObserver;

class ISniffer {
 public:
  ISniffer(ISnifferObserver* observer);
  virtual ~ISniffer();

  virtual common::Error Open() WARN_UNUSED_RESULT = 0;
  virtual common::Error Close() WARN_UNUSED_RESULT;

  virtual void Run() = 0;
  virtual void Stop() = 0;

  size_t GetCurrentPos() const;

  bool IsValid() const;
  bool IsOpen() const;

 protected:
  pcap_t* pcap_;
  void HandlePacket(const u_char* packet, const struct pcap_pkthdr* header);

 private:
  DISALLOW_COPY_AND_ASSIGN(ISniffer);

  size_t pos_;
  ISnifferObserver* observer_;
};
}
}
