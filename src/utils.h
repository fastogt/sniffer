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

#include "entry.h"

namespace sniffer {

enum PARSE_RESULT {
  PARSE_OK,
  PARSE_INVALID_INPUT,
  PARSE_INVALID_RADIOTAP_SIZE,
  PARSE_INVALID_FRAMECONTROL_SIZE,
  PARSE_CNTRL_PACKET,
  PARSE_INVALID_PACKET,
  PARSE_SKIPPED_PACKET
};

PARSE_RESULT MakeEntry(const u_char* packet, const pcap_pkthdr* header, Entry* ent);
}
