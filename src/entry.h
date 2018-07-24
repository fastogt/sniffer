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

#include <string>

#include <common/types.h>

#define UNKNOWN_SSI 0

namespace sniffer {

struct Entry {
  Entry();
  explicit Entry(const std::string& mac_address, common::time64_t ts, int8_t ssi = UNKNOWN_SSI);

  std::string mac_address;
  common::time64_t timestamp;
  int8_t ssi;
};
}
