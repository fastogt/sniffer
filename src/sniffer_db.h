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

#include <vector>

#include <common/error.h>
#include <common/types.h>

namespace sniffer {
namespace database {
class Connection;
}

struct Entry {
  explicit Entry(const std::string& mac_address, common::time64_t ts);

  std::string mac_address;
  common::time64_t timestamp;
};

class SnifferDB {
 public:
  SnifferDB();
  ~SnifferDB();

  common::Error Connect(const std::vector<std::string>& hosts) WARN_UNUSED_RESULT;
  common::Error Disconnect() WARN_UNUSED_RESULT;

  common::Error Insert(const Entry& entry) WARN_UNUSED_RESULT;

 private:
  database::Connection* connection_;
};
}
