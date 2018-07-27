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

#include <common/error.h>
#include <common/types.h>

#include "entry_info.h"

namespace sniffer {
namespace service {
namespace database {
class Connection;
}

class SnifferDB {
 public:
  explicit SnifferDB(const std::string& table_name);
  ~SnifferDB();

  common::Error Connect(const std::string& hosts) WARN_UNUSED_RESULT;               // 127.0.0.1,127.0.0.1
  common::Error Connect(const std::vector<std::string>& hosts) WARN_UNUSED_RESULT;  // 127.0.0.1,127.0.0.1
  common::Error Disconnect() WARN_UNUSED_RESULT;

  common::Error Insert(const EntryInfo& entry) WARN_UNUSED_RESULT;
  common::Error Insert(const std::vector<EntryInfo>& entries) WARN_UNUSED_RESULT;

  std::string GetTableName() const;

 private:
  database::Connection* connection_;
  const std::string table_name_;

  const std::string create_table_query_;
  const std::string insert_query_;
};
}
}
