/*  Copyright (C) 2015-2017 Setplex. All right reserved.
    This file is part of Rixjob.
    Rixjob is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    Rixjob is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Rixjob.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "sniffer_db.h"

namespace sniffer {
namespace service {

class DatabaseHolder {
 public:
  DatabaseHolder();
  common::Error AttachNode(const std::string& table_name, const std::vector<std::string>& endpoints) WARN_UNUSED_RESULT;
  bool FindNode(const std::string& table_name, const SnifferDB** node) const;
  bool FindNode(const std::string& table_name, SnifferDB** node);

  void Clean();

 private:
  std::vector<SnifferDB*> nodes_;
};
}
}
