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

#include <cassandra.h>

#include <string>
#include <vector>

namespace database {

class Connection {
 public:
  Connection();
  ~Connection();

  void Connect(const std::vector<std::string>& hosts);
  void Disconnect();

  bool IsConnected() const;

 private:
  CassCluster* cluster_;
  CassFuture* connect_future_;
  CassSession* session_;
};
}
