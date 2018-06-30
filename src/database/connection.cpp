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

#include "database/connection.h"

namespace database {

Connection::Connection() : cluster_(NULL), connect_future_(NULL), session_(NULL) {}

Connection::~Connection() {}

void Connection::Connect(const std::vector<std::string>& hosts) {
  // Initialize the cpp-driver
  cluster_ = cass_cluster_new();
  cass_cluster_set_contact_points(cluster_, hosts);
  cass_cluster_set_connect_timeout(cluster_, 10000);
  cass_cluster_set_request_timeout(cluster_, 10000);
  cass_cluster_set_num_threads_io(cluster_, 1);
  cass_cluster_set_core_connections_per_host(cluster_, 2);
  cass_cluster_set_max_connections_per_host(cluster_, 4);

  // Establish the connection (if ssl)
  session_ = cass_session_new();
  connect_future_ = cass_session_connect(session_, cluster_);
}

void Connection::Disconnect() {
  if (session_) {
    cass_session_free(session_);
    session_ = NULL;
  }

  if (cluster_) {
    cass_cluster_free(cluster_);
    cluster_ = NULL;
  }

  if (connect_future_) {
    cass_future_free(connect_future_);
    connect_future_ = NULL;
  }
}

bool Connection::IsConnected() const {
  if (!connect_future_) {
    return false;
  }

  return cass_future_error_code(connect_future_) == CASS_OK;
}
}
