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

#include <common/string_util.h>

namespace sniffer {
namespace database {

namespace {
common::Error make_cassandra_error(CassFuture* future) {
  const char* message;
  size_t message_length;
  cass_future_error_message(future, &message, &message_length);
  return common::make_error(std::string(message, message_length));
}
}

bool ExecuteInfo::IsValid() const {
  return !query.empty();
}

Connection::Connection() : cluster_(NULL), connect_future_(NULL), session_(NULL) {}

Connection::~Connection() {}

common::Error Connection::Connect(const std::string& hosts) {
  if (hosts.empty()) {
    return common::make_error_inval();
  }

  if (IsConnected()) {
    return common::Error();
  }

  CassCluster* cluster = cass_cluster_new();
  cass_cluster_set_contact_points(cluster, hosts.c_str());
  cass_cluster_set_connect_timeout(cluster, 10000);
  cass_cluster_set_request_timeout(cluster, 10000);
  cass_cluster_set_num_threads_io(cluster, 1);
  cass_cluster_set_core_connections_per_host(cluster, 2);
  cass_cluster_set_max_connections_per_host(cluster, 4);

  // Establish the connection (if ssl)
  CassSession* session = cass_session_new();
  CassFuture* connect_future = cass_session_connect(session, cluster);

  if (cass_future_error_code(connect_future) != CASS_OK) {
    common::Error ferr = make_cassandra_error(connect_future);
    cass_session_free(session);
    cass_cluster_free(cluster);
    cass_future_free(connect_future);
    return ferr;
  }

  cluster_ = cluster;
  session_ = session;
  connect_future_ = connect_future;
  return common::Error();
}

common::Error Connection::Connect(const std::vector<std::string>& hosts) {
  if (hosts.empty()) {
    return common::make_error_inval();
  }

  return Connect(common::JoinString(hosts, ","));
}

common::Error Connection::Disconnect() {
  if (session_) {
    CassFuture* close_future = cass_session_close(session_);
    cass_future_wait(close_future);
    cass_future_free(close_future);

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
  return common::Error();
}

bool Connection::IsConnected() const {
  if (!connect_future_) {
    return false;
  }

  return cass_future_error_code(connect_future_) == CASS_OK;
}

common::Error Connection::Execute(const ExecuteInfo& query) {
  return Execute(query.query, query.parameter_count, query.prep_stat, query.succsess_cb);
}

common::Error Connection::Execute(const std::string& query,
                                  size_t parameter_count,
                                  statemet_prepare_func_t prep_stat,
                                  exec_func_t succsess_cb) {
  if (query.empty()) {
    return common::make_error_inval();
  }

  if (!IsConnected()) {
    return common::make_error_inval();
  }

  CassStatement* statement = cass_statement_new(query.c_str(), parameter_count);
  if (prep_stat) {
    prep_stat(statement);
  }

  CassFuture* result_future = cass_session_execute(session_, statement);
  // cass_future_wait(result_future);
  cass_statement_free(statement);
  if (cass_future_error_code(result_future) != CASS_OK) {
    common::Error ferr = make_cassandra_error(result_future);
    cass_future_free(result_future);
    return ferr;
  }

  if (succsess_cb) {
    succsess_cb(result_future);
  }

  cass_future_free(result_future);
  return common::Error();
}

common::Error Connection::ExecuteBatch(batch_prepare_func_t prep_stat, exec_func_t succsess_cb) {
  if (!prep_stat) {
    return common::make_error_inval();
  }

  if (!IsConnected()) {
    return common::make_error_inval();
  }

  CassBatch* batch = cass_batch_new(CASS_BATCH_TYPE_LOGGED);
  if (prep_stat) {
    prep_stat(batch);
  }

  CassFuture* result_future = cass_session_execute_batch(session_, batch);
  cass_batch_free(batch);
  if (cass_future_error_code(result_future) != CASS_OK) {
    common::Error ferr = make_cassandra_error(result_future);
    cass_future_free(result_future);
    return ferr;
  }

  if (succsess_cb) {
    succsess_cb(result_future);
  }

  cass_future_free(result_future);
  return common::Error();
}
}
}
