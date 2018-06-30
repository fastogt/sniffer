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

#include <stdio.h>
#include <cassandra.h>

class Connection {
 public:
  Connection() : cluster_(NULL), connect_future_(NULL), session_(NULL) {}
  ~Connection() { cleanup(); }

  void setup(const char* hosts) {
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

  /**
   * Cleanup the driver connection
   */
  void cleanup() {
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

 private:
  CassCluster* cluster_;
  CassFuture* connect_future_;
  CassSession* session_;
};

int main(int argc, char* argv[]) {
  /* Setup and connect to cluster */
  CassCluster* cluster = cass_cluster_new();
  CassSession* session = cass_session_new();
  const char* hosts = "127.0.0.1";
  if (argc > 1) {
    hosts = argv[1];
  }

  /* Add contact points */
  cass_cluster_set_contact_points(cluster, hosts);

  /* Provide the cluster object as configuration to connect the session */
  CassFuture* connect_future = cass_session_connect(session, cluster);

  if (cass_future_error_code(connect_future) == CASS_OK) {
    CassFuture* close_future = NULL;

    /* Build statement and execute query */
    const char* query = "SELECT release_version FROM system.local";
    CassStatement* statement = cass_statement_new(query, 0);

    CassFuture* result_future = cass_session_execute(session, statement);

    if (cass_future_error_code(result_future) == CASS_OK) {
      /* Retrieve result set and get the first row */
      const CassResult* result = cass_future_get_result(result_future);
      const CassRow* row = cass_result_first_row(result);

      if (row) {
        const CassValue* value = cass_row_get_column_by_name(row, "release_version");

        const char* release_version;
        size_t release_version_length;
        cass_value_get_string(value, &release_version, &release_version_length);
        printf("release_version: '%.*s'\n", (int)release_version_length, release_version);
      }

      cass_result_free(result);
    } else {
      /* Handle error */
      const char* message;
      size_t message_length;
      cass_future_error_message(result_future, &message, &message_length);
      fprintf(stderr, "Unable to run query: '%.*s'\n", (int)message_length, message);
    }

    cass_statement_free(statement);
    cass_future_free(result_future);

    /* Close the session */
    close_future = cass_session_close(session);
    cass_future_wait(close_future);
    cass_future_free(close_future);
  } else {
    /* Handle error */
    const char* message;
    size_t message_length;
    cass_future_error_message(connect_future, &message, &message_length);
    fprintf(stderr, "Unable to connect: '%.*s'\n", (int)message_length, message);
  }

  cass_future_free(connect_future);
  cass_cluster_free(cluster);
  cass_session_free(session);

  return 0;
}
