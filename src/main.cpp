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

// https://stackoverflow.com/questions/39456131/improve-insertion-time-in-cassandra-database-with-datastax-cpp-driver

#include <stdlib.h>

#include "database/connection.h"

#define CREATE_KEYSPACE_QUERY                                                                                         \
  "CREATE KEYSPACE IF NOT EXISTS examples WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '3' " \
  "};"

#define USE_KEYSPACE_QUERY "USE examples;"

#define CREATE_TABLE_QUERY                                                                                    \
  "CREATE TABLE IF NOT EXISTS test (mac_address text, date timestamp, primary key (mac_address, date)) with " \
  "compaction = {'class' : 'DateTieredCompactionStrategy'};"

#define SELECT_ALL_QUERY "SELECT mac_address, date FROM test"

#define INSERT_QUERY "INSERT INTO test (mac_address, date) VALUES (?, ?)"

int main(int argc, char* argv[]) {
  const char* hosts = "127.0.0.1";
  if (argc > 1) {
    hosts = argv[1];
  }

  database::Connection con;
  common::Error err = con.Connect({hosts});
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    return EXIT_FAILURE;
  }

  err = con.Execute(CREATE_KEYSPACE_QUERY, 0);
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    con.Disconnect();
    return EXIT_FAILURE;
  }

  err = con.Execute(USE_KEYSPACE_QUERY, 0);
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    con.Disconnect();
    return EXIT_FAILURE;
  }

  err = con.Execute(CREATE_TABLE_QUERY, 0);
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    con.Disconnect();
    return EXIT_FAILURE;
  }

  auto prep_stat_cb = [](CassStatement* statement) {
    time_t now = time(NULL);
    cass_statement_bind_string(statement, 0, "test");
    cass_statement_bind_int64(statement, 1, now * 1000);
  };
  err = con.Execute(INSERT_QUERY, 2, prep_stat_cb);
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    con.Disconnect();
    return EXIT_FAILURE;
  }

  auto select_cb = [](CassFuture* result_future) { /* Retrieve result set and get the first row */
                                                   const CassResult* result = cass_future_get_result(result_future);
                                                   CassIterator* iterator = cass_iterator_from_result(result);
                                                   while (cass_iterator_next(iterator)) {
                                                     const CassRow* row = cass_iterator_get_row(iterator);
                                                     const char* mac_address;
                                                     size_t mac_address_size;
                                                     cass_value_get_string(cass_row_get_column(row, 0), &mac_address,
                                                                           &mac_address_size);

                                                     time_t ts;
                                                     cass_value_get_int64(cass_row_get_column(row, 1), &ts);

                                                     printf("%s, %llu\n", mac_address, ts);
                                                   }
                                                   cass_iterator_free(iterator);
                                                   cass_result_free(result);
  };

  database::ExecuteInfo select_data_query;
  select_data_query.query = SELECT_ALL_QUERY;
  select_data_query.parameter_count = 0;
  select_data_query.succsess_cb = select_cb;
  err = con.Execute(select_data_query);
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    con.Disconnect();
    return EXIT_FAILURE;
  }

  con.Disconnect();
  return EXIT_SUCCESS;
}
