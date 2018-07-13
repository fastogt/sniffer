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

#include "sniffer_db.h"

#include "database/connection.h"

#define CREATE_KEYSPACE_QUERY                                                                                         \
  "CREATE KEYSPACE IF NOT EXISTS examples WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '3' " \
  "};"

#define USE_KEYSPACE_QUERY "USE examples;"

#define CREATE_TABLE_QUERY \
  "CREATE TABLE IF NOT EXISTS test (mac_address text, date timestamp, primary key (mac_address, date));"

#define SELECT_ALL_QUERY "SELECT mac_address, date FROM test"

#define INSERT_QUERY "INSERT INTO test (mac_address, date) VALUES (?, ?)"

namespace sniffer {

namespace {
void init_insert(const Entry& entry, CassStatement* statement) {
  CassError err = cass_statement_bind_string(statement, 0, entry.mac_address.c_str());
  DCHECK(err == CASS_OK);
  err = cass_statement_bind_int64(statement, 1, entry.timestamp);
  DCHECK(err == CASS_OK);
}
}

Entry::Entry(const std::string& mac, common::time64_t ts) : mac_address(mac), timestamp(ts) {}

SnifferDB::SnifferDB() : connection_(new database::Connection) {}

SnifferDB::~SnifferDB() {
  delete connection_;
  connection_ = nullptr;
}

common::Error SnifferDB::Connect(const std::string& hosts) {
  common::Error err = connection_->Connect(hosts);
  if (err) {
    return err;
  }

  err = connection_->Execute(CREATE_KEYSPACE_QUERY, 0);
  if (err) {
    connection_->Disconnect();
    return err;
  }

  err = connection_->Execute(USE_KEYSPACE_QUERY, 0);
  if (err) {
    connection_->Disconnect();
    return err;
  }

  err = connection_->Execute(CREATE_TABLE_QUERY, 0);
  if (err) {
    connection_->Disconnect();
    return err;
  }

  return common::Error();
}

common::Error SnifferDB::Disconnect() {
  return connection_->Disconnect();
}

common::Error SnifferDB::Insert(const Entry& entry) {
  auto prep_stat_cb = [entry](CassStatement* statement) { init_insert(entry, statement); };
  common::Error err = connection_->Execute(INSERT_QUERY, 2, prep_stat_cb);
  if (err) {
    return err;
  }

  return common::Error();
}

common::Error SnifferDB::Insert(const std::vector<Entry>& entries) {
  auto prep_batch_cb = [entries](CassBatch* batch) {
    for (size_t i = 0; i < entries.size(); ++i) {
      CassStatement* statement = cass_statement_new(INSERT_QUERY, 2);
      init_insert(entries[i], statement);
      cass_batch_add_statement(batch, statement);
      cass_statement_free(statement);
    }
  };
  common::Error err = connection_->ExecuteBatch(prep_batch_cb);
  if (err) {
    return err;
  }

  return common::Error();
}
}
