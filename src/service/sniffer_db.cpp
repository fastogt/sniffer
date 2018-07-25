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

#include "service/sniffer_db.h"

#include <common/sprintf.h>

#include "database/connection.h"

#define CREATE_KEYSPACE_QUERY                                                                                         \
  "CREATE KEYSPACE IF NOT EXISTS examples WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '3' " \
  "};"

#define USE_KEYSPACE_QUERY "USE examples;"

#define CREATE_TABLE_QUERY_1S                                                                                      \
  "CREATE TABLE IF NOT EXISTS %s (mac_address text, date timestamp, ssi tinyint, primary key (mac_address, date, " \
  "ssi));"

#define SELECT_ALL_QUERY_1S "SELECT mac_address, date, ssi FROM %s"

#define INSERT_QUERY_1S "INSERT INTO %s (mac_address, date, ssi) VALUES (?, ?, ?)"

namespace sniffer {
namespace service {
namespace {
void init_insert(const Entry& entry, CassStatement* statement) {
  std::string mac_str = entry.GetMacAddress();
  CassError err = cass_statement_bind_string(statement, 0, mac_str.c_str());
  DCHECK(err == CASS_OK) << "error: " << err;
  err = cass_statement_bind_int64(statement, 1, entry.GetTimestamp());
  DCHECK(err == CASS_OK) << "error: " << err;
  err = cass_statement_bind_int8(statement, 2, entry.GetSSI());
  DCHECK(err == CASS_OK) << "error: " << err;
}
}

SnifferDB::SnifferDB(const std::string& table_name)
    : connection_(new database::Connection),
      table_name_(table_name),
      create_table_query_(common::MemSPrintf(CREATE_TABLE_QUERY_1S, table_name)),
      insert_query_(common::MemSPrintf(INSERT_QUERY_1S, table_name)) {}

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

  err = connection_->Execute(create_table_query_, 0);
  if (err) {
    connection_->Disconnect();
    return err;
  }

  return common::Error();
}

common::Error SnifferDB::Connect(const std::vector<std::string>& hosts) {
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

  err = connection_->Execute(create_table_query_, 0);
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
  common::Error err = connection_->Execute(insert_query_, 3, prep_stat_cb);
  if (err) {
    return err;
  }

  return common::Error();
}

common::Error SnifferDB::Insert(const std::vector<Entry>& entries) {
#if 1
  auto prep_batch_cb = [this, entries](CassBatch* batch) {
    for (size_t i = 0; i < entries.size(); ++i) {
      CassStatement* statement = cass_statement_new(insert_query_.c_str(), 3);
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
#else
  for (size_t i = 0; i < entries.size(); ++i) {
    Insert(entries[i]);
  }
  return common::Error();
#endif
}

std::string SnifferDB::GetTableName() const {
  return table_name_;
}
}
}
