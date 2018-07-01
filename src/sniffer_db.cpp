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

Entry::Entry(const std::string& mac, common::time64_t ts) : mac_address(mac), timestamp(ts) {}

SnifferDB::SnifferDB() : connection_(new database::Connection) {}

SnifferDB::~SnifferDB() {
  delete connection_;
  connection_ = nullptr;
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
  auto prep_stat_cb = [entry](CassStatement* statement) {
    CassError err = cass_statement_bind_string(statement, 0, entry.mac_address.c_str());
    DCHECK(err == CASS_OK);
    err = cass_statement_bind_int64(statement, 1, entry.timestamp);
    DCHECK(err == CASS_OK);
  };

  common::Error err = connection_->Execute(INSERT_QUERY, 2, prep_stat_cb);
  if (err) {
    return err;
  }

  return common::Error();
}
}
