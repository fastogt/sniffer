#pragma once

#include <vector>

#include <common/error.h>
#include <common/types.h>

namespace sniffer {
namespace database {
class Connection;
}

struct Entry {
  explicit Entry(const std::string& mac_address, common::time64_t ts);

  std::string mac_address;
  common::time64_t timestamp;
};

class SnifferDB {
 public:
  SnifferDB();
  ~SnifferDB();

  common::Error Connect(const std::vector<std::string>& hosts) WARN_UNUSED_RESULT;
  common::Error Disconnect() WARN_UNUSED_RESULT;

  common::Error Insert(const Entry& entry) WARN_UNUSED_RESULT;

 private:
  database::Connection* connection_;
};
}
