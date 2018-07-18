#include "service/database_holder.h"

namespace sniffer {
namespace service {

DatabaseHolder::DatabaseHolder() : nodes_() {}

common::Error DatabaseHolder::AttachNode(const std::string& table_name, const std::vector<std::string>& endpoints) {
  if (table_name.empty() || endpoints.empty()) {
    return common::make_error_inval();
  }

  const SnifferDB* node = nullptr;
  if (FindNode(table_name, &node)) {
    common::ErrnoError errn = common::make_errno_error(EEXIST);
    return common::make_error_from_errno(errn);
  }

  SnifferDB* snif = new SnifferDB(table_name);
  common::Error err = snif->Connect(endpoints);
  if (err) {
    delete snif;
    return err;
  }

  nodes_.push_back(snif);
  return common::Error();
}

bool DatabaseHolder::FindNode(const std::string& table_name, const SnifferDB** node) const {
  if (table_name.empty() || !node) {
    return false;
  }

  for (size_t i = 0; i < nodes_.size(); ++i) {
    if (nodes_[i]->GetTableName() == table_name) {
      *node = nodes_[i];
      return true;
    }
  }

  return false;
}

bool DatabaseHolder::FindNode(const std::string& table_name, SnifferDB** node) {
  if (table_name.empty() || !node) {
    return false;
  }

  for (size_t i = 0; i < nodes_.size(); ++i) {
    if (nodes_[i]->GetTableName() == table_name) {
      *node = nodes_[i];
      return true;
    }
  }

  return false;
}

void DatabaseHolder::Clean() {
  for (size_t i = 0; i < nodes_.size(); ++i) {
    nodes_[i]->Disconnect();
    delete nodes_[i];
  }
  nodes_.clear();
}
}
}
