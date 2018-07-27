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

#include "entry_info.h"

#define ENTRY_MAC_ADDRESS_FIELD "mac_address"
#define ENTRY_TIMESTAMP_FIELD "timestamp"
#define ENTRY_SSI_FIELD "ssi"

namespace sniffer {

EntryInfo::EntryInfo() : mac_address_(), timestamp_(0), ssi_(0) {}

EntryInfo::EntryInfo(const std::string& mac, common::time64_t ts, int8_t ssi) : mac_address_(mac), timestamp_(ts), ssi_(ssi) {}

bool EntryInfo::Equals(const EntryInfo& ent) const {
  return mac_address_ == ent.mac_address_ && timestamp_ == ent.timestamp_ && ssi_ == ent.ssi_;
}

bool EntryInfo::IsValid() const {
  return !mac_address_.empty();
}

std::string EntryInfo::GetMacAddress() const {
  return mac_address_;
}

common::time64_t EntryInfo::GetTimestamp() const {
  return timestamp_;
}

void EntryInfo::SetTimestamp(common::time64_t ts) {
  timestamp_ = ts;
}

int8_t EntryInfo::GetSSI() const {
  return ssi_;
}

common::Error EntryInfo::DoDeSerialize(json_object* serialized) {
  std::string mac_address;
  json_object* jmac_address = NULL;
  json_bool jmac_address_exists = json_object_object_get_ex(serialized, ENTRY_MAC_ADDRESS_FIELD, &jmac_address);
  if (jmac_address_exists) {
    mac_address = json_object_get_string(jmac_address);
  }

  common::time64_t timestamp;
  json_object* jtimestamp = NULL;
  json_bool jtimestamp_exists = json_object_object_get_ex(serialized, ENTRY_TIMESTAMP_FIELD, &jtimestamp);
  if (jtimestamp_exists) {
    timestamp = json_object_get_int64(jtimestamp);
  }

  int8_t ssi;
  json_object* jssi = NULL;
  json_bool jssi_exists = json_object_object_get_ex(serialized, ENTRY_SSI_FIELD, &jssi);
  if (jssi_exists) {
    ssi = json_object_get_int(jssi);
  }

  *this = EntryInfo(mac_address, timestamp, ssi);
  return common::Error();
}

common::Error EntryInfo::SerializeFields(json_object* deserialized) const {
  if (!IsValid()) {
    return common::make_error_inval();
  }

  const char* mac_str = mac_address_.c_str();
  json_object_object_add(deserialized, ENTRY_MAC_ADDRESS_FIELD, json_object_new_string(mac_str));
  json_object_object_add(deserialized, ENTRY_TIMESTAMP_FIELD, json_object_new_int64(timestamp_));
  json_object_object_add(deserialized, ENTRY_SSI_FIELD, json_object_new_int(ssi_));
  return common::Error();
}
}
