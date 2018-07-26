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

#include "commands_info/activate_info.h"

#define ACTIVATE_INFO_TYPE_FIELD "type"

#define ACTIVATE_SLAVE_INFO_ID_FIELD "id"

namespace sniffer {
namespace commands_info {

ActivateInfo::ActivateInfo() : LicenseInfo() {}

ActivateInfo::ActivateInfo(const std::string& license) : base_class(license) {}

// ActivateSlaveInfo

ActivateSlaveInfo::ActivateSlaveInfo() : base_class(), id_() {}

bool ActivateSlaveInfo::IsValid() const {
  return base_class::IsValid() && !id_.empty();
}

ActivateSlaveInfo::id_t ActivateSlaveInfo::GetID() const {
  return id_;
}

bool ActivateSlaveInfo::GetID(json_object* serialized, id_t* id) {
  if (!serialized || !id) {
    return false;
  }

  json_object* jid = NULL;
  json_bool jid_exists = json_object_object_get_ex(serialized, ACTIVATE_SLAVE_INFO_ID_FIELD, &jid);
  if (!jid_exists) {
    return false;
  }

  *id = json_object_get_string(jid);
  return true;
}

common::Error ActivateSlaveInfo::DoDeSerialize(json_object* serialized) {
  ActivateSlaveInfo inf;
  common::Error err = inf.base_class::DoDeSerialize(serialized);
  if (err) {
    return err;
  }

  if (!GetID(serialized, &inf.id_)) {
    DNOTREACHED();
    return common::make_error_inval();
  }

  *this = inf;
  return common::Error();
}

common::Error ActivateSlaveInfo::SerializeFields(json_object* obj) const {
  DCHECK(IsValid());
  json_object_object_add(obj, ACTIVATE_SLAVE_INFO_ID_FIELD, json_object_new_string(id_.c_str()));
  return base_class::SerializeFields(obj);
}

}  // namespace server
}  // namespace iptv_cloud
