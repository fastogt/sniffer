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

#include "commands_info/license_info.h"

#define LICENSE_INFO_KEY_FIELD "license_key"

namespace sniffer {
namespace commands_info {

LicenseInfo::LicenseInfo() : base_class(), license_() {}

LicenseInfo::LicenseInfo(const std::string& license) : base_class(), license_(license) {}

common::Error LicenseInfo::SerializeFields(json_object* out) const {
  DCHECK(IsValid());

  json_object_object_add(out, LICENSE_INFO_KEY_FIELD, json_object_new_string(license_.c_str()));
  return common::Error();
}

common::Error LicenseInfo::DoDeSerialize(json_object* serialized) {
  LicenseInfo inf;
  if (!GetLicense(serialized, &inf.license_)) {
    DNOTREACHED();
    return common::make_error_inval();
  }

  *this = inf;
  return common::Error();
}

bool LicenseInfo::IsValid() const {
  return !license_.empty();
}

std::string LicenseInfo::GetLicense() const {
  return license_;
}

bool LicenseInfo::GetLicense(json_object* serialized, license_t* license) {
  if (!serialized || !license) {
    return false;
  }

  json_object* jlicense = NULL;
  json_bool jlicense_exists = json_object_object_get_ex(serialized, LICENSE_INFO_KEY_FIELD, &jlicense);
  if (!jlicense_exists) {
    return false;
  }

  *license = json_object_get_string(jlicense);
  return true;
}

}  // namespace server
}
