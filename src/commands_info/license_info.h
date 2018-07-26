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

#pragma once

#include <common/serializer/json_serializer.h>

namespace sniffer {
namespace commands_info {

class LicenseInfo : public common::serializer::JsonSerializer<LicenseInfo> {
 public:
  typedef JsonSerializer<LicenseInfo> base_class;
  typedef std::string license_t;

  LicenseInfo();
  explicit LicenseInfo(const std::string& license);

  bool IsValid() const;

  std::string GetLicense() const;
  static bool GetLicense(json_object* serialized, license_t* license);

 protected:
  virtual common::Error DoDeSerialize(json_object* serialized) override;
  virtual common::Error SerializeFields(json_object* out) const override;

 private:
  std::string license_;
};

}  // namespace server
}
