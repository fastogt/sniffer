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

#include "commands_info/license_info.h"

namespace sniffer {
namespace commands_info {

class ActivateInfo : public LicenseInfo {
 public:
  typedef LicenseInfo base_class;
  ActivateInfo();
  explicit ActivateInfo(const std::string& license);
};

class ActivateSlaveInfo : public ActivateInfo {
 public:
  typedef ActivateInfo base_class;
  typedef std::string id_t;

  ActivateSlaveInfo();

  bool IsValid() const;

  id_t GetID() const;
  static bool GetID(json_object* serialized, id_t* id);

 protected:
  virtual common::Error DoDeSerialize(json_object* serialized) override;
  virtual common::Error SerializeFields(json_object* obj) const override;

 private:
  id_t id_;
};
}
}
