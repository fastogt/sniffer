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

#include "entry_info.h"

namespace sniffer {
namespace commands_info {

class EntriesInfo : public common::serializer::JsonSerializerArray<EntriesInfo> {
 public:
  typedef EntryInfo entry_t;
  typedef std::vector<entry_t> entries_t;
  EntriesInfo();

  void AddEntry(entry_t entry);
  entries_t GetEntries() const;

  size_t GetSize() const;
  bool IsEmpty() const;

  bool Equals(const EntriesInfo& chan) const;

 protected:
  virtual common::Error DoDeSerialize(json_object* serialized) override;
  virtual common::Error SerializeArray(json_object* deserialized_array) const override;

 private:
  entries_t entries_;
};

inline bool operator==(const EntriesInfo& lhs, const EntriesInfo& rhs) {
  return lhs.Equals(rhs);
}

inline bool operator!=(const EntriesInfo& x, const EntriesInfo& y) {
  return !(x == y);
}

}  // namespace server
}
