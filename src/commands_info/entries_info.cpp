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

#include "commands_info/entries_info.h"

namespace sniffer {
namespace commands_info {

EntriesInfo::EntriesInfo() : entries_() {}

void EntriesInfo::AddEntry(entry_t entry) {
  entries_.push_back(entry);
}

EntriesInfo::entries_t EntriesInfo::GetEntries() const {
  return entries_;
}

size_t EntriesInfo::GetSize() const {
  return entries_.size();
}

bool EntriesInfo::IsEmpty() const {
  return entries_.empty();
}

bool EntriesInfo::Equals(const EntriesInfo& chan) const {
  return entries_ == chan.entries_;
}

common::Error EntriesInfo::SerializeArray(json_object* deserialized_array) const {
  for (entry_t ent : entries_) {
    json_object* jurl = NULL;
    common::Error err = ent.Serialize(&jurl);
    if (err) {
      continue;
    }
    json_object_array_add(deserialized_array, jurl);
  }

  return common::Error();
}

common::Error EntriesInfo::DoDeSerialize(json_object* serialized) {
  entries_t chan;
  size_t len = json_object_array_length(serialized);
  for (size_t i = 0; i < len; ++i) {
    json_object* jurl = json_object_array_get_idx(serialized, i);
    entry_t ent;
    common::Error err = ent.DeSerialize(jurl);
    if (err) {
      continue;
    }
    chan.push_back(ent);
  }

  (*this).entries_ = chan;
  return common::Error();
}

}  // namespace server
}
