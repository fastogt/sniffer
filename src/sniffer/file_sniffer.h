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

#include <common/file_system/path.h>

#include "sniffer/isniffer.h"

namespace sniffer {
namespace sniffer {

class FileSniffer : public ISniffer {
 public:
  typedef ISniffer base_class;
  typedef common::file_system::ascii_file_string_path path_type;

  FileSniffer(const path_type& file_path, ISnifferObserver* observer);
  ~FileSniffer();

  virtual common::Error Open() override WARN_UNUSED_RESULT;

  path_type GetPath() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(FileSniffer);
  path_type file_path_;
};
}
}
