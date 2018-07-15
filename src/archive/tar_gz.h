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

#include <common/error.h>
#include <common/file_system/path.h>

#include <zlib.h>

namespace sniffer {
namespace archive {

class TarGZ {
 public:
  typedef common::file_system::ascii_string_path path_t;

  TarGZ();
  ~TarGZ();

  common::Error Open(const path_t& path, const char* mode) WARN_UNUSED_RESULT;
  common::Error Write(const common::buffer_t& data) WARN_UNUSED_RESULT;
  common::Error Close() WARN_UNUSED_RESULT;

 private:
  gzFile file_;
};
}
}
