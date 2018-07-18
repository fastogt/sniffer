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

#include "service/archive/tar_gz.h"

#include <common/sprintf.h>

namespace sniffer {
namespace service {
namespace archive {

TarGZ::TarGZ() : file_(NULL) {}

TarGZ::~TarGZ() {}

common::Error TarGZ::Open(const path_t& path, const char* mode) {
  if (!path.IsValid()) {
    return common::make_error_inval();
  }

  std::string path_str = path.GetPath();
  gzFile file = gzopen(path_str.c_str(), mode);
  if (!file) {
    return common::make_error(common::MemSPrintf("error open file path: %s, errno: %d", path_str, errno));
  }

  file_ = file;
  return common::Error();
}

common::Error TarGZ::Write(const common::buffer_t& data) {
  if (data.empty() || !file_) {
    return common::make_error_inval();
  }

  int writed = gzwrite(file_, data.data(), data.size());
  if (writed == 0) {
    int err;
    const char* error = gzerror(file_, &err);
    return common::make_error(error);
  }
  return common::Error();
}

common::Error TarGZ::Close() {
  if (file_) {
    gzclose(file_);
    file_ = NULL;
  }
  return common::Error();
}
}
}
}
