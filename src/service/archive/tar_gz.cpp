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
#include <common/file_system/file.h>

namespace sniffer {
namespace service {
namespace archive {

common::Error MakeArchive(const common::file_system::ascii_file_string_path& file_path,
                          const common::file_system::ascii_file_string_path& archive_path) {
  if (!file_path.IsValid() || !archive_path.IsValid()) {
    return common::make_error_inval();
  }

  archive::TarGZ tr;
  common::Error err = tr.Open(archive_path, "wb");
  if (err) {
    return err;
  }

  common::file_system::ANSIFile fl;
  common::ErrnoError errn = fl.Open(file_path, "rb");
  if (errn) {
    tr.Close();
    return common::make_error_from_errno(errn);
  }

  common::buffer_t buff;
  while (fl.Read(&buff, 8192)) {
    tr.Write(buff);
  }

  fl.Close();
  tr.Close();
  return common::Error();
}

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
