/*  Copyright (C) 2015-2017 Setplex. All right reserved.
    This file is part of Rixjob.
    Rixjob is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    Rixjob is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Rixjob.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "folder_change_reader.h"

#include <sys/inotify.h>

#include <unistd.h>

#include <common/net/net.h>

namespace sniffer {

FolderChangeReader::FolderChangeReader(common::libev::IoLoop* server, descriptor_t inode_fd, descriptor_t watcher_fd)
    : common::libev::IoClient(server), inode_fd_(inode_fd), watcher_fd_(watcher_fd) {}

common::Error FolderChangeReader::Write(const void* data, size_t size, size_t* nwrite_out) {
  if (!data || !size || !nwrite_out) {
    return common::make_error_inval();
  }

  NOTREACHED();
  return common::Error();
}

common::Error FolderChangeReader::Read(unsigned char* out_data, size_t max_size, size_t* nread_out) {
  if (!out_data || !max_size || !nread_out) {
    return common::make_error_inval();
  }

  ssize_t length = read(inode_fd_, out_data, max_size);
  if (length == ERROR_RESULT_VALUE) {
    common::ErrnoError errn = common::make_errno_error(errno);
    return common::make_error_from_errno(errn);
  }

  *nread_out = length;
  return common::Error();
}

common::Error FolderChangeReader::Read(char* out_data, size_t max_size, size_t* nread_out) {
  if (!out_data || !max_size || !nread_out) {
    return common::make_error_inval();
  }

  ssize_t length = read(inode_fd_, out_data, max_size);
  if (length == ERROR_RESULT_VALUE) {
    common::ErrnoError errn = common::make_errno_error(errno);
    return common::make_error_from_errno(errn);
  }

  *nread_out = length;
  return common::Error();
}

descriptor_t FolderChangeReader::GetFd() const {
  return inode_fd_;
}

common::Error FolderChangeReader::DoClose() {
  if (inode_fd_ == INVALID_DESCRIPTOR) {
    return common::Error();
  }

  if (watcher_fd_ != INVALID_DESCRIPTOR) {
    inotify_rm_watch(inode_fd_, watcher_fd_);
  }

  common::net::close(inode_fd_);
  return common::Error();
}

}  // namespace rixjob
