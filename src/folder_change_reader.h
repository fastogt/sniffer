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

#pragma once

#include <common/libev/io_client.h>

namespace sniffer {

class FolderChangeReader : public common::libev::IoClient {
 public:
  FolderChangeReader(common::libev::IoLoop* server, descriptor_t inode_fd, descriptor_t watcher_fd);

  virtual common::Error Write(const void* data, size_t size, size_t* nwrite_out) WARN_UNUSED_RESULT;

  virtual common::Error Read(unsigned char* out_data, size_t max_size, size_t* nread_out) WARN_UNUSED_RESULT;
  virtual common::Error Read(char* out_data, size_t max_size, size_t* nread_out) WARN_UNUSED_RESULT;

 protected:  // executed IoLoop
  virtual descriptor_t GetFd() const;

 private:
  virtual common::Error DoClose();

  descriptor_t watcher_fd_;
  descriptor_t inode_fd_;
};

}  // namespace sniffer
