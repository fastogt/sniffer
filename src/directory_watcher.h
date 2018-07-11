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

#include "idirectory_watcher.h"

#include "events/libev_loop.h"

namespace rixjob {

class PosixDirectoryWatcher : public IDirectoryWatcher {
 public:
  enum { read_timeout_msec = 1000 };
  PosixDirectoryWatcher(IDirectoryWatcherClient* client, const base::PathString& directory, LibevLoop* loop);

  virtual ~PosixDirectoryWatcher();

 private:
  void OnDirChanged();

  virtual int PreExecImpl() override;
  virtual int ExecImpl() override;
  virtual int PostExecImpl() override;
  virtual void QuitImpl() override;

  static void dir_changed_cb(struct ev_loop* loop, ev_io* w, int revents);

  int inode_fd_;
  int watcher_fd_;

  ev_io* watcher_;
  LibevLoop* loop_;
};

}  // namespace rixjob
