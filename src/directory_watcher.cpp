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

#include "platform/posix_directory_watcher.h"

#include <sys/inotify.h>

#include <unistd.h>

#include "base/file_system.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

namespace rixjob {

PosixDirectoryWatcher::PosixDirectoryWatcher(IDirectoryWatcherClient* client,
                                             const base::PathString& directory,
                                             LibevLoop* loop)
    : IDirectoryWatcher(client, directory),
      inode_fd_(INVALID_DESCRIPTOR),
      watcher_fd_(INVALID_DESCRIPTOR),
      watcher_(new ev_io),
      loop_(loop) {}

int PosixDirectoryWatcher::PreExecImpl() {
  inode_fd_ = inotify_init();
  if (inode_fd_ == ERROR_RESULT_VALUE) {
    return EXIT_FAILURE;
  }

  const base::PathString& dir = GetDirectory();
  const std::string dir_str = dir.GetPath();
  watcher_fd_ = inotify_add_watch(inode_fd_, dir_str.c_str(), IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_CLOSE_WRITE);
  if (watcher_fd_ == ERROR_RESULT_VALUE) {
    return EXIT_FAILURE;
  }

  ev_io_init(watcher_, dir_changed_cb, inode_fd_, EV_READ);
  watcher_->data = this;
  return EXIT_SUCCESS;
}

void PosixDirectoryWatcher::OnDirChanged() {
  char data[BUF_LEN] = {0};
  ssize_t length = ::read(inode_fd_, data, BUF_LEN);
  if (length == ERROR_RESULT_VALUE) {
    return;
  }

  const base::PathString& dir = GetDirectory();
  ssize_t i = 0;
  while (i < length) {
    struct inotify_event* event = reinterpret_cast<struct inotify_event*>(data + i);
    if (event->len) {
      if (event->mask & IN_CREATE) {
        if (client_) {
          client_->HandleChanges(this, dir, event->name, event->mask & IN_ISDIR, FS_CREATE);
        }
      } else if (event->mask & IN_DELETE) {
        if (client_) {
          client_->HandleChanges(this, dir, event->name, event->mask & IN_ISDIR, FS_DELETE);
        }
      } else if (event->mask & IN_MOVED_TO) {
        if (client_) {
          client_->HandleChanges(this, dir, event->name, event->mask & IN_ISDIR, FS_MOVED_TO);
        }
      } else if (event->mask & IN_CLOSE_WRITE) {
        if (client_) {
          client_->HandleChanges(this, dir, event->name, event->mask & IN_ISDIR, FS_CLOSE_WRITE);
        }
      }
    }
    i += EVENT_SIZE + event->len;
  }
}

void PosixDirectoryWatcher::dir_changed_cb(struct ev_loop* loop, ev_io* w, int revents) {
  UNUSED(loop);
  UNUSED(revents);

  PosixDirectoryWatcher* self = reinterpret_cast<PosixDirectoryWatcher*>(w->data);
  self->OnDirChanged();
}

int PosixDirectoryWatcher::ExecImpl() {
  if (!loop_) {
    return EXIT_FAILURE;
  }

  auto fn = [this] { loop_->StartIO(watcher_); };
  loop_->ExecInLoopThread(fn);
  return EXIT_SUCCESS;
}

int PosixDirectoryWatcher::PostExecImpl() {
  if (inode_fd_ == INVALID_DESCRIPTOR) {
    return EXIT_SUCCESS;
  }

  if (watcher_fd_ != INVALID_DESCRIPTOR) {
    inotify_rm_watch(inode_fd_, watcher_fd_);
  }
  base::close(&inode_fd_);
  return EXIT_SUCCESS;
}

void PosixDirectoryWatcher::QuitImpl() {
  if (loop_) {
    auto fn = [this] { loop_->StopIO(watcher_); };
    loop_->ExecInLoopThread(fn);
  }
}

PosixDirectoryWatcher::~PosixDirectoryWatcher() {
  destroy(&watcher_);
}

}  // namespace rixjob
