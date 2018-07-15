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

#include <string>

#include <common/libev/io_loop_observer.h>

#include "protocol/types.h"

#include "config.h"
#include "thread_pool.h"
#include "entry.h"

namespace sniffer {
class DaemonClient;
class FolderChangeReader;
class DatabaseHolder;

class ProcessWrapper : public common::libev::IoLoopObserver {
 public:
  typedef uint64_t seq_id_t;
  enum { ping_timeout_clients_seconds = 60, cleanup_seconds = 5, thread_pool_size = 3 };
  ProcessWrapper(const std::string& license_key);
  virtual ~ProcessWrapper();

  int Exec(int argc, char** argv);

  static int SendStopDaemonRequest(const std::string& license_key);
  static common::file_system::ascii_file_string_path GetConfigPath();

 protected:
  virtual void PreLooped(common::libev::IoLoop* server) override;
  virtual void Accepted(common::libev::IoClient* client) override;
  virtual void Moved(common::libev::IoLoop* server,
                     common::libev::IoClient* client) override;  // owner server, now client is orphan
  virtual void Closed(common::libev::IoClient* client) override;
  virtual void TimerEmited(common::libev::IoLoop* server, common::libev::timer_id_t id) override;

#if LIBEV_CHILD_ENABLE
  virtual void Accepted(common::libev::IoChild* child) override;
  virtual void Moved(common::libev::IoLoop* server, common::libev::IoChild* child) override;
  virtual void ChildStatusChanged(common::libev::IoChild* child, int status) override;
#endif

  virtual void DataReceived(common::libev::IoClient* client) override;
  virtual void DataReadyToWrite(common::libev::IoClient* client) override;
  virtual void PostLooped(common::libev::IoLoop* server) override;

  virtual common::Error HandleRequestServiceCommand(DaemonClient* dclient,
                                                    protocol::sequance_id_t id,
                                                    int argc,
                                                    char* argv[]) WARN_UNUSED_RESULT;
  virtual common::Error HandleResponceServiceCommand(DaemonClient* dclient,
                                                     protocol::sequance_id_t id,
                                                     int argc,
                                                     char* argv[]) WARN_UNUSED_RESULT;

  virtual void HandlePcapFile(const common::file_system::ascii_directory_string_path& node,
                              const common::file_system::ascii_file_string_path& path);
  virtual void HandleEntries(const common::file_system::ascii_directory_string_path& path,
                             const std::vector<Entry>& entries);

 private:
  void TouchEntries(const common::file_system::ascii_directory_string_path& path, const std::vector<Entry>& entries);

  common::Error DaemonDataReceived(DaemonClient* dclient) WARN_UNUSED_RESULT;
  common::Error FolderChanged(FolderChangeReader* fclient) WARN_UNUSED_RESULT;

  protocol::sequance_id_t NextRequestID();
  common::Error HandleRequestClientActivate(DaemonClient* dclient, protocol::sequance_id_t id, int argc, char* argv[])
      WARN_UNUSED_RESULT;
  common::Error HandleRequestClientStopService(DaemonClient* dclient,
                                               protocol::sequance_id_t id,
                                               int argc,
                                               char* argv[]) WARN_UNUSED_RESULT;

  void ReadConfig(const common::file_system::ascii_file_string_path& config_path);
  static common::net::HostAndPort GetServerHostAndPort();

  Config config_;
  common::libev::IoLoop* loop_;
  common::libev::timer_id_t ping_client_id_timer_;
  common::libev::timer_id_t cleanup_timer_;
  FolderChangeReader* watcher_;
  DatabaseHolder* db_;
  std::atomic<seq_id_t> id_;

  ThreadPool thread_pool_;

  const std::string license_key_;
};
}
