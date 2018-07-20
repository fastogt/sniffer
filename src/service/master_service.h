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

#include <common/threads/thread_pool.h>

#include "process_wrapper.h"
#include "sniffer/isniffer_observer.h"

#include "config.h"
#include "entry.h"

namespace sniffer {
namespace service {
class FolderChangeReader;
class DatabaseHolder;

class MasterService : public ProcessWrapper, public sniffer::ISnifferObserver {
 public:
  typedef ProcessWrapper base_class;
  enum { cleanup_seconds = 5, thread_pool_size = 3, client_port = 6317 };
  MasterService(const std::string& license_key);
  virtual ~MasterService();

  static common::file_system::ascii_file_string_path GetConfigPath();
  static common::net::HostAndPort GetServerHostAndPort();

 protected:
  virtual void PreLooped(common::libev::IoLoop* server) override;
  virtual void TimerEmited(common::libev::IoLoop* server, common::libev::timer_id_t id) override;

  virtual void DataReceived(common::libev::IoClient* client) override;
  virtual void PostLooped(common::libev::IoLoop* server) override;

  virtual void HandlePcapFile(const common::file_system::ascii_directory_string_path& node,
                              const common::file_system::ascii_file_string_path& path);
  virtual void HandleEntries(const common::file_system::ascii_directory_string_path& path,
                             const std::vector<Entry>& entries);

  virtual void HandlePacket(sniffer::ISniffer* sniffer,
                            const u_char* packet,
                            const struct pcap_pkthdr* header) override;

 private:
  void TouchEntries(const common::file_system::ascii_directory_string_path& path, const std::vector<Entry>& entries);

  common::Error FolderChanged(FolderChangeReader* fclient) WARN_UNUSED_RESULT;

  void ReadConfig(const common::file_system::ascii_file_string_path& config_path);

  Config config_;
  common::libev::timer_id_t cleanup_timer_;
  FolderChangeReader* watcher_;
  DatabaseHolder* db_;
  common::threads::ThreadPool thread_pool_;
};
}
}
