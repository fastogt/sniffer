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

#include "service/master_service.h"

#include <sys/inotify.h>

#include <common/file_system/file_system.h>
#include <common/file_system/string_path_utils.h>
#include <common/libev/io_loop.h>

#include "commands_info/stop_service_info.h"

#include "service/folder_change_reader.h"
#include "service/database_holder.h"

#include "utils.h"

#include "sniffer/file_sniffer.h"

#include "daemon_client/daemon_client.h"
#include "daemon_client/slave_master_commands.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

// #define ARCHIVE_EXTENSION ".gz"

namespace sniffer {
namespace {
class Pcaper : public sniffer::FileSniffer {
 public:
  typedef sniffer::FileSniffer base_class;
  typedef EntryInfo entry_t;
  typedef std::vector<entry_t> entries_t;
  Pcaper(common::utctime_t ts_file, const path_type& file_path, sniffer::ISnifferObserver* observer)
      : base_class(file_path, observer), ts_file_(ts_file), entries_() {}

  entries_t GetEntries() const { return entries_; }
  common::utctime_t GetTSFile() const { return ts_file_; }
  void AddEntry(const entry_t& entry) { entries_.push_back(entry); }

 private:
  common::utctime_t ts_file_;
  std::vector<entry_t> entries_;
};
}

namespace service {

MasterService::MasterService(const std::string& license_key)
    : base_class("master_service", GetServerHostAndPort(), license_key),
      config_(),
      cleanup_timer_(INVALID_TIMER_ID),
      watcher_(nullptr),
      db_(nullptr),
      thread_pool_() {
  ReadConfig(GetConfigPath());
}

MasterService::~MasterService() {}

common::file_system::ascii_file_string_path MasterService::GetConfigPath() {
  return common::file_system::ascii_file_string_path(CONFIG_FILE_PATH);
}

void MasterService::PreLooped(common::libev::IoLoop* server) {
  int inode_fd = inotify_init();
  if (inode_fd == ERROR_RESULT_VALUE) {
    return;
  }

  db_ = new DatabaseHolder;
  watcher_ = new FolderChangeReader(loop_, inode_fd);
  for (size_t i = 0; i < config_.server.scaning_paths.size(); ++i) {
    common::file_system::ascii_directory_string_path folder_path = config_.server.scaning_paths[i];
    common::Error err = watcher_->AddDirWatcher(folder_path, IN_CLOSE_WRITE);
    if (err) {
      DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    }

    err = db_->AttachNode(folder_path.GetFolderName(), config_.server.db_hosts);
    if (err) {
      DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    }
  }
  server->RegisterClient(watcher_);

  thread_pool_.Start(thread_pool_size);
  base_class::PreLooped(server);
}

void MasterService::TimerEmited(common::libev::IoLoop* server, common::libev::timer_id_t id) {
  if (cleanup_timer_ == id) {
    loop_->Stop();
  }
  base_class::TimerEmited(server, id);
}

void MasterService::DataReceived(common::libev::IoClient* client) {
  if (FolderChangeReader* fclient = dynamic_cast<FolderChangeReader*>(client)) {
    common::Error err = FolderChanged(fclient);
    if (err) {
      DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
      fclient->Close();
      delete fclient;
    }
    return;
  }

  base_class::DataReceived(client);
}

void MasterService::PostLooped(common::libev::IoLoop* server) {
  thread_pool_.Stop();

  watcher_->Close();
  delete watcher_;
  watcher_ = nullptr;

  db_->Clean();
  delete db_;
  db_ = nullptr;

  base_class::PostLooped(server);
}

void MasterService::ReadConfig(const common::file_system::ascii_file_string_path& config_path) {
  common::Error err = load_config_file(config_path, &config_);
  if (err) {
    ERROR_LOG() << "Can't open config file path: " << config_path.GetPath() << ", error: " << err->GetDescription();
  }
}

common::net::HostAndPort MasterService::GetServerHostAndPort() {
  return common::net::HostAndPort::CreateLocalHost(client_port);
}

common::Error MasterService::FolderChanged(FolderChangeReader* fclient) {
  char data[BUF_LEN] = {0};
  size_t nread;
  common::Error err = fclient->Read(data, BUF_LEN, &nread);
  if (err) {
    return err;
  }

  size_t i = 0;
  while (i < nread) {
    struct inotify_event* event = reinterpret_cast<struct inotify_event*>(data + i);
    if (event->len) {
      if (event->mask & IN_CLOSE_WRITE) {
        if (event->mask & IN_ISDIR) {
        } else {
          const Watcher* watcher = nullptr;
          if (fclient->FindWatcherByDescriptor(event->wd, &watcher)) {
            std::string file_name = event->name;
            auto path = watcher->directory.MakeFileStringPath(file_name);
            if (path) {
              HandlePcapFile(watcher->directory, *path);
            }
          }
        }
      }
    }
    i += EVENT_SIZE + event->len;
  }

  return common::Error();
}

void MasterService::HandlePcapFile(const common::file_system::ascii_directory_string_path& node,
                                   const common::file_system::ascii_file_string_path& path) {
  CHECK(loop_->IsLoopThread());

  INFO_LOG() << "Handle pcap file path: " << path.GetPath();
  auto pcap_task = [node, path, this]() {
    std::string file_name = path.GetBaseFileName();
    // YYYY-MM-DD_HH:MM:SS
    struct tm tm;
    memset(&tm, 0, sizeof(struct tm));
    char* res = strptime(file_name.c_str(), "%Y-%m-%d_%H:%M:%S", &tm);
    if (!res) {
      return;
    }

    Pcaper pcap(common::time::tm2utctime(&tm), path, this);
    common::Error err = pcap.Open();
    if (err) {
      return;
    }

    pcap.Run();
    pcap.Close();
    TouchEntries(node, pcap.GetEntries());

#if 0
    // archive file
    std::string table_name = node.GetFolderName();
    auto path_to_folder = config_.server.archive_path.MakeDirectoryStringPath(table_name);
    if (path_to_folder) {
      common::file_system::ascii_directory_string_path archive_dir = *path_to_folder;
      std::string archive_dir_str = archive_dir.GetPath();
      bool is_exist_archive_dir = common::file_system::is_directory_exist(archive_dir_str);
      if (!is_exist_archive_dir) {
        common::ErrnoError errn = common::file_system::create_directory(archive_dir_str, true);
        if (errn) {
          DEBUG_MSG_ERROR(errn, common::logging::LOG_LEVEL_WARNING);
        } else {
          is_exist_archive_dir = true;
        }
      }

      if (is_exist_archive_dir) {
        auto path_to = archive_dir.MakeFileStringPath(path.GetBaseFileName() + ARCHIVE_EXTENSION);
        err = archive::MakeArchive(path, *path_to);
        if (err) {
          DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_WARNING);
        }
      }
    } else {
      // Can't generate archive folder
    }
#endif

    // remove file
    common::ErrnoError errn = common::file_system::remove_file(path.GetPath());
    if (errn) {
      DEBUG_MSG_ERROR(errn, common::logging::LOG_LEVEL_WARNING);
    }
  };

  thread_pool_.Post(pcap_task);
}

void MasterService::TouchEntries(const common::file_system::ascii_directory_string_path& path,
                                 const std::vector<EntryInfo>& entries) {
  loop_->ExecInLoopThread([this, path, entries]() { HandleEntries(path, entries); });
}

void MasterService::HandleEntries(const common::file_system::ascii_directory_string_path& path,
                                  const std::vector<EntryInfo>& entries) {
  CHECK(loop_->IsLoopThread());

  std::string table_name = path.GetFolderName();
  INFO_LOG() << "Handle entries count: " << entries.size() << ", table: " << table_name;

  SnifferDB* node = nullptr;
  if (!db_->FindNode(table_name, &node)) {
    return;
  }

  common::Error err = node->Insert(entries);
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
  }
}

void MasterService::HandlePacket(sniffer::ISniffer* sniffer, const u_char* packet, const pcap_pkthdr* header) {
  EntryInfo ent;
  Pcaper* pcaper = static_cast<Pcaper*>(sniffer);
  if (pcaper->GetLinkHeaderType() == DLT_IEEE802_11_RADIO) {
    PARSE_RESULT res = MakeEntryFromRadioTap(packet, header, &ent);
    if (res != PARSE_OK) {
      return;
    }
  } else if (pcaper->GetLinkHeaderType() == DLT_EN10MB) {
    PARSE_RESULT res = MakeEntryFromEthernet(packet, header, &ent);
    if (res != PARSE_OK) {
      return;
    }
  } else {
    return;
  }

  // pcaper->GetTSFile() * 1000
  ent.SetTimestamp((ent.GetTimestamp() / 1000) * 1000);
  pcaper->AddEntry(ent);
}

common::Error MasterService::HandleRequestServiceCommand(daemon_client::DaemonClient* dclient,
                                                         protocol::sequance_id_t id,
                                                         int argc,
                                                         char* argv[]) {
  char* command = argv[0];
  if (IS_EQUAL_COMMAND(command, SLAVE_SEND_ENTRY)) {
    return HandleRequestEntryFromSlave(dclient, id, argc, argv);
  }

  return base_class::HandleRequestServiceCommand(dclient, id, argc, argv);
}

common::Error MasterService::HandleResponceServiceCommand(daemon_client::DaemonClient* dclient,
                                                          protocol::sequance_id_t id,
                                                          int argc,
                                                          char* argv[]) {
  return base_class::HandleResponceServiceCommand(dclient, id, argc, argv);
}

common::Error MasterService::HandleRequestEntryFromSlave(daemon_client::DaemonClient* dclient,
                                                         protocol::sequance_id_t id,
                                                         int argc,
                                                         char* argv[]) {
  CHECK(loop_->IsLoopThread());
  if (argc > 1) {
    bool is_verified_request = dclient->IsVerified();
    if (!is_verified_request) {
      return common::make_error_inval();
    }

    json_object* jentry = json_tokener_parse(argv[1]);
    if (!jentry) {
      return common::make_error_inval();
    }

    EntryInfo entry_info;
    common::Error err = entry_info.DeSerialize(jentry);
    json_object_put(jentry);
    if (err) {
      return err;
    }

    daemon_client::ProtocoledDaemonClient* pdclient = static_cast<daemon_client::ProtocoledDaemonClient*>(dclient);
    protocol::responce_t resp = daemon_client::EntrySlaveResponceSuccess(id);
    pdclient->WriteResponce(resp);
    return common::Error();
  }

  return common::Error();
}
}
}
