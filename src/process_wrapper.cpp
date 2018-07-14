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

#include "process_wrapper.h"

#include <sys/inotify.h>
#include <netinet/ether.h>

#include <stdlib.h>

#include <common/sys_byteorder.h>
#include <common/convert2string.h>
#include <common/net/net.h>
#include <common/file_system/file_system.h>

extern "C" {
#include "sds_fasto.h"  // for sdsfreesplitres, sds
}

#include "daemon_client.h"
#include "daemon_server.h"
#include "daemon_commands.h"

#include "commands_info/activate_info.h"
#include "commands_info/stop_service_info.h"

#include "folder_change_reader.h"
#include "database_holder.h"

#include "pcaper.h"

#include "pcap_packages/radiotap_header.h"

#define CLIENT_PORT 6317

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

static const unsigned char BROADCAST_MAC[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

namespace sniffer {

ProcessWrapper::ProcessWrapper(const std::string& license_key)
    : config_(),
      loop_(nullptr),
      ping_client_id_timer_(INVALID_TIMER_ID),
      cleanup_timer_(INVALID_TIMER_ID),
      watcher_(nullptr),
      db_(nullptr),
      id_(),
      thread_pool_(),
      license_key_(license_key) {
  loop_ = new DaemonServer(GetServerHostAndPort(), this);
  loop_->SetName("back_end_server");
  ReadConfig(GetConfigPath());
}

ProcessWrapper::~ProcessWrapper() {
  destroy(&loop_);
}

int ProcessWrapper::Exec(int argc, char** argv) {
  UNUSED(argc);
  UNUSED(argv);
  return loop_->Exec();
}

int ProcessWrapper::SendStopDaemonRequest(const std::string& license_key) {
  commands_info::StopServiceInfo stop_req(license_key);
  std::string stop_str;
  common::Error serialize_error = stop_req.SerializeToString(&stop_str);
  if (serialize_error) {
    return EXIT_FAILURE;
  }

  protocol::request_t req = StopServiceRequest("0", stop_str);
  common::net::HostAndPort host = GetServerHostAndPort();
  common::net::socket_info client_info;
  common::ErrnoError err = common::net::connect(host, common::net::ST_SOCK_STREAM, 0, &client_info);
  if (err) {
    return EXIT_FAILURE;
  }

  DaemonClient* connection = new DaemonClient(nullptr, client_info);
  static_cast<ProtocoledDaemonClient*>(connection)->WriteRequest(req);
  connection->Close();
  delete connection;
  return EXIT_SUCCESS;
}

common::file_system::ascii_file_string_path ProcessWrapper::GetConfigPath() {
  return common::file_system::ascii_file_string_path(CONFIG_FILE_PATH);
}

void ProcessWrapper::PreLooped(common::libev::IoLoop* server) {
  ping_client_id_timer_ = server->CreateTimer(ping_timeout_clients_seconds, true);

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
}

void ProcessWrapper::Accepted(common::libev::IoClient* client) {
  UNUSED(client);
}

void ProcessWrapper::Moved(common::libev::IoLoop* server, common::libev::IoClient* client) {
  UNUSED(server);
  UNUSED(client);
}

void ProcessWrapper::Closed(common::libev::IoClient* client) {
  UNUSED(client);
}

void ProcessWrapper::TimerEmited(common::libev::IoLoop* server, common::libev::timer_id_t id) {
  if (ping_client_id_timer_ == id) {
    std::vector<common::libev::IoClient*> online_clients = server->GetClients();
    for (size_t i = 0; i < online_clients.size(); ++i) {
      common::libev::IoClient* client = online_clients[i];
      DaemonClient* dclient = dynamic_cast<DaemonClient*>(client);
      if (dclient && dclient->IsVerified()) {
        ProtocoledDaemonClient* pdclient = static_cast<ProtocoledDaemonClient*>(dclient);
        const protocol::request_t ping_request = PingRequest(NextRequestID());
        common::Error err = pdclient->WriteRequest(ping_request);
        if (err) {
          DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
          err = client->Close();
          DCHECK(!err);
          delete client;
        } else {
          INFO_LOG() << "Pinged to client[" << client->GetFormatedName() << "], from server["
                     << server->GetFormatedName() << "], " << online_clients.size() << " client(s) connected.";
        }
      }
    }
  } else if (cleanup_timer_ == id) {
    loop_->Stop();
  }
}

#if LIBEV_CHILD_ENABLE
void ProcessWrapper::Accepted(common::libev::IoChild* child) {
  UNUSED(child);
}

void ProcessWrapper::Moved(common::libev::IoLoop* server, common::libev::IoChild* child) {
  UNUSED(server);
  UNUSED(child);
}

void ProcessWrapper::ChildStatusChanged(common::libev::IoChild* child, int status) {
  UNUSED(child);
  UNUSED(status);
}
#endif

void ProcessWrapper::DataReceived(common::libev::IoClient* client) {
  if (DaemonClient* dclient = dynamic_cast<DaemonClient*>(client)) {
    common::Error err = DaemonDataReceived(dclient);
    if (err) {
      DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
      dclient->Close();
      delete dclient;
    }
  } else if (FolderChangeReader* fclient = dynamic_cast<FolderChangeReader*>(client)) {
    common::Error err = FolderChanged(fclient);
    if (err) {
      DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
      dclient->Close();
      delete dclient;
    }
  } else {
    NOTREACHED();
  }
}

void ProcessWrapper::DataReadyToWrite(common::libev::IoClient* client) {
  UNUSED(client);
}

void ProcessWrapper::PostLooped(common::libev::IoLoop* server) {
  if (ping_client_id_timer_ != INVALID_TIMER_ID) {
    server->RemoveTimer(ping_client_id_timer_);
    ping_client_id_timer_ = INVALID_TIMER_ID;
  }

  thread_pool_.Stop();

  watcher_->Close();
  delete watcher_;
  watcher_ = nullptr;

  db_->Clean();
  delete db_;
  db_ = nullptr;
}

void ProcessWrapper::ReadConfig(const common::file_system::ascii_file_string_path& config_path) {
  common::Error err = load_config_file(config_path, &config_);
  if (err) {
    ERROR_LOG() << "Can't open config file path: " << config_path.GetPath() << ", error: " << err->GetDescription();
  }
}

common::net::HostAndPort ProcessWrapper::GetServerHostAndPort() {
  return common::net::HostAndPort::CreateLocalHost(CLIENT_PORT);
}

protocol::sequance_id_t ProcessWrapper::NextRequestID() {
  const seq_id_t next_id = id_++;
  char bytes[sizeof(seq_id_t)];
  const seq_id_t stabled = common::NetToHost64(next_id);  // for human readable hex
  memcpy(&bytes, &stabled, sizeof(seq_id_t));
  protocol::sequance_id_t hexed = common::utils::hex::encode(std::string(bytes, sizeof(seq_id_t)), true);
  return hexed;
}

common::Error ProcessWrapper::FolderChanged(FolderChangeReader* fclient) {
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
              HandlePcapFile(*path);
            }
          }
        }
      }
    }
    i += EVENT_SIZE + event->len;
  }

  return common::Error();
}

void ProcessWrapper::HandlePcapFile(const common::file_system::ascii_file_string_path& path) {
  CHECK(loop_->IsLoopThread());

  INFO_LOG() << "Handle pcap file path: " << path.GetPath();
  auto pcap_task = [path, this]() {
    std::string file_name = path.GetBaseFileName();
    common::time64_t ts_file;
    if (!common::ConvertFromString(file_name, &ts_file)) {
      return;
    }

    Pcaper pcap;
    common::ErrnoError errn = pcap.Open(path);
    if (errn) {
      return;
    }

    std::vector<Entry> entries;
    size_t pcap_pos = 0;
    auto parse_cb = [path, ts_file, &entries, &pcap_pos](const unsigned char* packet, const pcap_pkthdr& header) {
      bpf_u_int32 packet_len = header.caplen;
      if (packet_len < sizeof(struct radiotap_header)) {
        pcap_pos++;
        return;
      }

      struct radiotap_header* radio = (struct radiotap_header*)packet;
      packet += sizeof(struct radiotap_header);
      packet_len -= sizeof(struct radiotap_header);
      if (packet_len < sizeof(struct ieee80211header)) {
        pcap_pos++;
        return;
      }

      // beacon
      struct ieee80211header* beac = (struct ieee80211header*)packet;
      if (ieee80211_dataqos(beac)) {
      }

      std::string receiver_mac = ether_ntoa((struct ether_addr*)beac->addr1);
      std::string transmit_mac = ether_ntoa((struct ether_addr*)beac->addr2);
      std::string destination_mac = ether_ntoa((struct ether_addr*)beac->addr3);
      struct timeval tv = header.ts;
      common::time64_t ts = common::time::timeval2mstime(&tv);
      Entry ent(receiver_mac, ts_file * 1000 + ts, radio->wt_ssi_signal);
      entries.push_back(ent);
      pcap_pos++;
    };

    pcap.Parse(parse_cb);
    pcap.Close();
    common::file_system::ascii_directory_string_path dir(path.GetDirectory());
    TouchEntries(dir, entries);
    errn = common::file_system::remove_file(path.GetPath());
    if (errn) {
      DEBUG_MSG_ERROR(errn, common::logging::LOG_LEVEL_WARNING);
    }
  };

  thread_pool_.Post(pcap_task);
}

void ProcessWrapper::TouchEntries(const common::file_system::ascii_directory_string_path& path,
                                  const std::vector<Entry>& entries) {
  loop_->ExecInLoopThread([this, path, entries]() { HandleEntries(path, entries); });
}

void ProcessWrapper::HandleEntries(const common::file_system::ascii_directory_string_path& path,
                                   const std::vector<Entry>& entries) {
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

common::Error ProcessWrapper::DaemonDataReceived(DaemonClient* dclient) {
  CHECK(loop_->IsLoopThread());
  std::string input_command;
  ProtocoledDaemonClient* pclient = static_cast<ProtocoledDaemonClient*>(dclient);
  common::Error err = pclient->ReadCommand(&input_command);
  if (err) {
    return err;  // i don't want handle spam, comand must be foramated according protocol
  }

  common::protocols::three_way_handshake::cmd_id_t seq;
  protocol::sequance_id_t id;
  std::string cmd_str;

  err = common::protocols::three_way_handshake::ParseCommand(input_command, &seq, &id, &cmd_str);
  if (err) {
    return err;
  }

  int argc;
  sds* argv = sdssplitargslong(cmd_str.c_str(), &argc);
  if (argv == NULL) {
    const std::string error_str = "PROBLEM PARSING INNER COMMAND: " + input_command;
    return common::make_error(error_str);
  }

  INFO_LOG() << "HANDLE INNER COMMAND client[" << pclient->GetFormatedName()
             << "] seq: " << common::protocols::three_way_handshake::CmdIdToString(seq) << ", id:" << id
             << ", cmd: " << cmd_str;

  if (seq == REQUEST_COMMAND) {
    err = HandleRequestServiceCommand(dclient, id, argc, argv);
    if (err) {
      DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    }
  } else if (seq == RESPONCE_COMMAND) {
    err = HandleResponceServiceCommand(dclient, id, argc, argv);
    if (err) {
      DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    }
  } else {
    DNOTREACHED();
    sdsfreesplitres(argv, argc);
    return common::make_error("Invalid command type.");
  }

  sdsfreesplitres(argv, argc);
  return common::Error();
}

common::Error ProcessWrapper::HandleRequestServiceCommand(DaemonClient* dclient,
                                                          protocol::sequance_id_t id,
                                                          int argc,
                                                          char* argv[]) {
  UNUSED(id);
  UNUSED(argc);
  char* command = argv[0];

  if (IS_EQUAL_COMMAND(command, CLIENT_STOP_SERVICE)) {
    return HandleRequestClientStopService(dclient, id, argc, argv);
  } else if (IS_EQUAL_COMMAND(command, CLIENT_ACTIVATE)) {
    return HandleRequestClientActivate(dclient, id, argc, argv);
  } else {
    WARNING_LOG() << "Received unknown command: " << command;
  }

  return common::Error();
}

common::Error ProcessWrapper::HandleResponceServiceCommand(DaemonClient* dclient,
                                                           protocol::sequance_id_t id,
                                                           int argc,
                                                           char* argv[]) {
  UNUSED(dclient);
  UNUSED(id);
  UNUSED(argc);
  UNUSED(argv);
  return common::Error();
}

common::Error ProcessWrapper::HandleRequestClientStopService(DaemonClient* dclient,
                                                             protocol::sequance_id_t id,
                                                             int argc,
                                                             char* argv[]) {
  CHECK(loop_->IsLoopThread());
  if (argc > 1) {
    json_object* jstop = json_tokener_parse(argv[1]);
    if (!jstop) {
      return common::make_error_inval();
    }

    commands_info::StopServiceInfo stop_info;
    common::Error err = stop_info.DeSerialize(jstop);
    json_object_put(jstop);
    if (err) {
      return err;
    }

    bool is_verified_request = stop_info.GetLicense() == license_key_ || dclient->IsVerified();
    if (!is_verified_request) {
      return common::make_error_inval();
    }

    if (cleanup_timer_ != INVALID_TIMER_ID) {
      // in progress
      ProtocoledDaemonClient* pdclient = static_cast<ProtocoledDaemonClient*>(dclient);
      protocol::responce_t resp = StopServiceResponceFail(id, "Stop service in progress...");
      pdclient->WriteResponce(resp);

      return common::Error();
    }

    ProtocoledDaemonClient* pdclient = static_cast<ProtocoledDaemonClient*>(dclient);
    protocol::responce_t resp = StopServiceResponceSuccess(id);
    pdclient->WriteResponce(resp);

    cleanup_timer_ = loop_->CreateTimer(cleanup_seconds, false);
    return common::Error();
  }

  return common::make_error_inval();
}

common::Error ProcessWrapper::HandleRequestClientActivate(DaemonClient* dclient,
                                                          protocol::sequance_id_t id,
                                                          int argc,
                                                          char* argv[]) {
  if (argc > 1) {
    json_object* jactivate = json_tokener_parse(argv[1]);
    if (!jactivate) {
      return common::make_error_inval();
    }

    commands_info::ActivateInfo activate_info;
    common::Error err = activate_info.DeSerialize(jactivate);
    json_object_put(jactivate);
    if (err) {
      return err;
    }

    bool is_active = activate_info.GetLicense() == license_key_;
    if (!is_active) {
      return common::make_error_inval();
    }

    ProtocoledDaemonClient* pdclient = static_cast<ProtocoledDaemonClient*>(dclient);
    protocol::responce_t resp = ActivateResponceSuccess(id);
    pdclient->WriteResponce(resp);
    dclient->SetVerified(true);
    return common::Error();
  }

  return common::make_error_inval();
}
}
