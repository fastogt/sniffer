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

#include <stdlib.h>

#include <common/sys_byteorder.h>
#include <common/convert2string.h>

#include "daemon_client.h"
#include "daemon_server.h"
#include "daemon_commands.h"

#include "commands_info/activate_info.h"

#define CLIENT_PORT 6317

namespace sniffer {

ProcessWrapper::ProcessWrapper(const std::string& license_key)
    : config_(), loop_(nullptr), ping_client_id_timer_(INVALID_TIMER_ID), id_(), license_key_(license_key) {
  loop_ = new DaemonServer(GetServerHostAndPort(), this);
  loop_->SetName("back_end_server");
  ReadConfig(GetConfigPath());
}

int ProcessWrapper::Exec(int argc, char** argv) {
  UNUSED(argc);
  UNUSED(argv);

  return loop_->Exec();
}

int ProcessWrapper::SendStopDaemonRequest(const std::string& license_key) {
  UNUSED(license_key);
  return EXIT_SUCCESS;
}

common::file_system::ascii_file_string_path ProcessWrapper::GetConfigPath() {
  return common::file_system::ascii_file_string_path(CONFIG_FILE_PATH);
}

void ProcessWrapper::PreLooped(common::libev::IoLoop* server) {
  UNUSED(server);
  ping_client_id_timer_ = server->CreateTimer(ping_timeout_clients_seconds, true);
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
  UNUSED(client);
}

void ProcessWrapper::DataReadyToWrite(common::libev::IoClient* client) {
  UNUSED(client);
}

void ProcessWrapper::PostLooped(common::libev::IoLoop* server) {
  if (ping_client_id_timer_ != INVALID_TIMER_ID) {
    server->RemoveTimer(ping_client_id_timer_);
    ping_client_id_timer_ = INVALID_TIMER_ID;
  }
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
