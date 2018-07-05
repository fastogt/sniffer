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

extern "C" {
#include "sds_fasto.h"  // for sdsfreesplitres, sds
}

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
  if (DaemonClient* dclient = dynamic_cast<DaemonClient*>(client)) {
    common::Error err = DaemonDataReceived(dclient);
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

  if (IS_EQUAL_COMMAND(command, CLIENT_ACTIVATE)) {
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
