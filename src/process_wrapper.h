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

#include <common/libev/io_loop_observer.h>
#include <common/net/net.h>

#include "protocol/types.h"

namespace sniffer {
namespace daemon_client {
class DaemonClient;
}

class ProcessWrapper : public common::libev::IoLoopObserver {
 public:
  typedef uint64_t seq_id_t;
  enum { ping_timeout_clients_seconds = 60 };
  ProcessWrapper(const std::string& service_name,
                 const common::net::HostAndPort& service_host,
                 const std::string& license_key);
  virtual ~ProcessWrapper();

  virtual int Exec(int argc, char** argv);

  static int SendStopDaemonRequest(const std::string& license_key, const common::net::HostAndPort& service_host);

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

  virtual common::Error HandleRequestServiceCommand(daemon_client::DaemonClient* dclient,
                                                    protocol::sequance_id_t id,
                                                    int argc,
                                                    char* argv[]) WARN_UNUSED_RESULT;
  virtual common::Error HandleResponceServiceCommand(daemon_client::DaemonClient* dclient,
                                                     protocol::sequance_id_t id,
                                                     int argc,
                                                     char* argv[]) WARN_UNUSED_RESULT;

  protocol::sequance_id_t NextRequestID();

  virtual common::Error DaemonDataReceived(daemon_client::DaemonClient* dclient) WARN_UNUSED_RESULT;
  virtual common::Error HandleRequestClientActivate(daemon_client::DaemonClient* dclient,
                                                    protocol::sequance_id_t id,
                                                    int argc,
                                                    char* argv[]) WARN_UNUSED_RESULT;
  virtual common::Error HandleRequestClientStopService(daemon_client::DaemonClient* dclient,
                                                       protocol::sequance_id_t id,
                                                       int argc,
                                                       char* argv[]) WARN_UNUSED_RESULT;

  common::libev::IoLoop* loop_;

 private:
  common::libev::timer_id_t ping_client_id_timer_;
  std::atomic<seq_id_t> id_;

  const std::string license_key_;
};
}
