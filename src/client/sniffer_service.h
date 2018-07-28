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

#include "process_wrapper.h"

#include "sniffer/isniffer_observer.h"

#include "config.h"

namespace sniffer {
namespace client {

class SnifferService : public ProcessWrapper, public sniffer::ISnifferObserver {
 public:
  typedef ProcessWrapper base_class;
  enum { client_port = 6318 };

  SnifferService(const std::string& license_key);
  virtual ~SnifferService();

  static common::file_system::ascii_file_string_path GetConfigPath();
  static common::net::HostAndPort GetServerHostAndPort();

  virtual int Exec(int argc, char** argv) override;

 protected:
  virtual void PreLooped(common::libev::IoLoop* server) override;
  virtual void PostLooped(common::libev::IoLoop* server) override;
  virtual void Closed(common::libev::IoClient* client) override;

  virtual void HandlePacket(sniffer::ISniffer* sniffer,
                            const u_char* packet,
                            const struct pcap_pkthdr* header) override;

  virtual common::Error HandleRequestServiceCommand(daemon_client::DaemonClient* dclient,
                                                    protocol::sequance_id_t id,
                                                    int argc,
                                                    char* argv[]) override WARN_UNUSED_RESULT;
  virtual common::Error HandleResponceServiceCommand(daemon_client::DaemonClient* dclient,
                                                     protocol::sequance_id_t id,
                                                     int argc,
                                                     char* argv[]) override WARN_UNUSED_RESULT;

 private:
  void Connect(common::libev::IoLoop* server);
  void DisConnect(common::Error err);

  void ReadConfig(const common::file_system::ascii_file_string_path& config_path);

  Config config_;
  daemon_client::DaemonClient* inner_connection_;
};
}
}
