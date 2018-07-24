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

#include "client/sniffer_service.h"

#include <thread>

#include <common/time.h>

#include "pcap_packages/radiotap_header.h"

#include "sniffer/live_sniffer.h"

#include "utils.h"

namespace sniffer {
namespace client {

SnifferService::SnifferService(const std::string& license_key)
    : base_class("sniffer_service", GetServerHostAndPort(), license_key), config_() {
  ReadConfig(GetConfigPath());
}

SnifferService::~SnifferService() {}

int SnifferService::Exec(int argc, char** argv) {
  sniffer::LiveSniffer* live = new sniffer::LiveSniffer(config_.server.device, this);
  common::Error err = live->Open();
  if (err) {
    DEBUG_MSG_ERROR(err, common::logging::LOG_LEVEL_ERR);
    return EXIT_FAILURE;
  }

  int header_type = live->GetLinkHeaderType();
  if (!(header_type == DLT_IEEE802_11_RADIO || header_type == DLT_EN10MB)) {
    ERROR_LOG() << "Not supported headers, device header type: " << header_type;
    return EXIT_FAILURE;
  }

  INFO_LOG() << "Opended device: " << live->GetDevice() << ", mac address: " << live->GetMacAddress()
             << ", link header type: " << header_type;
  auto th = std::thread([live]() { live->Run(); });
  int res = base_class::Exec(argc, argv);
  th.join();
  live->Close();
  delete live;
  return res;
}

common::file_system::ascii_file_string_path SnifferService::GetConfigPath() {
  return common::file_system::ascii_file_string_path(CONFIG_FILE_PATH);
}

void SnifferService::HandlePacket(sniffer::ISniffer* sniffer, const u_char* packet, const pcap_pkthdr* header) {
  Entry ent;
  sniffer::LiveSniffer* live = static_cast<sniffer::LiveSniffer*>(sniffer);
  if (live->GetLinkHeaderType() == DLT_IEEE802_11_RADIO) {
    PARSE_RESULT res = MakeEntryFromRadioTap(packet, header, &ent);
    if (res != PARSE_OK) {
      return;
    }
  } else if (live->GetLinkHeaderType() == DLT_EN10MB) {
    PARSE_RESULT res = MakeEntryFromEthernet(packet, header, &ent);
    if (res != PARSE_OK) {
      return;
    }
  }

  ent.timestamp = (ent.timestamp / 1000) * 1000;
  INFO_LOG() << "Received packet, mac: " << ent.mac_address << ", time: " << ent.timestamp
             << ", ssi: " << static_cast<int>(ent.ssi);
}

void SnifferService::ReadConfig(const common::file_system::ascii_file_string_path& config_path) {
  common::Error err = load_config_file(config_path, &config_);
  if (err) {
    ERROR_LOG() << "Can't open config file path: " << config_path.GetPath() << ", error: " << err->GetDescription();
  }
}

common::net::HostAndPort SnifferService::GetServerHostAndPort() {
  return common::net::HostAndPort::CreateLocalHost(client_port);
}
}
}
