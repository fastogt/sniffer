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

#include <sys/inotify.h>
#include <netinet/ether.h>

#define CLIENT_PORT 6317

#define SIZE_OF_MAC_ADDRESS ETH_ALEN
#define BROADCAST_MAC \
  { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }

namespace {

typedef unsigned char mac_address_t[SIZE_OF_MAC_ADDRESS];

const std::array<mac_address_t, 1> g_filtered_macs = {{BROADCAST_MAC}};

bool need_to_skipped_mac(mac_address_t mac) {
  for (size_t i = 0; i < g_filtered_macs.size(); ++i) {
    if (memcmp(g_filtered_macs[i], mac, SIZE_OF_MAC_ADDRESS) == 0) {
      return true;
    }
  }

  return false;
}
}

namespace sniffer {
namespace client {

SnifferService::SnifferService(const std::string& license_key)
    : base_class("sniffer_service", GetServerHostAndPort(), license_key), config_() {
  ReadConfig(GetConfigPath());
}

SnifferService::~SnifferService() {
}

common::file_system::ascii_file_string_path SnifferService::GetConfigPath() {
  return common::file_system::ascii_file_string_path(CONFIG_FILE_PATH);
}
void SnifferService::ReadConfig(const common::file_system::ascii_file_string_path& config_path) {
  common::Error err = load_config_file(config_path, &config_);
  if (err) {
    ERROR_LOG() << "Can't open config file path: " << config_path.GetPath() << ", error: " << err->GetDescription();
  }
}

common::net::HostAndPort SnifferService::GetServerHostAndPort() {
  return common::net::HostAndPort::CreateLocalHost(CLIENT_PORT);
}
}
}
