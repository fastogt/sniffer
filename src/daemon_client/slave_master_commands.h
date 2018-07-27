/*  Copyright (C) 2014-2018 FastoGT. All right reserved.
    This file is part of iptv_cloud.
    iptv_cloud is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    iptv_cloud is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with iptv_cloud.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "protocol/protocol.h"

#define SLAVE_ACTIVATE "activate_request"
#define SLAVE_SEND_ENTRY "send_entry"
#define SLAVE_SEND_ENTRIES "send_entries"

namespace sniffer {
namespace daemon_client {

protocol::responce_t ActivateSlaveResponceSuccess(protocol::sequance_id_t id);
protocol::responce_t EntrySlaveResponceSuccess(protocol::sequance_id_t id);
protocol::responce_t EntriesSlaveResponceSuccess(protocol::sequance_id_t id);

}  // namespace server
}
