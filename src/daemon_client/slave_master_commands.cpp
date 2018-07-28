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

#include "daemon_client/slave_master_commands.h"

// activate
#define SLAVE_ACTIVATE_RESP_FAIL_1E GENEATATE_FAIL_FMT(SLAVE_ACTIVATE, "%s")
#define SLAVE_ACTIVATE_RESP_SUCCESS GENEATATE_SUCCESS(SLAVE_ACTIVATE)

// entry
#define SLAVE_SEND_ENTRY_REQ_1E GENERATE_REQUEST_FMT_ARGS(SLAVE_SEND_ENTRY, "%s")
#define SLAVE_SEND_ENTRY_RESP_FAIL_1E GENEATATE_FAIL_FMT(SLAVE_SEND_ENTRY, "%s")
#define SLAVE_SEND_ENTRY_RESP_SUCCESS GENEATATE_SUCCESS(SLAVE_SEND_ENTRY)

// entries
#define SLAVE_SEND_ENTRIES_RESP_FAIL_1E GENEATATE_FAIL_FMT(SLAVE_SEND_ENTRIES, "%s")
#define SLAVE_SEND_ENTRIES_RESP_SUCCESS GENEATATE_SUCCESS(SLAVE_SEND_ENTRIES)

namespace sniffer {
namespace daemon_client {

protocol::responce_t ActivateSlaveResponceSuccess(protocol::sequance_id_t id) {
  return common::protocols::three_way_handshake::MakeResponce(id, SLAVE_ACTIVATE_RESP_SUCCESS);
}

protocol::responce_t EntrySlaveResponceSuccess(protocol::sequance_id_t id) {
  return common::protocols::three_way_handshake::MakeResponce(id, SLAVE_SEND_ENTRY_RESP_SUCCESS);
}

protocol::request_t EntrySlaveRequest(protocol::sequance_id_t id, protocol::serializet_t msg) {
  return common::protocols::three_way_handshake::MakeRequest(id, SLAVE_SEND_ENTRY_REQ_1E, msg);
}

protocol::responce_t EntriesSlaveResponceSuccess(protocol::sequance_id_t id) {
  return common::protocols::three_way_handshake::MakeResponce(id, SLAVE_SEND_ENTRIES_RESP_SUCCESS);
}

}  // namespace server
}
