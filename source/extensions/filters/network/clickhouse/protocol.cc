#include "protocol.h"

//#include "source/common/common/logger.h"
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <utility>

#include <iostream>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ClickHouse {


bool ReaderPacketCleintAddendum::onData(Buffer::Iterator &data)
{
    if (handshake.hello.client_tcp_protocol_version.value >= ProtocolVersion::DBMS_MIN_PROTOCOL_VERSION_WITH_QUOTA_KEY)
        if (!quota_key.isReady())
            if (!quota_key.onData(data))
                return false;

    if (handshake.hello.client_tcp_protocol_version.value >= ProtocolVersion::DBMS_MIN_PROTOCOL_VERSION_WITH_ADDENDUM)
    {
        if (!proto_send_chunked_cl.isReady())
            if (!proto_send_chunked_cl.onData(data))
                return false;

        if (!proto_recv_chunked_cl.isReady())
            if (!proto_recv_chunked_cl.onData(data))
                return false;
    }

    handshake.protocol_state.chunked_client = (proto_send_chunked_cl.value == "chunked");
    handshake.protocol_state.chunked_server = (proto_recv_chunked_cl.value == "chunked");

    ready = true;
    return true;
}


bool ReaderPacketServerHello::onData(Buffer::Iterator & data)
{
    if (!packet_type.isReady())
        if (!packet_type.onData(data))
            return false;
    if (packet_type.value != Server::Hello)
        throw ProtocolException("Hello is expected in handshake");

    while (!isReady() && data)
    {
        if (handshake.tcp_protocol_version < current_reader->second)
            ++current_reader;
        else if (current_reader->first->onData(data))
            ++current_reader;
    }

    return isReady();
}


} // namespace ClickHouse
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
