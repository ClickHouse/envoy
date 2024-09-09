#include "protocol.h"

//#include "source/common/common/logger.h"
#include <cstdint>
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
        switch (current_reader)
        {
            case 0:
            case 1:
            case 2:
            case 3:
                if (readers[current_reader]->onData(data))
                    ++current_reader;
                break;
            case 4:
                if (handshake.tcp_protocol_version < ProtocolVersion::DBMS_MIN_REVISION_WITH_SERVER_TIMEZONE)
                    ++current_reader;
                else
                {
                    if (readers[current_reader]->onData(data))
                        ++current_reader;
                    break;
                }
            case 5:
                if (handshake.tcp_protocol_version < ProtocolVersion::DBMS_MIN_REVISION_WITH_SERVER_DISPLAY_NAME)
                    ++current_reader;
                else
                {
                    if (readers[current_reader]->onData(data))
                        ++current_reader;
                    break;
                }
            case 6:
                if (handshake.tcp_protocol_version < ProtocolVersion::DBMS_MIN_REVISION_WITH_VERSION_PATCH)
                    ++current_reader;
                else
                {
                    if (readers[current_reader]->onData(data))
                        ++current_reader;
                    break;
                }
            case 7:
            case 8:
                if (handshake.tcp_protocol_version < ProtocolVersion::DBMS_MIN_PROTOCOL_VERSION_WITH_CHUNKED_PACKETS)
                    ++current_reader;
                else
                {
                    if (readers[current_reader]->onData(data))
                        ++current_reader;
                    break;
                }
            case 9:
                if (handshake.tcp_protocol_version < ProtocolVersion::DBMS_MIN_PROTOCOL_VERSION_WITH_PASSWORD_COMPLEXITY_RULES)
                    ++current_reader;
                else
                {
                    if (readers[current_reader]->onData(data))
                        ++current_reader;
                    break;
                }
            case 10:
                if (handshake.tcp_protocol_version < ProtocolVersion::DBMS_MIN_REVISION_WITH_INTERSERVER_SECRET_V2)
                        ++current_reader;
                else
                {
                    if (readers[current_reader]->onData(data))
                        ++current_reader;
                    break;
                }
        }
    }

    return isReady();
}


} // namespace ClickHouse
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
