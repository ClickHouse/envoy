#include "source/extensions/filters/network/clickhouse/clickhouse.h"
#include "protocol.h"
#include "source/extensions/filters/network/clickhouse/util.h"

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"

#include "source/common/common/logger.h"
#include <cstdint>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ClickHouse {


Network::FilterStatus ClickHouseFilter::onWrite(Buffer::Instance& data, bool end_stream)
{
    ENVOY_CONN_LOG(debug, "ClickHouse: onWrite: buffer size {} bytes, end stream {}",
                 read_callbacks_->connection(), data.length(), end_stream);

    if (server_hands_off)
        return Network::FilterStatus::Continue;

    Buffer::Iterator it(data);

    try
    {
        if (!server_handshake.isReady())
            if (!server_handshake.onData(it))
                return Network::FilterStatus::Continue;

        assert(server_handshake.isReady());

        server_hands_off = true;

        ENVOY_CONN_LOG(info,
            "ClickHouse from server: Hello - version_name '{}', version_major '{}', version_minor '{}', dbms_tcp_protocol_version '{}', time_zone '{}', server_display_name '{}', version_patch '{}', proto_send_chunked_srv '{}', proto_recv_chunked_srv '{}', nonce '{}'",
            write_callbacks_->connection(),
            server_handshake.hello.version_name.value,
            server_handshake.hello.version_major.value,
            server_handshake.hello.version_minor.value,
            server_handshake.hello.dbms_tcp_protocol_version.value,
            server_handshake.hello.time_zone.value,
            server_handshake.hello.server_display_name.value,
            server_handshake.hello.version_patch.value,
            server_handshake.hello.proto_send_chunked_srv.value,
            server_handshake.hello.proto_recv_chunked_srv.value,
            server_handshake.hello.nonce.value);
    }
    catch (const ProtocolException & e)
    {
        ENVOY_CONN_LOG(error, "ClickHouse from server: error protocol processing: {}",
                 read_callbacks_->connection(), e.what());
        server_hands_off = true;
    }

    return Network::FilterStatus::Continue;
}

Network::FilterStatus ClickHouseFilter::onData(Buffer::Instance& data, [[maybe_unused]] bool end_stream)
{
    ENVOY_CONN_LOG(debug, "ClickHouse from client: onData: buffer size {} bytes, end stream {}",
                 read_callbacks_->connection(), data.length(), end_stream);

    if (client_hands_off)
        return Network::FilterStatus::Continue;

    Buffer::Iterator it(data);

    try
    {
        if (!client_handshake.isReady())
            if (!client_handshake.onData(it))
                return Network::FilterStatus::Continue;

        assert(client_handshake.isReady());

        client_hands_off = true;

        ENVOY_CONN_LOG(info,
            "ClickHouse from client: Hello - client_name '{}', client_version_major '{}', client_version_minor '{}', client_tcp_protocol_version '{}', default_db '{}', user '{}', password '{}'",
            read_callbacks_->connection(),
            client_handshake.hello.client_name.value,
            client_handshake.hello.client_version_major.value,
            client_handshake.hello.client_version_minor.value,
            client_handshake.hello.client_tcp_protocol_version.value,
            client_handshake.hello.default_db.value,
            client_handshake.hello.user.value,
            client_handshake.hello.password.value);
    }
    catch (const ProtocolException & e)
    {
        ENVOY_CONN_LOG(error, "ClickHouse from server: error protocol processing: {}",
                 read_callbacks_->connection(), e.what());
        client_hands_off = true;
    }

    return Network::FilterStatus::Continue;
}

} // namespace ClickHouse
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy