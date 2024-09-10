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
                write_callbacks_->connection(), data.length(), end_stream);

    if (server_hands_off)
        return Network::FilterStatus::Continue;

    Buffer::Iterator it(data);

    if (protocol_state.chunked_server.get())
    {
        auto packet_processor = [this](Buffer::Iterator & data) -> bool
        {
            if (this->server_packet_type.isReady())
                return true;
            if (!this->server_packet_type.onData(data))
                return false;
            ENVOY_CONN_LOG(debug, "ClickHouse from server: packet ({}) {}",
                write_callbacks_->connection(), this->server_packet_type.value, Server::toString(this->server_packet_type.value));
            return true;
        };

        while (it)
        {
            if (!server_chunk.isReady())
            {
                if (!server_chunk.onData(it))
                    return Network::FilterStatus::Continue;
                if (server_end_of_chunk)
                {
                    // it's a begining of a new chunk
                    // client_chunk.value shouldn't be 0
                    ENVOY_CONN_LOG(debug, "ClickHouse from server: chunk started, size {}", write_callbacks_->connection(), server_chunk.value);
                }
                else
                {
                    // if client_chunk.value > 0 it's a chunk continuation
                    if (server_chunk.value)
                        ENVOY_CONN_LOG(debug, "ClickHouse from server: chunk started, size {}", write_callbacks_->connection(), server_chunk.value);
                    else
                        ENVOY_CONN_LOG(debug, "ClickHouse from server: chunk ended", write_callbacks_->connection());
                }
            }

            if (server_chunk.value == 0)
            {
                // it's the end of the chunk
                server_chunk.reset();
                server_end_of_chunk = true;

                server_packet_type.reset();

                continue;
            }

            // it's a begining of a new chunk
            if (server_end_of_chunk)
                server_end_of_chunk = false;

            if (it.available() < server_chunk.value)
            {
                server_chunk.value -= it.available();
                // process it
                packet_processor(it);
                return Network::FilterStatus::Continue;
            }

            Buffer::Iterator sub(it, server_chunk.value);
            // process sub
            packet_processor(sub);
            it += server_chunk.value;
            server_chunk.reset();
        }

        return Network::FilterStatus::Continue;
    }

    try
    {
        if (!server_handshake.isReady())
            if (!server_handshake.onData(it))
                return Network::FilterStatus::Continue;

        assert(server_handshake.isReady());

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
                 write_callbacks_->connection(), e.what());
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

    if (protocol_state.chunked_client.get())
    {
        auto packet_processor = [this](Buffer::Iterator & data) -> bool
        {
            if (this->client_packet_type.isReady())
                return true;
            if (!this->client_packet_type.onData(data))
                return false;
            ENVOY_CONN_LOG(debug, "ClickHouse from client: packet ({}) {}",
                read_callbacks_->connection(), this->client_packet_type.value, Server::toString(this->client_packet_type.value));
            return true;
        };

        while (it)
        {
            if (!client_chunk.isReady())
            {
                if (!client_chunk.onData(it))
                    return Network::FilterStatus::Continue;
                if (client_end_of_chunk)
                {
                    // it's a begining of a new chunk
                    // client_chunk.value shouldn't be 0
                    ENVOY_CONN_LOG(debug, "ClickHouse from client: chunk started, size {}", read_callbacks_->connection(), client_chunk.value);
                }
                else
                {
                    // if client_chunk.value > 0 it's a chunk continuation
                    if (client_chunk.value)
                        ENVOY_CONN_LOG(debug, "ClickHouse from client: chunk started, size {}", read_callbacks_->connection(), client_chunk.value);
                    else
                        ENVOY_CONN_LOG(debug, "ClickHouse from client: chunk ended", read_callbacks_->connection());
                }
            }

            if (client_chunk.value == 0)
            {
                // it's the end of the chunk
                client_chunk.reset();
                client_end_of_chunk = true;

                client_packet_type.reset();

                continue;
            }

            // it's a begining of a new chunk
            if (client_end_of_chunk)
                client_end_of_chunk = false;

            if (it.available() < client_chunk.value)
            {
                client_chunk.value -= it.available();
                // process it
                packet_processor(it);
                return Network::FilterStatus::Continue;
            }

            Buffer::Iterator sub(it, client_chunk.value);
            // process sub
            packet_processor(sub);
            it += client_chunk.value;
            client_chunk.reset();
        }

        return Network::FilterStatus::Continue;
    }

    try
    {
        if (!client_handshake.isReady())
            if (!client_handshake.onData(it))
                return Network::FilterStatus::Continue;

        assert(client_handshake.isReady());

        if (!protocol_state.chunked_client.get())
            client_hands_off = true;
        if (!protocol_state.chunked_server.get())
            server_hands_off = true;

        ENVOY_CONN_LOG(info,
            "ClickHouse from client: Hello - client_name '{}', client_version_major '{}', client_version_minor '{}', client_tcp_protocol_version '{}', default_db '{}', user '{}', password '{}', quota_key '{}', proto_send_chunked_cl '{}', proto_recv_chunked_cl '{}'",
            read_callbacks_->connection(),
            client_handshake.hello.client_name.value,
            client_handshake.hello.client_version_major.value,
            client_handshake.hello.client_version_minor.value,
            client_handshake.hello.client_tcp_protocol_version.value,
            client_handshake.hello.default_db.value,
            client_handshake.hello.user.value,
            client_handshake.hello.password.value,
            client_handshake.addendum.quota_key.value,
            client_handshake.addendum.proto_send_chunked_cl.value,
            client_handshake.addendum.proto_recv_chunked_cl.value);
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