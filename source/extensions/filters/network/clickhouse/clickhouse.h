#pragma once

#include "envoy/network/filter.h"

#include "protocol.h"

#include "source/common/common/logger.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <openssl/pkcs7.h>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ClickHouse {


class ClickHouseFilter : public Network::Filter, Logger::Loggable<Logger::Id::filter>
{
public:
    explicit ClickHouseFilter() : client_handshake(protocol_state), server_handshake(protocol_state) {}
    // Network::Filter
    Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
    Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;
    Network::FilterStatus onNewConnection() override { return Network::FilterStatus::Continue; }
    void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override { read_callbacks_ = &callbacks; }
    void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override { write_callbacks_ = &callbacks; }

private:
    ProtocolState protocol_state {};

    ReaderPacketCleintHandshake client_handshake;
    bool client_hands_off {false};

    ReaderPODBinary<uint32_t> client_chunk;
    bool client_end_of_chunk {true};
    ReaderVarUInt client_packet_type;

    ReaderPODBinary<uint32_t> server_chunk;
    bool server_end_of_chunk {true};
    ReaderVarUInt server_packet_type;

    ReaderPacketServerHandshake server_handshake;
    bool server_hands_off {false};

    Network::ReadFilterCallbacks* read_callbacks_{};
    Network::WriteFilterCallbacks* write_callbacks_{};
};

} // namespace ClickHouse
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy