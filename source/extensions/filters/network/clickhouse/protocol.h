#pragma once

#include "util.h"
#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ClickHouse {

class ProtocolException : public EnvoyException
{
public:
    explicit ProtocolException(const std::string & message) : EnvoyException(message) {}
};

namespace EncodedUserInfo
{
    /// Marker for the inter-server secret (passed as the user name)
    /// (anyway user cannot be started with a whitespace)
    const std::string USER_INTERSERVER_MARKER {" INTERSERVER SECRET "};
    /// Marker for SSH-keys-based authentication (passed as the user name)
    const std::string SSH_KEY_AUTHENTICAION_MARKER {" SSH KEY AUTHENTICATION "};
    /// Marker for JSON Web Token authentication
    const std::string JWT_AUTHENTICAION_MARKER {" JWT AUTHENTICATION "};
};


namespace ProtocolVersion
{
    static constexpr auto DBMS_MIN_REVISION_WITH_SERVER_TIMEZONE = 54058;
    static constexpr auto DBMS_MIN_REVISION_WITH_SERVER_DISPLAY_NAME = 54372;
    static constexpr auto DBMS_MIN_REVISION_WITH_VERSION_PATCH = 54401;
    static constexpr auto DBMS_MIN_PROTOCOL_VERSION_WITH_PASSWORD_COMPLEXITY_RULES = 54461;
    static constexpr auto DBMS_MIN_REVISION_WITH_INTERSERVER_SECRET_V2 = 54462;
    static constexpr auto DBMS_MIN_PROTOCOL_VERSION_WITH_ADDENDUM = 54458;
    static constexpr auto DBMS_MIN_PROTOCOL_VERSION_WITH_QUOTA_KEY = 54458;
    static constexpr auto DBMS_MIN_PROTOCOL_VERSION_WITH_CHUNKED_PACKETS = 54470;
}

struct ProtocolState
{
    std::mutex mutex;
    Synchronized<uint64_t> tcp_protocol_version { 0, mutex };
    Synchronized<bool> is_ssh_based_auth { false, mutex };
    Synchronized<bool> chunked_client { false, mutex };
    Synchronized<bool> chunked_server { false, mutex };
};

namespace Client
{
    enum Enum
    {
        Hello = 0,                      /// Name, version, revision, default DB
        Query = 1,                      /// Query id, query settings, stage up to which the query must be executed,
                                        /// whether the compression must be used,
                                        /// query text (without data for INSERTs).
        Data = 2,                       /// A block of data (compressed or not).
        Cancel = 3,                     /// Cancel the query execution.
        Ping = 4,                       /// Check that connection to the server is alive.
        TablesStatusRequest = 5,        /// Check status of tables on the server.
        KeepAlive = 6,                  /// Keep the connection alive
        Scalar = 7,                     /// A block of data (compressed or not).
        IgnoredPartUUIDs = 8,           /// List of unique parts ids to exclude from query processing
        ReadTaskResponse = 9,           /// A filename to read from s3 (used in s3Cluster)
        MergeTreeReadTaskResponse = 10, /// Coordinator's decision with a modified set of mark ranges allowed to read

        SSHChallengeRequest = 11,       /// Request SSH signature challenge
        SSHChallengeResponse = 12,      /// Reply to SSH signature challenge
        MAX = SSHChallengeResponse,
    };

    inline const char * toString(uint64_t packet)
    {
        static const char * data[] = {
            "Hello",
            "Query",
            "Data",
            "Cancel",
            "Ping",
            "TablesStatusRequest",
            "KeepAlive",
            "Scalar",
            "IgnoredPartUUIDs",
            "ReadTaskResponse",
            "MergeTreeReadTaskResponse",
            "SSHChallengeRequest",
            "SSHChallengeResponse"
        };
        return packet <= MAX
            ? data[packet]
            : "Unknown packet";
    }
}

namespace Server
{
    enum Enum
    {
        Hello = 0,                      /// Name, version, revision.
        Data = 1,                       /// A block of data (compressed or not).
        Exception = 2,                  /// The exception during query execution.
        Progress = 3,                   /// Query execution progress: rows read, bytes read.
        Pong = 4,                       /// Ping response
        EndOfStream = 5,                /// All packets were transmitted
        ProfileInfo = 6,                /// Packet with profiling info.
        Totals = 7,                     /// A block with totals (compressed or not).
        Extremes = 8,                   /// A block with minimums and maximums (compressed or not).
        TablesStatusResponse = 9,       /// A response to TablesStatus request.
        Log = 10,                       /// System logs of the query execution
        TableColumns = 11,              /// Columns' description for default values calculation
        PartUUIDs = 12,                 /// List of unique parts ids.
        ReadTaskRequest = 13,           /// String (UUID) describes a request for which next task is needed
                                        /// This is such an inverted logic, where server sends requests
                                        /// And client returns back response
        ProfileEvents = 14,             /// Packet with profile events from server.
        MergeTreeAllRangesAnnouncement = 15,
        MergeTreeReadTaskRequest = 16,  /// Request from a MergeTree replica to a coordinator
        TimezoneUpdate = 17,            /// Receive server's (session-wide) default timezone
        SSHChallenge = 18,              /// Return challenge for SSH signature signing
        MAX = SSHChallenge,

    };

    /// NOTE: If the type of packet argument would be Enum, the comparison packet >= 0 && packet < 10
    /// would always be true because of compiler optimization. That would lead to out-of-bounds error
    /// if the packet is invalid.
    /// See https://www.securecoding.cert.org/confluence/display/cplusplus/INT36-CPP.+Do+not+use+out-of-range+enumeration+values
    inline const char * toString(uint64_t packet)
    {
        static const char * data[] = {
            "Hello",
            "Data",
            "Exception",
            "Progress",
            "Pong",
            "EndOfStream",
            "ProfileInfo",
            "Totals",
            "Extremes",
            "TablesStatusResponse",
            "Log",
            "TableColumns",
            "PartUUIDs",
            "ReadTaskRequest",
            "ProfileEvents",
            "MergeTreeAllRangesAnnouncement",
            "MergeTreeReadTaskRequest",
            "TimezoneUpdate",
            "SSHChallenge",
        };
        return packet <= MAX
            ? data[packet]
            : "Unknown packet";
    }
}

struct Reader
{
    virtual ~Reader() = default;
    virtual bool onData(Buffer::Iterator & data) = 0;
    virtual bool isReady() = 0;
    virtual void reset() = 0;
};


struct ReaderVarUInt : public Reader
{
    using value_type = uint64_t;
    value_type value {};
    size_t i = 0;

    bool onData(Buffer::Iterator & data) override
    {
        for (; i < 10 && data; ++data)
        {
            value |= (*data & 0x7F) << (7 * i);
            if (*data & 0x80)
                ++i;
            else
                i = 10;
        }
        return isReady();
    }

    bool isReady() override { return i == 10; }

    void reset() override
    {
        value = 0;
        i = 0;
    }
};

struct ReaderString : public Reader
{
    using value_type = std::string;
    value_type value;
    size_t i = 0;

    ReaderVarUInt size;

    bool onData(Buffer::Iterator & data) override
    {
        if (!size.isReady())
            if (!size.onData(data))
                return false;

        size_t available = data.available();
        if (available <= size.value - i)
        {
            value.append(data, data.end());
            data = data.end();
            i += available;
        }
        else
        {
            value.append(data, data + static_cast<Buffer::Iterator::difference_type>(size.value - i));
            data += size.value - i;
            i = size.value;
        }

        return isReady();
    }

    bool isReady() override { return size.isReady() && i == size.value; }

    void reset() override
    {
        value.erase();
        i = 0;
        size.reset();
    }
};

template <typename T>
struct ReaderPODBinary : public Reader
{
    using value_type = T;
    value_type value {};
    size_t i = 0;

    bool onData(Buffer::Iterator & data) override
    {
        size_t available = data.available();
        if (available <= sizeof(T) - i)
        {
            std::copy(data, data.end(), reinterpret_cast<char*>(&value) + i);
            data = data.end();
            i += available;
        }
        else
        {
            std::copy(data, data + static_cast<Buffer::Iterator::difference_type>(sizeof(T) - i), reinterpret_cast<char*>(&value) + i);
            data += sizeof(T) - i;
            i = sizeof(T);
        }

        return isReady();
    }

    bool isReady() override { return i == sizeof(T); }

    void reset() override
    {
        value = T{};
        i = 0;
    }
};


struct ReaderPacketCleintHandshake;

struct ReaderPacketCleintHello : public Reader
{
    ReaderVarUInt packet_type;

    using reader_vector = std::vector<Reader*>;
    using reader_iterator = reader_vector::const_iterator;

    ReaderPacketCleintHandshake & handshake;

    ReaderString  client_name;
    ReaderVarUInt client_version_major;
    ReaderVarUInt client_version_minor;
    ReaderVarUInt client_tcp_protocol_version;
    ReaderString  default_db;
    ReaderString  user;
    ReaderString  password;

    reader_vector readers {
        &client_name,
        &client_version_major,
        &client_version_minor,
        &client_tcp_protocol_version,
        &default_db,
        &user,
        &password
    };

    reader_iterator current_reader = readers.begin();

    explicit ReaderPacketCleintHello(ReaderPacketCleintHandshake & handshake) : handshake(handshake) {}

    bool onData(Buffer::Iterator & data) override
    {
        if (!packet_type.isReady())
            if (!packet_type.onData(data))
                return false;
        if (packet_type.value != Client::Hello)
            throw ProtocolException("Hello is expected in handshake");

        while (!isReady() && data)
            if ((*current_reader)->onData(data))
                ++current_reader;

        return isReady();
    }

    bool isReady() override { return current_reader == readers.end(); }

    void reset() override
    {
        packet_type.reset();
        client_name.reset();
        client_version_major.reset();
        client_version_minor.reset();
        client_tcp_protocol_version.reset();
        default_db.reset();
        user.reset();
        password.reset();
        current_reader = readers.begin();
    }
};

struct ReaderPacketCleintSSHChallengeRequest : public Reader
{
    ReaderVarUInt packet_type;

    ReaderPacketCleintHandshake & handshake;
    explicit ReaderPacketCleintSSHChallengeRequest(ReaderPacketCleintHandshake & handshake) : handshake(handshake) {}

    bool onData(Buffer::Iterator & data) override
    {
        if (!packet_type.isReady())
            if (!packet_type.onData(data))
                return false;
        if (packet_type.value != Client::SSHChallengeRequest)
            throw ProtocolException("SSHChallengeRequest is expected in handshake");

        return isReady();
    }
    bool isReady() override { return packet_type.isReady(); }
    void reset() override { packet_type.reset(); }
};

struct ReaderPacketCleintSSHChallengeResponse : public Reader
{
    ReaderVarUInt packet_type;
    ReaderString  signature;

    ReaderPacketCleintHandshake & handshake;
    explicit ReaderPacketCleintSSHChallengeResponse(ReaderPacketCleintHandshake & handshake) : handshake(handshake) {}

    bool onData(Buffer::Iterator & data) override
    {
        if (!packet_type.isReady())
            if (!packet_type.onData(data))
                return false;
        if (packet_type.value != Client::SSHChallengeRequest)
            throw ProtocolException("SSHChallengeResponse is expected in handshake");

        if (!signature.isReady())
            signature.onData(data);

        return isReady();
    }

    bool isReady() override
    {
        return
            packet_type.isReady() &&
            signature.isReady();
    }

    void reset() override
    {
        packet_type.reset();
        signature.reset();
    }
};

struct ReaderPacketCleintAddendum : public Reader
{
    ReaderString quota_key;
    ReaderString proto_send_chunked_cl;
    ReaderString proto_recv_chunked_cl;

    bool ready = false;

    ReaderPacketCleintHandshake & handshake;
    explicit ReaderPacketCleintAddendum(ReaderPacketCleintHandshake & handshake) : handshake(handshake) {}

    bool onData(Buffer::Iterator &data) override;

    bool isReady() override { return ready; }

    void reset() override
    {
        ready = false;
        quota_key.reset();
        proto_send_chunked_cl.reset();
        proto_recv_chunked_cl.reset();
    }
};

struct ReaderPacketCleintHandshake : public Reader
{
    enum class State
    {
        Hello = 0,
        SSHChalengeRequest,
        SSHChalengeResponse,
        Addendum,
        Done
    } state {State::Hello};

    ProtocolState & protocol_state;

    explicit ReaderPacketCleintHandshake(ProtocolState & protocol_state) : protocol_state(protocol_state) {}

    ReaderPacketCleintHello hello {*this};
    ReaderPacketCleintSSHChallengeRequest ssh_chalange_request {*this};
    ReaderPacketCleintSSHChallengeResponse ssh_chalange_response {*this};
    ReaderPacketCleintAddendum addendum {*this};

    bool onData(Buffer::Iterator & data) override
    {
        do
        {
            switch (state)
            {
                case State::Hello:
                {
                    if (!hello.onData(data))
                        break;
                    
                    if (hello.user.value.compare(0, EncodedUserInfo::SSH_KEY_AUTHENTICAION_MARKER.size(), EncodedUserInfo::SSH_KEY_AUTHENTICAION_MARKER) == 0 && hello.password.value.empty())
                        state = State::SSHChalengeRequest;
                    else if (hello.client_tcp_protocol_version.value >= ProtocolVersion::DBMS_MIN_PROTOCOL_VERSION_WITH_ADDENDUM)
                        state = State::Addendum;
                    else
                        state = State::Done;

                    protocol_state.tcp_protocol_version.set(hello.client_tcp_protocol_version.value);
                    protocol_state.is_ssh_based_auth.set(state == State::SSHChalengeRequest);

                    break;
                }
                case State::SSHChalengeRequest:
                {
                    if (!ssh_chalange_request.onData(data))
                        break;
                    state = State::SSHChalengeResponse;
                    break;
                }
                case State::SSHChalengeResponse:
                {
                    if (!ssh_chalange_response.onData(data))
                        break;
                    if (hello.client_tcp_protocol_version.value >= ProtocolVersion::DBMS_MIN_PROTOCOL_VERSION_WITH_ADDENDUM)
                        state = State::Addendum;
                    else
                        state = State::Done;
                    break;
                }
                case State::Addendum:
                {
                    if (!addendum.onData(data))
                        break;
                    state = State::Done;
                    break;
                }
                case State::Done:
                    throw ProtocolException("Hello is unexpected");
            }
        } while (state != State::Done && data);

        return isReady();
    }

    bool isReady() override { return state == State::Done; }
    void reset() override
    {
        state = State::Hello;
        hello.reset();
        ssh_chalange_request.reset();
        ssh_chalange_response.reset();
        addendum.reset();
    }
};



struct ReaderPasswordComplexityRules : public Reader
{
    struct ReaderRule : public Reader
    {
        ReaderString original_pattern;
        ReaderString exception_message;

        bool onData(Buffer::Iterator & data) override
        {
            if (!original_pattern.isReady())
                if (!original_pattern.onData(data))
                    return false;

            if (!exception_message.isReady())
                if (!exception_message.onData(data))
                    return false;

            return true;
        }

        bool isReady() override { return original_pattern.isReady() && exception_message.isReady(); }

        void reset() override
        {
            original_pattern.reset();
            exception_message.reset();
        }
    };

    ReaderVarUInt size;
    std::vector<ReaderRule> rules;

    bool size_is_ready = false;
    bool rules_is_ready = false;

    bool onData(Buffer::Iterator &data) override
    {
        if (!size_is_ready)
        {
            if (!size.onData(data))
                return false;
            size_is_ready = true;
            if (size.value > 0)
                rules.reserve(size.value);
            else
                rules_is_ready = true;
        }

        while (!rules_is_ready || data)
        {
            if (!rules.empty())
            {
                if (!rules.back().original_pattern.isReady())
                    if (!rules.back().original_pattern.onData(data))
                        break;
                if (!rules.back().exception_message.isReady())
                    if (!rules.back().exception_message.onData(data))
                        break;
            }
            if (rules.size() == size.value)
            {
                rules_is_ready = true;
                return true;
            }
            rules.emplace_back();
        }

        return false;
    }

    bool isReady() override { return rules_is_ready; }

    void reset() override
    {
        size_is_ready = false;
        rules_is_ready = false;
        size.reset();
        rules.clear();
    }
};

struct ReaderPacketServerHandshake;

struct ReaderPacketServerSSHChallenge : public Reader
{
    ReaderVarUInt packet_type;

    ReaderPacketServerHandshake & handshake;
    explicit ReaderPacketServerSSHChallenge(ReaderPacketServerHandshake & handshake) : handshake(handshake) {}

    bool onData(Buffer::Iterator & data) override
    {
        if (!packet_type.isReady())
            if (!packet_type.onData(data))
                return false;
        if (packet_type.value != Server::SSHChallenge)
            throw ProtocolException("SSHChallenge is expected in handshake");

        return isReady();
    }
    bool isReady() override { return packet_type.isReady(); }
    void reset() override { packet_type.reset(); }
};

struct ReaderPacketServerHello : public Reader
{
    using reader_vector = std::vector<std::pair<Reader*, uint64_t>>;
    using reader_iterator = reader_vector::const_iterator;

    ReaderPacketServerHandshake & handshake;
    explicit ReaderPacketServerHello(ReaderPacketServerHandshake & handshake) : handshake(handshake) {}

    ReaderVarUInt packet_type;

    ReaderString  version_name;
    ReaderVarUInt version_major;
    ReaderVarUInt version_minor;
    ReaderVarUInt dbms_tcp_protocol_version;
    ReaderString  time_zone;
    ReaderString  server_display_name;
    ReaderVarUInt version_patch;
    ReaderString proto_send_chunked_srv;
    ReaderString proto_recv_chunked_srv;
    ReaderPasswordComplexityRules password_complexity_rules;
    ReaderPODBinary<unsigned long> nonce;

    reader_vector readers {
        { &version_name, 0 },
        { &version_major, 0 },
        { &version_minor, 0 },
        { &dbms_tcp_protocol_version, 0 },
        { &time_zone, ProtocolVersion::DBMS_MIN_REVISION_WITH_SERVER_TIMEZONE },
        { &server_display_name, ProtocolVersion::DBMS_MIN_REVISION_WITH_SERVER_DISPLAY_NAME },
        { &version_patch, ProtocolVersion::DBMS_MIN_REVISION_WITH_VERSION_PATCH },
        { &proto_send_chunked_srv, ProtocolVersion::DBMS_MIN_PROTOCOL_VERSION_WITH_CHUNKED_PACKETS },
        { &proto_recv_chunked_srv, ProtocolVersion::DBMS_MIN_PROTOCOL_VERSION_WITH_CHUNKED_PACKETS },
        { &password_complexity_rules, ProtocolVersion::DBMS_MIN_PROTOCOL_VERSION_WITH_PASSWORD_COMPLEXITY_RULES },
        { &nonce, ProtocolVersion::DBMS_MIN_REVISION_WITH_INTERSERVER_SECRET_V2 }
    };

    reader_iterator current_reader {readers.begin()};

    bool onData(Buffer::Iterator & data) override;

    bool isReady() override { return current_reader == readers.end(); }

    void reset() override
    {
        version_name.reset();
        version_major.reset();
        version_minor.reset();
        dbms_tcp_protocol_version.reset();
        time_zone.reset();
        server_display_name.reset();
        version_patch.reset();
        proto_send_chunked_srv.reset();
        proto_recv_chunked_srv.reset();
        password_complexity_rules.reset();
        nonce.reset();
    }
};

struct ReaderPacketServerHandshake : public Reader
{
    enum class State
    {
        SSHChallenge = 0,
        Hello,
        Done
    } state {State::SSHChallenge};

    uint64_t tcp_protocol_version = 0;
    bool is_ssh_based_auth = false;

    ProtocolState & protocol_state;
    explicit ReaderPacketServerHandshake(ProtocolState & protocol_state) : protocol_state(protocol_state) {}

    ReaderPacketServerSSHChallenge ssh_chalange {*this};
    ReaderPacketServerHello hello {*this};

    bool onData(Buffer::Iterator & data) override
    {
        tcp_protocol_version = protocol_state.tcp_protocol_version.get();
        is_ssh_based_auth = protocol_state.is_ssh_based_auth.get();

        if (!is_ssh_based_auth)
            state = State::Hello;

        do
        {
            switch (state)
            {
                case State::SSHChallenge:
                {
                    if (!ssh_chalange.onData(data))
                        break;
                    state = State::Hello;
                    break;
                }
                case State::Hello:
                {
                    if (!hello.onData(data))
                        break;
                    state = State::Done;
                    break;
                }
                case State::Done:
                    throw ProtocolException("Hello is unexpected");
            }
        } while (state != State::Done && data);

        return isReady();
    }

    bool isReady() override { return state == State::Done; }
    void reset() override
    {
        state = State::SSHChallenge;
        ssh_chalange.reset();
        hello.reset();
    }
};


} // namespace ClickHouse
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
