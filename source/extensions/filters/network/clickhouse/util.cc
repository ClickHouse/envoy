
#include "source/extensions/filters/network/clickhouse/util.h"

#include "source/common/common/logger.h"
#include <cstdint>
#include <stdexcept>
#include <utility>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ClickHouse {


bool readVarUInt(Buffer::Instance& data, uint64_t& offset, uint64_t& value) {
  value = 0;
  char byte;
  bool finished = false;

  // Under variable length encoding it's possible that required length is less than 10 bytes.
  // So we check byte by byte and avoid causing errors on the buffer.
  // TODO: add length check.
  for (size_t i = 0; i < 10 && !finished; ++i) {
    data.copyOut(offset, 1, &byte);
    value |= (byte & 0x7F) << (7 * i);
    offset++;
    if (!(byte & 0x80)) {
      return value;
    }
  }
  // NOTE to myself: data.drain would cause the further filter not to see the data.
  // So we just track the offset without touching data.
  return value;
}

void readStrict(Buffer::Instance& buf, size_t& offset, char* to, size_t n) {
  buf.copyOut(offset, n, to);
  offset += n;
}

void readStringBinary(Buffer::Instance& buf, uint64_t& offset, std::string& s) {
  size_t size = 0;
  ENVOY_LOG_MISC(debug, "before reading string size, offset {}", offset);
  readVarUInt(buf, offset, size);
  ENVOY_LOG_MISC(debug, "after reading string size {}, offset {}", size, offset);

  s.resize(size);
  readStrict(buf, offset, s.data(), size);
}

} // namespace ClickHouse
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
