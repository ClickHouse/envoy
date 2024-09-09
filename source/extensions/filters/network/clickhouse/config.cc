#include "envoy/extensions/filters/network/clickhouse/v3/clickhouse.pb.h"
#include "envoy/extensions/filters/network/clickhouse/v3/clickhouse.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/clickhouse/clickhouse.h"
#include "source/extensions/filters/network/well_known_names.h"


namespace Envoy
{
namespace Extensions
{
namespace NetworkFilters
{
namespace ClickHouse
{

class ClickHouseConfigFactory
    : public Common::FactoryBase<envoy::extensions::filters::network::clickhouse::v3::ClickHouse>
{
public:
    ClickHouseConfigFactory() : FactoryBase("envoy.filters.network.clickhouse") {}

private:
    Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
        const envoy::extensions::filters::network::clickhouse::v3::ClickHouse&,
        Envoy::Server::Configuration::FactoryContext&) override
    {
        return [](Network::FilterManager& filter_manager) -> void
        {
            auto filter = std::make_shared<ClickHouseFilter>();
            filter_manager.addReadFilter(filter);
            filter_manager.addWriteFilter(filter);
        };
    }

    bool isTerminalFilterByProtoTyped(
        const envoy::extensions::filters::network::clickhouse::v3::ClickHouse&,
        Envoy::Server::Configuration::FactoryContext&) override
    {
        return false;
    }
};

REGISTER_FACTORY(ClickHouseConfigFactory, Envoy::Server::Configuration::NamedNetworkFilterConfigFactory) {"envoy.clickhouse"};

} // namespace ClickHouse
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
