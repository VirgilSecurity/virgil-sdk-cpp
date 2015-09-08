#include <iostream>
#include <memory>
#include <string>

#include <json.hpp>

#include "fakeit.hpp"

#include <virgil/sdk/keys/client/KeysClient.h>
#include <virgil/sdk/keys/model/ContainerType.h>
#include <virgil/sdk/keys/util/JsonKey.h>

using json = nlohmann::json;
using namespace fakeit;

using virgil::sdk::keys::client::KeysClientConnection;
using virgil::sdk::keys::client::KeysClient;
using virgil::sdk::keys::model::ContainerType;
using virgil::sdk::keys::util::JsonKey;


ContainerType foo();


TEST_CASE("Container foo", "normal") {


    ContainerType t = foo();


}

ContainerType foo() {
    json containerTypeJson =  { JsonKey::containerType, "normal" };
    std::string containerTypeStr = containerTypeJson[1];
    return containerTypeStr == "easy" ? ContainerType::kEasy : ContainerType::kNormal;
}


