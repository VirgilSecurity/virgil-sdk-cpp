#include <iostream>
#include <string>
#include <thread>

#include <json.hpp>

#include <restless.hpp>

#include "Client.h"
#include "Constants.h"

using json = nlohmann::json;

using Http = asoni::Handle;

namespace vipm = virgil::IPMessaging;

vipm::Client::Client(const std::string& userName) : userName_(userName) {
}

vipm::Channel vipm::Client::joinChannel(const std::string& channelName) {
    std::string endpoint = "/channels/" + channelName + "/join";
    json payload = {{"identifier", userName_}};
    auto response = Http().post(IPMESSAGING_API_URL + endpoint).content("application/json", payload.dump()).exec();

    json body = json::parse(response.body);
    std::string identityToken = body["identity_token"];

    vipm::Channel channel(channelName, identityToken);

    // std::cout << "Join channel. watch()..." << std::endl;

    // std::thread thr(&vipm::Channel::watch, channel);
    // thr.detach();

    return channel;
}
