#include <iostream>
#include <vector>

#include <nlohman/json.hpp>

#include <restless/restless.hpp>

#include <virgil/IPMessaging/Channel.h>
#include <virgil/IPMessaging/Constants.h>
#include <virgil/IPMessaging/dto/Message.h>

using json = nlohmann::json;

using HttpRequest = asoni::Handle;

namespace vipm = virgil::IPMessaging;

vipm::Channel::Channel(const std::string& channelName, const std::string& identityToken) {
    channelName_ = channelName;
    identityToken_ = identityToken;
}

void vipm::Channel::sendMessage(const std::string& message) {
    try {
        HttpRequest httpRequest;
        json payload = {{"message", message}};

        httpRequest.header({{"X-IDENTITY-TOKEN", identityToken_}}).content("application/json", payload.dump());

        std::string endpoint = "/channels/" + channelName_ + "/messages";
        httpRequest.post(vipm::IPMESSAGING_API_URL + endpoint).exec();

    } catch (std::exception& exception) {
        throw std::logic_error(std::string("void vipm::Channel::sendMessage(const std::string& message) ") +
                               exception.what());
    }
}

std::vector<std::string> vipm::Channel::getMembers() const {
    try {
        HttpRequest httpRequest;
        httpRequest.header({{"X-IDENTITY-TOKEN", identityToken_}}).content("application/json", "");

        std::string endpoint = "/channels/" + channelName_ + "/members";
        httpRequest.get(vipm::IPMESSAGING_API_URL + endpoint);

        auto response = httpRequest.exec();

        std::string braces = "{},";
        std::size_t start = response.body.find(braces);
        if (start != std::string::npos) {
            response.body.erase(start, braces.length());
        }

        if (response.body.empty()) {
            return std::vector<std::string>();
        }

        json jEmails = json::parse(response.body);
        std::vector<std::string> emails;
        for (const auto& jEmail : jEmails) {
            emails.push_back(jEmail["identifier"]);
        }

        return emails;

    } catch (std::exception& exception) {
        throw std::logic_error(std::string("std::vector<std::string> vipm::Channel::getMembers() const ") +
                               exception.what());
    }
}

void vipm::Channel::watch() {
    HttpRequest httpRequest;
    httpRequest.header({{"X-IDENTITY-TOKEN", identityToken_}}).content("application/json", "");

    std::string endpoint = "/channels/" + channelName_ + "/messages";
    if (!lastMessageId_.empty()) {
        endpoint += "?last_message_id=" + lastMessageId_;
    }
    httpRequest.get(vipm::IPMESSAGING_API_URL + endpoint);
    auto response = httpRequest.exec();

    json jMessages;

    try {
        jMessages = json::parse(response.body);
    } catch (std::exception& exception) {
        return;
    }

    std::vector<vipm::dto::Message> messagesDto = vipm::dto::messagesFromJson(jMessages.dump());
    if (!messagesDto.empty()) {
        vipm::dto::Message lastMessageDto = messagesDto.back();
        lastMessageId_ = lastMessageDto.getId();
    } else {
        return;
    }

    if (messageRecived.empty()) {
        return;
    }

    for (const auto& messageDto : messagesDto) {
        for (const auto& onMessageRecived : messageRecived) {
            onMessageRecived(messageDto.getSenderIdentifier(), messageDto.getMessage());
        }
    }
}
