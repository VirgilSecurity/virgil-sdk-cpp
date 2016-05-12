#include <stdexcept>

#include <nlohman/json.hpp>

#include <virgil/IPMessaging/dto/Message.h>

using json = nlohmann::json;

namespace vidto = virgil::IPMessaging::dto;

vidto::Message::Message(const std::string& channelName, const std::string& id, const std::string& createdAt,
                        const std::string& senderIdentifier, const std::string& message)
        : channelName_(channelName),
          id_(id),
          createdAt_(createdAt),
          senderIdentifier_(senderIdentifier),
          message_(message) {
}

bool vidto::Message::isEmpty() const {
    return (channelName_.empty() && id_.empty() && createdAt_.empty() && senderIdentifier_.empty() && message_.empty());
}

std::string vidto::Message::getChannelName() const {
    return channelName_;
}

std::string vidto::Message::getId() const {
    return id_;
}

std::string vidto::Message::getCreatedAt() const {
    return createdAt_;
}

std::string vidto::Message::getSenderIdentifier() const {
    return senderIdentifier_;
}

std::string vidto::Message::getMessage() const {
    return message_;
}

std::string vidto::toJson(const Message& message) {
    try {
        json jMessage = {
            {"channel_name", message.getChannelName()}, {"id", message.getId()},
            {"created_at", message.getCreatedAt()},     {"sender_identifier", message.getSenderIdentifier()},
            {"message", message.getMessage()},
        };
        return jMessage.dump(4);

    } catch (std::exception& exception) {
        throw std::logic_error(std::string("string toJson(Message) ") + exception.what());
    }
}

vidto::Message vidto::fromJson(const std::string& message) {
    try {
        json jMessage = json::parse(message);
        std::string channelName = jMessage["channel_name"];
        std::string id = jMessage["id"];
        long int createdAt = jMessage["created_at"];
        std::string createdAtStr = std::to_string(createdAt);
        std::string senderIdentifier = jMessage["sender_identifier"];
        std::string jEncryptedMessageModelStr = jMessage["message"];

        return Message(channelName, id, createdAtStr, senderIdentifier, jEncryptedMessageModelStr);
    } catch (std::exception& exception) {
        return vidto::Message();
        // throw std::logic_error(std::string("Message fromJson(string) ") + exception.what());
    }
}

std::vector<vidto::Message> vidto::messagesFromJson(const std::string& messages) {
    try {
        json jMessages = json::parse(messages);
        std::vector<Message> messagesDto;
        for (const auto& jMessage : jMessages) {
            Message message = vidto::fromJson(jMessage.dump());
            messagesDto.push_back(message);
        }

        return messagesDto;
    } catch (std::exception& exception) {
        throw std::logic_error(std::string("vector<Message> messagesFromJson(string) ") + exception.what());
    }
}
