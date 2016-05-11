#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <vector>

namespace virgil {
namespace IPMessaging {
    namespace dto {
        class Message {
        public:
            Message() = default;

            Message(const std::string& channelName, const std::string& id, const std::string& createdAt,
                    const std::string& senderIdentifier, const std::string& message);

            bool isEmpty() const;

            std::string getChannelName() const;
            std::string getId() const;
            std::string getCreatedAt() const;
            std::string getSenderIdentifier() const;
            std::string getMessage() const;

        private:
            std::string channelName_;
            std::string id_;
            std::string createdAt_;
            std::string senderIdentifier_;
            std::string message_;
        };

        std::string toJson(const Message& message);
        Message fromJson(const std::string& message);

        std::vector<Message> messagesFromJson(const std::string& messages);
    }
}
}

#endif // MESSAGE_H
