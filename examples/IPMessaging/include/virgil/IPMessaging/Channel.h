#ifndef CHANNEL_H
#define CHANNEL_H

#include <string>
#include <functional>
#include <vector>

namespace virgil {
namespace IPMessaging {

    class Channel {
    public:
        std::vector<std::function<void(const std::string&, const std::string&)>> messageRecived;

    public:
        Channel() = default;

        Channel(const std::string& channelName_, const std::string& identityToken);

        void sendMessage(const std::string& message);

        std::vector<std::string> getMembers() const;

        void watch();

    private:
        std::string channelName_;
        std::string identityToken_;
        std::string lastMessageId_;

    private:
        void getChannelMessages();
    };
}
}

#endif
