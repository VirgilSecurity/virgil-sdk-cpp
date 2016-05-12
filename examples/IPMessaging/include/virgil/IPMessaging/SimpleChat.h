#ifndef SIMPLE_CHAT_H
#define SIMPLE_CHAT_H

#include <map>
#include <string>

#include <virgil/sdk/ServicesHub.h>

#include <virgil/IPMessaging/Client.h>
#include <virgil/IPMessaging/ChatMember.h>
#include <virgil/IPMessaging/Channel.h>
#include <virgil/IPMessaging/Constants.h>

using MapCardIdPublicKey = std::map<virgil::crypto::VirgilByteArray, virgil::crypto::VirgilByteArray>;

namespace virgil {
namespace IPMessaging {

    class SimpleChat {
    public:
        SimpleChat() = default;
        ~SimpleChat();

        void launch();
        void onMessageRecived(const std::string& sender, const std::string& message);

    private:
        void startMessaging();
        void onMessageSend(const std::string& message);
        virgil::IPMessaging::ChatMember autorize(const std::string& emailAddress);
        virgil::IPMessaging::ChatMember registerUser(const std::string& emailAddress);
        MapCardIdPublicKey getChannelRecipients();
        virgil::sdk::dto::ValidatedIdentity identityConfirm(const std::string& email);

    private:
        virgil::sdk::ServicesHub servicesHub_ = virgil::sdk::ServicesHub(virgil::IPMessaging::VIRGIL_ACCESS_TOKEN);
        virgil::IPMessaging::Client client_;
        virgil::IPMessaging::ChatMember currentMember_;
        virgil::IPMessaging::Channel channel_;
        std::string logFile_;
    };
}
}

#endif
