#ifndef SIMPLE_CHAT_H
#define SIMPLE_CHAT_H

#include <map>
#include <string>

#include <virgil/sdk/ServicesHub.h>

#include "Client.h"
#include "ChatMember.h"
#include "Channel.h"
#include "Constants.h"

using MapCardIdPublicKey = std::map<virgil::crypto::VirgilByteArray, virgil::crypto::VirgilByteArray>;

namespace virgil {
namespace IPMessaging {

    class SimpleChat {
    public:
        SimpleChat() = default;

        void launch();
        void onMessageRecived(const std::string& sender, const std::string& message);

    private:
        void startMessaging();
        void onMessageSend(const std::string& message);
        virgil::IPMessaging::ChatMember autorize(const std::string& emailAddress);
        virgil::IPMessaging::ChatMember registerUser(const virgil::sdk::dto::ValidatedIdentity& validatedIdentity);
        MapCardIdPublicKey getChannelRecipients();

    private:
        virgil::sdk::ServicesHub servicesHub_ = virgil::sdk::ServicesHub(virgil::IPMessaging::VIRGIL_ACCESS_TOKEN);
        virgil::IPMessaging::Client client_;
        virgil::IPMessaging::ChatMember currentMember_;
        virgil::IPMessaging::Channel channel_;
    };
}
}

#endif
