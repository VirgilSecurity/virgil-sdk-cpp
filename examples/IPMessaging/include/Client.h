#ifndef IPMESSAGING_CLIENT_H
#define IPMESSAGING_CLIENT_H

#include <string>

#include "Channel.h"

namespace virgil {
namespace IPMessaging {

    class Client {
    public:
        Client() = default;
        explicit Client(const std::string& userName);

        Channel joinChannel(const std::string& channelName);

    private:
        std::string userName_;
    };
}
}

#endif
