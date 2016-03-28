#include <iostream>

#include "SimpleChat.h"

int main() {

    std::cin.exceptions(std::ios::failbit | std::ios::badbit);
    virgil::IPMessaging::SimpleChat chat;
    chat.launch();

    return 0;
}
