#include <virgil/sdk/keys/Version.h>

using virgil::sdk::keys::Version;

size_t Version::asNumber() {
    return (majorVersion() << 16) | (minorVersion() << 8) | patchVersion();
}

std::string Version::asString() {
    return std::string("@VIRGIL_SDK_KEYS_VERSION@");
}

size_t Version::majorVersion() {
    return @VIRGIL_SDK_KEYS_VERSION_MAJOR@;
}

size_t Version::minorVersion() {
    return @VIRGIL_SDK_KEYS_VERSION_MINOR@;
}

size_t Version::patchVersion() {
    return @VIRGIL_SDK_KEYS_VERSION_PATCH@;
}
