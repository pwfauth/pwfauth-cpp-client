#include "PwfClient.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace
{
    using ByteVector = std::vector<unsigned char>;

    class InternetHandle
    {
    public:
        explicit InternetHandle(HINTERNET handle = nullptr) : handle_(handle) {}
        ~InternetHandle() { if (handle_) WinHttpCloseHandle(handle_); }
        InternetHandle(const InternetHandle&) = delete;
        InternetHandle& operator=(const InternetHandle&) = delete;
        operator HINTERNET() const { return handle_; }
        bool Valid() const { return handle_ != nullptr; }

    private:
        HINTERNET handle_;
    };

    void CheckNt(NTSTATUS status, const char* operation)
    {
        if (status < 0)
            throw std::runtime_error(std::string(operation) + " failed (NTSTATUS " +
                std::to_string(static_cast<long>(status)) + ").");
    }

    void ThrowLastError(const char* operation)
    {
        throw std::runtime_error(std::string(operation) + " failed (Windows error " +
            std::to_string(GetLastError()) + ").");
    }

    // No connection at all: offline, DNS, firewall, proxy or TLS.
    void ThrowNetworkError(const char* operation)
    {
        throw PwfNetworkError("Cannot reach the license server: " + std::string(operation) +
            " failed (Windows error " + std::to_string(GetLastError()) + ").");
    }

    constexpr char NetworkLostMessage[] =
        "Cannot reach the license server. Please check your connection and sign in again.";
    constexpr char ClockSkewMessage[] =
        "Cannot verify your license because this computer's date and time are wrong. "
        "Correct them and sign in again.";
    constexpr int TooManyRequests = 429;
    constexpr std::size_t MaxResetReason = 255;  // characters, as the server counts them

    std::string JsonText(const nlohmann::json& object, const char* key)
    {
        if (object.is_object() && object.contains(key) && object[key].is_string())
            return object[key].get<std::string>();
        return {};
    }

    // The server's clock refusal: "reason": "CLOCK_SKEW", or the older plain
    // CRYPTO_ERROR whose message says the request expired.
    bool IsClockRefusal(const PwfResponse& reply)
    {
        if (JsonText(reply.data, "reason") == "CLOCK_SKEW")
            return true;
        std::string message = reply.Message();
        std::transform(message.begin(), message.end(), message.begin(),
            [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
        return reply.ErrorCode() == "CRYPTO_ERROR" && message.find("expired") != std::string::npos;
    }

    // At most `limit` characters (code points) of UTF-8 text, never cut inside one.
    std::string TruncateUtf8(const std::string& text, std::size_t limit)
    {
        std::size_t characters = 0;
        for (std::size_t index = 0; index < text.size(); ++index)
        {
            const bool startsCharacter = (static_cast<unsigned char>(text[index]) & 0xC0) != 0x80;
            if (startsCharacter && ++characters > limit)
                return text.substr(0, index);
        }
        return text;
    }

    std::string TrimAscii(const std::string& text)
    {
        const auto first = text.find_first_not_of(" \t\r\n");
        if (first == std::string::npos)
            return {};
        return text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
    }

    DWORD ToDword(std::size_t value)
    {
        if (value > std::numeric_limits<DWORD>::max())
            throw std::runtime_error("Payload is too large.");
        return static_cast<DWORD>(value);
    }

    std::wstring Utf8ToWide(const std::string& value)
    {
        if (value.empty())
            return {};
        const int required = MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
        if (required <= 0)
            ThrowLastError("UTF-8 conversion");
        std::wstring result(static_cast<std::size_t>(required), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), required) <= 0)
            ThrowLastError("UTF-8 conversion");
        return result;
    }

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty())
            return {};
        const int required = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
            nullptr, 0, nullptr, nullptr);
        if (required <= 0)
            ThrowLastError("UTF-16 conversion");
        std::string result(static_cast<std::size_t>(required), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), required, nullptr, nullptr) <= 0)
            ThrowLastError("UTF-16 conversion");
        return result;
    }

    ByteVector Sha256(const std::string& value)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        ByteVector hashObject;
        ByteVector digest;
        try
        {
            CheckNt(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
                "Opening SHA-256");
            DWORD objectSize = 0;
            DWORD digestSize = 0;
            DWORD copied = 0;
            CheckNt(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &copied, 0),
                "Reading SHA-256 object size");
            CheckNt(BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&digestSize), sizeof(digestSize), &copied, 0),
                "Reading SHA-256 digest size");
            hashObject.resize(objectSize);
            digest.resize(digestSize);
            CheckNt(BCryptCreateHash(algorithm, &hash, hashObject.data(), objectSize,
                nullptr, 0, 0), "Creating SHA-256 hash");
            CheckNt(BCryptHashData(hash,
                reinterpret_cast<PUCHAR>(const_cast<char*>(value.data())), ToDword(value.size()), 0),
                "Hashing SHA-256 data");
            CheckNt(BCryptFinishHash(hash, digest.data(), digestSize, 0),
                "Finishing SHA-256 hash");
        }
        catch (...)
        {
            if (hash) BCryptDestroyHash(hash);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            throw;
        }
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return digest;
    }

    ByteVector HmacSha256(const ByteVector& key, const std::string& message)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        ByteVector hashObject;
        ByteVector digest;
        try
        {
            CheckNt(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG), "Opening HMAC-SHA256");
            DWORD objectSize = 0;
            DWORD digestSize = 0;
            DWORD copied = 0;
            CheckNt(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &copied, 0),
                "Reading HMAC object size");
            CheckNt(BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&digestSize), sizeof(digestSize), &copied, 0),
                "Reading HMAC digest size");
            hashObject.resize(objectSize);
            digest.resize(digestSize);
            CheckNt(BCryptCreateHash(algorithm, &hash, hashObject.data(), objectSize,
                const_cast<PUCHAR>(key.data()), ToDword(key.size()), 0), "Creating HMAC hash");
            CheckNt(BCryptHashData(hash,
                reinterpret_cast<PUCHAR>(const_cast<char*>(message.data())),
                ToDword(message.size()), 0), "Hashing HMAC data");
            CheckNt(BCryptFinishHash(hash, digest.data(), digestSize, 0), "Finishing HMAC hash");
        }
        catch (...)
        {
            if (hash) BCryptDestroyHash(hash);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            throw;
        }
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return digest;
    }

    std::string HexLower(const ByteVector& bytes)
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string result;
        result.resize(bytes.size() * 2);
        for (std::size_t index = 0; index < bytes.size(); ++index)
        {
            result[index * 2] = digits[(bytes[index] >> 4) & 0x0F];
            result[index * 2 + 1] = digits[bytes[index] & 0x0F];
        }
        return result;
    }

    bool ConstantTimeEquals(const std::string& left, const std::string& right)
    {
        const std::size_t maximum = (std::max)(left.size(), right.size());
        unsigned int difference = static_cast<unsigned int>(left.size() ^ right.size());
        for (std::size_t index = 0; index < maximum; ++index)
        {
            const unsigned char a = index < left.size() ?
                static_cast<unsigned char>(left[index]) : 0;
            const unsigned char b = index < right.size() ?
                static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(right[index]))) : 0;
            difference |= static_cast<unsigned int>(a ^ b);
        }
        return difference == 0;
    }

    std::string Base64Encode(const ByteVector& bytes)
    {
        DWORD characters = 0;
        if (!CryptBinaryToStringA(bytes.data(), ToDword(bytes.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &characters))
            ThrowLastError("Base64 encoding");
        std::string result(characters, '\0');
        if (!CryptBinaryToStringA(bytes.data(), ToDword(bytes.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result.data(), &characters))
            ThrowLastError("Base64 encoding");
        if (!result.empty() && result.back() == '\0')
            result.pop_back();
        return result;
    }

    ByteVector Base64Decode(const std::string& value)
    {
        DWORD bytes = 0;
        if (!CryptStringToBinaryA(value.data(), ToDword(value.size()), CRYPT_STRING_BASE64,
            nullptr, &bytes, nullptr, nullptr))
            ThrowLastError("Base64 decoding");
        ByteVector result(bytes);
        if (!CryptStringToBinaryA(value.data(), ToDword(value.size()), CRYPT_STRING_BASE64,
            result.data(), &bytes, nullptr, nullptr))
            ThrowLastError("Base64 decoding");
        result.resize(bytes);
        return result;
    }

    ByteVector AesCbcEncrypt(const ByteVector& key, const ByteVector& iv, const std::string& plain)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_KEY_HANDLE aesKey = nullptr;
        ByteVector keyObject;
        ByteVector output;
        try
        {
            CheckNt(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0),
                "Opening AES");
            CheckNt(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                sizeof(BCRYPT_CHAIN_MODE_CBC), 0), "Selecting AES-CBC");
            DWORD objectSize = 0;
            DWORD copied = 0;
            CheckNt(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &copied, 0),
                "Reading AES object size");
            keyObject.resize(objectSize);
            CheckNt(BCryptGenerateSymmetricKey(algorithm, &aesKey, keyObject.data(), objectSize,
                const_cast<PUCHAR>(key.data()), ToDword(key.size()), 0), "Creating AES key");

            DWORD outputSize = 0;
            ByteVector ivCopy = iv;
            CheckNt(BCryptEncrypt(aesKey,
                reinterpret_cast<PUCHAR>(const_cast<char*>(plain.data())), ToDword(plain.size()),
                nullptr, ivCopy.data(), ToDword(ivCopy.size()), nullptr, 0, &outputSize,
                BCRYPT_BLOCK_PADDING), "Sizing AES ciphertext");
            output.resize(outputSize);
            ivCopy = iv;
            CheckNt(BCryptEncrypt(aesKey,
                reinterpret_cast<PUCHAR>(const_cast<char*>(plain.data())), ToDword(plain.size()),
                nullptr, ivCopy.data(), ToDword(ivCopy.size()), output.data(), outputSize,
                &outputSize, BCRYPT_BLOCK_PADDING), "Encrypting AES ciphertext");
            output.resize(outputSize);
        }
        catch (...)
        {
            if (aesKey) BCryptDestroyKey(aesKey);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            throw;
        }
        BCryptDestroyKey(aesKey);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return output;
    }

    std::string AesCbcDecrypt(const ByteVector& key, const ByteVector& iv, const ByteVector& cipher)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_KEY_HANDLE aesKey = nullptr;
        ByteVector keyObject;
        ByteVector output;
        try
        {
            CheckNt(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0),
                "Opening AES");
            CheckNt(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                sizeof(BCRYPT_CHAIN_MODE_CBC), 0), "Selecting AES-CBC");
            DWORD objectSize = 0;
            DWORD copied = 0;
            CheckNt(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &copied, 0),
                "Reading AES object size");
            keyObject.resize(objectSize);
            CheckNt(BCryptGenerateSymmetricKey(algorithm, &aesKey, keyObject.data(), objectSize,
                const_cast<PUCHAR>(key.data()), ToDword(key.size()), 0), "Creating AES key");

            DWORD outputSize = 0;
            ByteVector ivCopy = iv;
            CheckNt(BCryptDecrypt(aesKey, const_cast<PUCHAR>(cipher.data()), ToDword(cipher.size()),
                nullptr, ivCopy.data(), ToDword(ivCopy.size()), nullptr, 0, &outputSize,
                BCRYPT_BLOCK_PADDING), "Sizing AES plaintext");
            output.resize(outputSize);
            ivCopy = iv;
            CheckNt(BCryptDecrypt(aesKey, const_cast<PUCHAR>(cipher.data()), ToDword(cipher.size()),
                nullptr, ivCopy.data(), ToDword(ivCopy.size()), output.data(), outputSize,
                &outputSize, BCRYPT_BLOCK_PADDING), "Decrypting AES plaintext");
            output.resize(outputSize);
        }
        catch (...)
        {
            if (aesKey) BCryptDestroyKey(aesKey);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            throw;
        }
        BCryptDestroyKey(aesKey);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::string(output.begin(), output.end());
    }

    std::string ReadHardwareId()
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0,
            KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
        {
            DWORD type = 0;
            DWORD bytes = 0;
            if (RegQueryValueExW(key, L"MachineGuid", nullptr, &type, nullptr, &bytes) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ) && bytes >= sizeof(wchar_t))
            {
                std::vector<wchar_t> value(bytes / sizeof(wchar_t) + 1, L'\0');
                if (RegQueryValueExW(key, L"MachineGuid", nullptr, &type,
                    reinterpret_cast<LPBYTE>(value.data()), &bytes) == ERROR_SUCCESS)
                {
                    RegCloseKey(key);
                    std::wstring wide(value.data());
                    if (!wide.empty())
                        return WideToUtf8(wide);
                }
            }
            RegCloseKey(key);
        }

        std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> name{};
        DWORD length = static_cast<DWORD>(name.size());
        if (GetComputerNameW(name.data(), &length) && length > 0)
            return WideToUtf8(std::wstring(name.data(), length));
        return "unknown-host";
    }

    bool EndsSession(const std::string& code)
    {
        static const std::array<const char*, 22> codes = {
            "BANNED", "PAUSED", "EXPIRED", "HWID_RESET", "MAINTENANCE",
            "SESSION_REVOKED", "SESSION_EXPIRED", "SESSION_MISMATCH", "NETWORK_LOST",
            "KEY_BANNED", "KEY_PAUSED", "KEY_EXPIRED", "KEY_REVOKED", "KEY_NOT_FOUND",
            "HWID_MISMATCH", "SESSION_NOT_FOUND", "APP_DISABLED", "INVALID_KEY",
            "REVOKED", "DISABLED", "ACCOUNT_BANNED", "ACCOUNT_EXPIRED"
        };
        return std::any_of(codes.begin(), codes.end(),
            [&code](const char* value) { return code == value; });
    }
}

class PwfClient::CryptoEnvelope
{
public:
    explicit CryptoEnvelope(const std::string& appSecret)
        : encryptionKey_(Sha256("enc:" + appSecret)),
          macKey_(Sha256("mac:" + appSecret))
    {
    }

    // This computer's clock, shifted to match the server's (0 normally).
    std::int64_t Now() const
    {
        return static_cast<std::int64_t>(std::time(nullptr)) + clockOffset_.load();
    }

    std::int64_t ClockOffset() const { return clockOffset_.load(); }
    void SetClockOffset(std::int64_t seconds) { clockOffset_ = seconds; }

    std::string Encrypt(const std::string& plainJson) const
    {
        ByteVector iv(16);
        CheckNt(BCryptGenRandom(nullptr, iv.data(), ToDword(iv.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG), "Generating AES IV");
        ByteVector cipher = AesCbcEncrypt(encryptionKey_, iv, plainJson);
        ByteVector combined = iv;
        combined.insert(combined.end(), cipher.begin(), cipher.end());
        const std::string payload = Base64Encode(combined);
        const std::int64_t timestamp = Now();
        const std::string signature = HexLower(HmacSha256(macKey_, payload + std::to_string(timestamp)));
        return nlohmann::json{
            {"p", payload},
            {"t", timestamp},
            {"s", signature}
        }.dump();
    }

    std::string Decrypt(const std::string& envelopeJson) const
    {
        nlohmann::json envelope;
        try
        {
            envelope = nlohmann::json::parse(envelopeJson);
        }
        catch (const std::exception&)
        {
            throw std::runtime_error("Invalid encrypted-envelope JSON.");
        }
        if (!envelope.is_object() || !envelope.contains("p") || !envelope["p"].is_string() ||
            !envelope.contains("t") || !envelope["t"].is_number_integer() ||
            !envelope.contains("s") || !envelope["s"].is_string())
            throw std::runtime_error("Invalid encrypted-envelope format.");

        const std::string payload = envelope["p"].get<std::string>();
        const std::int64_t timestamp = envelope["t"].get<std::int64_t>();
        const std::string receivedSignature = envelope["s"].get<std::string>();
        const std::string expectedSignature =
            HexLower(HmacSha256(macKey_, payload + std::to_string(timestamp)));
        if (!ConstantTimeEquals(expectedSignature, receivedSignature))
            throw std::runtime_error(
                "HMAC verification failed - check the application secret and response integrity.");

        if (std::llabs(Now() - timestamp) > 300)
            throw std::runtime_error(
                "The encrypted response timestamp is outside the accepted window; check the system clock.");

        ByteVector combined = Base64Decode(payload);
        if (combined.size() <= 16 || (combined.size() - 16) % 16 != 0)
            throw std::runtime_error("Malformed encrypted payload.");
        ByteVector iv(combined.begin(), combined.begin() + 16);
        ByteVector cipher(combined.begin() + 16, combined.end());
        return AesCbcDecrypt(encryptionKey_, iv, cipher);
    }

    static bool LooksLikeEnvelope(const std::string& body)
    {
        const nlohmann::json value = nlohmann::json::parse(body, nullptr, false);
        return value.is_object() && value.contains("p") && value.contains("t") && value.contains("s");
    }

private:
    ByteVector encryptionKey_;
    ByteVector macKey_;
    std::atomic<std::int64_t> clockOffset_{ 0 };
};

bool PwfResponse::Success() const
{
    return data.is_object() && data.value("success", false);
}

std::string PwfResponse::ErrorCode() const
{
    if (data.is_object() && data.contains("error_code") && data["error_code"].is_string())
        return data["error_code"].get<std::string>();
    return {};
}

std::string PwfResponse::Message() const
{
    if (data.is_object() && data.contains("message") && data["message"].is_string())
        return data["message"].get<std::string>();
    return {};
}

PwfResponse PwfResponse::Parse(const std::string& body)
{
    PwfResponse response;
    response.rawJson = body;
    response.data = nlohmann::json::parse(body, nullptr, false);
    if (response.data.is_discarded() || !response.data.is_object())
        throw std::runtime_error("The license server returned a body that is not a JSON object.");
    return response;
}

PwfClient::PwfClient(
    std::string appSecret,
    std::string baseUrl,
    int timeoutMilliseconds,
    int maxHeartbeatFailures,
    int maxRateLimitedBeats)
    : appSecret_(std::move(appSecret)),
      baseUrl_(std::move(baseUrl)),
      hardwareId_(ReadHardwareId()),
      timeoutMilliseconds_(timeoutMilliseconds),
      maxHeartbeatFailures_(maxHeartbeatFailures),
      maxRateLimitedBeats_(maxRateLimitedBeats)
{
    if (appSecret_.empty())
        throw std::invalid_argument("The application secret is required.");
    // Zero would leave an unreachable server (or a proxy answering 429 forever)
    // keeping the app running.
    if (maxHeartbeatFailures_ < 1 || maxRateLimitedBeats_ < 1)
        throw std::invalid_argument("The heartbeat failure budgets must be at least 1.");
    while (!baseUrl_.empty() && baseUrl_.back() == '/')
        baseUrl_.pop_back();
    crypto_ = std::make_unique<CryptoEnvelope>(appSecret_);
}

PwfClient::~PwfClient()
{
    StopHeartbeat();
}

PwfResponse PwfClient::Login(const std::string& licenseKey)
{
    if (licenseKey.empty())
        throw std::invalid_argument("The license key is required.");
    PwfResponse response = SendEnvelope(L"/api/auth/login.php", {
        {"license_key", licenseKey},
        {"hwid", hardwareId_}
    });
    if (response.Success())
    {
        const std::string session = response.data.value("session_id", std::string{});
        if (session.empty())
            throw std::runtime_error("The login reply did not contain a session ID.");
        std::lock_guard<std::mutex> lock(stateMutex_);
        sessionId_ = session;
        licenseKey_ = licenseKey;
        if (response.data.contains("heartbeat_interval") &&
            response.data["heartbeat_interval"].is_number_integer())
        {
            const int interval = response.data["heartbeat_interval"].get<int>();
            if (interval > 0)
                heartbeatSeconds_ = (std::max)(5, interval);
        }
    }
    return response;
}

PwfResponse PwfClient::Heartbeat()
{
    std::string session;
    std::string license;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        session = sessionId_;
        license = licenseKey_;
    }
    if (session.empty())
        throw std::runtime_error("Not signed in; call Login before Heartbeat.");
    return SendEnvelope(L"/api/auth/heartbeat.php", {
        {"session_id", session},
        {"license_key", license},
        {"hwid", hardwareId_}
    });
}

PwfResponse PwfClient::Logout()
{
    StopHeartbeat();
    std::string session;
    std::string license;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        session = sessionId_;
        license = licenseKey_;
    }
    if (session.empty())
        throw std::runtime_error("Not signed in.");

    try
    {
        PwfResponse response = SendEnvelope(L"/api/auth/logout.php", {
            {"session_id", session},
            {"license_key", license}
        });
        std::lock_guard<std::mutex> lock(stateMutex_);
        sessionId_.clear();
        licenseKey_.clear();
        return response;
    }
    catch (...)
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        sessionId_.clear();
        licenseKey_.clear();
        throw;
    }
}

PwfResponse PwfClient::ResetHardwareId(const std::string& licenseKey, const std::string& reason)
{
    const std::string key = TrimAscii(licenseKey);
    if (key.empty())
        throw std::invalid_argument("The license key is required.");
    std::string text = TrimAscii(reason);
    if (text.empty())
        text = "Reset from app";
    return SendPlain(L"/api/customer/reset-hwid.php", {
        {"key", key},
        {"reason", TruncateUtf8(text, MaxResetReason)}
    });
}

void PwfClient::StartHeartbeat()
{
    StopHeartbeat();
    if (!IsSignedIn())
        throw std::runtime_error("Not signed in; call Login before StartHeartbeat.");
    stopHeartbeat_ = false;
    heartbeatThread_ = std::thread(&PwfClient::HeartbeatLoop, this);
}

void PwfClient::StopHeartbeat()
{
    stopHeartbeat_ = true;
    heartbeatWake_.notify_all();
    if (heartbeatThread_.joinable() && heartbeatThread_.get_id() != std::this_thread::get_id())
        heartbeatThread_.join();
}

void PwfClient::SetSessionEndedCallback(SessionEndedCallback callback)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    sessionEnded_ = std::move(callback);
}

void PwfClient::SetAutoCorrectClock(bool enabled)
{
    autoCorrectClock_ = enabled;
}

std::int64_t PwfClient::ClockOffsetSeconds() const
{
    return crypto_->ClockOffset();
}

bool PwfClient::IsSignedIn() const
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    return !sessionId_.empty();
}

std::string PwfClient::SessionId() const
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    return sessionId_;
}

std::string PwfClient::HardwareId() const
{
    return hardwareId_;
}

int PwfClient::HeartbeatSeconds() const
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    return heartbeatSeconds_;
}

// POST an encrypted envelope. A plain failure (a bad app secret, a rate limit) comes
// back as a failed reply; a plain SUCCESS throws PwfSecurityError. When the server
// refuses this computer's clock it sends its own time: shift by the difference and
// send the request once more.
PwfResponse PwfClient::SendEnvelope(const std::wstring& path, const nlohmann::json& body)
{
    PwfResponse reply = SendEnvelopeOnce(path, body);
    if (autoCorrectClock_ && TryCorrectClock(reply))
        reply = SendEnvelopeOnce(path, body);
    return reply;
}

PwfResponse PwfClient::SendEnvelopeOnce(const std::wstring& path, const nlohmann::json& body)
{
    const HttpReply http = HttpPost(path, crypto_->Encrypt(body.dump()));
    if (CryptoEnvelope::LooksLikeEnvelope(http.body))
    {
        PwfResponse response = PwfResponse::Parse(crypto_->Decrypt(http.body));
        response.isEnveloped = true;
        response.statusCode = http.status;
        return response;
    }

    PwfResponse response = ParseReply(http);
    // Encrypted endpoints seal EVERY reply once the request is verified; only refusals
    // before that point travel as plain JSON. A plain success therefore came from a
    // proxy, a hosts-file redirect or a fake server, and accepting it would let any of
    // them unlock the application.
    if (response.Success())
        throw PwfSecurityError("The license server's reply was not encrypted, so it cannot be trusted.");
    return response;
}

// POST unencrypted JSON, for the endpoints that do not use the envelope.
PwfResponse PwfClient::SendPlain(const std::wstring& path, const nlohmann::json& body)
{
    return ParseReply(HttpPost(path, body.dump()));
}

PwfResponse PwfClient::ParseReply(const HttpReply& http)
{
    if (http.body.empty())
        throw PwfHttpError(http.status, "The license server returned HTTP " +
            std::to_string(http.status) + " with an empty body.");
    PwfResponse response;
    try
    {
        response = PwfResponse::Parse(http.body);
    }
    catch (const std::runtime_error&)
    {
        // An HTML error page from a proxy or CDN is the usual cause.
        throw PwfHttpError(http.status, "The license server returned a body that is not JSON (HTTP " +
            std::to_string(http.status) + "). Check the base URL.");
    }
    response.statusCode = http.status;

    // The API answers its own refusals with {success, error_code, message}. Anything
    // else with a failing status is a transport problem, not an answer: a wrong app
    // secret (HTTP 401 {"detail": ...}) or a CDN page.
    if (http.status >= 400 && !response.data.contains("success"))
    {
        const std::string detail = JsonText(response.data, "detail");
        throw PwfHttpError(http.status, "The license server returned HTTP " +
            std::to_string(http.status) + (detail.empty() ? std::string(".") : ": " + detail));
    }
    return response;
}

bool PwfClient::TryCorrectClock(const PwfResponse& reply)
{
    // The server's plain refusal for a timestamp outside its window carries
    // "reason": "CLOCK_SKEW" and "server_time" (unix seconds). It never sends that
    // refusal encrypted, so only a plain reply qualifies.
    if (reply.isEnveloped || JsonText(reply.data, "reason") != "CLOCK_SKEW")
        return false;
    const auto serverTime = reply.data.find("server_time");
    if (serverTime == reply.data.end() || !serverTime->is_number_integer() ||
        serverTime->get<std::int64_t>() <= 0)
        return false;
    crypto_->SetClockOffset(serverTime->get<std::int64_t>() -
        static_cast<std::int64_t>(std::time(nullptr)));
    return true;
}

PwfClient::HttpReply PwfClient::HttpPost(const std::wstring& path, const std::string& body) const
{
    const std::wstring url = Utf8ToWide(baseUrl_) + path;
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = static_cast<DWORD>(-1);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts))
        ThrowLastError("Parsing the PWF Auth URL");

    const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
    std::wstring requestPath(parts.lpszUrlPath, parts.dwUrlPathLength);
    if (parts.dwExtraInfoLength > 0)
        requestPath.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);

    InternetHandle session(WinHttpOpen(
        L"PwfAuthCpp/1.1 (+https://pwfauth.com)",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0));
    if (!session.Valid())
        ThrowLastError("Opening the HTTP session");
    WinHttpSetTimeouts(session, timeoutMilliseconds_, timeoutMilliseconds_,
        timeoutMilliseconds_, timeoutMilliseconds_);

    InternetHandle connection(WinHttpConnect(session, host.c_str(), parts.nPort, 0));
    if (!connection.Valid())
        ThrowNetworkError("Connecting");
    const DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    InternetHandle request(WinHttpOpenRequest(connection, L"POST", requestPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!request.Valid())
        ThrowLastError("Creating the HTTP request");

    const std::wstring headers = L"Content-Type: application/json\r\nX-App-Secret: " +
        Utf8ToWide(appSecret_) + L"\r\n";
    void* requestData = body.empty() ? WINHTTP_NO_REQUEST_DATA :
        static_cast<void*>(const_cast<char*>(body.data()));
    if (!WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1), requestData,
        ToDword(body.size()), ToDword(body.size()), 0))
        ThrowNetworkError("Sending the request");
    if (!WinHttpReceiveResponse(request, nullptr))
        ThrowNetworkError("Receiving the reply");

    HttpReply reply;
    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX))
        reply.status = static_cast<int>(status);

    // A 4xx still carries the API's JSON refusal worth reading.
    while (true)
    {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available))
            ThrowNetworkError("Reading the reply");
        if (available == 0)
            break;
        const std::size_t offset = reply.body.size();
        reply.body.resize(offset + available);
        DWORD read = 0;
        if (!WinHttpReadData(request, reply.body.data() + offset, available, &read))
            ThrowNetworkError("Reading the reply");
        reply.body.resize(offset + read);
    }
    return reply;
}

void PwfClient::HeartbeatLoop()
{
    // Only an encrypted reply proves the license server answered: nothing else can seal
    // one. Every other outcome is an unanswered beat: no reply, a reply that fails
    // verification, a forged plain "success" (PwfSecurityError), and plain refusals,
    // which the server sends when it cannot verify the request at all. The commonest of
    // those is its replay check rejecting a clock more than five minutes off. Treating
    // any parsed reply as an answer (as 1.0 did) let an app whose clock was moved run
    // forever, deaf to bans.
    int unanswered = 0;     // beats in a row without an encrypted reply (not 429)
    int plainRefusals = 0;  //   ...of which were plain refusals from the server
    int clockRefusals = 0;  //   ...of which blamed this computer's clock
    int rateLimited = 0;    // beats in a row answered with HTTP 429

    while (!stopHeartbeat_)
    {
        int interval = 60;
        {
            std::lock_guard<std::mutex> lock(stateMutex_);
            interval = heartbeatSeconds_;
        }
        std::unique_lock<std::mutex> waitLock(heartbeatMutex_);
        if (heartbeatWake_.wait_for(waitLock, std::chrono::seconds(interval),
            [this] { return stopHeartbeat_.load(); }))
            return;
        waitLock.unlock();

        PwfResponse response;
        bool replied = false;
        int failedStatus = 0;
        try
        {
            response = Heartbeat();
            replied = true;
        }
        catch (const PwfHttpError& error)
        {
            failedStatus = error.Status();
        }
        catch (const std::exception&)
        {
        }
        // Signed out (or stopped) while the beat was in flight: say nothing.
        if (stopHeartbeat_)
            return;

        if (!replied || !response.isEnveloped)
        {
            // Shared IPs get rate limited legitimately, so 429 has its own, larger budget.
            if ((replied ? response.statusCode : failedStatus) == TooManyRequests)
            {
                if (++rateLimited >= maxRateLimitedBeats_)
                {
                    EndSession("NETWORK_LOST", NetworkLostMessage);
                    return;
                }
                continue;
            }
            if (replied)
            {
                ++plainRefusals;
                if (IsClockRefusal(response))
                    ++clockRefusals;
            }
            if (++unanswered >= maxHeartbeatFailures_)
            {
                // When every plain refusal blamed the clock, say so: signing in again
                // cannot work until it is corrected.
                if (plainRefusals > 0 && clockRefusals == plainRefusals)
                    EndSession("CLOCK_SKEW", ClockSkewMessage);
                else
                    EndSession("NETWORK_LOST", NetworkLostMessage);
                return;
            }
            continue;
        }

        // Encrypted: the server is reachable and the clock is fine. Every count starts
        // over, and neither kind of failure resets the other, so alternating them cannot
        // keep the loop alive either.
        unanswered = plainRefusals = clockRefusals = rateLimited = 0;
        if (!response.Success() && EndsSession(response.ErrorCode()))
        {
            EndSession(response.ErrorCode(), response.Message());
            return;
        }
        // An unknown encrypted failure: transient, keep beating.
    }
}

void PwfClient::EndSession(const std::string& code, const std::string& message)
{
    SessionEndedCallback callback;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        sessionId_.clear();
        licenseKey_.clear();
        callback = sessionEnded_;
    }
    stopHeartbeat_ = true;
    if (callback)
        callback(code, message);
}

bool PwfClient::ProtocolSelfTest()
{
    try
    {
        CryptoEnvelope envelope(std::string(64, 'a'));
        const std::string plain = R"({"success":true,"message":"PWF Auth crypto test"})";
        return envelope.Decrypt(envelope.Encrypt(plain)) == plain;
    }
    catch (...)
    {
        return false;
    }
}
