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

    std::string Encrypt(const std::string& plainJson) const
    {
        ByteVector iv(16);
        CheckNt(BCryptGenRandom(nullptr, iv.data(), ToDword(iv.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG), "Generating AES IV");
        ByteVector cipher = AesCbcEncrypt(encryptionKey_, iv, plainJson);
        ByteVector combined = iv;
        combined.insert(combined.end(), cipher.begin(), cipher.end());
        const std::string payload = Base64Encode(combined);
        const auto timestamp = static_cast<std::int64_t>(std::time(nullptr));
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

        const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
        if (std::llabs(now - timestamp) > 300)
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
    int maxHeartbeatFailures)
    : appSecret_(std::move(appSecret)),
      baseUrl_(std::move(baseUrl)),
      hardwareId_(ReadHardwareId()),
      timeoutMilliseconds_(timeoutMilliseconds),
      maxHeartbeatFailures_(maxHeartbeatFailures)
{
    if (appSecret_.empty())
        throw std::invalid_argument("The application secret is required.");
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
                heartbeatSeconds_ = interval;
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

PwfResponse PwfClient::SendEnvelope(const std::wstring& path, const nlohmann::json& body)
{
    std::string raw = HttpPost(path, crypto_->Encrypt(body.dump()));
    if (CryptoEnvelope::LooksLikeEnvelope(raw))
        raw = crypto_->Decrypt(raw);
    return PwfResponse::Parse(raw);
}

std::string PwfClient::HttpPost(const std::wstring& path, const std::string& body) const
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
        L"PwfAuthCpp/1.0 (+https://pwfauth.com)",
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
        ThrowLastError("Connecting to the license server");
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
        ThrowLastError("Sending the license request");
    if (!WinHttpReceiveResponse(request, nullptr))
        ThrowLastError("Receiving the license response");

    std::string response;
    while (true)
    {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available))
            ThrowLastError("Reading the license response");
        if (available == 0)
            break;
        const std::size_t offset = response.size();
        response.resize(offset + available);
        DWORD read = 0;
        if (!WinHttpReadData(request, response.data() + offset, available, &read))
            ThrowLastError("Reading the license response");
        response.resize(offset + read);
    }
    if (response.empty())
        throw std::runtime_error("The license server returned an empty response.");
    return response;
}

void PwfClient::HeartbeatLoop()
{
    int failures = 0;
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

        try
        {
            PwfResponse response = Heartbeat();
            failures = 0;
            if (!response.Success() && EndsSession(response.ErrorCode()))
            {
                EndSession(response.ErrorCode(), response.Message());
                return;
            }
        }
        catch (const std::exception&)
        {
            ++failures;
            if (failures >= maxHeartbeatFailures_)
            {
                EndSession("NETWORK_LOST", "The license server is unreachable.");
                return;
            }
        }
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
