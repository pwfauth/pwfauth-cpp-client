#pragma once

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

// The license server could not be reached at all: offline, DNS, firewall, proxy or TLS.
class PwfNetworkError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

// A reply that is not the API's JSON: an empty body, or an HTML error page from a
// proxy or CDN. Status() is the HTTP status.
class PwfHttpError : public std::runtime_error
{
public:
    PwfHttpError(int status, const std::string& message)
        : std::runtime_error(message), status_(status) {}
    int Status() const { return status_; }

private:
    int status_;
};

// An encrypted endpoint answered with an UNENCRYPTED "success". The license server
// encrypts every reply of these endpoints once it has accepted the app secret; only
// refusals travel as plain JSON. A plain success therefore came from a proxy, a
// hosts-file redirect or a fake server. Never unlock the application on it.
class PwfSecurityError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

class PwfResponse
{
public:
    nlohmann::json data = nlohmann::json::object();
    std::string rawJson;
    bool isEnveloped = false;  // true = sealed by the license server
    int statusCode = 0;        // the HTTP status

    bool Success() const;
    std::string ErrorCode() const;
    std::string Message() const;

    static PwfResponse Parse(const std::string& body);
};

class PwfClient
{
public:
    using SessionEndedCallback = std::function<void(const std::string&, const std::string&)>;

    explicit PwfClient(
        std::string appSecret,
        std::string baseUrl = "https://pwfauth.com",
        int timeoutMilliseconds = 15000,
        int maxHeartbeatFailures = 3,
        int maxRateLimitedBeats = 10);
    ~PwfClient();

    PwfClient(const PwfClient&) = delete;
    PwfClient& operator=(const PwfClient&) = delete;

    PwfResponse Login(const std::string& licenseKey);
    PwfResponse Heartbeat();
    PwfResponse Logout();

    // Moves a license to a new PC, instantly: unbinds the key from every computer it
    // is bound to (the next Login binds it here) and ends its sessions. The developer
    // decides whether self-service moves are allowed and the cooldown between two of
    // them (12 hours by default). Refusals: INVALID_KEY, KEY_NOT_ACTIVE, NO_HWID,
    // RATE_LIMITED or SELF_RESET_DISABLED.
    PwfResponse ResetHardwareId(const std::string& licenseKey, const std::string& reason = "");

    // Keeps the session alive AND obeys the kill switch. Only an encrypted reply counts
    // as an answer: maxHeartbeatFailures beats in a row without one (no reply, a plain
    // refusal, a forged plain success) end the session with NETWORK_LOST, or with
    // CLOCK_SKEW when the server kept refusing this computer's clock.
    void StartHeartbeat();
    void StopHeartbeat();
    void SetSessionEndedCallback(SessionEndedCallback callback);

    // When the server refuses a request because this computer's clock is wrong, shift
    // by the server's time and send it once more. On by default.
    void SetAutoCorrectClock(bool enabled);
    std::int64_t ClockOffsetSeconds() const;

    bool IsSignedIn() const;
    std::string SessionId() const;
    std::string HardwareId() const;
    int HeartbeatSeconds() const;

    static bool ProtocolSelfTest();

private:
    class CryptoEnvelope;
    struct HttpReply
    {
        int status = 0;
        std::string body;
    };

    PwfResponse SendEnvelope(const std::wstring& path, const nlohmann::json& body);
    PwfResponse SendEnvelopeOnce(const std::wstring& path, const nlohmann::json& body);
    PwfResponse SendPlain(const std::wstring& path, const nlohmann::json& body);
    bool TryCorrectClock(const PwfResponse& reply);
    static PwfResponse ParseReply(const HttpReply& http);
    HttpReply HttpPost(const std::wstring& path, const std::string& body) const;
    void HeartbeatLoop();
    void EndSession(const std::string& code, const std::string& message);

    std::string appSecret_;
    std::string baseUrl_;
    std::string hardwareId_;
    int timeoutMilliseconds_;
    int maxHeartbeatFailures_;
    int maxRateLimitedBeats_;
    std::atomic<bool> autoCorrectClock_{ true };
    std::unique_ptr<CryptoEnvelope> crypto_;

    mutable std::mutex stateMutex_;
    std::string sessionId_;
    std::string licenseKey_;
    int heartbeatSeconds_ = 60;
    SessionEndedCallback sessionEnded_;

    std::thread heartbeatThread_;
    std::atomic<bool> stopHeartbeat_{ false };
    std::mutex heartbeatMutex_;
    std::condition_variable heartbeatWake_;
};
