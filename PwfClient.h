#pragma once

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

class PwfResponse
{
public:
    nlohmann::json data = nlohmann::json::object();
    std::string rawJson;

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
        int maxHeartbeatFailures = 3);
    ~PwfClient();

    PwfClient(const PwfClient&) = delete;
    PwfClient& operator=(const PwfClient&) = delete;

    PwfResponse Login(const std::string& licenseKey);
    PwfResponse Heartbeat();
    PwfResponse Logout();

    void StartHeartbeat();
    void StopHeartbeat();
    void SetSessionEndedCallback(SessionEndedCallback callback);

    bool IsSignedIn() const;
    std::string SessionId() const;
    std::string HardwareId() const;
    int HeartbeatSeconds() const;

    static bool ProtocolSelfTest();

private:
    class CryptoEnvelope;

    PwfResponse SendEnvelope(const std::wstring& path, const nlohmann::json& body);
    std::string HttpPost(const std::wstring& path, const std::string& body) const;
    void HeartbeatLoop();
    void EndSession(const std::string& code, const std::string& message);

    std::string appSecret_;
    std::string baseUrl_;
    std::string hardwareId_;
    int timeoutMilliseconds_;
    int maxHeartbeatFailures_;
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
