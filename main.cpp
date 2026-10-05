#include "PwfClient.h"
#include "resource.h"

#include <windows.h>
#include <commctrl.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace
{
    // Educational sample: replace this value with your real 64-character hex secret.
    constexpr char APP_SECRET[] = "YOUR_64_CHARACTER_APP_SECRET";

    constexpr COLORREF PageColor = RGB(11, 18, 32);
    constexpr COLORREF CardColor = RGB(23, 33, 51);
    constexpr COLORREF EntryColor = RGB(15, 23, 42);
    constexpr COLORREF BlueColor = RGB(59, 130, 246);
    constexpr COLORREF BlueLightColor = RGB(96, 165, 250);
    constexpr COLORREF WhiteColor = RGB(255, 255, 255);
    constexpr COLORREF SurfaceColor = RGB(241, 245, 249);
    constexpr COLORREF TextColor = RGB(15, 23, 42);
    constexpr COLORREF MutedColor = RGB(100, 116, 139);
    constexpr COLORREF MutedDarkColor = RGB(148, 163, 184);
    constexpr COLORREF SuccessColor = RGB(22, 163, 74);
    constexpr COLORREF WarningColor = RGB(217, 119, 6);
    constexpr COLORREF ErrorColor = RGB(248, 113, 113);
    constexpr int CardHeight = 515;  // the sign-in card

    struct DetailRow
    {
        std::wstring field;
        std::wstring path;
        std::wstring value;
    };

    struct LoginResult
    {
        std::unique_ptr<PwfClient> client;
        PwfResponse response;
        std::wstring error;
        std::wstring licenseKey;
        bool boundElsewhere = false;  // HWID_MISMATCH or DEVICE_LIMIT: offer the move
    };

    struct LogoutResult
    {
        std::unique_ptr<PwfClient> client;
        std::wstring warning;
        bool closeAfter = false;
    };

    struct SessionEndedResult
    {
        std::wstring code;
        std::wstring message;
    };

    std::wstring Utf8ToWide(const std::string& value)
    {
        if (value.empty())
            return {};
        const int required = MultiByteToWideChar(
            CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
        if (required <= 0)
            return L"Invalid UTF-8 text";
        std::wstring result(static_cast<std::size_t>(required), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
            result.data(), required);
        return result;
    }

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty())
            return {};
        const int required = WideCharToMultiByte(
            CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (required <= 0)
            return {};
        std::string result(static_cast<std::size_t>(required), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
            result.data(), required, nullptr, nullptr);
        return result;
    }

    std::wstring Trim(const std::wstring& value)
    {
        const auto isSpace = [](wchar_t character) { return iswspace(character) != 0; };
        const auto first = std::find_if_not(value.begin(), value.end(), isSpace);
        const auto last = std::find_if_not(value.rbegin(), value.rend(), isSpace).base();
        return first < last ? std::wstring(first, last) : std::wstring{};
    }

    std::string EnvironmentValue(const wchar_t* name)
    {
        wchar_t buffer[512]{};
        const DWORD length = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(std::size(buffer)));
        if (length == 0 || length >= std::size(buffer))
            return {};
        return WideToUtf8(Trim(std::wstring(buffer, length)));
    }

    // The PWFAUTH_SECRET environment variable overrides the in-code demo secret.
    std::string AppSecret()
    {
        const std::string fromEnvironment = EnvironmentValue(L"PWFAUTH_SECRET");
        return fromEnvironment.empty() ? std::string(APP_SECRET) : fromEnvironment;
    }

    // Optional: another server, e.g. a staging copy. Empty = https://pwfauth.com.
    std::string BaseUrl()
    {
        const std::string fromEnvironment = EnvironmentValue(L"PWFAUTH_BASE_URL");
        return fromEnvironment.empty() ? std::string("https://pwfauth.com") : fromEnvironment;
    }

    bool HasConfiguredSecret()
    {
        const std::string secret = AppSecret();
        return secret.size() == 64 && secret != "YOUR_64_CHARACTER_APP_SECRET" &&
            std::all_of(secret.begin(), secret.end(), [](unsigned char character)
            {
                return std::isxdigit(character) != 0;
            });
    }

    HFONT CreateUiFont(HWND window, int points, int weight = FW_NORMAL, const wchar_t* face = L"Segoe UI")
    {
        HDC dc = GetDC(window);
        const int dpi = GetDeviceCaps(dc, LOGPIXELSY);
        ReleaseDC(window, dc);
        return CreateFontW(-MulDiv(points, dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, face);
    }

    void Fill(HDC dc, const RECT& rectangle, COLORREF color)
    {
        HBRUSH brush = CreateSolidBrush(color);
        FillRect(dc, &rectangle, brush);
        DeleteObject(brush);
    }

    void DrawLabel(HDC dc, const std::wstring& text, RECT rectangle, HFONT font,
        COLORREF color, UINT flags = DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS)
    {
        const HFONT previousFont = static_cast<HFONT>(SelectObject(dc, font));
        const int previousMode = SetBkMode(dc, TRANSPARENT);
        const COLORREF previousColor = SetTextColor(dc, color);
        DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &rectangle, flags);
        SetTextColor(dc, previousColor);
        SetBkMode(dc, previousMode);
        SelectObject(dc, previousFont);
    }

    std::wstring JsonString(const nlohmann::json& object, const char* key)
    {
        if (object.is_object() && object.contains(key) && object[key].is_string())
            return Utf8ToWide(object[key].get<std::string>());
        return {};
    }

    // The server's message (safe to show the user) plus its error code.
    std::wstring Describe(const PwfResponse& response, const char* fallback)
    {
        std::wstring text = Utf8ToWide(response.Message().empty() ? fallback : response.Message());
        if (!response.ErrorCode().empty())
            text += L" (" + Utf8ToWide(response.ErrorCode()) + L")";
        return text;
    }

    std::wstring JsonScalar(const nlohmann::json& value)
    {
        if (value.is_null())
            return L"null";
        if (value.is_boolean())
            return value.get<bool>() ? L"true (Yes)" : L"false (No)";
        if (value.is_string())
            return Utf8ToWide(value.get<std::string>());
        return Utf8ToWide(value.dump());
    }

    std::string NormalizeArrayPath(const std::string& path)
    {
        std::string result;
        bool insideIndex = false;
        for (char character : path)
        {
            if (character == '[')
            {
                insideIndex = true;
                continue;
            }
            if (character == ']')
            {
                insideIndex = false;
                continue;
            }
            if (!insideIndex)
                result.push_back(character);
        }
        return result;
    }

    const std::unordered_map<std::string, std::wstring>& FriendlyFields()
    {
        static const std::unordered_map<std::string, std::wstring> fields = {
            {"success", L"Request successful"},
            {"message", L"Server message"},
            {"error_code", L"Error code"},
            {"session_id", L"Session ID"},
            {"heartbeat_interval", L"Heartbeat interval"},
            {"user.license_key", L"License key"},
            {"user.key_type", L"Key type"},
            {"user.duration", L"Key duration"},
            {"user.hwid", L"Device HWID"},
            {"user.activated_at", L"Activation date"},
            {"user.expires_at", L"Expiration date"},
            {"user.days_remaining", L"Days remaining"},
            {"user.status", L"Key status"},
            {"app.name", L"Application name"},
            {"app.version", L"Application version"},
            {"app.message", L"Application message"},
            {"seller.type", L"Sold by (type)"},
            {"seller.name", L"Sold by"},
            {"seller.contact", L"Seller contact"},
            {"texts", L"Remote texts"},
            {"features", L"Key features"},
            {"slides", L"Announcement slides"}
        };
        return fields;
    }

    std::wstring FriendlyFieldName(const std::string& path)
    {
        const auto& fields = FriendlyFields();
        auto found = fields.find(path);
        if (found != fields.end())
            return found->second;
        const std::string normalized = NormalizeArrayPath(path);
        found = fields.find(normalized);
        if (found != fields.end())
            return found->second;
        const std::size_t dot = normalized.find_last_of('.');
        return Utf8ToWide(dot == std::string::npos ? normalized : normalized.substr(dot + 1));
    }

    void FlattenJson(const nlohmann::json& value, const std::string& path,
        std::vector<DetailRow>& rows)
    {
        if (value.is_object())
        {
            if (value.empty() && !path.empty())
                rows.push_back({ FriendlyFieldName(path), Utf8ToWide(path), L"{}" });
            for (auto iterator = value.begin(); iterator != value.end(); ++iterator)
            {
                const std::string childPath = path.empty() ? iterator.key() : path + "." + iterator.key();
                FlattenJson(iterator.value(), childPath, rows);
            }
            return;
        }
        if (value.is_array())
        {
            if (value.empty())
                rows.push_back({ FriendlyFieldName(path), Utf8ToWide(path), L"[]" });
            for (std::size_t index = 0; index < value.size(); ++index)
                FlattenJson(value[index], path + "[" + std::to_string(index) + "]", rows);
            return;
        }

        std::wstring display = JsonScalar(value);
        if (value.is_null() &&
            (path.size() >= 10 && path.compare(path.size() - 10, 10, "expires_at") == 0 ||
             path.size() >= 14 && path.compare(path.size() - 14, 14, "days_remaining") == 0))
            display = L"Lifetime (null)";
        rows.push_back({ FriendlyFieldName(path), Utf8ToWide(path), display });
    }

    std::wstring TitleCaseStatus(std::wstring status)
    {
        if (status.empty())
            return L"Active";
        std::transform(status.begin(), status.end(), status.begin(), towlower);
        status.front() = static_cast<wchar_t>(towupper(status.front()));
        return status;
    }

    class AppWindow
    {
    public:
        AppWindow() = default;
        ~AppWindow()
        {
            if (client_)
                client_->StopHeartbeat();
            for (HFONT font : { font8_, font9_, font10_, font10Bold_, font11Bold_, font13_, font16Bold_, font18Bold_, font20Bold_, monoFont_ })
                if (font) DeleteObject(font);
            if (pageBrush_) DeleteObject(pageBrush_);
            if (cardBrush_) DeleteObject(cardBrush_);
            if (entryBrush_) DeleteObject(entryBrush_);
            if (surfaceBrush_) DeleteObject(surfaceBrush_);
        }

        bool Create(HINSTANCE instance)
        {
            WNDCLASSEXW windowClass{};
            windowClass.cbSize = sizeof(windowClass);
            windowClass.style = CS_HREDRAW | CS_VREDRAW;
            windowClass.lpfnWndProc = WindowProcedure;
            windowClass.hInstance = instance;
            windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
            windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
            windowClass.hbrBackground = nullptr;
            windowClass.lpszClassName = L"PwfAuthCppWindow";
            windowClass.hIconSm = windowClass.hIcon;
            if (!RegisterClassExW(&windowClass) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
                return false;

            RECT frame{ 0, 0, 1084, 721 };
            AdjustWindowRectEx(&frame, WS_OVERLAPPEDWINDOW, FALSE, 0);
            window_ = CreateWindowExW(0, windowClass.lpszClassName, L"PWF Auth - Sign In",
                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                frame.right - frame.left, frame.bottom - frame.top,
                nullptr, nullptr, instance, this);
            return window_ != nullptr;
        }

        void Show(int command)
        {
            ShowWindow(window_, command);
            UpdateWindow(window_);
        }

        void CloseForSmokeTest()
        {
            if (window_)
                DestroyWindow(window_);
        }

    private:
        enum class Page { Login, Dashboard };

        static LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
        {
            AppWindow* self = reinterpret_cast<AppWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
            if (message == WM_NCCREATE)
            {
                const auto create = reinterpret_cast<CREATESTRUCTW*>(lParam);
                self = static_cast<AppWindow*>(create->lpCreateParams);
                self->window_ = window;
                SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
            }
            return self ? self->HandleMessage(message, wParam, lParam) :
                DefWindowProcW(window, message, wParam, lParam);
        }

        LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam)
        {
            switch (message)
            {
            case WM_CREATE:
                CreateResources();
                CreateControls();
                ShowLogin();
                return 0;
            case WM_SIZE:
                LayoutControls();
                return 0;
            case WM_GETMINMAXINFO:
            {
                auto info = reinterpret_cast<MINMAXINFO*>(lParam);
                info->ptMinTrackSize.x = 900;
                info->ptMinTrackSize.y = 650;
                return 0;
            }
            case WM_COMMAND:
                if (HIWORD(wParam) == BN_CLICKED)
                    HandleCommand(LOWORD(wParam));
                // "Move this license" applies to the key that failed; editing it
                // withdraws the offer.
                else if (HIWORD(wParam) == EN_CHANGE && LOWORD(wParam) == IDC_LICENSE_KEY)
                    SetMoveVisible(false);
                return 0;
            case WM_DRAWITEM:
                DrawOwnerButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lParam));
                return TRUE;
            case WM_CTLCOLOREDIT:
            {
                HDC dc = reinterpret_cast<HDC>(wParam);
                SetTextColor(dc, WhiteColor);
                SetBkColor(dc, EntryColor);
                return reinterpret_cast<LRESULT>(entryBrush_);
            }
            case WM_CTLCOLORSTATIC:
            {
                HDC dc = reinterpret_cast<HDC>(wParam);
                const HWND control = reinterpret_cast<HWND>(lParam);
                SetBkMode(dc, TRANSPARENT);
                if (control == jsonEdit_)
                {
                    SetTextColor(dc, RGB(226, 232, 240));
                    SetBkColor(dc, EntryColor);
                    return reinterpret_cast<LRESULT>(entryBrush_);
                }
                SetTextColor(dc, loginError_ ? ErrorColor : MutedDarkColor);
                return reinterpret_cast<LRESULT>(page_ == Page::Login ? cardBrush_ : surfaceBrush_);
            }
            case WM_TIMER:
                if (wParam == 1)
                {
                    KillTimer(window_, 1);
                    SetWindowTextW(copyButton_, L"Copy JSON");
                    InvalidateRect(copyButton_, nullptr, TRUE);
                }
                return 0;
            case WM_PAINT:
                Paint();
                return 0;
            case WM_ERASEBKGND:
                return 1;
            case WM_PWF_LOGIN_COMPLETE:
                HandleLoginComplete(std::unique_ptr<LoginResult>(reinterpret_cast<LoginResult*>(lParam)));
                return 0;
            case WM_PWF_LOGOUT_COMPLETE:
                HandleLogoutComplete(std::unique_ptr<LogoutResult>(reinterpret_cast<LogoutResult*>(lParam)));
                return 0;
            case WM_PWF_SESSION_ENDED:
                HandleSessionEnded(std::unique_ptr<SessionEndedResult>(
                    reinterpret_cast<SessionEndedResult*>(lParam)));
                return 0;
            case WM_CLOSE:
                RequestClose();
                return 0;
            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
            }
            return DefWindowProcW(window_, message, wParam, lParam);
        }

        void CreateResources()
        {
            pageBrush_ = CreateSolidBrush(PageColor);
            cardBrush_ = CreateSolidBrush(CardColor);
            entryBrush_ = CreateSolidBrush(EntryColor);
            surfaceBrush_ = CreateSolidBrush(SurfaceColor);
            font8_ = CreateUiFont(window_, 8);
            font9_ = CreateUiFont(window_, 9);
            font10_ = CreateUiFont(window_, 10);
            font10Bold_ = CreateUiFont(window_, 10, FW_BOLD);
            font11Bold_ = CreateUiFont(window_, 11, FW_BOLD);
            font13_ = CreateUiFont(window_, 13, FW_BOLD);
            font16Bold_ = CreateUiFont(window_, 16, FW_BOLD);
            font18Bold_ = CreateUiFont(window_, 18, FW_BOLD);
            font20Bold_ = CreateUiFont(window_, 20, FW_BOLD);
            monoFont_ = CreateUiFont(window_, 10, FW_NORMAL, L"Consolas");
        }

        HWND MakeControl(const wchar_t* className, const wchar_t* text, DWORD style,
            int id, DWORD extendedStyle = 0)
        {
            return CreateWindowExW(extendedStyle, className, text, style | WS_CHILD,
                0, 0, 0, 0, window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                GetModuleHandleW(nullptr), nullptr);
        }

        void CreateControls()
        {
            licenseEdit_ = MakeControl(L"EDIT", L"", WS_TABSTOP | ES_CENTER | ES_AUTOHSCROLL,
                IDC_LICENSE_KEY, WS_EX_CLIENTEDGE);
            SendMessageW(licenseEdit_, WM_SETFONT, reinterpret_cast<WPARAM>(monoFont_), TRUE);
            SendMessageW(licenseEdit_, EM_SETLIMITTEXT, 160, 0);

            loginButton_ = MakeControl(L"BUTTON", L"Sign In", WS_TABSTOP | BS_OWNERDRAW, IDC_LOGIN);
            loginStatus_ = MakeControl(L"STATIC", L"", SS_CENTER, IDC_LOGIN_STATUS);
            SendMessageW(loginStatus_, WM_SETFONT, reinterpret_cast<WPARAM>(font9_), TRUE);
            // Shown only when the key is bound to another computer (HWID_MISMATCH or
            // DEVICE_LIMIT): a self-service move, then sign-in here.
            moveButton_ = MakeControl(L"BUTTON", L"Move this license to this PC",
                WS_TABSTOP | BS_OWNERDRAW, IDC_MOVE_LICENSE);

            logoutButton_ = MakeControl(L"BUTTON", L"Sign Out", WS_TABSTOP | BS_OWNERDRAW, IDC_LOGOUT);
            detailsTabButton_ = MakeControl(L"BUTTON", L"All Information",
                WS_TABSTOP | BS_OWNERDRAW, IDC_TAB_DETAILS);
            jsonTabButton_ = MakeControl(L"BUTTON", L"Complete JSON",
                WS_TABSTOP | BS_OWNERDRAW, IDC_TAB_JSON);
            copyButton_ = MakeControl(L"BUTTON", L"Copy JSON", WS_TABSTOP | BS_OWNERDRAW, IDC_COPY_JSON);

            detailsList_ = MakeControl(WC_LISTVIEWW, L"",
                WS_TABSTOP | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
                IDC_DETAILS, WS_EX_CLIENTEDGE);
            ListView_SetExtendedListViewStyle(detailsList_,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
            ListView_SetBkColor(detailsList_, WhiteColor);
            ListView_SetTextBkColor(detailsList_, WhiteColor);
            SendMessageW(detailsList_, WM_SETFONT, reinterpret_cast<WPARAM>(font9_), TRUE);
            InsertListColumn(0, L"Field", 220);
            InsertListColumn(1, L"API Path", 230);
            InsertListColumn(2, L"Value", 500);

            jsonEdit_ = MakeControl(L"EDIT", L"",
                WS_TABSTOP | WS_BORDER | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL |
                ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL,
                IDC_JSON, WS_EX_CLIENTEDGE);
            SendMessageW(jsonEdit_, WM_SETFONT, reinterpret_cast<WPARAM>(monoFont_), TRUE);
        }

        void InsertListColumn(int index, const wchar_t* title, int width)
        {
            LVCOLUMNW column{};
            column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            column.pszText = const_cast<wchar_t*>(title);
            column.cx = width;
            column.fmt = LVCFMT_LEFT;
            ListView_InsertColumn(detailsList_, index, &column);
        }

        void LayoutControls()
        {
            if (!window_)
                return;
            RECT client{};
            GetClientRect(window_, &client);
            const int width = client.right;
            const int height = client.bottom;

            if (page_ == Page::Login)
            {
                const int cardX = (width - 500) / 2;
                const int cardY = (height - CardHeight) / 2;
                MoveWindow(licenseEdit_, cardX + 42, cardY + 239, 416, 30, TRUE);
                MoveWindow(loginButton_, cardX + 42, cardY + 289, 416, 46, TRUE);
                MoveWindow(loginStatus_, cardX + 42, cardY + 354, 416, 52, TRUE);
                MoveWindow(moveButton_, cardX + 42, cardY + 410, 416, 40, TRUE);
            }
            else
            {
                MoveWindow(logoutButton_, width - 150, 28, 120, 40, TRUE);
                MoveWindow(detailsTabButton_, 30, 222, 130, 36, TRUE);
                MoveWindow(jsonTabButton_, 160, 222, 130, 36, TRUE);

                const int bodyBottom = height - 42;
                if (!showJson_)
                {
                    MoveWindow(detailsList_, 30, 258, width - 60,
                        (std::max)(100, bodyBottom - 258), TRUE);
                    const int thirdWidth = (std::max)(220, width - 60 - 220 - 230 - 24);
                    ListView_SetColumnWidth(detailsList_, 2, thirdWidth);
                }
                else
                {
                    MoveWindow(copyButton_, width - 155, 266, 125, 38, TRUE);
                    MoveWindow(jsonEdit_, 30, 310, width - 60,
                        (std::max)(100, bodyBottom - 310), TRUE);
                }
            }
            InvalidateRect(window_, nullptr, TRUE);
        }

        void SetVisible(HWND control, bool visible)
        {
            ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
        }

        void ShowLogin()
        {
            page_ = Page::Login;
            SetWindowTextW(window_, L"PWF Auth - Sign In");
            SetVisible(licenseEdit_, true);
            SetVisible(loginButton_, true);
            SetVisible(loginStatus_, true);
            SetMoveVisible(false);
            for (HWND control : { logoutButton_, detailsTabButton_, jsonTabButton_, detailsList_, jsonEdit_, copyButton_ })
                SetVisible(control, false);
            LayoutControls();
            SetFocus(licenseEdit_);
        }

        void ShowDashboard()
        {
            page_ = Page::Dashboard;
            SetWindowTextW(window_, L"PWF Auth - License Information");
            SetVisible(licenseEdit_, false);
            SetVisible(loginButton_, false);
            SetVisible(loginStatus_, false);
            SetMoveVisible(false);
            SetVisible(logoutButton_, true);
            SetVisible(detailsTabButton_, true);
            SetVisible(jsonTabButton_, true);
            SetVisible(detailsList_, !showJson_);
            SetVisible(jsonEdit_, showJson_);
            SetVisible(copyButton_, showJson_);
            LayoutControls();
        }

        void SwitchDataTab(bool json)
        {
            showJson_ = json;
            SetVisible(detailsList_, !showJson_);
            SetVisible(jsonEdit_, showJson_);
            SetVisible(copyButton_, showJson_);
            LayoutControls();
        }

        void HandleCommand(int identifier)
        {
            switch (identifier)
            {
            case IDC_LOGIN: BeginLogin(false); break;
            case IDC_MOVE_LICENSE: BeginLogin(true); break;
            case IDC_LOGOUT: BeginLogout(false); break;
            case IDC_TAB_DETAILS: SwitchDataTab(false); break;
            case IDC_TAB_JSON: SwitchDataTab(true); break;
            case IDC_COPY_JSON: CopyJson(); break;
            }
        }

        void SetLoginMessage(const std::wstring& message, bool error)
        {
            loginError_ = error;
            SetWindowTextW(loginStatus_, message.c_str());
            InvalidateRect(loginStatus_, nullptr, TRUE);
        }

        void SetMoveVisible(bool visible)
        {
            SetVisible(moveButton_, visible);
            if (!visible)
                moveKey_.clear();
        }

        void SetLoginBusy(bool busy)
        {
            loginBusy_ = busy;
            EnableWindow(licenseEdit_, !busy);
            EnableWindow(loginButton_, !busy);
            SetWindowTextW(loginButton_, busy ? L"Verifying..." : L"Sign In");
            SetCursor(LoadCursorW(nullptr, busy ? IDC_WAIT : IDC_ARROW));
            InvalidateRect(loginButton_, nullptr, TRUE);
        }

        std::wstring ReadWindowText(HWND control) const
        {
            const int length = GetWindowTextLengthW(control);
            std::wstring value(static_cast<std::size_t>(length) + 1, L'\0');
            if (length > 0)
                GetWindowTextW(control, value.data(), length + 1);
            value.resize(static_cast<std::size_t>(length));
            return value;
        }

        // Shared by Sign In and "Move this license to this PC". moveFirst = the user agreed
        // to unbind the key from the computer it is bound to, then sign in here.
        void BeginLogin(bool moveFirst)
        {
            if (loginBusy_)
                return;
            std::wstring key = moveFirst ? moveKey_ : Trim(ReadWindowText(licenseEdit_));
            if (key.empty())
            {
                SetLoginMessage(L"Enter your license key first.", true);
                SetFocus(licenseEdit_);
                return;
            }
            if (!moveFirst)
            {
                std::transform(key.begin(), key.end(), key.begin(),
                    [](wchar_t character) { return static_cast<wchar_t>(towupper(character)); });
                SetWindowTextW(licenseEdit_, key.c_str());
            }
            if (!HasConfiguredSecret())
            {
                SetLoginMessage(
                    L"Replace APP_SECRET near the top of main.cpp (or set PWFAUTH_SECRET) with your "
                    L"64-character hex secret.",
                    true);
                return;
            }

            SetMoveVisible(false);
            SetLoginBusy(true);
            SetLoginMessage(moveFirst ? L"Moving the license to this computer..." :
                L"Verifying the key and connecting to the server...", false);
            const HWND target = window_;
            const std::string utf8Key = WideToUtf8(key);
            std::thread([target, utf8Key, key, moveFirst]
            {
                auto result = std::make_unique<LoginResult>();
                result->licenseKey = key;
                try
                {
                    auto client = std::make_unique<PwfClient>(AppSecret(), BaseUrl());
                    bool moved = true;
                    if (moveFirst)
                    {
                        // Self-service move: unbinds the key from every computer it is
                        // bound to, so the login below binds it here. The developer's
                        // cooldown (12 hours by default) applies between two moves.
                        const PwfResponse reset = client->ResetHardwareId(utf8Key,
                            "Moved with the C++ desktop sample");
                        if (!reset.Success())
                        {
                            moved = false;
                            result->error = Describe(reset, "The license could not be moved.");
                        }
                    }
                    if (moved)
                    {
                        result->response = client->Login(utf8Key);
                        const std::string code = result->response.ErrorCode();
                        if (result->response.Success())
                            result->client = std::move(client);
                        else if (code == "HWID_MISMATCH" || code == "DEVICE_LIMIT")
                            result->boundElsewhere = true;
                        else
                            result->error = Describe(result->response, "Sign-in failed.");
                    }
                }
                catch (const PwfSecurityError&)
                {
                    result->error = L"The reply claimed success without encryption, so it did not come "
                        L"from the license server. A proxy, a hosts-file entry or a fake server is in the way.";
                }
                catch (const PwfNetworkError&)
                {
                    result->error = L"Cannot reach the license server. Check your internet connection "
                        L"and try again.";
                }
                catch (const PwfHttpError& exception)
                {
                    if (exception.Status() == 401)
                        result->error = L"The license server refused the application secret (HTTP 401). "
                            L"Check APP_SECRET in main.cpp or PWFAUTH_SECRET.";
                    else
                        result->error = L"The license server did not return a valid response (HTTP " +
                            std::to_wstring(exception.Status()) + L").";
                }
                catch (const std::exception& exception)
                {
                    result->error = L"Sign-in failed: " + Utf8ToWide(exception.what());
                }
                LoginResult* payload = result.release();
                if (!PostMessageW(target, WM_PWF_LOGIN_COMPLETE, 0,
                    reinterpret_cast<LPARAM>(payload)))
                    delete payload;
            }).detach();
        }

        void HandleLoginComplete(std::unique_ptr<LoginResult> result)
        {
            SetLoginBusy(false);
            if (result && result->boundElsewhere)
            {
                SetLoginMessage(L"This key is bound to another computer (" +
                    Utf8ToWide(result->response.ErrorCode()) + L").\r\n"
                    L"You can move it here — it then stops working on the other one.", true);
                SetMoveVisible(true);
                moveKey_ = result->licenseKey;
                return;
            }
            if (!result || !result->client)
            {
                SetLoginMessage(result ? result->error : L"Sign-in failed.", true);
                return;
            }
            try
            {
                const HWND target = window_;
                result->client->SetSessionEndedCallback([target](const std::string& code,
                    const std::string& message)
                {
                    auto payload = std::make_unique<SessionEndedResult>();
                    payload->code = Utf8ToWide(code);
                    payload->message = Utf8ToWide(message);
                    SessionEndedResult* raw = payload.release();
                    if (!PostMessageW(target, WM_PWF_SESSION_ENDED, 0,
                        reinterpret_cast<LPARAM>(raw)))
                        delete raw;
                });
                client_ = std::move(result->client);
                client_->StartHeartbeat();
                PopulateDashboard(result->response);
                SetLoginMessage(L"", false);
                showJson_ = false;
                ShowDashboard();
            }
            catch (const std::exception& exception)
            {
                client_.reset();
                SetLoginMessage(L"Could not start the licensed session: " +
                    Utf8ToWide(exception.what()), true);
                ShowLogin();
            }
        }

        void BeginLogout(bool closeAfter)
        {
            if (logoutBusy_)
            {
                if (closeAfter)
                    closing_ = true;
                return;
            }
            if (!client_)
            {
                if (closeAfter || closing_)
                    DestroyWindow(window_);
                else
                    ShowLogin();
                return;
            }

            logoutBusy_ = true;
            closing_ = closing_ || closeAfter;
            EnableWindow(logoutButton_, FALSE);
            SetWindowTextW(logoutButton_, L"Closing...");
            sessionLive_ = false;
            std::unique_ptr<PwfClient> client = std::move(client_);
            const HWND target = window_;
            std::thread([target, closeAfter, client = std::move(client)]() mutable
            {
                auto result = std::make_unique<LogoutResult>();
                result->closeAfter = closeAfter;
                try
                {
                    if (client->IsSignedIn())
                        client->Logout();
                    else
                        client->StopHeartbeat();
                }
                catch (const std::exception& exception)
                {
                    client->StopHeartbeat();
                    result->warning = L"Signed out locally, but the server could not be notified: " +
                        Utf8ToWide(exception.what());
                }
                result->client = std::move(client);
                LogoutResult* payload = result.release();
                if (!PostMessageW(target, WM_PWF_LOGOUT_COMPLETE, 0,
                    reinterpret_cast<LPARAM>(payload)))
                    delete payload;
            }).detach();
            InvalidateRect(window_, nullptr, TRUE);
        }

        void HandleLogoutComplete(std::unique_ptr<LogoutResult> result)
        {
            logoutBusy_ = false;
            EnableWindow(logoutButton_, TRUE);
            SetWindowTextW(logoutButton_, L"Sign Out");
            if (closing_ || (result && result->closeAfter))
            {
                DestroyWindow(window_);
                return;
            }
            ShowLogin();
            SetLoginMessage(result ? result->warning : L"", result && !result->warning.empty());
        }

        void HandleSessionEnded(std::unique_ptr<SessionEndedResult> result)
        {
            client_.reset();
            sessionLive_ = false;
            ShowLogin();
            if (result)
                SetLoginMessage(L"Session ended: " + result->message + L" (" + result->code + L")", true);
            else
                SetLoginMessage(L"The licensed session ended.", true);
        }

        void RequestClose()
        {
            if (closing_)
                return;
            closing_ = true;
            if (client_)
                BeginLogout(true);
            else
                DestroyWindow(window_);
        }

        void PopulateDashboard(const PwfResponse& response)
        {
            const nlohmann::json& root = response.data;
            const nlohmann::json user = root.contains("user") && root["user"].is_object() ?
                root["user"] : nlohmann::json::object();
            const nlohmann::json app = root.contains("app") && root["app"].is_object() ?
                root["app"] : nlohmann::json::object();

            const std::wstring appName = JsonString(app, "name");
            const std::wstring version = JsonString(app, "version");
            const std::wstring appMessage = JsonString(app, "message");
            const nlohmann::json seller = root.contains("seller") && root["seller"].is_object() ?
                root["seller"] : nlohmann::json::object();
            const std::wstring sellerName = JsonString(seller, "name");
            const std::wstring license = JsonString(user, "license_key");
            dashboardTitle_ = appName.empty() ? L"License Information" :
                appName + L" - License Information";

            std::vector<std::wstring> subtitleParts;
            if (!license.empty()) subtitleParts.push_back(license);
            if (!version.empty()) subtitleParts.push_back(L"Version " + version);
            if (!sellerName.empty()) subtitleParts.push_back(L"Sold by " + sellerName);
            if (!appMessage.empty()) subtitleParts.push_back(appMessage);
            dashboardSubtitle_.clear();
            for (std::size_t index = 0; index < subtitleParts.size(); ++index)
            {
                if (index) dashboardSubtitle_ += L"  |  ";
                dashboardSubtitle_ += subtitleParts[index];
            }

            statusValue_ = TitleCaseStatus(JsonString(user, "status"));
            const std::wstring keyType = JsonString(user, "key_type");
            if (keyType == L"lifetime" || !user.contains("expires_at") || user["expires_at"].is_null())
                typeValue_ = L"Lifetime";
            else if (user.contains("duration") && !user["duration"].is_null())
                typeValue_ = JsonScalar(user["duration"]) + L" " + keyType;
            else
                typeValue_ = keyType.empty() ? L"Not specified" : keyType;

            if (!user.contains("expires_at") || user["expires_at"].is_null())
            {
                expiryValue_ = L"Never expires";
                remainingValue_ = L"Lifetime";
            }
            else
            {
                expiryValue_ = JsonScalar(user["expires_at"]);
                if (expiryValue_.size() >= 16)
                {
                    expiryValue_ = expiryValue_.substr(0, 16);
                    std::replace(expiryValue_.begin(), expiryValue_.end(), L'T', L' ');
                }
                remainingValue_ = user.contains("days_remaining") && !user["days_remaining"].is_null() ?
                    JsonScalar(user["days_remaining"]) + L" days" : L"Not specified";
            }

            sessionLive_ = true;
            sessionInfo_ = L"Device ID: " + Utf8ToWide(client_->HardwareId()) +
                L"   |   Heartbeat every " + std::to_wstring(client_->HeartbeatSeconds()) +
                L" seconds   |   Session ID: " + Utf8ToWide(client_->SessionId());

            details_.clear();
            FlattenJson(root, "", details_);
            ListView_DeleteAllItems(detailsList_);
            for (std::size_t index = 0; index < details_.size(); ++index)
            {
                LVITEMW item{};
                item.mask = LVIF_TEXT;
                item.iItem = static_cast<int>(index);
                item.pszText = const_cast<wchar_t*>(details_[index].field.c_str());
                const int inserted = ListView_InsertItem(detailsList_, &item);
                ListView_SetItemText(detailsList_, inserted, 1,
                    const_cast<wchar_t*>(details_[index].path.c_str()));
                ListView_SetItemText(detailsList_, inserted, 2,
                    const_cast<wchar_t*>(details_[index].value.c_str()));
            }

            rawJson_ = Utf8ToWide(root.dump(2));
            for (std::size_t position = 0; (position = rawJson_.find(L'\n', position)) != std::wstring::npos;
                position += 2)
                rawJson_.replace(position, 1, L"\r\n");
            SetWindowTextW(jsonEdit_, rawJson_.c_str());
            InvalidateRect(window_, nullptr, TRUE);
        }

        void CopyJson()
        {
            if (rawJson_.empty() || !OpenClipboard(window_))
                return;
            EmptyClipboard();
            const SIZE_T bytes = (rawJson_.size() + 1) * sizeof(wchar_t);
            HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (memory)
            {
                void* target = GlobalLock(memory);
                if (target)
                {
                    std::memcpy(target, rawJson_.c_str(), bytes);
                    GlobalUnlock(memory);
                    if (!SetClipboardData(CF_UNICODETEXT, memory))
                        GlobalFree(memory);
                    else
                    {
                        SetWindowTextW(copyButton_, L"Copied!");
                        SetTimer(window_, 1, 1600, nullptr);
                    }
                }
                else
                    GlobalFree(memory);
            }
            CloseClipboard();
        }

        void Paint()
        {
            PAINTSTRUCT paint{};
            HDC dc = BeginPaint(window_, &paint);
            RECT client{};
            GetClientRect(window_, &client);
            if (page_ == Page::Login)
                PaintLogin(dc, client);
            else
                PaintDashboard(dc, client);
            EndPaint(window_, &paint);
        }

        void PaintLogin(HDC dc, const RECT& client)
        {
            Fill(dc, client, PageColor);
            const int cardX = (client.right - 500) / 2;
            const int cardY = (client.bottom - CardHeight) / 2;
            RECT card{ cardX, cardY, cardX + 500, cardY + CardHeight };
            Fill(dc, card, CardColor);
            Fill(dc, RECT{ cardX, cardY, cardX + 500, cardY + 5 }, BlueColor);
            DrawLabel(dc, L"\u25C6  PWF AUTH", RECT{ cardX + 42, cardY + 43, cardX + 458, cardY + 87 },
                font16Bold_, BlueLightColor, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            DrawLabel(dc, L"Welcome Back", RECT{ cardX + 42, cardY + 102, cardX + 458, cardY + 143 },
                font18Bold_, WhiteColor, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            DrawLabel(dc,
                L"Enter your key to connect to the license server\nand view your complete subscription details",
                RECT{ cardX + 42, cardY + 150, cardX + 458, cardY + 193 },
                font9_, MutedDarkColor, DT_CENTER | DT_TOP | DT_WORDBREAK);
            DrawLabel(dc, L"License key", RECT{ cardX + 42, cardY + 207, cardX + 458, cardY + 230 },
                font9_, RGB(203, 213, 225));
            DrawLabel(dc, L"Encrypted connection  \u2022  Key bound to this device",
                RECT{ cardX + 42, cardY + 466, cardX + 458, cardY + 488 },
                font9_, RGB(139, 151, 173), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }

        void PaintDashboard(HDC dc, const RECT& client)
        {
            Fill(dc, client, SurfaceColor);
            DrawLabel(dc, dashboardTitle_, RECT{ 30, 13, client.right - 390, 56 },
                font20Bold_, TextColor);
            DrawLabel(dc, dashboardSubtitle_, RECT{ 30, 55, client.right - 390, 83 },
                font9_, MutedColor);
            DrawLabel(dc, sessionLive_ ? L"\u25CF Session active and protected" : L"Closing session...",
                RECT{ client.right - 380, 44, client.right - 165, 70 }, font9_,
                sessionLive_ ? SuccessColor : WarningColor, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

            const int left = 30;
            const int available = client.right - 60;
            const int gap = 10;
            const int cardWidth = (available - gap * 3) / 4;
            const std::wstring captions[] = { L"KEY STATUS", L"SUBSCRIPTION TYPE",
                L"EXPIRATION DATE", L"TIME REMAINING" };
            const std::wstring values[] = { statusValue_, typeValue_, expiryValue_, remainingValue_ };
            for (int index = 0; index < 4; ++index)
            {
                const int x = left + index * (cardWidth + gap);
                RECT card{ x, 112, x + cardWidth, 202 };
                Fill(dc, card, WhiteColor);
                DrawLabel(dc, captions[index], RECT{ x + 18, 125, x + cardWidth - 18, 150 },
                    font8_, MutedColor);
                DrawLabel(dc, values[index], RECT{ x + 18, 153, x + cardWidth - 18, 192 },
                    index == 2 ? font13_ : font16Bold_,
                    index == 0 ? SuccessColor : (index == 3 ? BlueColor : TextColor));
            }

            if (showJson_)
                DrawLabel(dc, L"The complete original response returned by the server",
                    RECT{ 34, 266, client.right - 170, 304 }, font9_, MutedColor);
            DrawLabel(dc, sessionInfo_, RECT{ 30, client.bottom - 39, client.right - 30, client.bottom - 5 },
                font8_, MutedColor);
        }

        void DrawOwnerButton(const DRAWITEMSTRUCT& item)
        {
            RECT rectangle = item.rcItem;
            COLORREF background = WhiteColor;
            COLORREF foreground = TextColor;
            HFONT font = font9_;

            if (item.CtlID == IDC_LOGIN)
            {
                background = (item.itemState & ODS_DISABLED) ? RGB(96, 130, 184) : BlueColor;
                foreground = WhiteColor;
                font = font11Bold_;
            }
            else if (item.CtlID == IDC_MOVE_LICENSE)
            {
                background = CardColor;
                foreground = BlueLightColor;
                font = font10Bold_;
            }
            else if (item.CtlID == IDC_COPY_JSON)
            {
                background = RGB(51, 65, 85);
                foreground = WhiteColor;
            }
            else if ((item.CtlID == IDC_TAB_DETAILS && !showJson_) ||
                (item.CtlID == IDC_TAB_JSON && showJson_))
            {
                background = WhiteColor;
                foreground = TextColor;
            }
            else if (item.CtlID == IDC_TAB_DETAILS || item.CtlID == IDC_TAB_JSON)
            {
                background = RGB(226, 232, 240);
                foreground = TextColor;
            }

            if (item.itemState & ODS_SELECTED)
                background = RGB(GetRValue(background) * 9 / 10,
                    GetGValue(background) * 9 / 10, GetBValue(background) * 9 / 10);
            Fill(item.hDC, rectangle, background);
            if (item.CtlID == IDC_LOGOUT || item.CtlID == IDC_MOVE_LICENSE)
            {
                HPEN pen = CreatePen(PS_SOLID, 1,
                    item.CtlID == IDC_MOVE_LICENSE ? BlueColor : RGB(203, 213, 225));
                HGDIOBJ previous = SelectObject(item.hDC, pen);
                SelectObject(item.hDC, GetStockObject(NULL_BRUSH));
                Rectangle(item.hDC, rectangle.left, rectangle.top, rectangle.right, rectangle.bottom);
                SelectObject(item.hDC, previous);
                DeleteObject(pen);
            }
            wchar_t text[128]{};
            GetWindowTextW(item.hwndItem, text, static_cast<int>(std::size(text)));
            DrawLabel(item.hDC, text, rectangle, font, foreground,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            if (item.itemState & ODS_FOCUS)
            {
                InflateRect(&rectangle, -3, -3);
                DrawFocusRect(item.hDC, &rectangle);
            }
        }

        HWND window_ = nullptr;
        HWND licenseEdit_ = nullptr;
        HWND loginButton_ = nullptr;
        HWND loginStatus_ = nullptr;
        HWND moveButton_ = nullptr;
        HWND logoutButton_ = nullptr;
        HWND detailsTabButton_ = nullptr;
        HWND jsonTabButton_ = nullptr;
        HWND detailsList_ = nullptr;
        HWND jsonEdit_ = nullptr;
        HWND copyButton_ = nullptr;

        HBRUSH pageBrush_ = nullptr;
        HBRUSH cardBrush_ = nullptr;
        HBRUSH entryBrush_ = nullptr;
        HBRUSH surfaceBrush_ = nullptr;
        HFONT font8_ = nullptr;
        HFONT font9_ = nullptr;
        HFONT font10_ = nullptr;
        HFONT font10Bold_ = nullptr;
        HFONT font11Bold_ = nullptr;
        HFONT font13_ = nullptr;
        HFONT font16Bold_ = nullptr;
        HFONT font18Bold_ = nullptr;
        HFONT font20Bold_ = nullptr;
        HFONT monoFont_ = nullptr;

        Page page_ = Page::Login;
        bool showJson_ = false;
        bool loginBusy_ = false;
        bool loginError_ = false;
        bool logoutBusy_ = false;
        bool closing_ = false;
        bool sessionLive_ = false;
        std::unique_ptr<PwfClient> client_;
        std::wstring moveKey_;  // the key "Move this license" would move

        std::wstring dashboardTitle_ = L"License Information";
        std::wstring dashboardSubtitle_;
        std::wstring statusValue_ = L"Active";
        std::wstring typeValue_ = L"Not specified";
        std::wstring expiryValue_ = L"Never expires";
        std::wstring remainingValue_ = L"Lifetime";
        std::wstring sessionInfo_;
        std::wstring rawJson_;
        std::vector<DetailRow> details_;
    };
}

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int showCommand)
{
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    INITCOMMONCONTROLSEX controls{ sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&controls);

    const std::wstring commandLine = GetCommandLineW();
    const bool protocolPassed = PwfClient::ProtocolSelfTest();
    if (commandLine.find(L"--self-test") != std::wstring::npos)
        return protocolPassed ? 0 : 1;
    if (!protocolPassed)
    {
        MessageBoxW(nullptr, L"The AES/HMAC protocol self-test failed.", L"PWF Auth",
            MB_OK | MB_ICONERROR);
        return 1;
    }

    AppWindow application;
    if (!application.Create(instance))
    {
        MessageBoxW(nullptr, L"Could not create the application window.", L"PWF Auth",
            MB_OK | MB_ICONERROR);
        return 1;
    }
    if (commandLine.find(L"--ui-smoke") != std::wstring::npos)
    {
        application.CloseForSmokeTest();
        return 0;
    }
    application.Show(showCommand);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
