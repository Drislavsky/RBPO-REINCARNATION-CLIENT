#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <strsafe.h>
#include <sddl.h>
#include <winhttp.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "bmtx_rpc.h"

namespace {

constexpr wchar_t kServiceName[] = L"BMTXService";
constexpr wchar_t kServiceDisplayName[] = L"BMTX Service";
constexpr wchar_t kRpcEndpoint[] = L"BMTX_RPC_ALPC_ENDPOINT";
constexpr wchar_t kClientExeName[] = L"BMTX.exe";

constexpr wchar_t kServerHost[] = L"localhost";
constexpr INTERNET_PORT kServerPort = 8443;
constexpr wchar_t kAuthLoginEndpoint[] = L"/api/auth/login";
constexpr wchar_t kAuthRefreshEndpoint[] = L"/api/auth/refresh";
constexpr wchar_t kAuthLogoutEndpoint[] = L"/api/auth/logout";
constexpr wchar_t kLicenseActivateEndpoint[] = L"/api/license/activate";
constexpr wchar_t kLicenseVerifyPathPrefix[] = L"/api/license/verify?mac=";

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
HANDLE g_refresh_thread = nullptr;
CRITICAL_SECTION g_process_lock{};
CRITICAL_SECTION g_state_lock{};
std::map<DWORD, PROCESS_INFORMATION> g_clients;

struct ServiceState {
    std::wstring username;
    std::wstring access_token;
    std::wstring refresh_token;
    FILETIME access_expires_at{};
    FILETIME refresh_expires_at{};
    std::wstring license_code;
    std::wstring license_ticket_json;
    std::wstring license_signature;
    FILETIME license_expires_at{};
    FILETIME license_ticket_received_at{};
    DWORD license_ticket_lifetime_seconds = 0;
    std::wstring last_message;
};

ServiceState g_state;

void LogDebug(const wchar_t* message) {
    OutputDebugStringW(message);
    OutputDebugStringW(L"\n");
}

std::wstring GetModuleDirectory() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    std::wstring result(path);
    const size_t slash = result.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        result.resize(slash);
    }
    return result;
}

std::wstring Quote(const std::wstring& value) {
    return L"\"" + value + L"\"";
}

void SetServiceState(DWORD state, DWORD win32_exit_code = NO_ERROR, DWORD wait_hint = 0) {
    static DWORD checkpoint = 1;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32_exit_code;
    g_status.dwWaitHint = wait_hint;

    if (state == SERVICE_RUNNING) {
        g_status.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;
    } else {
        g_status.dwControlsAccepted = 0;
    }

    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        g_status.dwCheckPoint = checkpoint++;
    } else {
        g_status.dwCheckPoint = 0;
        checkpoint = 1;
    }

    SetServiceStatus(g_status_handle, &g_status);
}

bool IsProcessRunning(HANDLE process) {
    if (process == nullptr) {
        return false;
    }

    DWORD exit_code = 0;
    return GetExitCodeProcess(process, &exit_code) && exit_code == STILL_ACTIVE;
}

void CloseProcessInfo(PROCESS_INFORMATION& pi) {
    if (pi.hThread != nullptr) {
        CloseHandle(pi.hThread);
        pi.hThread = nullptr;
    }
    if (pi.hProcess != nullptr) {
        CloseHandle(pi.hProcess);
        pi.hProcess = nullptr;
    }
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        return {};
    }
    std::string result(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), needed, nullptr, nullptr);
    return result;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring result(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), needed);
    return result;
}

std::wstring JsonEscape(const std::wstring& input) {
    std::wstring output;
    output.reserve(input.size() + 8);
    for (wchar_t ch : input) {
        switch (ch) {
        case L'\\': output += L"\\\\"; break;
        case L'\"': output += L"\\\""; break;
        case L'\r': output += L"\\r"; break;
        case L'\n': output += L"\\n"; break;
        case L'\t': output += L"\\t"; break;
        default: output.push_back(ch); break;
        }
    }
    return output;
}

std::string JsonEscapeUtf8(const std::wstring& input) {
    return WideToUtf8(JsonEscape(input));
}

std::string UrlEncodeUtf8(const std::wstring& input) {
    const std::string raw = WideToUtf8(input);
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (unsigned char ch : raw) {
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
            result.push_back(static_cast<char>(ch));
        } else {
            result.push_back('%');
            result.push_back(hex[ch >> 4]);
            result.push_back(hex[ch & 0x0F]);
        }
    }
    return result;
}

std::wstring GetDeviceMacString() {
    wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = ARRAYSIZE(computer_name);
    if (!GetComputerNameW(computer_name, &size)) {
        return L"BMTX-DEVICE";
    }
    return L"BMTX-" + std::wstring(computer_name);
}

std::wstring GetDeviceNameString() {
    wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = ARRAYSIZE(computer_name);
    if (!GetComputerNameW(computer_name, &size)) {
        return L"BMTX Windows Client";
    }
    return std::wstring(computer_name);
}

bool ParseIsoUtcToFileTime(const std::wstring& value, FILETIME* output) {
    if (output == nullptr || value.size() < 19) {
        return false;
    }

    SYSTEMTIME st{};
    st.wYear = static_cast<WORD>(_wtoi(value.substr(0, 4).c_str()));
    st.wMonth = static_cast<WORD>(_wtoi(value.substr(5, 2).c_str()));
    st.wDay = static_cast<WORD>(_wtoi(value.substr(8, 2).c_str()));
    st.wHour = static_cast<WORD>(_wtoi(value.substr(11, 2).c_str()));
    st.wMinute = static_cast<WORD>(_wtoi(value.substr(14, 2).c_str()));
    st.wSecond = static_cast<WORD>(_wtoi(value.substr(17, 2).c_str()));
    st.wMilliseconds = 0;

    if (st.wYear == 0 || st.wMonth == 0 || st.wDay == 0) {
        return false;
    }

    return SystemTimeToFileTime(&st, output) != FALSE;
}

ULONGLONG FileTimeToUInt64(const FILETIME& ft) {
    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

FILETIME UInt64ToFileTime(ULONGLONG value) {
    ULARGE_INTEGER integer{};
    integer.QuadPart = value;
    FILETIME ft{};
    ft.dwLowDateTime = integer.LowPart;
    ft.dwHighDateTime = integer.HighPart;
    return ft;
}

FILETIME NowFileTime() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    return ft;
}

ULONGLONG SecondsToFileTimeTicks(DWORD seconds) {
    return static_cast<ULONGLONG>(seconds) * 10000000ULL;
}

__int64 FileTimeToUnixSeconds(const FILETIME& ft) {
    const ULONGLONG value = FileTimeToUInt64(ft);
    if (value == 0 || value < 116444736000000000ULL) {
        return 0;
    }
    return static_cast<__int64>((value - 116444736000000000ULL) / 10000000ULL);
}

bool IsFileTimeSet(const FILETIME& ft) {
    return ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0;
}

bool IsFileTimeExpiredOrNear(const FILETIME& ft, DWORD safety_seconds) {
    if (!IsFileTimeSet(ft)) {
        return true;
    }
    const ULONGLONG now = FileTimeToUInt64(NowFileTime());
    const ULONGLONG target = FileTimeToUInt64(ft);
    const ULONGLONG safety = SecondsToFileTimeTicks(safety_seconds);
    return target <= now + safety;
}

std::wstring ExtractJsonString(const std::wstring& json, const std::wstring& key) {
    const std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = json.find(pattern);
    if (pos == std::wstring::npos) {
        return {};
    }
    pos = json.find(L':', pos + pattern.size());
    if (pos == std::wstring::npos) {
        return {};
    }
    pos = json.find(L'\"', pos + 1);
    if (pos == std::wstring::npos) {
        return {};
    }

    std::wstring result;
    bool escaped = false;
    for (size_t i = pos + 1; i < json.size(); ++i) {
        const wchar_t ch = json[i];
        if (escaped) {
            switch (ch) {
            case L'\"': result.push_back(L'\"'); break;
            case L'\\': result.push_back(L'\\'); break;
            case L'/': result.push_back(L'/'); break;
            case L'b': result.push_back(L'\b'); break;
            case L'f': result.push_back(L'\f'); break;
            case L'n': result.push_back(L'\n'); break;
            case L'r': result.push_back(L'\r'); break;
            case L't': result.push_back(L'\t'); break;
            default: result.push_back(ch); break;
            }
            escaped = false;
            continue;
        }
        if (ch == L'\\') {
            escaped = true;
            continue;
        }
        if (ch == L'\"') {
            return result;
        }
        result.push_back(ch);
    }
    return {};
}

bool ExtractJsonBool(const std::wstring& json, const std::wstring& key, bool default_value = false) {
    const std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = json.find(pattern);
    if (pos == std::wstring::npos) {
        return default_value;
    }
    pos = json.find(L':', pos + pattern.size());
    if (pos == std::wstring::npos) {
        return default_value;
    }
    size_t start = json.find_first_not_of(L" \t\r\n", pos + 1);
    if (start == std::wstring::npos) {
        return default_value;
    }
    if (json.compare(start, 4, L"true") == 0) {
        return true;
    }
    if (json.compare(start, 5, L"false") == 0) {
        return false;
    }
    return default_value;
}

DWORD ExtractJsonDword(const std::wstring& json, const std::wstring& key, DWORD default_value = 0) {
    const std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = json.find(pattern);
    if (pos == std::wstring::npos) {
        return default_value;
    }
    pos = json.find(L':', pos + pattern.size());
    if (pos == std::wstring::npos) {
        return default_value;
    }
    size_t start = json.find_first_of(L"0123456789", pos + 1);
    if (start == std::wstring::npos) {
        return default_value;
    }
    return static_cast<DWORD>(wcstoul(json.c_str() + start, nullptr, 10));
}

std::wstring ExtractJsonObject(const std::wstring& json, const std::wstring& key) {
    const std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = json.find(pattern);
    if (pos == std::wstring::npos) {
        return {};
    }
    pos = json.find(L'{', pos + pattern.size());
    if (pos == std::wstring::npos) {
        return {};
    }

    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (size_t i = pos; i < json.size(); ++i) {
        const wchar_t ch = json[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch == L'\\' && in_string) {
            escaped = true;
            continue;
        }
        if (ch == L'\"') {
            in_string = !in_string;
            continue;
        }
        if (in_string) {
            continue;
        }
        if (ch == L'{') {
            ++depth;
        } else if (ch == L'}') {
            --depth;
            if (depth == 0) {
                return json.substr(pos, i - pos + 1);
            }
        }
    }
    return {};
}

struct HttpResponse {
    DWORD status = 0;
    std::wstring body;
    DWORD error = ERROR_SUCCESS;
};

HttpResponse HttpsRequest(const wchar_t* method, const std::wstring& path, const std::string& body, const std::wstring& bearer_token = L"") {
    HttpResponse result{};

    HINTERNET session = WinHttpOpen(L"BMTXService/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) {
        result.error = GetLastError();
        return result;
    }

    HINTERNET connection = WinHttpConnect(session, kServerHost, kServerPort, 0);
    if (connection == nullptr) {
        result.error = GetLastError();
        WinHttpCloseHandle(session);
        return result;
    }

    HINTERNET request = WinHttpOpenRequest(
        connection,
        method,
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (request == nullptr) {
        result.error = GetLastError();
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return result;
    }

    DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                           SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags));

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearer_token.empty()) {
        headers += L"Authorization: Bearer ";
        headers += bearer_token;
        headers += L"\r\n";
    }

    const BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);

    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        result.error = GetLastError();
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return result;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status_code, &status_size, nullptr);
    result.status = status_code;

    std::string response_bytes;
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), available, &read)) {
            result.error = GetLastError();
            break;
        }
        chunk.resize(read);
        response_bytes += chunk;
    }

    result.body = Utf8ToWide(response_bytes);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return result;
}

void ClearLicenseLocked() {
    g_state.license_code.clear();
    g_state.license_ticket_json.clear();
    g_state.license_signature.clear();
    g_state.license_expires_at = FILETIME{};
    g_state.license_ticket_received_at = FILETIME{};
    g_state.license_ticket_lifetime_seconds = 0;
}

void ClearAuthLocked() {
    g_state.username.clear();
    g_state.access_token.clear();
    g_state.refresh_token.clear();
    g_state.access_expires_at = FILETIME{};
    g_state.refresh_expires_at = FILETIME{};
    ClearLicenseLocked();
}

void SetMessageLocked(const std::wstring& message) {
    g_state.last_message = message;
}

void FillClientStateLocked(BMTX_CLIENT_STATE* state) {
    ZeroMemory(state, sizeof(*state));
    state->authenticated = !g_state.access_token.empty() && !g_state.refresh_token.empty();
    state->licensed = !g_state.license_ticket_json.empty() && !ExtractJsonBool(g_state.license_ticket_json, L"blocked", false) && !IsFileTimeExpiredOrNear(g_state.license_expires_at, 0);
    state->antivirusEnabled = state->authenticated && state->licensed;
    state->licenseExpiresAtUnix = FileTimeToUnixSeconds(g_state.license_expires_at);
    StringCchCopyW(state->username, ARRAYSIZE(state->username), g_state.username.empty() ? L"" : g_state.username.c_str());
    StringCchCopyW(state->message, ARRAYSIZE(state->message), g_state.last_message.empty() ? L"" : g_state.last_message.c_str());
}

void FillClientState(BMTX_CLIENT_STATE* state) {
    EnterCriticalSection(&g_state_lock);
    FillClientStateLocked(state);
    LeaveCriticalSection(&g_state_lock);
}

bool StoreTokensFromResponseLocked(const std::wstring& username, const std::wstring& json, std::wstring* error_message) {
    const std::wstring access_token = ExtractJsonString(json, L"accessToken");
    const std::wstring refresh_token = ExtractJsonString(json, L"refreshToken");
    const std::wstring access_expires = ExtractJsonString(json, L"accessExpiresAt");
    const std::wstring refresh_expires = ExtractJsonString(json, L"refreshExpiresAt");

    FILETIME access_ft{};
    FILETIME refresh_ft{};
    if (access_token.empty() || refresh_token.empty() || !ParseIsoUtcToFileTime(access_expires, &access_ft) || !ParseIsoUtcToFileTime(refresh_expires, &refresh_ft)) {
        if (error_message != nullptr) {
            *error_message = L"Invalid token response from server";
        }
        return false;
    }

    g_state.username = username;
    g_state.access_token = access_token;
    g_state.refresh_token = refresh_token;
    g_state.access_expires_at = access_ft;
    g_state.refresh_expires_at = refresh_ft;
    SetMessageLocked(L"Authenticated");
    return true;
}

bool StoreTicketFromResponseLocked(const std::wstring& json, std::wstring* error_message) {
    const std::wstring ticket = ExtractJsonObject(json, L"ticket");
    const std::wstring signature = ExtractJsonString(json, L"signature");
    if (ticket.empty()) {
        if (error_message != nullptr) {
            *error_message = L"License ticket was not returned by server";
        }
        return false;
    }

    FILETIME expiration_ft{};
    const std::wstring expiration = ExtractJsonString(ticket, L"expirationDate");
    if (!ParseIsoUtcToFileTime(expiration, &expiration_ft)) {
        if (error_message != nullptr) {
            *error_message = L"Invalid license expiration date";
        }
        return false;
    }

    if (ExtractJsonBool(ticket, L"blocked", false)) {
        ClearLicenseLocked();
        if (error_message != nullptr) {
            *error_message = L"License is blocked";
        }
        return false;
    }

    g_state.license_ticket_json = ticket;
    g_state.license_signature = signature;
    g_state.license_expires_at = expiration_ft;
    g_state.license_ticket_received_at = NowFileTime();
    g_state.license_ticket_lifetime_seconds = ExtractJsonDword(ticket, L"ticketLifetime", 3600);
    if (g_state.license_ticket_lifetime_seconds == 0) {
        g_state.license_ticket_lifetime_seconds = 3600;
    }
    SetMessageLocked(L"License is active");
    return true;
}

DWORD RefreshTokensInternal() {
    std::wstring refresh_token;
    std::wstring username;
    EnterCriticalSection(&g_state_lock);
    refresh_token = g_state.refresh_token;
    username = g_state.username;
    LeaveCriticalSection(&g_state_lock);

    if (refresh_token.empty()) {
        return ERROR_NOT_LOGGED_ON;
    }

    const std::string body = std::string("{\"refreshToken\":\"") + JsonEscapeUtf8(refresh_token) + "\"}";
    const HttpResponse response = HttpsRequest(L"POST", kAuthRefreshEndpoint, body);
    if (response.error != ERROR_SUCCESS) {
        return response.error;
    }
    if (response.status < 200 || response.status >= 300) {
        EnterCriticalSection(&g_state_lock);
        ClearAuthLocked();
        SetMessageLocked(L"Token refresh failed; user logged out");
        LeaveCriticalSection(&g_state_lock);
        return ERROR_ACCESS_DENIED;
    }

    std::wstring error;
    EnterCriticalSection(&g_state_lock);
    const bool ok = StoreTokensFromResponseLocked(username, response.body, &error);
    if (!ok) {
        ClearAuthLocked();
        SetMessageLocked(error);
    }
    LeaveCriticalSection(&g_state_lock);
    return ok ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

DWORD RefreshLicenseInternal() {
    std::wstring access_token;
    std::wstring license_code;
    EnterCriticalSection(&g_state_lock);
    access_token = g_state.access_token;
    license_code = g_state.license_code;
    LeaveCriticalSection(&g_state_lock);

    if (access_token.empty()) {
        return ERROR_NOT_LOGGED_ON;
    }
    if (license_code.empty()) {
        return ERROR_LICENSE_QUOTA_EXCEEDED;
    }

    const std::wstring path = std::wstring(kLicenseVerifyPathPrefix) + Utf8ToWide(UrlEncodeUtf8(GetDeviceMacString())) + L"&code=" + Utf8ToWide(UrlEncodeUtf8(license_code));
    HttpResponse response = HttpsRequest(L"GET", path, {}, access_token);
    if (response.error != ERROR_SUCCESS) {
        return response.error;
    }
    if (response.status == 401 || response.status == 403) {
        const DWORD refreshed = RefreshTokensInternal();
        if (refreshed == ERROR_SUCCESS) {
            EnterCriticalSection(&g_state_lock);
            access_token = g_state.access_token;
            LeaveCriticalSection(&g_state_lock);
            response = HttpsRequest(L"GET", path, {}, access_token);
        }
    }
    if (response.status < 200 || response.status >= 300) {
        EnterCriticalSection(&g_state_lock);
        ClearLicenseLocked();
        SetMessageLocked(L"License is missing or invalid");
        LeaveCriticalSection(&g_state_lock);
        return ERROR_LICENSE_QUOTA_EXCEEDED;
    }

    std::wstring error;
    EnterCriticalSection(&g_state_lock);
    const bool ok = StoreTicketFromResponseLocked(response.body, &error);
    if (!ok) {
        SetMessageLocked(error);
    }
    LeaveCriticalSection(&g_state_lock);
    return ok ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

DWORD LoginInternal(const std::wstring& username, const std::wstring& password) {
    const std::string body = std::string("{\"username\":\"") + JsonEscapeUtf8(username) + "\",\"password\":\"" + JsonEscapeUtf8(password) + "\"}";
    const HttpResponse response = HttpsRequest(L"POST", kAuthLoginEndpoint, body);
    if (response.error != ERROR_SUCCESS) {
        return response.error;
    }
    if (response.status < 200 || response.status >= 300) {
        EnterCriticalSection(&g_state_lock);
        ClearAuthLocked();
        SetMessageLocked(L"Authentication failed");
        LeaveCriticalSection(&g_state_lock);
        return ERROR_LOGON_FAILURE;
    }

    std::wstring error;
    EnterCriticalSection(&g_state_lock);
    ClearAuthLocked();
    const bool ok = StoreTokensFromResponseLocked(username, response.body, &error);
    if (!ok) {
        SetMessageLocked(error);
    }
    LeaveCriticalSection(&g_state_lock);
    return ok ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

DWORD LogoutInternal() {
    std::wstring refresh_token;
    EnterCriticalSection(&g_state_lock);
    refresh_token = g_state.refresh_token;
    LeaveCriticalSection(&g_state_lock);

    if (!refresh_token.empty()) {
        const std::string body = std::string("{\"refreshToken\":\"") + JsonEscapeUtf8(refresh_token) + "\"}";
        HttpsRequest(L"POST", kAuthLogoutEndpoint, body);
    }

    EnterCriticalSection(&g_state_lock);
    ClearAuthLocked();
    SetMessageLocked(L"Logged out");
    LeaveCriticalSection(&g_state_lock);
    return ERROR_SUCCESS;
}

DWORD ActivateProductInternal(const std::wstring& activation_code) {
    std::wstring access_token;
    EnterCriticalSection(&g_state_lock);
    access_token = g_state.access_token;
    LeaveCriticalSection(&g_state_lock);

    if (access_token.empty()) {
        return ERROR_NOT_LOGGED_ON;
    }

    const std::string body = std::string("{\"deviceMac\":\"") + JsonEscapeUtf8(GetDeviceMacString()) +
        "\",\"deviceName\":\"" + JsonEscapeUtf8(GetDeviceNameString()) +
        "\",\"licenseCode\":\"" + JsonEscapeUtf8(activation_code) + "\"}";

    HttpResponse response = HttpsRequest(L"POST", kLicenseActivateEndpoint, body, access_token);
    if (response.error != ERROR_SUCCESS) {
        return response.error;
    }
    if (response.status == 401 || response.status == 403) {
        const DWORD refreshed = RefreshTokensInternal();
        if (refreshed == ERROR_SUCCESS) {
            EnterCriticalSection(&g_state_lock);
            access_token = g_state.access_token;
            LeaveCriticalSection(&g_state_lock);
            response = HttpsRequest(L"POST", kLicenseActivateEndpoint, body, access_token);
        }
    }
    if (response.status < 200 || response.status >= 300) {
        EnterCriticalSection(&g_state_lock);
        ClearLicenseLocked();
        SetMessageLocked(L"Activation failed");
        LeaveCriticalSection(&g_state_lock);
        return ERROR_LICENSE_QUOTA_EXCEEDED;
    }

    std::wstring error;
    EnterCriticalSection(&g_state_lock);
    g_state.license_code = activation_code;
    const bool has_ticket = StoreTicketFromResponseLocked(response.body, &error);
    LeaveCriticalSection(&g_state_lock);

    if (!has_ticket) {
        const DWORD refreshed_license = RefreshLicenseInternal();
        if (refreshed_license != ERROR_SUCCESS) {
            EnterCriticalSection(&g_state_lock);
            SetMessageLocked(error.empty() ? L"Activation succeeded, but license status request failed" : error);
            LeaveCriticalSection(&g_state_lock);
            return refreshed_license;
        }
    }

    return ERROR_SUCCESS;
}

DWORD WINAPI RefreshWorkerThread(LPVOID) {
    while (WaitForSingleObject(g_stop_event, 5000) == WAIT_TIMEOUT) {
        bool need_token_refresh = false;
        bool need_license_refresh = false;
        bool has_auth = false;
        bool has_license = false;

        EnterCriticalSection(&g_state_lock);
        has_auth = !g_state.refresh_token.empty();
        has_license = !g_state.license_ticket_json.empty();
        need_token_refresh = has_auth && (IsFileTimeExpiredOrNear(g_state.access_expires_at, 60) || IsFileTimeExpiredOrNear(g_state.refresh_expires_at, 300));
        const DWORD lifetime = g_state.license_ticket_lifetime_seconds == 0 ? 3600 : g_state.license_ticket_lifetime_seconds;
        const DWORD refresh_after = std::max<DWORD>(30, lifetime * 8 / 10);
        const DWORD license_safety = lifetime > 120 ? 60 : 10;
        const ULONGLONG received_at = FileTimeToUInt64(g_state.license_ticket_received_at);
        const ULONGLONG now = FileTimeToUInt64(NowFileTime());
        need_license_refresh = has_license && received_at != 0 && now >= received_at + SecondsToFileTimeTicks(refresh_after);
        if (has_license && IsFileTimeExpiredOrNear(g_state.license_expires_at, license_safety)) {
            need_license_refresh = true;
        }
        LeaveCriticalSection(&g_state_lock);

        if (need_token_refresh) {
            RefreshTokensInternal();
        }
        if (need_license_refresh) {
            RefreshLicenseInternal();
        }
    }
    return 0;
}

bool LaunchClientInSession(DWORD session_id) {
    if (session_id == 0) {
        return false;
    }

    EnterCriticalSection(&g_process_lock);
    auto existing = g_clients.find(session_id);
    if (existing != g_clients.end()) {
        if (IsProcessRunning(existing->second.hProcess)) {
            LeaveCriticalSection(&g_process_lock);
            return true;
        }
        CloseProcessInfo(existing->second);
        g_clients.erase(existing);
    }
    LeaveCriticalSection(&g_process_lock);

    HANDLE user_token = nullptr;
    if (!WTSQueryUserToken(session_id, &user_token)) {
        return false;
    }

    HANDLE primary_token = nullptr;
    SECURITY_ATTRIBUTES token_sa{};
    token_sa.nLength = sizeof(token_sa);
    if (!DuplicateTokenEx(
            user_token,
            MAXIMUM_ALLOWED,
            &token_sa,
            SecurityImpersonation,
            TokenPrimary,
            &primary_token)) {
        CloseHandle(user_token);
        return false;
    }
    CloseHandle(user_token);

    void* environment = nullptr;
    if (!CreateEnvironmentBlock(&environment, primary_token, FALSE)) {
        environment = nullptr;
    }

    const std::wstring exe_path = GetModuleDirectory() + L"\\" + kClientExeName;
    wchar_t service_pid_arg[64]{};
    StringCchPrintfW(service_pid_arg, ARRAYSIZE(service_pid_arg), L" --bmtx-service-pid=%lu", GetCurrentProcessId());
    std::wstring command_line = Quote(exe_path) + L" --hidden --bmtx-service-child" + service_pid_arg;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    const DWORD flags = CREATE_UNICODE_ENVIRONMENT;
    const BOOL created = CreateProcessAsUserW(
        primary_token,
        exe_path.c_str(),
        command_line.data(),
        nullptr,
        nullptr,
        FALSE,
        flags,
        environment,
        nullptr,
        &si,
        &pi);

    if (environment != nullptr) {
        DestroyEnvironmentBlock(environment);
    }
    CloseHandle(primary_token);

    if (!created) {
        wchar_t text[256]{};
        StringCchPrintfW(text, ARRAYSIZE(text), L"BMTXService: CreateProcessAsUserW failed for session %lu, error %lu", session_id, GetLastError());
        LogDebug(text);
        return false;
    }

    EnterCriticalSection(&g_process_lock);
    g_clients[session_id] = pi;
    LeaveCriticalSection(&g_process_lock);
    return true;
}

void LaunchClientsInExistingSessions() {
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        return;
    }

    for (DWORD i = 0; i < count; ++i) {
        const DWORD session_id = sessions[i].SessionId;
        if (session_id == 0) {
            continue;
        }
        LaunchClientInSession(session_id);
    }

    WTSFreeMemory(sessions);
}

void TerminateClients() {
    EnterCriticalSection(&g_process_lock);
    std::vector<PROCESS_INFORMATION> processes;
    for (auto& item : g_clients) {
        processes.push_back(item.second);
    }
    g_clients.clear();
    LeaveCriticalSection(&g_process_lock);

    for (auto& pi : processes) {
        if (IsProcessRunning(pi.hProcess)) {
            TerminateProcess(pi.hProcess, 0);
            WaitForSingleObject(pi.hProcess, 5000);
        }
        CloseProcessInfo(pi);
    }
}

bool StartRpcServer() {
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr);
    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
        return false;
    }

    status = RpcServerRegisterIf2(
        BmtxRpc_v1_0_s_ifspec,
        nullptr,
        nullptr,
        RPC_IF_ALLOW_LOCAL_ONLY,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        static_cast<unsigned int>(-1),
        nullptr);
    if (status != RPC_S_OK) {
        return false;
    }

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    return status == RPC_S_OK || status == RPC_S_ALREADY_LISTENING;
}

void StopRpcServer() {
    RpcMgmtStopServerListening(nullptr);
    RpcServerUnregisterIf(BmtxRpc_v1_0_s_ifspec, nullptr, FALSE);
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD event_type, LPVOID event_data, LPVOID) {
    switch (control) {
    case SERVICE_CONTROL_SESSIONCHANGE:
        if (event_type == WTS_SESSION_LOGON || event_type == WTS_SESSION_UNLOCK || event_type == WTS_REMOTE_CONNECT) {
            auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(event_data);
            if (notification != nullptr) {
                LaunchClientInSession(notification->dwSessionId);
            } else {
                LaunchClientsInExistingSessions();
            }
        }
        return NO_ERROR;

    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        return NO_ERROR;

    default:
        return NO_ERROR;
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandler, nullptr);
    if (g_status_handle == nullptr) {
        return;
    }

    SetServiceState(SERVICE_START_PENDING, NO_ERROR, 3000);

    InitializeCriticalSection(&g_process_lock);
    InitializeCriticalSection(&g_state_lock);
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stop_event == nullptr) {
        SetServiceState(SERVICE_STOPPED, GetLastError());
        DeleteCriticalSection(&g_state_lock);
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    if (!StartRpcServer()) {
        const DWORD error = GetLastError();
        CloseHandle(g_stop_event);
        g_stop_event = nullptr;
        SetServiceState(SERVICE_STOPPED, error);
        DeleteCriticalSection(&g_state_lock);
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    g_refresh_thread = CreateThread(nullptr, 0, RefreshWorkerThread, nullptr, 0, nullptr);

    LaunchClientsInExistingSessions();
    SetServiceState(SERVICE_RUNNING);

    WaitForSingleObject(g_stop_event, INFINITE);

    SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    TerminateClients();
    StopRpcServer();

    if (g_refresh_thread != nullptr) {
        WaitForSingleObject(g_refresh_thread, 5000);
        CloseHandle(g_refresh_thread);
        g_refresh_thread = nullptr;
    }

    CloseHandle(g_stop_event);
    g_stop_event = nullptr;
    DeleteCriticalSection(&g_state_lock);
    DeleteCriticalSection(&g_process_lock);
    SetServiceState(SERVICE_STOPPED);
}

bool ConfigureServiceDaclForUserStart(SC_HANDLE service) {
    constexpr wchar_t sddl[] =
        L"D:"
        L"(A;;GA;;;SY)"
        L"(A;;GA;;;BA)"
        L"(A;;CCLCSWRPLOCRRC;;;AU)";

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, nullptr)) {
        return false;
    }

    const BOOL ok = SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, descriptor);
    LocalFree(descriptor);
    return ok != FALSE;
}

bool InstallService() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        return false;
    }

    bool service_already_existed = false;
    SC_HANDLE service = CreateServiceW(
        scm,
        kServiceName,
        kServiceDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        path,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);

    if (service == nullptr && GetLastError() == ERROR_SERVICE_EXISTS) {
        service_already_existed = true;
        service = OpenServiceW(scm, kServiceName, SERVICE_ALL_ACCESS);
    }

    if (service == nullptr) {
        CloseServiceHandle(scm);
        return false;
    }

    const BOOL reconfigured = ChangeServiceConfigW(
        service,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        path,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        kServiceDisplayName);

    SERVICE_DESCRIPTIONW description{};
    description.lpDescription = const_cast<LPWSTR>(L"BMTX session launcher, local RPC controller, authentication, and license cache.");
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);
    ConfigureServiceDaclForUserStart(service);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    if (service_already_existed && !reconfigured) {
        return false;
    }

    return true;
}

bool UninstallService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    const BOOL deleted = DeleteService(service);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return deleted != FALSE;
}

bool HasArgument(LPWSTR command_line, const wchar_t* argument) {
    return command_line != nullptr && wcsstr(command_line, argument) != nullptr;
}

} // namespace

extern "C" void BmtxStopService(handle_t) {
    if (g_stop_event != nullptr) {
        SetEvent(g_stop_event);
    }
}

extern "C" unsigned long BmtxGetClientState(handle_t, BMTX_CLIENT_STATE* state) {
    if (state == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    FillClientState(state);
    return ERROR_SUCCESS;
}

extern "C" unsigned long BmtxLogin(handle_t, wchar_t* username, wchar_t* password, BMTX_CLIENT_STATE* state) {
    if (username == nullptr || password == nullptr || state == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    const DWORD result = LoginInternal(username, password);
    FillClientState(state);
    return result;
}

extern "C" unsigned long BmtxLogout(handle_t, BMTX_CLIENT_STATE* state) {
    if (state == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    const DWORD result = LogoutInternal();
    FillClientState(state);
    return result;
}

extern "C" unsigned long BmtxActivateProduct(handle_t, wchar_t* activation_code, BMTX_CLIENT_STATE* state) {
    if (activation_code == nullptr || state == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    const DWORD result = ActivateProductInternal(activation_code);
    FillClientState(state);
    return result;
}

extern "C" unsigned long BmtxRefreshLicenseState(handle_t, BMTX_CLIENT_STATE* state) {
    if (state == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    DWORD result = ERROR_SUCCESS;
    EnterCriticalSection(&g_state_lock);
    const bool has_license = !g_state.license_ticket_json.empty();
    LeaveCriticalSection(&g_state_lock);
    if (has_license) {
        result = RefreshLicenseInternal();
    } else {
        result = ERROR_LICENSE_QUOTA_EXCEEDED;
    }
    FillClientState(state);
    return result;
}

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR command_line, int) {
    if (HasArgument(command_line, L"--install")) {
        return InstallService() ? 0 : 1;
    }

    if (HasArgument(command_line, L"--uninstall")) {
        return UninstallService() ? 0 : 1;
    }

    SERVICE_TABLE_ENTRYW service_table[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(service_table)) {
        return GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT ? 2 : 1;
    }

    return 0;
}
