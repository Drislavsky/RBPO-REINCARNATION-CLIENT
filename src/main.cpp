#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <rpc.h>
#include <commdlg.h>
#include <shlobj.h>

#include <string>
#include <vector>
#include <algorithm>

#include "resource.h"
#include "bmtx_rpc.h"

namespace {

constexpr wchar_t kWindowClassName[] = L"BMTXMainWindow";
constexpr wchar_t kAppTitle[] = L"BMTX";
constexpr wchar_t kMutexName[] = L"Local\\BMTX_SINGLE_INSTANCE";
constexpr wchar_t kServiceName[] = L"BMTXService";
constexpr wchar_t kServiceProcessName[] = L"BMTXService.exe";
constexpr wchar_t kRpcEndpoint[] = L"BMTX_RPC_ALPC_ENDPOINT";
constexpr wchar_t kServiceChildFlag[] = L"--bmtx-service-child";
constexpr wchar_t kServicePidPrefix[] = L"--bmtx-service-pid=";
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kAsyncScanCompleteMessage = WM_APP + 2;
constexpr UINT kTrayId = 1;
constexpr UINT_PTR kTrayRetryTimerId = 1001;
constexpr UINT_PTR kStatePollTimerId = 1002;
constexpr UINT_PTR kScheduledScanTimerId = 1003;
constexpr UINT_PTR kMonitorScanTimerId = 1004;
constexpr UINT kTrayRetryDelayMs = 2000;
constexpr UINT kStatePollDelayMs = 15000;
constexpr UINT kMonitorScanDelayMs = 30000;
constexpr int kMaxTrayRetryCount = 30;
constexpr int kDesignWidth = 1280;
constexpr int kVirtualContentHeight = 920;
constexpr int kMinWindowTrackWidth = 640;
constexpr int kMinWindowTrackHeight = 420;

constexpr int IDC_LOGIN_EDIT = 50001;
constexpr int IDC_PASSWORD_EDIT = 50002;
constexpr int IDC_LOGIN_BUTTON = 50003;
constexpr int IDC_LICENSE_EDIT = 50004;
constexpr int IDC_ACTIVATE_BUTTON = 50005;
constexpr int IDC_LOGOUT_BUTTON = 50006;
constexpr int IDC_REFRESH_LICENSE_BUTTON = 50007;
constexpr int IDC_SCAN_FILE_BUTTON = 50008;
constexpr int IDC_SCAN_DIR_BUTTON = 50009;
constexpr int IDC_REFRESH_DB_BUTTON = 50010;
constexpr int IDC_SCAN_ALL_FIXED_BUTTON = 50011;
constexpr int IDC_SCHEDULE_INTERVAL_EDIT = 50012;
constexpr int IDC_SCHEDULE_START_BUTTON = 50013;
constexpr int IDC_SCHEDULE_STOP_BUTTON = 50014;
constexpr int IDC_MONITOR_ADD_BUTTON = 50015;
constexpr int IDC_MONITOR_SCAN_BUTTON = 50016;
constexpr int IDC_MONITOR_CLEAR_BUTTON = 50017;

HINSTANCE g_instance = nullptr;
HWND g_main_window = nullptr;
HMENU g_main_menu = nullptr;
HICON g_app_icon = nullptr;
HICON g_tray_icon = nullptr;
NOTIFYICONDATAW g_tray_data{};
UINT g_taskbar_created_message = 0;
HANDLE g_mutex = nullptr;
bool g_tray_added = false;
int g_tray_retry_count = 0;

HWND g_login_edit = nullptr;
HWND g_password_edit = nullptr;
HWND g_login_button = nullptr;
HWND g_license_edit = nullptr;
HWND g_activate_button = nullptr;
HWND g_logout_button = nullptr;
HWND g_refresh_license_button = nullptr;
HWND g_scan_file_button = nullptr;
HWND g_scan_dir_button = nullptr;
HWND g_refresh_db_button = nullptr;
HWND g_scan_all_fixed_button = nullptr;
HWND g_schedule_interval_edit = nullptr;
HWND g_schedule_start_button = nullptr;
HWND g_schedule_stop_button = nullptr;
HWND g_monitor_add_button = nullptr;
HWND g_monitor_scan_button = nullptr;
HWND g_monitor_clear_button = nullptr;

BMTX_CLIENT_STATE g_client_state{};
BMTX_AV_DB_INFO g_av_db_info{};
BMTX_SCAN_RESULT g_last_scan_result{};
std::wstring g_ui_error;
std::wstring g_scan_status;
std::vector<std::wstring> g_monitored_directories;
DWORD g_schedule_interval_minutes = 0;
bool g_schedule_enabled = false;
bool g_monitoring_enabled = false;
volatile LONG g_background_scan_running = 0;
HANDLE g_background_scan_thread = nullptr;
std::wstring g_background_scan_title;
int g_scroll_y = 0;
double g_ui_scale = 1.0;
int g_content_offset_x = 0;


struct AsyncScanRequest {
    std::vector<std::wstring> directories;
    std::wstring title;
};

struct AsyncScanResult {
    BMTX_SCAN_RESULT aggregate{};
    DWORD failed_count = 0;
    DWORD last_error = ERROR_SUCCESS;
    size_t directory_count = 0;
    std::wstring scanned_list;
    std::wstring title;
};


bool HasHiddenStartupFlag(LPWSTR command_line) {
    if (command_line == nullptr) {
        return false;
    }

    return wcsstr(command_line, L"--hidden") != nullptr ||
           wcsstr(command_line, L"--background") != nullptr ||
           wcsstr(command_line, L"--minimized") != nullptr ||
           wcsstr(command_line, L"/hidden") != nullptr;
}

std::vector<std::wstring> GetCommandLineArguments() {
    std::vector<std::wstring> result;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) {
        return result;
    }

    for (int i = 0; i < argc; ++i) {
        result.emplace_back(argv[i]);
    }

    LocalFree(argv);
    return result;
}

bool HasCommandLineArgument(const wchar_t* argument) {
    const auto args = GetCommandLineArguments();
    for (const auto& arg : args) {
        if (_wcsicmp(arg.c_str(), argument) == 0) {
            return true;
        }
    }
    return false;
}

DWORD GetServicePidFromCommandLine() {
    const auto args = GetCommandLineArguments();
    const size_t prefix_length = wcslen(kServicePidPrefix);

    for (const auto& arg : args) {
        if (_wcsnicmp(arg.c_str(), kServicePidPrefix, prefix_length) == 0) {
            wchar_t* end = nullptr;
            const unsigned long value = wcstoul(arg.c_str() + prefix_length, &end, 10);
            if (end != nullptr && *end == L'\0' && value != 0 && value <= 0xFFFFFFFFul) {
                return static_cast<DWORD>(value);
            }
        }
    }

    return 0;
}

void WriteClientDebugLog(const wchar_t* message) {
    wchar_t temp_path[MAX_PATH]{};
    if (GetTempPathW(ARRAYSIZE(temp_path), temp_path) == 0) {
        return;
    }

    wchar_t log_path[MAX_PATH]{};
    StringCchPrintfW(log_path, ARRAYSIZE(log_path), L"%sBMTX_client_debug.log", temp_path);

    HANDLE file = CreateFileW(
        log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    wchar_t line[768]{};
    StringCchPrintfW(line, ARRAYSIZE(line), L"PID %lu: %s\r\n", GetCurrentProcessId(), message);
    DWORD bytes_written = 0;
    WriteFile(file, line, static_cast<DWORD>(wcslen(line) * sizeof(wchar_t)), &bytes_written, nullptr);
    CloseHandle(file);
}

void ShowStartupError(const wchar_t* operation) {
    const DWORD error = GetLastError();
    wchar_t text[512]{};
    StringCchPrintfW(text, ARRAYSIZE(text), L"%s failed. GetLastError = %lu", operation, error);
    MessageBoxW(nullptr, text, kAppTitle, MB_OK | MB_ICONERROR);
}

bool QueryBmtxServiceStatus(SERVICE_STATUS_PROCESS* status) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
    if (service == nullptr) {
        CloseServiceHandle(scm);
        return false;
    }

    DWORD bytes_needed = 0;
    const BOOL ok = QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(status),
        sizeof(*status),
        &bytes_needed);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok != FALSE;
}

bool StartBmtxServiceAndWaitRunning() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        ShowStartupError(L"OpenSCManagerW");
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
    if (service == nullptr) {
        CloseServiceHandle(scm);
        ShowStartupError(L"OpenServiceW(BMTXService)");
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes_needed)) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        ShowStartupError(L"QueryServiceStatusEx");
        return false;
    }

    if (status.dwCurrentState == SERVICE_STOPPED) {
        if (!StartServiceW(service, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            ShowStartupError(L"StartServiceW(BMTXService)");
            return false;
        }
    }

    const DWORD start_tick = GetTickCount();
    while (true) {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes_needed)) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            ShowStartupError(L"QueryServiceStatusEx(wait)");
            return false;
        }

        if (status.dwCurrentState == SERVICE_RUNNING) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return true;
        }

        if (status.dwCurrentState == SERVICE_STOPPED || GetTickCount() - start_tick > 30000) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            MessageBoxW(nullptr, L"BMTXService did not reach the Running state.", kAppTitle, MB_OK | MB_ICONERROR);
            return false;
        }

        Sleep(500);
    }
}

bool EnsureServiceRunningOrStartAndExit(bool* should_exit) {
    *should_exit = false;

    SERVICE_STATUS_PROCESS status{};
    if (!QueryBmtxServiceStatus(&status)) {
        ShowStartupError(L"QueryBmtxServiceStatus");
        return false;
    }

    if (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_START_PENDING) {
        const bool started = StartBmtxServiceAndWaitRunning();
        *should_exit = true;
        return started;
    }

    return true;
}

DWORD GetParentProcessId() {
    const DWORD current_pid = GetCurrentProcessId();
    DWORD parent_pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == current_pid) {
                parent_pid = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return parent_pid;
}

std::wstring GetProcessImageNameByPid(DWORD pid) {
    std::wstring result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return result;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                result = entry.szExeFile;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return result;
}

DWORD GetRunningServiceProcessId() {
    SERVICE_STATUS_PROCESS status{};
    if (!QueryBmtxServiceStatus(&status)) {
        return 0;
    }

    if (status.dwCurrentState != SERVICE_RUNNING) {
        return 0;
    }

    return status.dwProcessId;
}

bool IsParentBmtxService() {
    const DWORD parent_pid = GetParentProcessId();
    if (parent_pid == 0) {
        WriteClientDebugLog(L"parent check failed: parent PID is 0");
        return false;
    }

    const DWORD service_pid = GetRunningServiceProcessId();
    if (service_pid == 0) {
        WriteClientDebugLog(L"parent check failed: service is not running or PID is 0");
        return false;
    }

    if (parent_pid != service_pid) {
        wchar_t text[256]{};
        StringCchPrintfW(text, ARRAYSIZE(text), L"parent check failed: parent PID %lu != service PID %lu", parent_pid, service_pid);
        WriteClientDebugLog(text);
        return false;
    }

    const std::wstring parent_name = GetProcessImageNameByPid(parent_pid);
    if (_wcsicmp(parent_name.c_str(), kServiceProcessName) != 0) {
        wchar_t text[256]{};
        StringCchPrintfW(text, ARRAYSIZE(text), L"parent check failed: parent image is '%s'", parent_name.c_str());
        WriteClientDebugLog(text);
        return false;
    }

    return true;
}

bool IsValidServiceLaunchedClient() {
    if (!HasCommandLineArgument(kServiceChildFlag)) {
        WriteClientDebugLog(L"manual launch rejected: missing --bmtx-service-child");
        return false;
    }

    const DWORD command_line_service_pid = GetServicePidFromCommandLine();
    if (command_line_service_pid == 0) {
        WriteClientDebugLog(L"manual launch rejected: missing or invalid --bmtx-service-pid=<pid>");
        return false;
    }

    const DWORD actual_service_pid = GetRunningServiceProcessId();
    if (actual_service_pid == 0 || command_line_service_pid != actual_service_pid) {
        wchar_t text[256]{};
        StringCchPrintfW(text, ARRAYSIZE(text), L"service marker rejected: command line service PID %lu != actual service PID %lu", command_line_service_pid, actual_service_pid);
        WriteClientDebugLog(text);
        return false;
    }

    return IsParentBmtxService();
}

bool ComposeRpcBinding(handle_t* binding) {
    if (binding == nullptr) {
        return false;
    }
    *binding = nullptr;

    RPC_WSTR string_binding = nullptr;
    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr,
        &string_binding);
    if (status != RPC_S_OK) {
        SetLastError(status);
        return false;
    }

    status = RpcBindingFromStringBindingW(string_binding, binding);
    RpcStringFreeW(&string_binding);
    if (status != RPC_S_OK) {
        SetLastError(status);
        return false;
    }

    return true;
}

bool StopServiceThroughRpc() {
    handle_t binding = nullptr;
    if (!ComposeRpcBinding(&binding)) {
        return false;
    }

    bool ok = false;
    RpcTryExcept {
        BmtxStopService(binding);
        ok = true;
    }
    RpcExcept(1) {
        SetLastError(RpcExceptionCode());
        ok = false;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return ok;
}

DWORD GetClientStateThroughRpc(BMTX_CLIENT_STATE* state) {
    handle_t binding = nullptr;
    if (!ComposeRpcBinding(&binding)) {
        return GetLastError();
    }

    DWORD result = ERROR_SUCCESS;
    RpcTryExcept {
        result = BmtxGetClientState(binding, state);
    }
    RpcExcept(1) {
        result = RpcExceptionCode();
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

DWORD LoginThroughRpc(const std::wstring& username, const std::wstring& password, BMTX_CLIENT_STATE* state) {
    handle_t binding = nullptr;
    if (!ComposeRpcBinding(&binding)) {
        return GetLastError();
    }

    DWORD result = ERROR_SUCCESS;
    RpcTryExcept {
        result = BmtxLogin(binding, const_cast<wchar_t*>(username.c_str()), const_cast<wchar_t*>(password.c_str()), state);
    }
    RpcExcept(1) {
        result = RpcExceptionCode();
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

DWORD LogoutThroughRpc(BMTX_CLIENT_STATE* state) {
    handle_t binding = nullptr;
    if (!ComposeRpcBinding(&binding)) {
        return GetLastError();
    }

    DWORD result = ERROR_SUCCESS;
    RpcTryExcept {
        result = BmtxLogout(binding, state);
    }
    RpcExcept(1) {
        result = RpcExceptionCode();
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

DWORD ActivateThroughRpc(const std::wstring& activation_code, BMTX_CLIENT_STATE* state) {
    handle_t binding = nullptr;
    if (!ComposeRpcBinding(&binding)) {
        return GetLastError();
    }

    DWORD result = ERROR_SUCCESS;
    RpcTryExcept {
        result = BmtxActivateProduct(binding, const_cast<wchar_t*>(activation_code.c_str()), state);
    }
    RpcExcept(1) {
        result = RpcExceptionCode();
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

DWORD RefreshLicenseThroughRpc(BMTX_CLIENT_STATE* state) {
    handle_t binding = nullptr;
    if (!ComposeRpcBinding(&binding)) {
        return GetLastError();
    }

    DWORD result = ERROR_SUCCESS;
    RpcTryExcept {
        result = BmtxRefreshLicenseState(binding, state);
    }
    RpcExcept(1) {
        result = RpcExceptionCode();
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

DWORD GetAvDbInfoThroughRpc(BMTX_AV_DB_INFO* info) {
    handle_t binding = nullptr;
    if (!ComposeRpcBinding(&binding)) {
        return GetLastError();
    }
    DWORD result = ERROR_SUCCESS;
    RpcTryExcept {
        result = BmtxGetAvDbInfo(binding, info);
    }
    RpcExcept(1) {
        result = RpcExceptionCode();
    }
    RpcEndExcept
    RpcBindingFree(&binding);
    return result;
}

DWORD ScanFileThroughRpc(const std::wstring& path, BMTX_SCAN_RESULT* result) {
    handle_t binding = nullptr;
    if (!ComposeRpcBinding(&binding)) {
        return GetLastError();
    }
    DWORD rc = ERROR_SUCCESS;
    RpcTryExcept {
        rc = BmtxScanFile(binding, const_cast<wchar_t*>(path.c_str()), result);
    }
    RpcExcept(1) {
        rc = RpcExceptionCode();
    }
    RpcEndExcept
    RpcBindingFree(&binding);
    return rc;
}

DWORD ScanDirectoryThroughRpc(const std::wstring& path, BMTX_SCAN_RESULT* result) {
    handle_t binding = nullptr;
    if (!ComposeRpcBinding(&binding)) {
        return GetLastError();
    }
    DWORD rc = ERROR_SUCCESS;
    RpcTryExcept {
        rc = BmtxScanDirectory(binding, const_cast<wchar_t*>(path.c_str()), result);
    }
    RpcExcept(1) {
        rc = RpcExceptionCode();
    }
    RpcEndExcept
    RpcBindingFree(&binding);
    return rc;
}

void ShowLastErrorMessage(const wchar_t* operation) {
    const DWORD error = GetLastError();
    wchar_t text[512]{};
    StringCchPrintfW(text, ARRAYSIZE(text), L"%s failed. GetLastError = %lu", operation, error);
    MessageBoxW(g_main_window, text, L"BMTX", MB_OK | MB_ICONERROR);
}

HICON LoadApplicationIcon(int size) {
    HICON icon = reinterpret_cast<HICON>(LoadImageW(g_instance, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON, size, size, LR_DEFAULTCOLOR));
    if (icon == nullptr) {
        icon = LoadIconW(nullptr, IDI_APPLICATION);
    }
    return icon;
}

void ShowMainWindow() {
    if (g_main_window == nullptr) {
        return;
    }
    ShowWindow(g_main_window, SW_SHOWNORMAL);
    SetForegroundWindow(g_main_window);
    UpdateWindow(g_main_window);
}

void HideMainWindow() {
    if (g_main_window != nullptr) {
        ShowWindow(g_main_window, SW_HIDE);
    }
}

void RemoveTrayIcon() {
    if (g_main_window != nullptr) {
        KillTimer(g_main_window, kTrayRetryTimerId);
    }

    if (g_tray_added) {
        Shell_NotifyIconW(NIM_DELETE, &g_tray_data);
        g_tray_added = false;
    }

    g_tray_retry_count = 0;
    ZeroMemory(&g_tray_data, sizeof(g_tray_data));
}

void ScheduleTrayRetry() {
    if (g_main_window == nullptr || g_tray_retry_count >= kMaxTrayRetryCount) {
        return;
    }
    ++g_tray_retry_count;
    SetTimer(g_main_window, kTrayRetryTimerId, kTrayRetryDelayMs, nullptr);
}

bool AddTrayIcon() {
    if (g_main_window == nullptr) {
        return false;
    }
    if (g_tray_added) {
        return true;
    }

    ZeroMemory(&g_tray_data, sizeof(g_tray_data));
    g_tray_data.cbSize = sizeof(g_tray_data);
    g_tray_data.hWnd = g_main_window;
    g_tray_data.uID = kTrayId;
    g_tray_data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_tray_data.uCallbackMessage = kTrayMessage;
    g_tray_data.hIcon = g_tray_icon != nullptr ? g_tray_icon : LoadApplicationIcon(GetSystemMetrics(SM_CXSMICON));
    StringCchCopyW(g_tray_data.szTip, ARRAYSIZE(g_tray_data.szTip), kAppTitle);

    if (!Shell_NotifyIconW(NIM_ADD, &g_tray_data)) {
        ZeroMemory(&g_tray_data, sizeof(g_tray_data));
        ScheduleTrayRetry();
        return false;
    }

    g_tray_added = true;
    g_tray_retry_count = 0;
    KillTimer(g_main_window, kTrayRetryTimerId);
    g_tray_data.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_tray_data);
    return true;
}

void RecreateTrayIcon() {
    if (g_tray_added) {
        Shell_NotifyIconW(NIM_DELETE, &g_tray_data);
    }
    g_tray_added = false;
    g_tray_retry_count = 0;
    ZeroMemory(&g_tray_data, sizeof(g_tray_data));
    AddTrayIcon();
}

void ExitApplication() {
    if (!StopServiceThroughRpc()) {
        ShowLastErrorMessage(L"RPC BmtxStopService");
        return;
    }
    HideMainWindow();
}

std::wstring GetWindowTextString(HWND control) {
    const int length = GetWindowTextLengthW(control);
    if (length <= 0) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1);
    GetWindowTextW(control, buffer.data(), length + 1);
    return std::wstring(buffer.data());
}

std::wstring UnixTimeToText(__int64 unix_seconds) {
    if (unix_seconds <= 0) {
        return L"unknown";
    }
    const ULONGLONG file_time_value = static_cast<ULONGLONG>(unix_seconds) * 10000000ULL + 116444736000000000ULL;
    ULARGE_INTEGER integer{};
    integer.QuadPart = file_time_value;
    FILETIME ft{};
    ft.dwLowDateTime = integer.LowPart;
    ft.dwHighDateTime = integer.HighPart;

    SYSTEMTIME st_utc{};
    SYSTEMTIME st_local{};
    FileTimeToSystemTime(&ft, &st_utc);
    SystemTimeToTzSpecificLocalTime(nullptr, &st_utc, &st_local);

    wchar_t buffer[64]{};
    StringCchPrintfW(buffer, ARRAYSIZE(buffer), L"%02u.%02u.%04u %02u:%02u", st_local.wDay, st_local.wMonth, st_local.wYear, st_local.wHour, st_local.wMinute);
    return buffer;
}

void SetControlsVisible(bool auth, bool license, bool logged_in) {
    ShowWindow(g_login_edit, auth ? SW_SHOW : SW_HIDE);
    ShowWindow(g_password_edit, auth ? SW_SHOW : SW_HIDE);
    ShowWindow(g_login_button, auth ? SW_SHOW : SW_HIDE);
    ShowWindow(g_license_edit, license ? SW_SHOW : SW_HIDE);
    ShowWindow(g_activate_button, license ? SW_SHOW : SW_HIDE);
    ShowWindow(g_logout_button, logged_in ? SW_SHOW : SW_HIDE);
    ShowWindow(g_refresh_license_button, logged_in ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scan_file_button, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scan_dir_button, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
    ShowWindow(g_refresh_db_button, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scan_all_fixed_button, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
    ShowWindow(g_schedule_interval_edit, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
    ShowWindow(g_schedule_start_button, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
    ShowWindow(g_schedule_stop_button, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
    ShowWindow(g_monitor_add_button, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
    ShowWindow(g_monitor_scan_button, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
    ShowWindow(g_monitor_clear_button, logged_in && g_client_state.licensed ? SW_SHOW : SW_HIDE);
}

void UpdateControlsFromState() {
    const bool authenticated = g_client_state.authenticated != 0;
    const bool licensed = g_client_state.licensed != 0;
    SetControlsVisible(!authenticated, authenticated && !licensed, authenticated);
    InvalidateRect(g_main_window, nullptr, TRUE);
}

void RefreshStateFromService(bool refresh_license) {
    BMTX_CLIENT_STATE state{};
    DWORD result = refresh_license ? RefreshLicenseThroughRpc(&state) : GetClientStateThroughRpc(&state);
    if (result == ERROR_SUCCESS || result == ERROR_LICENSE_QUOTA_EXCEEDED) {
        g_client_state = state;
        g_ui_error.clear();
    } else {
        wchar_t text[128]{};
        StringCchPrintfW(text, ARRAYSIZE(text), L"RPC state request failed: %lu", result);
        g_ui_error = text;
    }
    if (g_client_state.licensed) {
        BMTX_AV_DB_INFO info{};
        if (GetAvDbInfoThroughRpc(&info) == ERROR_SUCCESS) {
            g_av_db_info = info;
        }
    }
    UpdateControlsFromState();
}

std::wstring BuildScanText(const BMTX_SCAN_RESULT& result) {
    wchar_t buffer[1024]{};
    StringCchPrintfW(buffer, ARRAYSIZE(buffer),
        L"Проверено файлов: %lu\r\nВирусных файлов: %lu\r\nРезультат: %s",
        result.scannedObjects, result.infectedObjects,
        result.message[0] != L'\0' ? result.message : L"сканирование завершено");
    std::wstring text = buffer;
    if (result.infectedObjects > 0) {
        text += L"\r\nНазвание угрозы: ";
        text += result.threatName[0] != L'\0' ? result.threatName : L"не указано";
        text += L"\r\nПервый зараженный файл: ";
        text += result.firstThreatPath[0] != L'\0' ? result.firstThreatPath : L"не указан";
    }
    return text;
}

void RefreshAvDbInfo() {
    BMTX_AV_DB_INFO info{};
    const DWORD rc = GetAvDbInfoThroughRpc(&info);
    if (rc == ERROR_SUCCESS) {
        g_av_db_info = info;
        g_scan_status = L"Antivirus database information refreshed";
    } else {
        wchar_t text[128]{};
        StringCchPrintfW(text, ARRAYSIZE(text), L"AV DB RPC failed: %lu", rc);
        g_ui_error = text;
    }
    UpdateControlsFromState();
}

bool PickFile(std::wstring* path) {
    wchar_t buffer[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_main_window;
    ofn.lpstrFile = buffer;
    ofn.nMaxFile = ARRAYSIZE(buffer);
    ofn.lpstrFilter = L"All files\0*.*\0";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) {
        return false;
    }
    *path = buffer;
    return true;
}

bool PickDirectory(std::wstring* path) {
    BROWSEINFOW bi{};
    bi.hwndOwner = g_main_window;
    bi.lpszTitle = L"Выберите папку для сканирования";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (pidl == nullptr) {
        return false;
    }
    wchar_t buffer[MAX_PATH]{};
    const BOOL ok = SHGetPathFromIDListW(pidl, buffer);
    CoTaskMemFree(pidl);
    if (!ok) {
        return false;
    }
    *path = buffer;
    return true;
}

void StartDirectoryListScanAsync(const std::vector<std::wstring>& directories, const wchar_t* title);

void OnScanFile() {
    std::wstring path;
    if (!PickFile(&path)) {
        return;
    }
    BMTX_SCAN_RESULT result{};
    const DWORD rc = ScanFileThroughRpc(path, &result);
    if (rc == ERROR_SUCCESS) {
        g_last_scan_result = result;
        g_scan_status = BuildScanText(result);
        g_ui_error.clear();
    } else {
        wchar_t text[128]{};
        StringCchPrintfW(text, ARRAYSIZE(text), L"Scan file failed: %lu", rc);
        g_ui_error = text;
    }
    UpdateControlsFromState();
}

void OnScanDirectory() {
    std::wstring path;
    if (!PickDirectory(&path)) {
        return;
    }
    StartDirectoryListScanAsync(std::vector<std::wstring>{path}, L"Сканирование выбранной папки");
}


void MergeScanResult(BMTX_SCAN_RESULT* aggregate, const BMTX_SCAN_RESULT& one) {
    if (aggregate == nullptr) {
        return;
    }
    aggregate->scannedObjects += one.scannedObjects;
    aggregate->infectedObjects += one.infectedObjects;
    if (one.infectedObjects > 0 && aggregate->firstThreatPath[0] == L'\0') {
        StringCchCopyW(aggregate->firstThreatPath, ARRAYSIZE(aggregate->firstThreatPath), one.firstThreatPath);
        StringCchCopyW(aggregate->threatName, ARRAYSIZE(aggregate->threatName), one.threatName);
    }
}

std::vector<std::wstring> GetFixedDriveRoots() {
    std::vector<std::wstring> roots;
    wchar_t buffer[512]{};
    const DWORD length = GetLogicalDriveStringsW(ARRAYSIZE(buffer) - 1, buffer);
    if (length == 0 || length >= ARRAYSIZE(buffer)) {
        return roots;
    }

    for (const wchar_t* current = buffer; *current != L'\0'; current += wcslen(current) + 1) {
        if (GetDriveTypeW(current) == DRIVE_FIXED) {
            roots.emplace_back(current);
        }
    }
    return roots;
}

void ApplyDirectoryScanResult(AsyncScanResult* result) {
    if (result == nullptr) {
        return;
    }

    wchar_t message[512]{};
    StringCchPrintfW(message, ARRAYSIZE(message), L"%s: папок: %zu; проверено файлов: %lu; вирусных файлов: %lu; ошибок: %lu",
        result->title.c_str(), result->directory_count,
        result->aggregate.scannedObjects, result->aggregate.infectedObjects, result->failed_count);

    StringCchCopyW(result->aggregate.message, ARRAYSIZE(result->aggregate.message), message);
    g_last_scan_result = result->aggregate;
    g_scan_status = BuildScanText(result->aggregate);
    if (!result->scanned_list.empty()) {
        g_scan_status += L"\r\nПроверенные объекты: ";
        g_scan_status += result->scanned_list;
    }
    if (result->failed_count > 0) {
        wchar_t error_text[128]{};
        StringCchPrintfW(error_text, ARRAYSIZE(error_text), L"Не все директории были просканированы, последняя ошибка: %lu", result->last_error);
        g_ui_error = error_text;
    } else {
        g_ui_error.clear();
    }
    UpdateControlsFromState();
}

DWORD WINAPI DirectoryScanWorkerThread(LPVOID parameter) {
    AsyncScanRequest* request = static_cast<AsyncScanRequest*>(parameter);
    AsyncScanResult* result = new AsyncScanResult();
    result->title = request->title;

    result->directory_count = request->directories.size();
    for (const auto& directory : request->directories) {
        BMTX_SCAN_RESULT one{};
        const DWORD rc = ScanDirectoryThroughRpc(directory, &one);
        if (rc == ERROR_SUCCESS) {
            MergeScanResult(&result->aggregate, one);
            if (!result->scanned_list.empty()) {
                result->scanned_list += L", ";
            }
            result->scanned_list += directory;
        } else {
            ++result->failed_count;
            result->last_error = rc;
        }
    }

    wchar_t message[512]{};
    StringCchPrintfW(message, ARRAYSIZE(message), L"%s: папок: %zu; проверено файлов: %lu; вирусных файлов: %lu; ошибок: %lu",
        result->title.c_str(), result->directory_count, result->aggregate.scannedObjects, result->aggregate.infectedObjects, result->failed_count);
    StringCchCopyW(result->aggregate.message, ARRAYSIZE(result->aggregate.message), message);

    delete request;

    if (g_main_window != nullptr && PostMessageW(g_main_window, kAsyncScanCompleteMessage, 0, reinterpret_cast<LPARAM>(result))) {
        return 0;
    }

    InterlockedExchange(&g_background_scan_running, 0);
    delete result;
    return 0;
}

bool IsBackgroundScanStillRunning() {
    if (InterlockedCompareExchange(&g_background_scan_running, 0, 0) == 0) {
        if (g_background_scan_thread != nullptr) {
            CloseHandle(g_background_scan_thread);
            g_background_scan_thread = nullptr;
        }
        g_background_scan_title.clear();
        return false;
    }

    if (g_background_scan_thread == nullptr) {
        InterlockedExchange(&g_background_scan_running, 0);
        g_background_scan_title.clear();
        return false;
    }

    const DWORD wait_result = WaitForSingleObject(g_background_scan_thread, 0);
    if (wait_result == WAIT_TIMEOUT) {
        return true;
    }

    CloseHandle(g_background_scan_thread);
    g_background_scan_thread = nullptr;
    InterlockedExchange(&g_background_scan_running, 0);
    g_background_scan_title.clear();
    return false;
}

void MarkBackgroundScanFinished() {
    InterlockedExchange(&g_background_scan_running, 0);
    g_background_scan_title.clear();
    if (g_background_scan_thread != nullptr) {
        CloseHandle(g_background_scan_thread);
        g_background_scan_thread = nullptr;
    }
}

void StartDirectoryListScanAsync(const std::vector<std::wstring>& directories, const wchar_t* title) {
    if (directories.empty()) {
        g_ui_error = L"No directories selected for scanning";
        UpdateControlsFromState();
        return;
    }

    if (IsBackgroundScanStillRunning()) {
        g_scan_status = L"Фоновое сканирование уже выполняется";
        if (!g_background_scan_title.empty()) {
            g_scan_status += L": ";
            g_scan_status += g_background_scan_title;
        }
        g_scan_status += L". Повторный запуск пропущен. Дождитесь результата.";
        UpdateControlsFromState();
        return;
    }

    InterlockedExchange(&g_background_scan_running, 1);
    g_background_scan_title = title != nullptr ? title : L"Сканирование";

    AsyncScanRequest* request = new AsyncScanRequest();
    request->directories = directories;
    request->title = title;

    g_ui_error.clear();
    g_scan_status = g_background_scan_title + L": запущено в фоне. Окно можно использовать, дождитесь результата.";
    UpdateControlsFromState();

    HANDLE thread = CreateThread(nullptr, 0, DirectoryScanWorkerThread, request, 0, nullptr);
    if (thread == nullptr) {
        delete request;
        MarkBackgroundScanFinished();
        ShowLastErrorMessage(L"CreateThread");
        g_scan_status.clear();
        UpdateControlsFromState();
        return;
    }
    g_background_scan_thread = thread;
}

void OnScanAllFixedDrives() {
    const std::vector<std::wstring> drives = GetFixedDriveRoots();
    StartDirectoryListScanAsync(drives, L"Сканирование всех несъемных дисков");
}

void OnStartScheduledScan() {
    const std::wstring value = GetWindowTextString(g_schedule_interval_edit);
    wchar_t* end = nullptr;
    const unsigned long minutes = wcstoul(value.c_str(), &end, 10);
    if (value.empty() || end == nullptr || *end != L'\0' || minutes == 0 || minutes > 1440) {
        g_ui_error = L"Enter schedule interval from 1 to 1440 minutes";
        UpdateControlsFromState();
        return;
    }

    g_schedule_interval_minutes = static_cast<DWORD>(minutes);
    g_schedule_enabled = true;
    SetTimer(g_main_window, kScheduledScanTimerId, g_schedule_interval_minutes * 60 * 1000, nullptr);
    wchar_t text[256]{};
    StringCchPrintfW(text, ARRAYSIZE(text), L"Scheduled scan enabled: every %lu minute(s)", g_schedule_interval_minutes);
    g_scan_status = text;
    g_ui_error.clear();
    UpdateControlsFromState();
}

void OnStopScheduledScan() {
    KillTimer(g_main_window, kScheduledScanTimerId);
    g_schedule_enabled = false;
    g_schedule_interval_minutes = 0;
    g_scan_status = L"Расписание отключено. Новые запуски по таймеру остановлены.";
    g_ui_error.clear();
    UpdateControlsFromState();
}

void OnAddMonitorDirectory() {
    std::wstring path;
    if (!PickDirectory(&path)) {
        return;
    }
    for (const auto& existing : g_monitored_directories) {
        if (_wcsicmp(existing.c_str(), path.c_str()) == 0) {
            g_ui_error = L"This directory is already monitored";
            UpdateControlsFromState();
            return;
        }
    }
    g_monitored_directories.push_back(path);
    g_monitoring_enabled = true;
    SetTimer(g_main_window, kMonitorScanTimerId, kMonitorScanDelayMs, nullptr);

    wchar_t text[512]{};
    StringCchPrintfW(text, ARRAYSIZE(text), L"Monitoring enabled: %zu directorie(s). Latest added: %s",
        g_monitored_directories.size(), path.c_str());
    g_scan_status = text;
    g_ui_error.clear();
    UpdateControlsFromState();
}

void OnScanMonitoredDirectories() {
    StartDirectoryListScanAsync(g_monitored_directories, L"Сканирование директорий мониторинга");
}

void OnClearMonitoredDirectories() {
    g_monitored_directories.clear();
    g_monitoring_enabled = false;
    KillTimer(g_main_window, kMonitorScanTimerId);
    g_scan_status = L"Monitored directory list cleared";
    g_ui_error.clear();
    UpdateControlsFromState();
}

void OnLogin() {
    const std::wstring username = GetWindowTextString(g_login_edit);
    const std::wstring password = GetWindowTextString(g_password_edit);
    if (username.empty() || password.empty()) {
        g_ui_error = L"Enter username and password";
        UpdateControlsFromState();
        return;
    }

    BMTX_CLIENT_STATE state{};
    const DWORD result = LoginThroughRpc(username, password, &state);
    g_client_state = state;
    if (result != ERROR_SUCCESS) {
        g_ui_error = L"Authentication failed";
        SetWindowTextW(g_password_edit, L"");
    } else {
        g_ui_error.clear();
        SetWindowTextW(g_password_edit, L"");
        RefreshStateFromService(true);
    }
    UpdateControlsFromState();
}

void OnLogout() {
    BMTX_CLIENT_STATE state{};
    const DWORD result = LogoutThroughRpc(&state);
    g_client_state = state;
    KillTimer(g_main_window, kScheduledScanTimerId);
    KillTimer(g_main_window, kMonitorScanTimerId);
    g_schedule_enabled = false;
    g_schedule_interval_minutes = 0;
    g_monitoring_enabled = false;
    g_monitored_directories.clear();
    g_ui_error = result == ERROR_SUCCESS ? L"Logged out" : L"Logout failed";
    SetWindowTextW(g_password_edit, L"");
    SetWindowTextW(g_license_edit, L"");
    UpdateControlsFromState();
}

void OnActivate() {
    const std::wstring code = GetWindowTextString(g_license_edit);
    if (code.empty()) {
        g_ui_error = L"Enter activation code";
        UpdateControlsFromState();
        return;
    }

    BMTX_CLIENT_STATE state{};
    const DWORD result = ActivateThroughRpc(code, &state);
    g_client_state = state;

    if (result == ERROR_SUCCESS) {
        g_ui_error.clear();

        // После успешной активации служба уже должна загрузить AV-базу с сервера.
        // Сразу запрашиваем информацию о базе, чтобы GUI не ждал ручного нажатия
        // кнопки "Инфо баз" и сразу показывал фактическое количество сигнатур.
        BMTX_AV_DB_INFO info{};
        const DWORD db_result = GetAvDbInfoThroughRpc(&info);
        if (db_result == ERROR_SUCCESS) {
            g_av_db_info = info;
            wchar_t text[256]{};
            StringCchPrintfW(text, ARRAYSIZE(text), L"License activated; AV database loaded: %lu records", info.recordCount);
            g_scan_status = text;
        } else {
            wchar_t text[256]{};
            StringCchPrintfW(text, ARRAYSIZE(text), L"License activated, but AV database load failed: %lu", db_result);
            g_ui_error = text;
        }
    } else {
        g_ui_error = L"Activation failed";
    }

    UpdateControlsFromState();
}

void ShowTrayMenu() {
    if (g_main_window == nullptr) {
        return;
    }

    HMENU menu = CreatePopupMenu();
    if (menu == nullptr) {
        return;
    }

    AppendMenuW(menu, MF_STRING, IDM_TRAY_OPEN, L"Открыть");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"Выход");

    POINT point{};
    GetCursorPos(&point);

    SetForegroundWindow(g_main_window);
    const UINT command = TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RETURNCMD, point.x, point.y, 0, g_main_window, nullptr);
    DestroyMenu(menu);

    if (command == IDM_TRAY_OPEN) {
        ShowMainWindow();
    } else if (command == IDM_TRAY_EXIT) {
        ExitApplication();
    }

    PostMessageW(g_main_window, WM_NULL, 0, 0);
}

void CreateMainMenu(HWND window) {
    g_main_menu = CreateMenu();
    HMENU file_menu = CreatePopupMenu();
    AppendMenuW(file_menu, MF_STRING, IDM_FILE_EXIT, L"Выход");
    AppendMenuW(g_main_menu, MF_POPUP, reinterpret_cast<UINT_PTR>(file_menu), L"Файл");
    SetMenu(window, g_main_menu);
}

HWND CreateChildEdit(HWND parent, int id, int x, int y, int w, int h, DWORD extra_style = 0) {
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL | extra_style, x, y, w, h, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_instance, nullptr);
}

HWND CreateChildButton(HWND parent, int id, const wchar_t* text, int x, int y, int w, int h) {
    return CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, x, y, w, h, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_instance, nullptr);
}

int ScaleUi(int value) {
    return static_cast<int>(value * g_ui_scale + 0.5);
}

void UpdateUiScale(HWND window) {
    RECT client{};
    GetClientRect(window, &client);
    const int client_width = std::max(static_cast<int>(client.right - client.left), 1);
    const int client_height = std::max(static_cast<int>(client.bottom - client.top), 1);

    const double scale_x = static_cast<double>(client_width) / static_cast<double>(kDesignWidth);
    const double scale_y = static_cast<double>(client_height) / static_cast<double>(kVirtualContentHeight);
    g_ui_scale = std::min(scale_x, scale_y);
    g_ui_scale = std::clamp(g_ui_scale, 0.50, 1.60);

    const int scaled_width = ScaleUi(kDesignWidth);
    g_content_offset_x = std::max(0, (client_width - scaled_width) / 2);
}

void MoveChild(HWND handle, int x, int y, int w, int h) {
    if (handle != nullptr) {
        MoveWindow(handle, g_content_offset_x + ScaleUi(x), ScaleUi(y) - g_scroll_y, ScaleUi(w), ScaleUi(h), TRUE);
    }
}

void LayoutUiControls(HWND window) {
    UpdateUiScale(window);
    const int right_button_x = kDesignWidth - 210;

    MoveChild(g_login_edit, 80, 260, 300, 30);
    MoveChild(g_password_edit, 80, 330, 300, 30);
    MoveChild(g_login_button, 410, 330, 150, 34);

    MoveChild(g_license_edit, 80, 300, 360, 30);
    MoveChild(g_activate_button, 470, 300, 170, 34);

    // These buttons used to overlap the scan result text. They are placed
    // lower and all coordinates are now scaled with the window size.
    MoveChild(g_logout_button, 80, 470, 225, 38);
    MoveChild(g_refresh_license_button, 325, 470, 225, 38);

    MoveChild(g_scan_file_button, 80, 565, 185, 38);
    MoveChild(g_scan_dir_button, 280, 565, 185, 38);
    MoveChild(g_scan_all_fixed_button, 480, 565, 220, 38);
    MoveChild(g_refresh_db_button, right_button_x, 565, 130, 38);

    MoveChild(g_schedule_interval_edit, 80, 655, 90, 30);
    MoveChild(g_schedule_start_button, 190, 651, 220, 38);
    MoveChild(g_schedule_stop_button, 425, 651, 220, 38);

    MoveChild(g_monitor_add_button, 80, 730, 270, 38);
    MoveChild(g_monitor_scan_button, 365, 730, 240, 38);
    MoveChild(g_monitor_clear_button, 620, 730, 120, 38);
}

void UpdateVerticalScroll(HWND window) {
    RECT client{};
    GetClientRect(window, &client);
    UpdateUiScale(window);
    const int client_height = static_cast<int>(client.bottom - client.top);
    const int max_scroll = std::max(0, ScaleUi(kVirtualContentHeight) - client_height);
    g_scroll_y = std::clamp(g_scroll_y, 0, max_scroll);

    SCROLLINFO info{};
    info.cbSize = sizeof(info);
    info.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    info.nMin = 0;
    info.nMax = std::max(0, ScaleUi(kVirtualContentHeight) - 1);
    info.nPage = static_cast<UINT>(std::max(client_height, 1));
    info.nPos = g_scroll_y;
    SetScrollInfo(window, SB_VERT, &info, TRUE);
    LayoutUiControls(window);
}

void SetScrollPosition(HWND window, int scroll_y) {
    RECT client{};
    GetClientRect(window, &client);
    UpdateUiScale(window);
    const int max_scroll = std::max(0, ScaleUi(kVirtualContentHeight) - static_cast<int>(client.bottom - client.top));
    const int next_scroll = std::clamp(scroll_y, 0, max_scroll);
    if (next_scroll == g_scroll_y) {
        return;
    }

    g_scroll_y = next_scroll;
    UpdateVerticalScroll(window);
    InvalidateRect(window, nullptr, TRUE);
}

void CreateUiControls(HWND window) {
    // Controls are laid out in virtual coordinates and shifted by the current
    // scroll offset, so the window works on smaller screens and when resized.
    g_login_edit = CreateChildEdit(window, IDC_LOGIN_EDIT, 0, 0, 300, 30);
    g_password_edit = CreateChildEdit(window, IDC_PASSWORD_EDIT, 0, 0, 300, 30, ES_PASSWORD);
    g_login_button = CreateChildButton(window, IDC_LOGIN_BUTTON, L"Войти", 0, 0, 150, 34);

    g_license_edit = CreateChildEdit(window, IDC_LICENSE_EDIT, 0, 0, 360, 30);
    g_activate_button = CreateChildButton(window, IDC_ACTIVATE_BUTTON, L"Активировать", 0, 0, 170, 34);

    g_logout_button = CreateChildButton(window, IDC_LOGOUT_BUTTON, L"Выйти из аккаунта", 0, 0, 225, 38);
    g_refresh_license_button = CreateChildButton(window, IDC_REFRESH_LICENSE_BUTTON, L"Обновить лицензию", 0, 0, 225, 38);

    g_scan_file_button = CreateChildButton(window, IDC_SCAN_FILE_BUTTON, L"Сканировать файл", 0, 0, 185, 38);
    g_scan_dir_button = CreateChildButton(window, IDC_SCAN_DIR_BUTTON, L"Сканировать папку", 0, 0, 185, 38);
    g_scan_all_fixed_button = CreateChildButton(window, IDC_SCAN_ALL_FIXED_BUTTON, L"Все несъемные диски", 0, 0, 220, 38);
    g_refresh_db_button = CreateChildButton(window, IDC_REFRESH_DB_BUTTON, L"Инфо баз", 0, 0, 130, 38);

    g_schedule_interval_edit = CreateChildEdit(window, IDC_SCHEDULE_INTERVAL_EDIT, 0, 0, 90, 30);
    SetWindowTextW(g_schedule_interval_edit, L"60");
    g_schedule_start_button = CreateChildButton(window, IDC_SCHEDULE_START_BUTTON, L"Включить расписание", 0, 0, 220, 38);
    g_schedule_stop_button = CreateChildButton(window, IDC_SCHEDULE_STOP_BUTTON, L"Отключить расписание", 0, 0, 220, 38);

    g_monitor_add_button = CreateChildButton(window, IDC_MONITOR_ADD_BUTTON, L"Добавить папку мониторинга", 0, 0, 270, 38);
    g_monitor_scan_button = CreateChildButton(window, IDC_MONITOR_SCAN_BUTTON, L"Сканировать мониторинг", 0, 0, 240, 38);
    g_monitor_clear_button = CreateChildButton(window, IDC_MONITOR_CLEAR_BUTTON, L"Очистить", 0, 0, 120, 38);

    LayoutUiControls(window);
}

void PaintInterface(HWND window) {
    PAINTSTRUCT paint{};
    HDC dc = BeginPaint(window, &paint);
    if (dc == nullptr) {
        return;
    }

    RECT client{};
    GetClientRect(window, &client);
    UpdateUiScale(window);
    const int content_width = kDesignWidth;

    HBRUSH background = CreateSolidBrush(RGB(7, 9, 13));
    FillRect(dc, &client, background);
    DeleteObject(background);

    SetBkMode(dc, TRANSPARENT);
    SetGraphicsMode(dc, GM_ADVANCED);
    XFORM transform{};
    transform.eM11 = static_cast<FLOAT>(g_ui_scale);
    transform.eM22 = static_cast<FLOAT>(g_ui_scale);
    transform.eDx = static_cast<FLOAT>(g_content_offset_x);
    transform.eDy = static_cast<FLOAT>(-g_scroll_y);
    SetWorldTransform(dc, &transform);

    HFONT title_font = CreateFontW(30, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT body_font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT small_font = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    SelectObject(dc, title_font);
    SetTextColor(dc, RGB(232, 238, 247));
    TextOutW(dc, 42, 42, kAppTitle, static_cast<int>(wcslen(kAppTitle)));

    SelectObject(dc, body_font);
    SetTextColor(dc, RGB(128, 146, 169));
    const wchar_t subtitle[] = L"BMTX // AUTHENTICATION AND LICENSE CONTROL";
    TextOutW(dc, 44, 86, subtitle, static_cast<int>(wcslen(subtitle)));

    HPEN border_pen = CreatePen(PS_SOLID, 1, RGB(40, 52, 70));
    HPEN accent_pen = CreatePen(PS_SOLID, 2, RGB(94, 234, 212));
    HBRUSH panel_brush = CreateSolidBrush(RGB(13, 17, 24));
    HGDIOBJ old_pen = SelectObject(dc, border_pen);
    HGDIOBJ old_brush = SelectObject(dc, panel_brush);

    RECT panel{42, 130, content_width - 42, kVirtualContentHeight - 72};
    RoundRect(dc, panel.left, panel.top, panel.right, panel.bottom, 18, 18);

    SelectObject(dc, accent_pen);
    MoveToEx(dc, panel.left + 22, panel.top + 34, nullptr);
    LineTo(dc, panel.right - 22, panel.top + 34);

    SelectObject(dc, body_font);
    SetTextColor(dc, RGB(214, 222, 235));

    if (!g_client_state.authenticated) {
        const wchar_t title[] = L"AUTHENTICATION REQUIRED";
        TextOutW(dc, panel.left + 24, panel.top + 58, title, static_cast<int>(wcslen(title)));
        SetTextColor(dc, RGB(145, 163, 187));
        const wchar_t login_label[] = L"Login";
        const wchar_t password_label[] = L"Password";
        TextOutW(dc, 80, 238, login_label, static_cast<int>(wcslen(login_label)));
        TextOutW(dc, 80, 308, password_label, static_cast<int>(wcslen(password_label)));
        const wchar_t locked[] = L"Antivirus functionality is locked until authentication succeeds.";
        TextOutW(dc, panel.left + 24, 390, locked, static_cast<int>(wcslen(locked)));
    } else if (!g_client_state.licensed) {
        std::wstring user_line = L"USER: ";
        user_line += g_client_state.username;
        TextOutW(dc, panel.left + 24, panel.top + 58, user_line.c_str(), static_cast<int>(user_line.size()));
        SetTextColor(dc, RGB(145, 163, 187));
        const wchar_t no_license[] = L"No active license. Antivirus functionality is locked.";
        const wchar_t activation_label[] = L"Activation code";
        TextOutW(dc, panel.left + 24, panel.top + 94, no_license, static_cast<int>(wcslen(no_license)));
        TextOutW(dc, 80, 278, activation_label, static_cast<int>(wcslen(activation_label)));
    } else {
        std::wstring user_line = L"USER: ";
        user_line += g_client_state.username;
        TextOutW(dc, panel.left + 24, panel.top + 58, user_line.c_str(), static_cast<int>(user_line.size()));
        SetTextColor(dc, RGB(94, 234, 212));
        const wchar_t unlocked[] = L"ANTIVIRUS FUNCTIONALITY: UNLOCKED";
        TextOutW(dc, panel.left + 24, panel.top + 94, unlocked, static_cast<int>(wcslen(unlocked)));
        SetTextColor(dc, RGB(145, 163, 187));
        std::wstring expiration = L"LICENSE EXPIRES: ";
        expiration += UnixTimeToText(g_client_state.licenseExpiresAtUnix);
        TextOutW(dc, panel.left + 24, panel.top + 130, expiration.c_str(), static_cast<int>(expiration.size()));

        SetTextColor(dc, RGB(145, 163, 187));
        wchar_t db_line[256]{};
        StringCchPrintfW(db_line, ARRAYSIZE(db_line), L"AV DB: %lu records, released %s", g_av_db_info.recordCount, UnixTimeToText(g_av_db_info.releaseDateUnix).c_str());
        TextOutW(dc, panel.left + 24, panel.top + 166, db_line, static_cast<int>(wcslen(db_line)));
        const wchar_t scan_label[] = L"Manual scan";
        const wchar_t schedule_label[] = L"Schedule interval, min";
        const wchar_t monitor_label[] = L"Directory monitoring";
        TextOutW(dc, 80, 543, scan_label, static_cast<int>(wcslen(scan_label)));
        TextOutW(dc, 80, 633, schedule_label, static_cast<int>(wcslen(schedule_label)));
        TextOutW(dc, 80, 708, monitor_label, static_cast<int>(wcslen(monitor_label)));

        wchar_t mode_line[512]{};
        if (g_schedule_enabled) {
            StringCchPrintfW(mode_line, ARRAYSIZE(mode_line), L"Schedule: ON, every %lu min; monitored dirs: %zu",
                g_schedule_interval_minutes, g_monitored_directories.size());
        } else {
            StringCchPrintfW(mode_line, ARRAYSIZE(mode_line), L"Schedule: OFF; monitored dirs: %zu",
                g_monitored_directories.size());
        }
        TextOutW(dc, panel.left + 24, panel.top + 202, mode_line, static_cast<int>(wcslen(mode_line)));

        if (!g_scan_status.empty()) {
            RECT scanRect{panel.left + 24, panel.top + 238, panel.right - 24, panel.top + 330};
            DrawTextW(dc, g_scan_status.c_str(), static_cast<int>(g_scan_status.size()), &scanRect, DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS);
        }
    }

    std::wstring message;
    if (!g_ui_error.empty()) {
        message = L"ERROR: " + g_ui_error;
        SetTextColor(dc, RGB(255, 125, 125));
    } else if (g_client_state.message[0] != L'\0') {
        message = L"STATUS: ";
        message += g_client_state.message;
        SetTextColor(dc, RGB(145, 163, 187));
    }
    if (!message.empty()) {
        SelectObject(dc, small_font);
        TextOutW(dc, 64, panel.bottom + 18, message.c_str(), static_cast<int>(message.size()));
    }

    SelectObject(dc, small_font);
    SetTextColor(dc, RGB(86, 102, 126));
    const wchar_t footer[] = L"BMTX / Win32 RPC client: fixed-drive scan, schedule and monitoring";
    TextOutW(dc, 44, kVirtualContentHeight - 42, footer, static_cast<int>(wcslen(footer)));

    SelectObject(dc, old_pen);
    SelectObject(dc, old_brush);
    DeleteObject(border_pen);
    DeleteObject(accent_pen);
    DeleteObject(panel_brush);
    DeleteObject(title_font);
    DeleteObject(body_font);
    DeleteObject(small_font);

    EndPaint(window, &paint);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
    if (message == g_taskbar_created_message) {
        RecreateTrayIcon();
        return 0;
    }

    switch (message) {
    case WM_NCCREATE:
        g_main_window = window;
        return DefWindowProcW(window, message, w_param, l_param);

    case WM_CREATE:
        g_main_window = window;
        CreateMainMenu(window);
        CreateUiControls(window);
        UpdateVerticalScroll(window);
        AddTrayIcon();
        RefreshStateFromService(false);
        SetTimer(window, kStatePollTimerId, kStatePollDelayMs, nullptr);
        return 0;

    case kAsyncScanCompleteMessage:
        MarkBackgroundScanFinished();
        ApplyDirectoryScanResult(reinterpret_cast<AsyncScanResult*>(l_param));
        delete reinterpret_cast<AsyncScanResult*>(l_param);
        return 0;

    case WM_TIMER:
        if (w_param == kTrayRetryTimerId) {
            KillTimer(window, kTrayRetryTimerId);
            AddTrayIcon();
            return 0;
        }
        if (w_param == kStatePollTimerId) {
            RefreshStateFromService(false);
            return 0;
        }
        if (w_param == kScheduledScanTimerId) {
            OnScanAllFixedDrives();
            return 0;
        }
        if (w_param == kMonitorScanTimerId) {
            if (g_monitoring_enabled && !g_monitored_directories.empty()) {
                OnScanMonitoredDirectories();
            }
            return 0;
        }
        return DefWindowProcW(window, message, w_param, l_param);

    case WM_COMMAND:
        switch (LOWORD(w_param)) {
        case IDM_FILE_EXIT:
            ExitApplication();
            return 0;
        case IDM_TRAY_EXIT:
            ExitApplication();
            return 0;
        case IDM_TRAY_OPEN:
            ShowMainWindow();
            return 0;
        case IDC_LOGIN_BUTTON:
            OnLogin();
            return 0;
        case IDC_LOGOUT_BUTTON:
            OnLogout();
            return 0;
        case IDC_ACTIVATE_BUTTON:
            OnActivate();
            return 0;
        case IDC_REFRESH_LICENSE_BUTTON:
            RefreshStateFromService(true);
            return 0;
        case IDC_REFRESH_DB_BUTTON:
            RefreshAvDbInfo();
            return 0;
        case IDC_SCAN_FILE_BUTTON:
            OnScanFile();
            return 0;
        case IDC_SCAN_DIR_BUTTON:
            OnScanDirectory();
            return 0;
        case IDC_SCAN_ALL_FIXED_BUTTON:
            OnScanAllFixedDrives();
            return 0;
        case IDC_SCHEDULE_START_BUTTON:
            OnStartScheduledScan();
            return 0;
        case IDC_SCHEDULE_STOP_BUTTON:
            OnStopScheduledScan();
            return 0;
        case IDC_MONITOR_ADD_BUTTON:
            OnAddMonitorDirectory();
            return 0;
        case IDC_MONITOR_SCAN_BUTTON:
            OnScanMonitoredDirectories();
            return 0;
        case IDC_MONITOR_CLEAR_BUTTON:
            OnClearMonitoredDirectories();
            return 0;
        default:
            break;
        }
        return 0;

    case kTrayMessage:
        switch (LOWORD(l_param)) {
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
            ShowMainWindow();
            return 0;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowTrayMenu();
            return 0;
        default:
            break;
        }
        return 0;

    case WM_CLOSE:
        HideMainWindow();
        return 0;

    case WM_SIZE:
        UpdateVerticalScroll(window);
        InvalidateRect(window, nullptr, TRUE);
        return 0;

    case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(l_param);
        info->ptMinTrackSize.x = kMinWindowTrackWidth;
        info->ptMinTrackSize.y = kMinWindowTrackHeight;
        return 0;
    }

    case WM_VSCROLL: {
        SCROLLINFO info{};
        info.cbSize = sizeof(info);
        info.fMask = SIF_ALL;
        GetScrollInfo(window, SB_VERT, &info);

        int next = g_scroll_y;
        switch (LOWORD(w_param)) {
        case SB_LINEUP:
            next -= 32;
            break;
        case SB_LINEDOWN:
            next += 32;
            break;
        case SB_PAGEUP:
            next -= static_cast<int>(info.nPage);
            break;
        case SB_PAGEDOWN:
            next += static_cast<int>(info.nPage);
            break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION:
            next = info.nTrackPos;
            break;
        default:
            break;
        }
        SetScrollPosition(window, next);
        return 0;
    }

    case WM_MOUSEWHEEL:
        SetScrollPosition(window, g_scroll_y - GET_WHEEL_DELTA_WPARAM(w_param) / WHEEL_DELTA * 96);
        return 0;

    case WM_PAINT:
        PaintInterface(window);
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
        KillTimer(window, kStatePollTimerId);
        KillTimer(window, kScheduledScanTimerId);
        KillTimer(window, kMonitorScanTimerId);
        if (g_main_menu != nullptr) {
            DestroyMenu(g_main_menu);
            g_main_menu = nullptr;
        }
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(window, message, w_param, l_param);
    }
}

bool RegisterMainWindowClass() {
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = WindowProc;
    window_class.hInstance = g_instance;
    window_class.hIcon = g_app_icon;
    window_class.hIconSm = g_tray_icon != nullptr ? g_tray_icon : LoadApplicationIcon(GetSystemMetrics(SM_CXSMICON));
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    window_class.lpszClassName = kWindowClassName;
    return RegisterClassExW(&window_class) != 0;
}

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR command_line, int show_command) {
    g_instance = instance;

    if (!HasCommandLineArgument(kServiceChildFlag)) {
        SERVICE_STATUS_PROCESS status{};
        if (QueryBmtxServiceStatus(&status) &&
            (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_START_PENDING)) {
            WriteClientDebugLog(L"manual bootstrap: service is stopped or starting; starting/waiting service, then exiting before UI/tray");
            StartBmtxServiceAndWaitRunning();
        } else {
            WriteClientDebugLog(L"manual launch rejected before UI/tray: missing --bmtx-service-child");
        }
        return 0;
    }

    bool should_exit_after_start = false;
    if (!EnsureServiceRunningOrStartAndExit(&should_exit_after_start)) {
        return 1;
    }

    if (should_exit_after_start) {
        WriteClientDebugLog(L"service-child instance saw stopped/starting service unexpectedly; exiting");
        return 0;
    }

    if (!IsValidServiceLaunchedClient()) {
        WriteClientDebugLog(L"service-child validation failed before UI/tray");
        return 0;
    }

    g_mutex = CreateMutexW(nullptr, TRUE, kMutexName);
    if (g_mutex == nullptr) {
        return 1;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_mutex);
        return 0;
    }

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    g_taskbar_created_message = RegisterWindowMessageW(L"TaskbarCreated");
    g_app_icon = LoadApplicationIcon(GetSystemMetrics(SM_CXICON));
    g_tray_icon = LoadApplicationIcon(GetSystemMetrics(SM_CXSMICON));

    if (!RegisterMainWindowClass()) {
        CoUninitialize();
        CloseHandle(g_mutex);
        return 1;
    }

    g_main_window = CreateWindowExW(
        0,
        kWindowClassName,
        kAppTitle,
        WS_OVERLAPPEDWINDOW | WS_VSCROLL,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        1100,
        820,
        nullptr,
        nullptr,
        instance,
        nullptr);

    if (g_main_window == nullptr) {
        CoUninitialize();
        CloseHandle(g_mutex);
        return 1;
    }

    const bool hidden_start = HasHiddenStartupFlag(command_line);
    if (!hidden_start) {
        ShowWindow(g_main_window, show_command);
        UpdateWindow(g_main_window);
    }

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    RemoveTrayIcon();

    if (g_app_icon != nullptr) {
        DestroyIcon(g_app_icon);
        g_app_icon = nullptr;
    }
    if (g_tray_icon != nullptr) {
        DestroyIcon(g_tray_icon);
        g_tray_icon = nullptr;
    }
    if (g_mutex != nullptr) {
        ReleaseMutex(g_mutex);
        CloseHandle(g_mutex);
        g_mutex = nullptr;
    }

    CoUninitialize();
    return static_cast<int>(msg.wParam);
}
