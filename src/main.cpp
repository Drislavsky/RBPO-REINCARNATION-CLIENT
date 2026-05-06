#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <rpc.h>

#include <string>
#include <vector>

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
constexpr UINT kTrayId = 1;

HINSTANCE g_instance = nullptr;
HWND g_main_window = nullptr;
HMENU g_main_menu = nullptr;
HICON g_app_icon = nullptr;
HICON g_tray_icon = nullptr;
NOTIFYICONDATAW g_tray_data{};
UINT g_taskbar_created_message = 0;
HANDLE g_mutex = nullptr;
bool g_tray_added = false;
bool g_exit_requested = false;

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

    if (status.dwCurrentState == SERVICE_STOPPED) {
        const bool started = StartBmtxServiceAndWaitRunning();
        *should_exit = true;
        return started;
    }

    if (status.dwCurrentState == SERVICE_START_PENDING) {
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

bool StopServiceThroughRpc() {
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

    handle_t binding = nullptr;
    status = RpcBindingFromStringBindingW(string_binding, &binding);
    RpcStringFreeW(&string_binding);
    if (status != RPC_S_OK) {
        SetLastError(status);
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

void ShowLastErrorMessage(const wchar_t* operation) {
    const DWORD error = GetLastError();
    wchar_t text[512]{};
    StringCchPrintfW(
        text,
        ARRAYSIZE(text),
        L"%s failed. GetLastError = %lu",
        operation,
        error);
    MessageBoxW(g_main_window, text, L"BMTX", MB_OK | MB_ICONERROR);
}

HICON LoadApplicationIcon(int size) {
    HICON icon = reinterpret_cast<HICON>(LoadImageW(
        g_instance,
        MAKEINTRESOURCEW(IDI_APPICON),
        IMAGE_ICON,
        size,
        size,
        LR_DEFAULTCOLOR));

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
    if (g_tray_added) {
        Shell_NotifyIconW(NIM_DELETE, &g_tray_data);
        g_tray_added = false;
    }
    ZeroMemory(&g_tray_data, sizeof(g_tray_data));
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
        ShowLastErrorMessage(L"Shell_NotifyIconW(NIM_ADD)");
        ZeroMemory(&g_tray_data, sizeof(g_tray_data));
        return false;
    }

    g_tray_added = true;
    g_tray_data.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_tray_data);
    return true;
}

void RecreateTrayIcon() {
    g_tray_added = false;
    ZeroMemory(&g_tray_data, sizeof(g_tray_data));
    AddTrayIcon();
}

void ExitApplication() {
    if (!StopServiceThroughRpc()) {
        ShowLastErrorMessage(L"RPC BmtxStopService");
        return;
    }

    // The service owns the GUI lifetime and will terminate this process during shutdown.
    HideMainWindow();
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
    const UINT command = TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RETURNCMD,
        point.x,
        point.y,
        0,
        g_main_window,
        nullptr);
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

void PaintInterface(HWND window) {
    PAINTSTRUCT paint{};
    HDC dc = BeginPaint(window, &paint);
    if (dc == nullptr) {
        return;
    }

    RECT client{};
    GetClientRect(window, &client);

    HBRUSH background = CreateSolidBrush(RGB(7, 9, 13));
    FillRect(dc, &client, background);
    DeleteObject(background);

    SetBkMode(dc, TRANSPARENT);

    HFONT title_font = CreateFontW(30, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT body_font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT small_font = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    SelectObject(dc, title_font);
    SetTextColor(dc, RGB(232, 238, 247));
    TextOutW(dc, 42, 42, kAppTitle, static_cast<int>(wcslen(kAppTitle)));

    SelectObject(dc, body_font);
    SetTextColor(dc, RGB(128, 146, 169));
    const wchar_t subtitle[] = L"BMTX // NEX GEN OF ANTI-MALWARE SOFTWARE";
    TextOutW(dc, 44, 86, subtitle, static_cast<int>(wcslen(subtitle)));

    HPEN border_pen = CreatePen(PS_SOLID, 1, RGB(40, 52, 70));
    HPEN accent_pen = CreatePen(PS_SOLID, 2, RGB(94, 234, 212));
    HBRUSH panel_brush = CreateSolidBrush(RGB(13, 17, 24));
    HGDIOBJ old_pen = SelectObject(dc, border_pen);
    HGDIOBJ old_brush = SelectObject(dc, panel_brush);

    RECT badge{client.right - 190, 38, client.right - 42, 96};
    RoundRect(dc, badge.left, badge.top, badge.right, badge.bottom, 16, 16);
    SelectObject(dc, small_font);
    SetTextColor(dc, RGB(94, 234, 212));
    const wchar_t badge_text[] = L"CORE ONLINE";
    TextOutW(dc, badge.left + 34, badge.top + 20, badge_text, static_cast<int>(wcslen(badge_text)));

    RECT panel{42, 130, client.right - 42, 326};
    RoundRect(dc, panel.left, panel.top, panel.right, panel.bottom, 18, 18);

    SelectObject(dc, accent_pen);
    MoveToEx(dc, panel.left + 22, panel.top + 34, nullptr);
    LineTo(dc, panel.right - 22, panel.top + 34);

    SelectObject(dc, body_font);
    SetTextColor(dc, RGB(214, 222, 235));
    const wchar_t status[] = L"STATUS / PROCESS IS ACTIVE";
    TextOutW(dc, panel.left + 24, panel.top + 58, status, static_cast<int>(wcslen(status)));

    SetTextColor(dc, RGB(145, 163, 187));
    const wchar_t hint1[] = L"• Крестик скрывает главное окно, процесс продолжает работу";
    const wchar_t hint2[] = L"• Полное завершение: Файл -> Выход или трей -> Выход";
    const wchar_t hint3[] = L"• ЛКМ по иконке трея открывает главное окно";
    const wchar_t hint4[] = L"• Для скрытого старта используйте параметр --hidden";
    TextOutW(dc, panel.left + 24, panel.top + 94, hint1, static_cast<int>(wcslen(hint1)));
    TextOutW(dc, panel.left + 24, panel.top + 124, hint2, static_cast<int>(wcslen(hint2)));
    TextOutW(dc, panel.left + 24, panel.top + 154, hint3, static_cast<int>(wcslen(hint3)));
    TextOutW(dc, panel.left + 24, panel.top + 178, hint4, static_cast<int>(wcslen(hint4)));

    SelectObject(dc, small_font);
    SetTextColor(dc, RGB(86, 102, 126));
    const wchar_t footer[] = L"BMTX 1.1 / Win32 API";
    TextOutW(dc, 44, client.bottom - 42, footer, static_cast<int>(wcslen(footer)));

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
        AddTrayIcon();
        return 0;

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

    case WM_PAINT:
        PaintInterface(window);
        return 0;

    case WM_DESTROY:
        if (g_exit_requested) {
            RemoveTrayIcon();
            if (g_main_menu != nullptr) {
                DestroyMenu(g_main_menu);
                g_main_menu = nullptr;
            }
            PostQuitMessage(0);
        }
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

    // IMPORTANT:
    // A manually started GUI process must never create a window or tray icon.
    // It may only perform the required bootstrap action: start BMTXService if it is stopped,
    // wait until it reaches Running, and then terminate immediately.
    // The real GUI is allowed to continue only when it was launched by BMTXService with
    // the service-child marker and a PID that matches the currently running service process.
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

    g_taskbar_created_message = RegisterWindowMessageW(L"TaskbarCreated");
    g_app_icon = LoadApplicationIcon(GetSystemMetrics(SM_CXICON));
    g_tray_icon = LoadApplicationIcon(GetSystemMetrics(SM_CXSMICON));

    if (!RegisterMainWindowClass()) {
        CloseHandle(g_mutex);
        return 1;
    }

    g_main_window = CreateWindowExW(
        0,
        kWindowClassName,
        kAppTitle,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        760,
        460,
        nullptr,
        nullptr,
        instance,
        nullptr);

    if (g_main_window == nullptr) {
        CloseHandle(g_mutex);
        return 1;
    }

    const bool hidden_start = HasHiddenStartupFlag(command_line);
    if (!hidden_start) {
        ShowWindow(g_main_window, show_command);
        UpdateWindow(g_main_window);
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
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

    return static_cast<int>(message.wParam);
}
