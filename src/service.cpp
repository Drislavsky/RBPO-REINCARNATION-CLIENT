#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <strsafe.h>
#include <sddl.h>

#include <map>
#include <string>
#include <vector>

#include "bmtx_rpc.h"

namespace {

constexpr wchar_t kServiceName[] = L"BMTXService";
constexpr wchar_t kServiceDisplayName[] = L"BMTX Service";
constexpr wchar_t kRpcEndpoint[] = L"BMTX_RPC_ALPC_ENDPOINT";
constexpr wchar_t kClientExeName[] = L"BMTX.exe";

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
CRITICAL_SECTION g_process_lock{};
std::map<DWORD, PROCESS_INFORMATION> g_clients;

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

    // Stop and Shutdown are intentionally not accepted by this assignment.
    // Session-change notifications are accepted so new interactive logons can be handled.
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

        // WTSQueryUserToken is the authoritative check here: it succeeds only for
        // sessions that currently have a user token available.
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
        // Stop and Shutdown are disabled by design for this assignment.
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
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stop_event == nullptr) {
        SetServiceState(SERVICE_STOPPED, GetLastError());
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    if (!StartRpcServer()) {
        const DWORD error = GetLastError();
        CloseHandle(g_stop_event);
        g_stop_event = nullptr;
        SetServiceState(SERVICE_STOPPED, error);
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    LaunchClientsInExistingSessions();
    SetServiceState(SERVICE_RUNNING);

    WaitForSingleObject(g_stop_event, INFINITE);

    SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    TerminateClients();
    StopRpcServer();

    CloseHandle(g_stop_event);
    g_stop_event = nullptr;
    DeleteCriticalSection(&g_process_lock);
    SetServiceState(SERVICE_STOPPED);
}


bool ConfigureServiceDaclForUserStart(SC_HANDLE service) {
    // Keep this descriptor deliberately non-hostile:
    //   SY / BA get GENERIC_ALL, so admins can always stop, configure, or delete the service.
    //   AU gets only query/interrogate/start, so the GUI can start the service if it is stopped.
    // Do NOT remove GA from BA/SY. The previous build used an over-restrictive descriptor
    // and could block even elevated maintenance commands such as `sc delete`.
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

    // Critical fix:
    // If BMTXService already existed, older builds left ImagePath pointing to an old
    // folder. Then `BMTXService.exe --install` appeared to succeed, but Windows still
    // started the old service binary, which launched the old GUI. Always rewrite the
    // service configuration to the current executable path.
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
    description.lpDescription = const_cast<LPWSTR>(L"BMTX session launcher and local RPC controller.");
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
