#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <strsafe.h>
#include <sddl.h>
#include <winhttp.h>
#include <shlwapi.h>


#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include <array>
#include <fstream>
#include <cstdint>
#include <sstream>
#include <wincrypt.h>
#include <bcrypt.h>

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
constexpr wchar_t kAvDatabaseEndpoint[] = L"/api/signatures";

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
HANDLE g_refresh_thread = nullptr;
CRITICAL_SECTION g_process_lock{};
CRITICAL_SECTION g_state_lock{};
CRITICAL_SECTION g_av_lock{};
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

enum class AvObjectType : unsigned long long {
    Any = 0,
    PeFile = 1,
    Script = 2,
};

struct AvRecord {
    unsigned long long objectSignaturePrefix = 0;
    unsigned long objectSignatureLength = 0;
    unsigned long serverLengthField = 0;
    std::vector<unsigned char> objectSignature;
    std::vector<unsigned char> firstBytes;
    unsigned long long offsetBegin = 0;
    unsigned long long offsetEnd = 0;
    AvObjectType objectType = AvObjectType::PeFile;
    std::vector<unsigned char> avRecordSignature;
    std::wstring threatName;
};

struct AvDatabase {
    bool loaded = false;
    FILETIME releaseDate{};
    std::map<unsigned long long, std::vector<AvRecord>> records;
};

AvDatabase g_av_database;

struct HttpResponse {
    DWORD status = 0;
    std::wstring body;
    DWORD error = ERROR_SUCCESS;
};

std::wstring ExtractJsonString(const std::wstring& json, const std::wstring& key);
bool ExtractJsonBool(const std::wstring& json, const std::wstring& key, bool default_value);
DWORD ExtractJsonDword(const std::wstring& json, const std::wstring& key, DWORD default_value);
HttpResponse HttpsRequest(const wchar_t* method, const std::wstring& path, const std::string& body, const std::wstring& bearer_token);
DWORD RefreshTokensInternal();
void SetMessageLocked(const std::wstring& message);
bool IsFileTimeExpiredOrNear(const FILETIME& ft, DWORD safety_seconds);

unsigned long long PrefixFromBytes(const unsigned char* data) {
    unsigned long long value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<unsigned long long>(data[i]) << (i * 8);
    }
    return value;
}

std::vector<unsigned char> Sha256Bytes(const unsigned char* data, size_t size) {
    std::vector<unsigned char> result(32);
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD cb_data = 0;
    DWORD object_length = 0;
    DWORD hash_length = 0;
    std::vector<unsigned char> hash_object;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return {};
    }
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &cb_data, 0) != 0 ||
        BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length), &cb_data, 0) != 0 ||
        hash_length == 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    hash_object.assign(object_length, 0);
    result.assign(hash_length, 0);
    if (BCryptCreateHash(algorithm, &hash, hash_object.data(), object_length, nullptr, 0, 0) != 0 ||
        BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0) != 0 ||
        BCryptFinishHash(hash, result.data(), hash_length, 0) != 0) {
        if (hash != nullptr) {
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

std::vector<unsigned char> HashRecordFields(const AvRecord& record) {
    std::vector<unsigned char> raw;
    raw.insert(raw.end(), reinterpret_cast<const unsigned char*>(&record.objectSignaturePrefix), reinterpret_cast<const unsigned char*>(&record.objectSignaturePrefix) + sizeof(record.objectSignaturePrefix));
    raw.insert(raw.end(), reinterpret_cast<const unsigned char*>(&record.objectSignatureLength), reinterpret_cast<const unsigned char*>(&record.objectSignatureLength) + sizeof(record.objectSignatureLength));
    raw.insert(raw.end(), record.objectSignature.begin(), record.objectSignature.end());
    raw.insert(raw.end(), reinterpret_cast<const unsigned char*>(&record.offsetBegin), reinterpret_cast<const unsigned char*>(&record.offsetBegin) + sizeof(record.offsetBegin));
    raw.insert(raw.end(), reinterpret_cast<const unsigned char*>(&record.offsetEnd), reinterpret_cast<const unsigned char*>(&record.offsetEnd) + sizeof(record.offsetEnd));
    const unsigned long long objectType = static_cast<unsigned long long>(record.objectType);
    raw.insert(raw.end(), reinterpret_cast<const unsigned char*>(&objectType), reinterpret_cast<const unsigned char*>(&objectType) + sizeof(objectType));
    return Sha256Bytes(raw.data(), raw.size());
}

std::vector<unsigned char> BytesFromHex(const std::wstring& hex) {
    std::vector<unsigned char> bytes;
    if (hex.size() % 2 != 0) {
        return bytes;
    }
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        wchar_t pair[3] = { hex[i], hex[i + 1], L'\0' };
        wchar_t* end = nullptr;
        const unsigned long value = wcstoul(pair, &end, 16);
        if (end == nullptr || *end != L'\0' || value > 0xFF) {
            bytes.clear();
            return bytes;
        }
        bytes.push_back(static_cast<unsigned char>(value));
    }
    return bytes;
}

std::wstring BytesToHex(const std::vector<unsigned char>& bytes) {
    static constexpr wchar_t hex[] = L"0123456789ABCDEF";
    std::wstring result;
    result.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0F]);
    }
    return result;
}

std::wstring LowerCopy(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
    return value;
}

bool ContainsToken(const std::wstring& value, const wchar_t* token) {
    return value.find(token) != std::wstring::npos;
}

bool HasPeExtensionInString(const std::wstring& value) {
    const std::wstring lowered = LowerCopy(value);
    return lowered.size() >= 4 &&
        (lowered.rfind(L".exe") == lowered.size() - 4 ||
         lowered.rfind(L".dll") == lowered.size() - 4 ||
         lowered.rfind(L".sys") == lowered.size() - 4 ||
         lowered.rfind(L".scr") == lowered.size() - 4);
}

bool HasScriptExtensionInString(const std::wstring& value) {
    const std::wstring lowered = LowerCopy(value);
    const wchar_t* exts[] = { L".js", L".py", L".ps1", L".bat", L".cmd", L".vbs", L".wsf", L".hta", L".script", L".txt" };
    for (const wchar_t* ext : exts) {
        const size_t len = wcslen(ext);
        if (lowered.size() >= len && lowered.rfind(ext) == lowered.size() - len) {
            return true;
        }
    }
    return false;
}

bool LooksLikePeMime(const std::wstring& lowered) {
    return ContainsToken(lowered, L"portable-executable") ||
        ContainsToken(lowered, L"portable executable") ||
        ContainsToken(lowered, L"msdownload") ||
        ContainsToken(lowered, L"x-msdownload") ||
        ContainsToken(lowered, L"x-dosexec") ||
        ContainsToken(lowered, L"x-msdos-program") ||
        ContainsToken(lowered, L"application/vnd.microsoft.portable-executable");
}

bool LooksLikeScriptMime(const std::wstring& lowered) {
    return ContainsToken(lowered, L"text/") ||
        ContainsToken(lowered, L"javascript") ||
        ContainsToken(lowered, L"powershell") ||
        ContainsToken(lowered, L"batch") ||
        ContainsToken(lowered, L"python");
}

AvObjectType ParseObjectType(const std::wstring& value,
                             const std::vector<unsigned char>& firstBytes,
                             const std::wstring& threatName,
                             const std::wstring& originalFileName,
                             const std::wstring& fileContentType) {
    // Convert the server record type to the engine ObjectType.
    // Important: /api/signatures/file in the provided server ignores form-data
    // fields fileType/offsetStart/offsetEnd; it stores MultipartFile contentType
    // in fileType and stores originalFileName separately. Therefore we must also
    // inspect originalFileName/fileContentType, otherwise PE records uploaded as
    // files can accidentally become SCRIPT and .exe scans return CLEAN.
    const std::wstring lowered = LowerCopy(value);
    const std::wstring contentLowered = LowerCopy(fileContentType);
    const std::wstring threatLowered = LowerCopy(threatName);

    // Explicit admin-created JSON values have the highest priority.
    if (lowered == L"1" || lowered == L"pe" || lowered == L"pefile" ||
        lowered == L"pe_file" || lowered == L"pe file" ||
        lowered == L"portable_executable" || lowered == L"portable executable" ||
        lowered == L"exe" || lowered == L"dll" || lowered == L"sys" ||
        lowered == L"win32" || lowered == L"windows_executable") {
        return AvObjectType::PeFile;
    }
    if (lowered == L"2" || lowered == L"script" || lowered == L"scripts" ||
        lowered == L"text" || lowered == L"txt" || lowered == L"js" ||
        lowered == L"javascript" || lowered == L"py" || lowered == L"python" ||
        lowered == L"ps1" || lowered == L"powershell" || lowered == L"bat" ||
        lowered == L"batch" || lowered == L"cmd" || lowered == L"vbs" ||
        lowered == L"wsf" || lowered == L"hta" || lowered == L"scriptfile") {
        return AvObjectType::Script;
    }

    // MIME values from MultipartFile contentType.
    if (LooksLikePeMime(lowered) || LooksLikePeMime(contentLowered)) {
        return AvObjectType::PeFile;
    }
    if (LooksLikeScriptMime(lowered) || LooksLikeScriptMime(contentLowered)) {
        return AvObjectType::Script;
    }

    // Original filename from /api/signatures/file.
    if (HasScriptExtensionInString(originalFileName)) {
        return AvObjectType::Script;
    }
    if (HasPeExtensionInString(originalFileName)) {
        return AvObjectType::PeFile;
    }

    // Last-resort lab compatibility: octet-stream .exe-like signatures beginning
    // with MZ are PE. This affects the DB record only, not scanned .txt files.
    if ((lowered.empty() || lowered == L"application/octet-stream" || lowered == L"octet-stream" ||
         contentLowered.empty() || contentLowered == L"application/octet-stream" || contentLowered == L"octet-stream") &&
        firstBytes.size() >= 2 && firstBytes[0] == 'M' && firstBytes[1] == 'Z') {
        return AvObjectType::PeFile;
    }

    if (ContainsToken(threatLowered, L"pe") || ContainsToken(threatLowered, L"exe")) {
        return AvObjectType::PeFile;
    }

    return AvObjectType::Script;
}

bool ParseServerSignatureObject(const std::wstring& object, AvRecord* record) {
    if (record == nullptr) {
        return false;
    }
    const std::wstring threatName = !ExtractJsonString(object, L"threatName").empty() ? ExtractJsonString(object, L"threatName") : ExtractJsonString(object, L"name");
    const std::wstring firstBytesHex = !ExtractJsonString(object, L"firstBytesHex").empty() ? ExtractJsonString(object, L"firstBytesHex") : ExtractJsonString(object, L"signaturePrefixHex");
    std::wstring objectSignatureHex = ExtractJsonString(object, L"remainderHashHex");
    if (objectSignatureHex.empty()) objectSignatureHex = ExtractJsonString(object, L"objectSignatureHex");
    if (objectSignatureHex.empty()) objectSignatureHex = ExtractJsonString(object, L"signatureHashHex");
    if (objectSignatureHex.empty()) objectSignatureHex = ExtractJsonString(object, L"hashHex");
    DWORD signatureLength = ExtractJsonDword(object, L"remainderLength", 0);
    if (signatureLength == 0) signatureLength = ExtractJsonDword(object, L"objectSignatureLength", 0);
    if (signatureLength == 0) signatureLength = ExtractJsonDword(object, L"signatureLength", 0);
    std::wstring fileType = ExtractJsonString(object, L"fileType");
    if (fileType.empty()) fileType = ExtractJsonString(object, L"objectType");
    if (fileType.empty()) fileType = ExtractJsonString(object, L"type");
    if (fileType.empty()) fileType = ExtractJsonString(object, L"objectFileType");
    const std::wstring originalFileName = ExtractJsonString(object, L"originalFileName");
    const std::wstring fileContentType = ExtractJsonString(object, L"fileContentType");
    DWORD offsetStart = ExtractJsonDword(object, L"offsetStart", 0);
    if (offsetStart == 0) offsetStart = ExtractJsonDword(object, L"offsetBegin", 0);
    DWORD offsetEnd = ExtractJsonDword(object, L"offsetEnd", 0);
    const std::wstring status = ExtractJsonString(object, L"status");
    const std::wstring recordSignatureBase64 = ExtractJsonString(object, L"digitalSignatureBase64");

    const std::vector<unsigned char> firstBytes = BytesFromHex(firstBytesHex);
    const std::vector<unsigned char> objectSignature = BytesFromHex(objectSignatureHex);
    if (firstBytes.size() < 8 || objectSignature.empty() || offsetEnd < offsetStart) {
        return false;
    }
    if (!status.empty() && _wcsicmp(status.c_str(), L"ACTUAL") != 0) {
        return false;
    }

    record->firstBytes = firstBytes;
    record->objectSignaturePrefix = PrefixFromBytes(firstBytes.data());
    // Server field remainderLength is the number of bytes AFTER firstBytesHex.
    // The assignment's ObjectSignatureLength is the whole signature length including prefix.
    record->serverLengthField = static_cast<unsigned long>(signatureLength);
    record->objectSignatureLength = static_cast<unsigned long>(firstBytes.size() + signatureLength);
    // Server field remainderHashHex is SHA-256 of the remainder only, not SHA-256 of the whole signature.
    record->objectSignature = objectSignature;
    record->offsetBegin = offsetStart;
    record->offsetEnd = offsetEnd;
    record->objectType = ParseObjectType(fileType, firstBytes, threatName, originalFileName, fileContentType);
    record->threatName = threatName.empty() ? L"Server.Signature" : threatName;

    if (!recordSignatureBase64.empty()) {
        // Base64 is ASCII text. Convert explicitly from wchar_t to bytes to avoid
        // MSVC C4244 warnings and keep the AV-record signature field deterministic.
        std::vector<unsigned char> sig;
        sig.reserve(recordSignatureBase64.size());
        for (wchar_t ch : recordSignatureBase64) {
            if (ch >= 0 && ch <= 0x7F) {
                sig.push_back(static_cast<unsigned char>(ch));
            }
        }
        record->avRecordSignature = sig;
    } else {
        record->avRecordSignature = HashRecordFields(*record);
    }
    return true;
}

std::vector<std::wstring> ExtractJsonObjectsFromArray(const std::wstring& json) {
    std::vector<std::wstring> objects;
    bool in_string = false;
    bool escaped = false;
    int depth = 0;
    size_t object_start = std::wstring::npos;
    for (size_t i = 0; i < json.size(); ++i) {
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
            if (depth == 0) {
                object_start = i;
            }
            ++depth;
        } else if (ch == L'}') {
            --depth;
            if (depth == 0 && object_start != std::wstring::npos) {
                objects.push_back(json.substr(object_start, i - object_start + 1));
                object_start = std::wstring::npos;
            }
        }
    }
    return objects;
}

DWORD LoadAntivirusDatabaseFromServer() {
    std::wstring access_token;
    EnterCriticalSection(&g_state_lock);
    access_token = g_state.access_token;
    LeaveCriticalSection(&g_state_lock);
    if (access_token.empty()) {
        return ERROR_NOT_LOGGED_ON;
    }

    HttpResponse response = HttpsRequest(L"GET", kAvDatabaseEndpoint, {}, access_token);
    if (response.error != ERROR_SUCCESS) {
        return response.error;
    }
    if (response.status == 401 || response.status == 403) {
        const DWORD refreshed = RefreshTokensInternal();
        if (refreshed == ERROR_SUCCESS) {
            EnterCriticalSection(&g_state_lock);
            access_token = g_state.access_token;
            LeaveCriticalSection(&g_state_lock);
            response = HttpsRequest(L"GET", kAvDatabaseEndpoint, {}, access_token);
        }
    }
    if (response.error != ERROR_SUCCESS) {
        return response.error;
    }
    if (response.status < 200 || response.status >= 300) {
        EnterCriticalSection(&g_state_lock);
        SetMessageLocked(L"Failed to download AV database from server");
        LeaveCriticalSection(&g_state_lock);
        return ERROR_INVALID_DATA;
    }

    AvDatabase database{};
    database.loaded = true;
    GetSystemTimeAsFileTime(&database.releaseDate);

    const std::vector<std::wstring> objects = ExtractJsonObjectsFromArray(response.body);
    for (const std::wstring& object : objects) {
        AvRecord record{};
        if (ParseServerSignatureObject(object, &record)) {
            database.records[record.objectSignaturePrefix].push_back(record);
        }
    }

    EnterCriticalSection(&g_av_lock);
    g_av_database = std::move(database);
    LeaveCriticalSection(&g_av_lock);

    EnterCriticalSection(&g_state_lock);
    SetMessageLocked(L"AV database loaded from server");
    LeaveCriticalSection(&g_state_lock);
    return ERROR_SUCCESS;
}

void ClearAntivirusDatabase() {
    EnterCriticalSection(&g_av_lock);
    g_av_database = AvDatabase{};
    LeaveCriticalSection(&g_av_lock);
}

bool IsAntivirusUnlocked() {
    EnterCriticalSection(&g_state_lock);
    const bool unlocked = !g_state.access_token.empty() &&
        !g_state.refresh_token.empty() &&
        !g_state.license_ticket_json.empty() &&
        !ExtractJsonBool(g_state.license_ticket_json, L"blocked", false) &&
        !IsFileTimeExpiredOrNear(g_state.license_expires_at, 0);
    LeaveCriticalSection(&g_state_lock);
    return unlocked;
}

DWORD EnsureAntivirusDatabaseLoaded() {
    if (!IsAntivirusUnlocked()) {
        return ERROR_ACCESS_DENIED;
    }
    EnterCriticalSection(&g_av_lock);
    const bool loaded = g_av_database.loaded;
    LeaveCriticalSection(&g_av_lock);
    if (loaded) {
        return ERROR_SUCCESS;
    }
    return LoadAntivirusDatabaseFromServer();
}

unsigned long CountAvRecordsLocked() {
    unsigned long total = 0;
    for (const auto& item : g_av_database.records) {
        total += static_cast<unsigned long>(item.second.size());
    }
    return total;
}

AvObjectType DetectObjectType(const std::wstring& path, const std::vector<unsigned char>& data) {
    // Extension has priority for scanned objects. This is what makes the negative
    // test work: PE bytes inside .txt/.bat/.script are still SCRIPT, not PE.
    if (HasScriptExtensionInString(path)) {
        return AvObjectType::Script;
    }
    if (HasPeExtensionInString(path)) {
        return AvObjectType::PeFile;
    }

    // Files without a known extension can still be PE if they begin with MZ.
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') {
        return AvObjectType::PeFile;
    }

    return AvObjectType::Any;
}

bool ReadWholeFile(const std::wstring& path, std::vector<unsigned char>* data) {
    if (data == nullptr) {
        return false;
    }
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 128LL * 1024LL * 1024LL) {
        CloseHandle(file);
        return false;
    }
    data->assign(static_cast<size_t>(size.QuadPart), 0);
    DWORD read = 0;
    const BOOL ok = data->empty() || ReadFile(file, data->data(), static_cast<DWORD>(data->size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read != data->size()) {
        data->clear();
        return false;
    }
    return true;
}

bool ScanByteStream(const std::wstring& path, const std::vector<unsigned char>& data, std::wstring* threatName) {
    if (data.size() < 8) {
        return false;
    }
    const AvObjectType type = DetectObjectType(path, data);
    std::map<unsigned long long, std::vector<AvRecord>> records;
    EnterCriticalSection(&g_av_lock);
    records = g_av_database.records;
    LeaveCriticalSection(&g_av_lock);

    for (size_t pos = 0; pos + 8 <= data.size(); ++pos) {
        const unsigned long long prefix = PrefixFromBytes(data.data() + pos);
        const auto found = records.find(prefix);
        if (found == records.end()) {
            continue;
        }
        for (const AvRecord& record : found->second) {
            // Type check must be strict for PE and SCRIPT records. Any is allowed only
            // for old server records that genuinely did not contain object type info.
            if (record.objectType != AvObjectType::Any && record.objectType != type) {
                continue;
            }
            // OffsetBegin/OffsetEnd describe the allowed interval for this signature.
            // First, reject candidates whose START position is outside the interval.
            // A second check below may also require the whole signature to fit into
            // the interval when the server stores OffsetEnd as the end of the
            // signature sample. This prevents a signature uploaded with interval
            // [0..signature_length-1] from also matching later in a file.
            if (pos < record.offsetBegin || pos > record.offsetEnd) {
                continue;
            }
            if (pos + record.firstBytes.size() > data.size()) {
                continue;
            }
            if (!std::equal(record.firstBytes.begin(), record.firstBytes.end(), data.begin() + pos)) {
                continue;
            }

            const size_t firstLen = record.firstBytes.size();
            const size_t rawLen = static_cast<size_t>(record.serverLengthField);
            std::vector<size_t> fullLengths;

            // Server variants seen in the project:
            // 1) remainderLength = bytes after firstBytesHex; remainderHashHex = SHA256(remainder)
            if (rawLen > 0) {
                fullLengths.push_back(firstLen + rawLen);
            }
            // 2) objectSignatureLength/signatureLength = whole signature length including prefix
            if (rawLen >= firstLen) {
                fullLengths.push_back(rawLen);
            }
            // 3) previously normalized engine length
            if (record.objectSignatureLength >= firstLen) {
                fullLengths.push_back(static_cast<size_t>(record.objectSignatureLength));
            }

            std::sort(fullLengths.begin(), fullLengths.end());
            fullLengths.erase(std::unique(fullLengths.begin(), fullLengths.end()), fullLengths.end());

            for (size_t fullLen : fullLengths) {
                if (fullLen < firstLen || pos + fullLen > data.size()) {
                    continue;
                }

                // If the configured interval is at least as large as the complete
                // signature, treat OffsetEnd as an end boundary for the whole
                // signature. This keeps normal tests with [0..10] working as a
                // start-position interval when the signature is longer than the
                // interval, but also fixes the /api/signatures/file case where the
                // server may save [0..signature_length-1] and would otherwise allow
                // the same signature to match at offset 20, 40, etc.
                const unsigned long long intervalSize = record.offsetEnd >= record.offsetBegin
                    ? (record.offsetEnd - record.offsetBegin + 1ULL)
                    : 0ULL;
                if (intervalSize >= static_cast<unsigned long long>(fullLen)) {
                    const unsigned long long signatureEnd = static_cast<unsigned long long>(pos + fullLen - 1);
                    if (signatureEnd > record.offsetEnd) {
                        continue;
                    }
                }

                const size_t remainderOffset = pos + firstLen;
                const size_t remainderLength = fullLen - firstLen;

                // Preferred current server format: hash only the remainder.
                const auto remainderHash = Sha256Bytes(data.data() + remainderOffset, remainderLength);
                if (remainderHash == record.objectSignature) {
                    if (threatName != nullptr) {
                        *threatName = record.threatName;
                    }
                    return true;
                }

                // Compatibility with older/alternate server format: hash whole signature.
                const auto wholeHash = Sha256Bytes(data.data() + pos, fullLen);
                if (wholeHash == record.objectSignature) {
                    if (threatName != nullptr) {
                        *threatName = record.threatName;
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

DWORD ScanSingleFile(const std::wstring& path, BMTX_SCAN_RESULT* result) {
    if (result == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(result, sizeof(*result));
    std::vector<unsigned char> data;
    if (!ReadWholeFile(path, &data)) {
        StringCchCopyW(result->message, ARRAYSIZE(result->message), L"File cannot be opened or is larger than 128 MB");
        return GetLastError() == ERROR_SUCCESS ? ERROR_OPEN_FAILED : GetLastError();
    }
    result->scannedObjects = 1;
    std::wstring threat;
    if (ScanByteStream(path, data, &threat)) {
        result->infectedObjects = 1;
        StringCchCopyW(result->firstThreatPath, ARRAYSIZE(result->firstThreatPath), path.c_str());
        StringCchCopyW(result->threatName, ARRAYSIZE(result->threatName), threat.c_str());
        StringCchCopyW(result->message, ARRAYSIZE(result->message), L"Malicious object detected");
    } else {
        StringCchCopyW(result->message, ARRAYSIZE(result->message), L"No threats found");
    }
    return ERROR_SUCCESS;
}

const DWORD kMaxFilesPerDirectoryScan = 1000;

void ScanDirectoryRecursive(const std::wstring& directory, BMTX_SCAN_RESULT* aggregate, DWORD maxFiles) {
    if (aggregate == nullptr || aggregate->scannedObjects >= maxFiles) {
        return;
    }

    std::wstring mask = directory;
    if (!mask.empty() && mask.back() != L'\\' && mask.back() != L'/') {
        mask += L"\\";
    }
    mask += L"*";

    WIN32_FIND_DATAW fd{};
    HANDLE find = FindFirstFileW(mask.c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (aggregate->scannedObjects >= maxFiles) {
            break;
        }

        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
            continue;
        }

        std::wstring path = directory;
        if (!path.empty() && path.back() != L'\\' && path.back() != L'/') {
            path += L"\\";
        }
        path += fd.cFileName;

        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            ScanDirectoryRecursive(path, aggregate, maxFiles);
            continue;
        }

        BMTX_SCAN_RESULT one{};
        if (ScanSingleFile(path, &one) == ERROR_SUCCESS) {
            aggregate->scannedObjects += one.scannedObjects;
            aggregate->infectedObjects += one.infectedObjects;
            if (one.infectedObjects > 0 && aggregate->firstThreatPath[0] == L'\0') {
                StringCchCopyW(aggregate->firstThreatPath, ARRAYSIZE(aggregate->firstThreatPath), one.firstThreatPath);
                StringCchCopyW(aggregate->threatName, ARRAYSIZE(aggregate->threatName), one.threatName);
            }
        }
    } while (FindNextFileW(find, &fd));

    FindClose(find);
}

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

HttpResponse HttpsRequest(const wchar_t* method, const std::wstring& path, const std::string& body, const std::wstring& bearer_token) {
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
    const HttpResponse response = HttpsRequest(L"POST", kAuthRefreshEndpoint, body, L"");
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
    const HttpResponse response = HttpsRequest(L"POST", kAuthLoginEndpoint, body, L"");
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
        HttpsRequest(L"POST", kAuthLogoutEndpoint, body, L"");
    }

    EnterCriticalSection(&g_state_lock);
    ClearAuthLocked();
    SetMessageLocked(L"Logged out");
    LeaveCriticalSection(&g_state_lock);
    ClearAntivirusDatabase();
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

    return LoadAntivirusDatabaseFromServer();
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
    InitializeCriticalSection(&g_av_lock);
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stop_event == nullptr) {
        SetServiceState(SERVICE_STOPPED, GetLastError());
        DeleteCriticalSection(&g_av_lock);
    DeleteCriticalSection(&g_state_lock);
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    if (!StartRpcServer()) {
        const DWORD error = GetLastError();
        CloseHandle(g_stop_event);
        g_stop_event = nullptr;
        SetServiceState(SERVICE_STOPPED, error);
        DeleteCriticalSection(&g_av_lock);
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
    DeleteCriticalSection(&g_av_lock);
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
        if (result == ERROR_SUCCESS) {
            result = LoadAntivirusDatabaseFromServer();
        }
    } else {
        result = ERROR_LICENSE_QUOTA_EXCEEDED;
    }
    FillClientState(state);
    return result;
}

extern "C" unsigned long BmtxGetAvDbInfo(handle_t, BMTX_AV_DB_INFO* info) {
    if (info == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    ZeroMemory(info, sizeof(*info));

    // Important: this RPC method is also the manual "reload DB from server" action.
    // If signatures are uploaded in Postman after activation, clicking "Инфо баз"
    // must download the fresh server state instead of returning the old in-memory cache.
    DWORD load_result = ERROR_SUCCESS;
    if (!IsAntivirusUnlocked()) {
        load_result = ERROR_ACCESS_DENIED;
    } else {
        load_result = LoadAntivirusDatabaseFromServer();
    }

    EnterCriticalSection(&g_av_lock);
    info->releaseDateUnix = FileTimeToUnixSeconds(g_av_database.releaseDate);
    info->recordCount = CountAvRecordsLocked();
    LeaveCriticalSection(&g_av_lock);
    StringCchCopyW(info->engineName, ARRAYSIZE(info->engineName), L"BMTX Server AV Engine");
    if (load_result == ERROR_SUCCESS) {
        StringCchCopyW(info->message, ARRAYSIZE(info->message), L"Antivirus database was reloaded from server into RAM std::map");
    } else {
        StringCchCopyW(info->message, ARRAYSIZE(info->message), L"AV database was not loaded from server; authenticate, activate license, and check /api/signatures");
    }
    return load_result;
}

extern "C" unsigned long BmtxScanFile(handle_t, wchar_t* path, BMTX_SCAN_RESULT* result) {
    if (path == nullptr || result == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    DWORD load_result = EnsureAntivirusDatabaseLoaded();
    if (load_result == ERROR_SUCCESS) {
        // Refresh before a scan so newly uploaded Postman signatures are used without restarting the service.
        load_result = LoadAntivirusDatabaseFromServer();
    }
    if (load_result != ERROR_SUCCESS) {
        ZeroMemory(result, sizeof(*result));
        StringCchCopyW(result->message, ARRAYSIZE(result->message), L"AV database was not loaded from server");
        return load_result;
    }
    return ScanSingleFile(path, result);
}

extern "C" unsigned long BmtxScanDirectory(handle_t, wchar_t* path, BMTX_SCAN_RESULT* result) {
    if (path == nullptr || result == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    DWORD load_result = EnsureAntivirusDatabaseLoaded();
    if (load_result == ERROR_SUCCESS) {
        // Refresh before a scan so newly uploaded Postman signatures are used without restarting the service.
        load_result = LoadAntivirusDatabaseFromServer();
    }
    if (load_result != ERROR_SUCCESS) {
        ZeroMemory(result, sizeof(*result));
        StringCchCopyW(result->message, ARRAYSIZE(result->message), L"AV database was not loaded from server");
        return load_result;
    }
    ZeroMemory(result, sizeof(*result));
    ScanDirectoryRecursive(path, result, kMaxFilesPerDirectoryScan);
    if (result->infectedObjects > 0) {
        if (result->scannedObjects >= kMaxFilesPerDirectoryScan) {
            StringCchCopyW(result->message, ARRAYSIZE(result->message), L"Threats found in directory. Scan limit reached: 1000 files");
        } else {
            StringCchCopyW(result->message, ARRAYSIZE(result->message), L"Threats found in directory");
        }
    } else {
        if (result->scannedObjects >= kMaxFilesPerDirectoryScan) {
            StringCchCopyW(result->message, ARRAYSIZE(result->message), L"No threats found in first 1000 files");
        } else {
            StringCchCopyW(result->message, ARRAYSIZE(result->message), L"No threats found in directory");
        }
    }
    return ERROR_SUCCESS;
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
