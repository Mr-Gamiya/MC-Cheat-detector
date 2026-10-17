// Optional user-configured startup-time JVMTI observer. No bytecode
// transformation, redefinition, runtime attach, or game behavior changes.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <jni.h>
#include <jvmti.h>
#include <rpc.h>
#include <filesystem>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Rpcrt4.lib")

namespace {
constexpr uint32_t kProtocol = 1;
constexpr uint32_t kMaxRequest = 4096;
constexpr uint32_t kMaxResponse = 16 * 1024 * 1024;
constexpr size_t kMaxClasses = 150000;
JavaVM* g_vm = nullptr;
jvmtiEnv* g_jvmti = nullptr;
DWORD g_pid = 0;
uint64_t g_creation = 0;
std::string g_session;
std::wstring g_pipe;
std::filesystem::path g_marker;
volatile LONG g_stopping = 0;

std::string utf8(const wchar_t* s) {
    if (!s || !*s) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n, nullptr, nullptr); out.resize(static_cast<size_t>(n - 1));
    return out;
}
std::wstring widen(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(static_cast<size_t>(std::max(0, n)), L'\0');
    if (n > 1) { MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), n); out.resize(static_cast<size_t>(n - 1)); }
    return out;
}
std::string escape_json(const std::string& in) {
    std::string out; out.reserve(in.size() + 8);
    for (unsigned char c : in) {
        switch (c) {
        case '"': out += "\\\""; break; case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break; case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break; case '\r': out += "\\r"; break; case '\t': out += "\\t"; break;
        default: if (c < 0x20) { char b[7]; sprintf_s(b, "\\u%04x", c); out += b; } else out += static_cast<char>(c);
        }
    }
    return out;
}
std::string class_name(const char* signature) {
    if (!signature) return {};
    std::string s(signature); size_t arrays = 0;
    while (arrays < s.size() && s[arrays] == '[') ++arrays;
    std::string body = s.substr(arrays);
    if (body.size() >= 2 && body.front() == 'L' && body.back() == ';') body = body.substr(1, body.size() - 2);
    std::replace(body.begin(), body.end(), '/', '.');
    while (arrays--) body += "[]";
    return body;
}
bool process_creation(uint64_t& value) {
    FILETIME c{}, e{}, k{}, u{};
    if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) return false;
    value = (static_cast<uint64_t>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    return true;
}
std::string new_session() {
    UUID id{}; RPC_STATUS status = UuidCreate(&id); if (status != RPC_S_OK && status != RPC_S_UUID_LOCAL_ONLY) return {};
    RPC_CSTR text = nullptr; if (UuidToStringA(&id, &text) != RPC_S_OK) return {};
    std::string out(reinterpret_cast<char*>(text)); RpcStringFreeA(&text); return out;
}
bool write_marker() {
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    if (!n) return false; std::vector<wchar_t> buf(n); if (!GetEnvironmentVariableW(L"LOCALAPPDATA", buf.data(), n)) return false;
    std::filesystem::path dir = std::filesystem::path(buf.data()) / L"MinecraftCheatScanner" / L"Agent";
    std::error_code ec; std::filesystem::create_directories(dir, ec); if (ec) return false;
    g_marker = dir / (L"agent-" + std::to_wstring(g_pid) + L".json");
    std::string body = "{\"protocolVersion\":" + std::to_string(kProtocol) + ",\"processId\":" + std::to_string(g_pid) + ",\"processCreationFiletime\":" + std::to_string(g_creation) + ",\"sessionId\":\"" + escape_json(g_session) + "\",\"pipeName\":\"" + escape_json(utf8(g_pipe.c_str())) + "\"}";
    HANDLE f = CreateFileW(g_marker.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0; bool ok = WriteFile(f, body.data(), static_cast<DWORD>(body.size()), &wrote, nullptr) && wrote == body.size(); CloseHandle(f); return ok;
}
bool make_pipe_security(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& sd) {
    HANDLE token = nullptr; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD need = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &need);
    std::vector<uint64_t> storage((need + 7) / 8); bool ok = need && GetTokenInformation(token, TokenUser, storage.data(), need, &need);
    CloseHandle(token); if (!ok) return false;
    auto* user = reinterpret_cast<TOKEN_USER*>(storage.data()); LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid)) return false;
    std::wstring sddl = L"D:P(A;;GA;;;" + std::wstring(sid) + L")(A;;GA;;;SY)"; LocalFree(sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return false;
    sa = { sizeof(sa), sd, FALSE }; return true;
}
bool read_exact(HANDLE pipe, void* buffer, DWORD length) {
    auto* p = static_cast<unsigned char*>(buffer); DWORD total = 0;
    while (total < length) { DWORD n = 0; if (!ReadFile(pipe, p + total, length - total, &n, nullptr) || n == 0) return false; total += n; }
    return true;
}
bool write_exact(HANDLE pipe, const void* buffer, DWORD length) {
    const auto* p = static_cast<const unsigned char*>(buffer); DWORD total = 0;
    while (total < length) { DWORD n = 0; if (!WriteFile(pipe, p + total, length - total, &n, nullptr) || n == 0) return false; total += n; }
    return true;
}
uint32_t loader_id(JNIEnv* env, jobject loader, std::vector<jobject>& known) {
    if (!loader) return 0;
    for (uint32_t i = 0; i < known.size(); ++i) if (env->IsSameObject(loader, known[i])) return i + 1;
    known.push_back(env->NewLocalRef(loader)); return static_cast<uint32_t>(known.size());
}
std::string snapshot(JNIEnv* env, const std::string& session) {
    jclass* classes = nullptr; jint count = 0; std::string error;
    jvmtiError err = g_jvmti->GetLoadedClasses(&count, &classes);
    std::ostringstream out;
    out << "{\"protocol_version\":" << kProtocol << ",\"process_id\":" << g_pid << ",\"process_creation_filetime\":" << g_creation
        << ",\"session_id\":\"" << escape_json(session) << "\",\"classes\":[";
    std::vector<jobject> loaders; size_t emitted = 0; jint processed = 0;
    if (err != JVMTI_ERROR_NONE) error = "GetLoadedClasses failed with JVMTI error " + std::to_string(err);
    else if (count < 0 || static_cast<size_t>(count) > kMaxClasses) error = "loaded class count exceeds configured limit";
    else {
        for (jint i = 0; i < count; ++i) {
            char* sig = nullptr; char* generic = nullptr;
            jvmtiError se = g_jvmti->GetClassSignature(classes[i], &sig, &generic);
            if (se == JVMTI_ERROR_NONE && sig) {
                jobject cl = nullptr; uint32_t lid = 0;
                if (g_jvmti->GetClassLoader(classes[i], &cl) == JVMTI_ERROR_NONE) lid = loader_id(env, cl, loaders);
                std::string name = class_name(sig);
                if (emitted++) out << ',';
                out << "{\"name\":\"" << escape_json(name) << "\",\"loader_id\":" << lid << ",\"loader_kind\":\"" << (lid ? "non-bootstrap" : "bootstrap") << "\"}";
                if (cl) env->DeleteLocalRef(cl);
            }
            if (classes[i]) env->DeleteLocalRef(classes[i]);
            processed = i + 1;
            if (sig) g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
            if (generic) g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(generic));
            if (emitted > kMaxClasses) { error = "class snapshot exceeded output limit"; break; }
        }
        for (jobject loader : loaders) if (loader) env->DeleteLocalRef(loader);
    }
    if (classes) { for (jint i = processed; i < count; ++i) if (classes[i]) env->DeleteLocalRef(classes[i]); g_jvmti->Deallocate(reinterpret_cast<unsigned char*>(classes)); }
    out << "],\"error\":" << (error.empty() ? "null" : "\"" + escape_json(error) + "\"") << '}';
    std::string result = out.str(); if (result.size() > kMaxResponse) return "{}"; return result;
}
DWORD WINAPI pipe_worker(void*) {
    while (InterlockedCompareExchange(&g_stopping, 0, 0) == 0) {
        SECURITY_ATTRIBUTES sa{}; PSECURITY_DESCRIPTOR sd = nullptr;
        if (!make_pipe_security(sa, sd)) { Sleep(1000); continue; }
        HANDLE pipe = CreateNamedPipeW(g_pipe.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 65536, 65536, 1000, &sa); LocalFree(sd);
        if (pipe == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }
        BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : GetLastError() == ERROR_PIPE_CONNECTED;
        if (connected) {
            uint32_t len = 0; std::vector<char> request(kMaxRequest + 1);
            if (read_exact(pipe, &len, sizeof(len)) && len > 0 && len <= kMaxRequest && read_exact(pipe, request.data(), len)) {
                std::istringstream in(std::string(request.data(), len)); std::string verb, session; DWORD pid = 0; uint64_t creation = 0;
                in >> verb >> pid >> creation >> session;
                if (verb == "SCAN" && pid == g_pid && creation == g_creation && session == g_session) {
                    JNIEnv* env = nullptr; bool attached = false;
                    jint ge = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
                    if (ge == JNI_EDETACHED && g_vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) == JNI_OK) attached = true;
                    std::string body = env ? snapshot(env, session) : "{\"protocol_version\":1,\"process_id\":" + std::to_string(g_pid) + ",\"process_creation_filetime\":" + std::to_string(g_creation) + ",\"session_id\":\"" + escape_json(session) + "\",\"classes\":[],\"error\":\"could not attach diagnostic worker thread to JVM\"}";
                    if (attached) g_vm->DetachCurrentThread();
                    uint32_t size = static_cast<uint32_t>(body.size()); DWORD wrote = 0;
                    if (size && size <= kMaxResponse) { write_exact(pipe, &size, sizeof(size)); write_exact(pipe, body.data(), size); }
                }
            }
            FlushFileBuffers(pipe); DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    }
    return 0;
}
} // namespace

extern "C" __declspec(dllexport) jint JNICALL Agent_OnLoad(JavaVM* vm, char* options, void*) {
    g_vm = vm; g_pid = GetCurrentProcessId();
    if (vm->GetEnv(reinterpret_cast<void**>(&g_jvmti), JVMTI_VERSION_1_2) != JNI_OK || !g_jvmti) return JNI_ERR;
    if (!process_creation(g_creation)) return JNI_ERR;
    g_session = options && *options ? options : new_session();
    if (g_session.empty() || g_session.size() > 128 || !std::all_of(g_session.begin(), g_session.end(), [](unsigned char c){return std::isxdigit(c) || c == '-';})) return JNI_ERR;
    g_pipe = LR"(\\.\pipe\MinecraftCheatScanner-v8-)" + widen(g_session);
    if (!write_marker()) return JNI_ERR;
    HANDLE thread = CreateThread(nullptr, 0, pipe_worker, nullptr, 0, nullptr);
    if (!thread) { DeleteFileW(g_marker.c_str()); return JNI_ERR; }
    CloseHandle(thread);
    return JNI_OK;
}
extern "C" __declspec(dllexport) void JNICALL Agent_OnUnload(JavaVM*) {
    InterlockedExchange(&g_stopping, 1);
    if (!g_marker.empty()) DeleteFileW(g_marker.c_str());
}

