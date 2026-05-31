// UCM_B2B_ANTIVIRUS_RC4_ARCHIVE_INSPECTOR_FIX1
// KeelCore Labs
// Reference: https://keelcore.org/
// Product class: lightweight B2B online-monitor / signatureless web-file gateway
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <mutex>
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <shellapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
using socket_t = SOCKET;
static const socket_t INVALID_SOCKET_T = INVALID_SOCKET;
static void close_socket(socket_t s) { closesocket(s); }
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static const socket_t INVALID_SOCKET_T = -1;
static void close_socket(socket_t s) { close(s); }
#endif

namespace fs = std::filesystem;

static constexpr const char* PRODUCT_VENDOR = "KeelCore Labs";
static constexpr const char* PRODUCT_REFERENCE_URL = "https://keelcore.org/";

static constexpr const char* UCM_EMBEDDED_JSON_PROTOCOL = R"json(
{
  "protocol_id": "LOVE_AR_UCM_PROTOCOL",
  "version": "4.0-RC4",
  "role": "EXTERNAL_API_MODEM_IMMUNE_GATEWAY",
  "port_name": "UDB8",
  "default_bind_host": "127.0.0.1",
  "default_port": 8888,

  "core_policy": {
    "direct_core_internet_access": false,
    "direct_core_api_access": false,
    "direct_core_download": false,
    "external_objects_enter": "QUARANTINE_FIRST",
    "safe_release_target": "LOVE_AR_SAFE_STORAGE"
  },

  "local_safe_browser_gate": {
    "enabled": true,
    "bind_host": "127.0.0.1",
    "port": 8888,
    "browser_role": "LOCAL_SAFE_VIEW_ONLY",
    "routes": {
      "/": "ucm_control_panel",
      "/open": "submit_external_url_to_ucm",
      "/download": "download_external_resource_to_quarantine",
      "/safe/view/{token}": "serve_safe_preview",
      "/safe/file/{token}": "serve_clean_file",
      "/quarantine/{token}": "serve_quarantine_status_only",
      "/status": "serve_ucm_status",
      "/proxy.pac": "serve_browser_proxy_config"
    },
    "safe_link_policy": {
      "tokenized_links": true,
      "time_limited_links": true,
      "hide_original_url_from_browser": true,
      "hide_api_keys_from_browser": true,
      "serve_only_local_artifacts": true
    }
  },

  "api_key_gate": {
    "secret_storage": "ENV/keys.env",
    "env_file_name": "keys.env",
    "embed_keys_in_json": false,
    "core_raw_key_access": false,
    "keys_return_to_love": false,
    "keys_write_to_trace": false,
    "scoped_keys_required": true,
    "rotation_supported": true,
    "profile_selector": "profile_id"
  },

  "love_connector_contract": {
    "body": "LOVE",
    "module_class": "EXTERNAL_COMMUNICATION_GATEWAY",
    "organ": "EYES",
    "position": "EXTERNAL",
    "route": "LOVE -> UNIVERSAL_CONNECTOR_CAP -> NAT_NATIVE_ACCESS_PORT -> UCM -> ENV/keys.env -> HTTPS/API -> RESULT -> RETURN_TO_LOVE",
    "rules": [
      "Request != Trust",
      "Response != Memory",
      "Keys != LOVE",
      "Raw external object enters quarantine first",
      "Module returns state and safe artifact only"
    ]
  },

  "api_profiles": {
    "profile_file": "ENV/keys.env",
    "supported_classes": [
      "LLM_RESEARCH_BRIDGE",
      "WEB_SOURCE_SCOUT",
      "MARKET_DATA",
      "REPOSITORY_METADATA",
      "EXTERNAL_VALIDATOR"
    ],
    "default_allowed_methods": ["GET", "POST"],
    "default_timeout_sec": 120,
    "max_response_bytes": 1048576
  },

  "three_stage_analyzer": {
    "enabled": true,
    "signatureless": true,

    "stage_1_ddos_check": {
      "purpose": "detect load attack before expensive scanning",
      "checks": [
        "connection_rate",
        "request_rate",
        "download_rate",
        "payload_size",
        "json_size",
        "queue_pressure",
        "quarantine_pressure",
        "scan_budget",
        "source_reputation",
        "repeated_violation_history"
      ],
      "actions": [
        "ALLOW_TO_STAGE_2",
        "THROTTLE",
        "HOLD",
        "DROP",
        "DETACH_SOURCE",
        "SAFE_MODE"
      ]
    },

    "stage_2_malware_spyware_core_write_check": {
      "purpose": "detect hostile capability and hidden core-write attempts",
      "checks": [
        "extension_policy",
        "mime_policy",
        "magic_bytes",
        "extension_magic_mismatch",
        "macro_presence",
        "embedded_script",
        "remote_execution_pattern",
        "spyware_pattern",
        "malware_pattern",
        "archive_nesting",
        "metadata_instruction",
        "direct_memory_overwrite",
        "core_patch_attempt",
        "config_overwrite_attempt",
        "protocol_mutation_attempt"
      ],
      "blocked_patterns": [
        "DIRECT_CORE_WRITE",
        "DIRECT_MEMORY_OVERWRITE",
        "REMOTE_EXEC",
        "BODY_CONTROL",
        "CORE_RELOAD",
        "UNAUTHORIZED_CONFIG_UPDATE",
        "HIDDEN_AUTOSTART",
        "PERSISTENCE_INSTALL"
      ]
    },

    "stage_25_url_lexical_analyzer": {"enabled": true, "mode": "VISIBLE_SEMANTIC_HIDDEN_PRE_FETCH"},
    "stage_26_redirect_chain_analyzer": {"enabled": true, "mode": "COVERT_RISK_AFTER_FETCH"},
    "stage_3_archive_shallow_inspector": {"enabled": true, "mode": "ZIP_CENTRAL_DIRECTORY_NO_EXTRACTION"},

    "stage_3_immune_sandbox_check": {
      "upgrade": "STATIC_V2_MAGIC_BYTES_AND_MISMATCH_DETECTION",
      "purpose": "behavioral immune validation before release",
      "sandbox_rules": {
        "network_disabled": true,
        "macro_execution_disabled": true,
        "script_execution_disabled": true,
        "core_access_disabled": true,
        "memory_write_disabled": true,
        "config_write_disabled": true,
        "process_spawn_disabled": true,
        "read_only_open_test": true
      },
      "verdicts": [
        "ADMIT",
        "HOLD",
        "QUARANTINE",
        "REJECT",
        "HUMAN_ARBITRATION"
      ]
    }
  },

  "web_surf_protection": {
    "enabled": true,
    "direct_browser_access_to_core": false,
    "default_mode": "TEXT_ONLY",
    "html_is_active_external_object": true
  },

  "archive_direct_file_resolver": {
    "enabled": true,
    "purpose": "resolve archive wrapper pages into safe direct file downloads",
    "page_fetch_mode": {
      "javascript": false,
      "iframes": false,
      "popups": false,
      "auto_download": false,
      "cookies": "minimal",
      "tracking": "blocked",
      "render_mode": "inert_html_parse"
    },
    "forbidden_bypass": [
      "authorization_bypass",
      "paid_access_bypass",
      "captcha_access_control_bypass",
      "account_permission_bypass",
      "terms_violation_bypass"
    ]
  },

  "safe_link_firewall": {
    "enabled": true,
    "external_links_open_directly": false,
    "browser_receives_internal_links_only": true,
    "phishing_resolver": {
      "enabled": true,
      "signatureless": true
    },
    "safe_link_proxy": {
      "enabled": true,
      "link_scheme": "local_http",
      "tokenized_links": true,
      "time_limited_links": true,
      "serve_only_clean_resource": true
    }
  },

  "ddos_shield": {
    "enabled": true,
    "core_direct_access": false,
    "default_overload_action": "DROP_BEFORE_CORE",
    "limits": {
      "max_connections_total": 128,
      "max_connections_per_source": 8,
      "max_requests_per_second_total": 40,
      "max_requests_per_second_per_source": 5,
      "max_download_requests_per_minute": 10,
      "max_quarantine_files": 64,
      "max_quarantine_mb": 512,
      "max_json_bytes": 65536,
      "max_file_size_mb": 200
    }
  },

  "final_verdicts": {
    "ADMIT": "release_to_LOVE_AR_SAFE_STORAGE",
    "HOLD": "keep_in_quarantine_pending_more_checks",
    "QUARANTINE": "isolate_without_release",
    "REJECT": "delete_or_block_without_core_access",
    "DETACH_SOURCE": "block_repeated_hostile_source",
    "HUMAN_ARBITRATION": "request_human_decision"
  }
}
)json";


static constexpr const char* UCM_DEFAULT_RESOURCE_ALLOWLIST = R"txt(# LOVE_AR_UCM RESOURCE_ALLOWLIST
# One host per line. Comments start with #.
# Subdomains are allowed by suffix match.
zenodo.org
arxiv.org
export.arxiv.org
projecteuclid.org
oeis.org
ncatlab.org
mathoverflow.net
zbmath.org
numdam.org
emis.de
ams.org
msp.org
)txt";

static constexpr const char* UCM_KEYS_ENV_TEMPLATE = R"env(
# keys.env
# Created by LOVE_AR_UCM on first run.
# Standard API connection profile file.
# DO NOT commit this file.
# DO NOT put secrets inside JSON protocol.
# LOVE core sees profile_id only. UCM reads this file.

PROFILE_ID=default
PROFILE_CLASS=LLM_RESEARCH_BRIDGE
PROVIDER=
HOST=
ENDPOINT=
METHOD=POST
API_KEY=
API_SECRET=
AUTH_HEADER=Authorization
AUTH_PREFIX=Bearer
TIMEOUT_SEC=120
MAX_RESPONSE_BYTES=1048576
ALLOW_METHODS=GET,POST
ALLOW_HOSTS=
TRACE_SECRETS=false

# Optional additional profiles may be added below by operator:
# [profile:gemini]
# PROFILE_ID=gemini
# PROFILE_CLASS=LLM_RESEARCH_BRIDGE
# PROVIDER=GEMINI
# HOST=
# ENDPOINT=
# METHOD=POST
# API_KEY=

# [profile:binance_market]
# PROFILE_ID=binance_market
# PROFILE_CLASS=MARKET_DATA
# PROVIDER=BINANCE
# HOST=api.binance.com
# ENDPOINT=/api/v3/ticker/price
# METHOD=GET
# API_KEY=
# API_SECRET=

# Optional future TLS inspection local CA paths:
UCM_LOCAL_CA_CERT=
UCM_LOCAL_CA_KEY=
)env";

enum class GateVerdict {
    ADMIT,
    HOLD,
    QUARANTINE,
    REJECT,
    DETACH_SOURCE,
    HUMAN_ARBITRATION
};

static std::string verdictToString(GateVerdict v) {
    switch (v) {
    case GateVerdict::ADMIT: return "ADMIT";
    case GateVerdict::HOLD: return "HOLD";
    case GateVerdict::QUARANTINE: return "QUARANTINE";
    case GateVerdict::REJECT: return "REJECT";
    case GateVerdict::DETACH_SOURCE: return "DETACH_SOURCE";
    case GateVerdict::HUMAN_ARBITRATION: return "HUMAN_ARBITRATION";
    }
    return "UNKNOWN";
}

struct RuntimePaths {
    fs::path root = "LOVE_AR_UCM_RUNTIME";
    fs::path config = root / "config";
    fs::path env = root / "ENV";
    fs::path quarantine = root / "quarantine";
    fs::path sandbox = root / "sandbox";
    fs::path safe = root / "safe";
    fs::path logs = root / "logs";
    fs::path protocolJson = config / "LOVE_AR_UCM_PROTOCOL.json";
    fs::path resourceAllowlist = config / "RESOURCE_ALLOWLIST.txt";
    fs::path keysEnv = env / "keys.env";
    fs::path tokenIndex = safe / "token_index.json";
    fs::path loveTokenPathHint = config / "LOVE_TOKEN_PATH.txt";
    fs::path immuneLog = logs / "immune_memory.log";
};

static std::string nowIso() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

static std::string htmlEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += c;
        }
    }
    return out;
}

static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 32) {
                std::ostringstream h;
                h << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                out += h.str();
            }
            else {
                out.push_back((char)c);
            }
        }
    }
    return out;
}

static std::string getEnvVarSafe(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) == 0 && value != nullptr) {
        std::string out(value);
        free(value);
        return out;
    }
    if (value) free(value);
    return "";
#else
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
#endif
}

static std::string readTextFileTrim(const fs::path& p, size_t maxBytes = 8192) {
    if (!fs::exists(p) || !fs::is_regular_file(p)) return "";
    std::ifstream in(p, std::ios::binary);
    std::string s;
    s.resize((size_t)std::min<uintmax_t>(fs::file_size(p), (uintmax_t)maxBytes));
    if (!s.empty()) in.read(&s[0], (std::streamsize)s.size());
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
    size_t a = 0;
    while (a < s.size() && (s[a] == '\n' || s[a] == '\r' || s[a] == ' ' || s[a] == '\t')) ++a;
    return s.substr(a);
}

static fs::path discoverLoveTokenPath(const RuntimePaths& p) {
    if (fs::exists(p.loveTokenPathHint)) {
        std::string hinted = readTextFileTrim(p.loveTokenPathHint);
        if (!hinted.empty() && fs::exists(fs::path(hinted))) return fs::path(hinted);
    }

    std::string loveHome = getEnvVarSafe("LOVE_HOME");
    if (!loveHome.empty()) {
        fs::path cand = fs::path(loveHome) / "09_STATUS" / "TOKEN.txt";
        if (fs::exists(cand)) return cand;
    }

    std::vector<fs::path> candidates = {
        fs::path("LOVE_HOME") / "09_STATUS" / "TOKEN.txt",
        fs::path("..") / "LOVE_HOME" / "09_STATUS" / "TOKEN.txt",
        fs::path("09_STATUS") / "TOKEN.txt",
        p.root.parent_path() / "LOVE_HOME" / "09_STATUS" / "TOKEN.txt"
    };
    for (const auto& c : candidates) {
        std::error_code ec;
        if (fs::exists(c, ec)) return c;
    }
    return fs::path();
}

static uintmax_t directoryBytes(const fs::path& dir) {
    uintmax_t total = 0;
    std::error_code ec;
    if (!fs::exists(dir, ec)) return 0;
    for (auto& e : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (e.is_regular_file(ec)) total += e.file_size(ec);
    }
    return total;
}

static void cleanupOldAndRotate(const fs::path& dir, int maxAgeDays, uintmax_t maxBytes) {
    std::error_code ec;
    if (!fs::exists(dir, ec)) return;

    const auto now = fs::file_time_type::clock::now();
    const auto maxAge = std::chrono::hours(24 * maxAgeDays);

    for (auto& e : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!e.is_regular_file(ec)) continue;
        auto age = now - e.last_write_time(ec);
        if (!ec && age > maxAge) fs::remove(e.path(), ec);
    }

    struct FileRec { fs::path p; fs::file_time_type t; uintmax_t size; };
    std::vector<FileRec> files;
    uintmax_t total = 0;
    for (auto& e : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!e.is_regular_file(ec)) continue;
        auto sz = e.file_size(ec);
        auto t = e.last_write_time(ec);
        if (!ec) {
            files.push_back({ e.path(), t, sz });
            total += sz;
        }
    }

    std::sort(files.begin(), files.end(), [](const FileRec& a, const FileRec& b) { return a.t < b.t; });
    for (const auto& f : files) {
        if (total <= maxBytes) break;
        fs::remove(f.p, ec);
        if (!ec && total >= f.size) total -= f.size;
    }
}

static std::string urlDecode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            std::string hex = in.substr(i + 1, 2);
            char* end = nullptr;
            long v = std::strtol(hex.c_str(), &end, 16);
            if (end && *end == '\0') {
                out.push_back(static_cast<char>(v));
                i += 2;
            }
            else {
                out.push_back(in[i]);
            }
        }
        else if (in[i] == '+') {
            out.push_back(' ');
        }
        else {
            out.push_back(in[i]);
        }
    }
    return out;
}

static std::string urlEncode(const std::string& in) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (unsigned char c : in) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        }
        else {
            escaped << '%' << std::setw(2) << int(c);
        }
    }
    return escaped.str();
}

static std::string lowerCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}

static bool startsWith(const std::string& s, const std::string& p) {
    return s.rfind(p, 0) == 0;
}


static void ensureRuntime(const RuntimePaths& p) {
    fs::create_directories(p.config);
    fs::create_directories(p.env);
    fs::create_directories(p.quarantine);
    fs::create_directories(p.sandbox);
    fs::create_directories(p.safe);
    fs::create_directories(p.logs);

    if (!fs::exists(p.protocolJson)) {
        std::ofstream out(p.protocolJson, std::ios::binary);
        out << UCM_EMBEDDED_JSON_PROTOCOL;
    }

    if (!fs::exists(p.keysEnv)) {
        std::ofstream out(p.keysEnv, std::ios::binary);
        out << UCM_KEYS_ENV_TEMPLATE;
    }

    if (!fs::exists(p.resourceAllowlist)) {
        std::ofstream out(p.resourceAllowlist, std::ios::binary);
        out << UCM_DEFAULT_RESOURCE_ALLOWLIST;
    }

    if (!fs::exists(p.loveTokenPathHint)) {
        std::ofstream out(p.loveTokenPathHint, std::ios::binary);
        out << "# Optional. Put full path to LOVE_HOME/09_STATUS/TOKEN.txt here if auto-discovery fails.\n";
    }
}

static void appendLog(const RuntimePaths& p, const std::string& line) {
    std::ofstream out(p.immuneLog, std::ios::app);
    out << nowIso() << " " << line << "\n";
}

struct ParsedUrl {
    std::string scheme;
    std::string host;
    std::string port;
    std::string path;
    bool ok = false;
};

static ParsedUrl parseUrl(const std::string& url) {
    ParsedUrl u;
    auto pos = url.find("://");
    if (pos == std::string::npos) return u;
    u.scheme = lowerCopy(url.substr(0, pos));
    std::string rest = url.substr(pos + 3);
    auto slash = rest.find('/');
    std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    u.path = (slash == std::string::npos) ? "/" : rest.substr(slash);
    auto colon = hostport.find(':');
    if (colon == std::string::npos) {
        u.host = hostport;
        u.port = (u.scheme == "https") ? "443" : "80";
    }
    else {
        u.host = hostport.substr(0, colon);
        u.port = hostport.substr(colon + 1);
    }
    u.ok = !u.scheme.empty() && !u.host.empty();
    return u;
}

static std::string trimCopy(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace((unsigned char)s[a])) ++a;
    size_t b = s.size();
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

static int parseHttpStatusCode(const std::string& headers) {
    std::istringstream in(headers);
    std::string first;
    if (!std::getline(in, first)) return 0;
    if (!first.empty() && first.back() == '\r') first.pop_back();
    std::istringstream fs(first);
    std::string http;
    int code = 0;
    fs >> http >> code;
    return code;
}

static std::string headerValue(const std::string& headers, const std::string& name) {
    std::string lname = lowerCopy(name);
    std::istringstream in(headers);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string k = lowerCopy(trimCopy(line.substr(0, colon)));
        if (k == lname) return trimCopy(line.substr(colon + 1));
    }
    return "";
}

static std::string urlPathExtension(const std::string& urlOrPath) {
    std::string path = urlOrPath;
    ParsedUrl u = parseUrl(urlOrPath);
    if (u.ok) path = u.path;
    auto q = path.find('?');
    if (q != std::string::npos) path = path.substr(0, q);
    auto h = path.find('#');
    if (h != std::string::npos) path = path.substr(0, h);
    fs::path p(path);
    return lowerCopy(p.extension().string());
}

static std::string makeAbsoluteUrl(const std::string& baseUrl, const std::string& location) {
    if (location.empty()) return baseUrl;
    std::string l = trimCopy(location);
    std::string ll = lowerCopy(l);
    if (startsWith(ll, "http://") || startsWith(ll, "https://")) return l;

    ParsedUrl b = parseUrl(baseUrl);
    if (!b.ok) return l;

    std::string root = b.scheme + "://" + b.host;
    if (!((b.scheme == "http" && b.port == "80") || (b.scheme == "https" && b.port == "443"))) {
        root += ":" + b.port;
    }

    if (!l.empty() && l[0] == '/') return root + l;

    std::string dir = b.path;
    auto slash = dir.rfind('/');
    if (slash == std::string::npos) dir = "/";
    else dir = dir.substr(0, slash + 1);
    return root + dir + l;
}

static bool extensionIsDocumentIntent(const std::string& ext) {
    static const std::vector<std::string> doc = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".csv", ".json"
    };
    return std::find(doc.begin(), doc.end(), lowerCopy(ext)) != doc.end();
}

static bool extensionIsExecutableOrArchiveRisk(const std::string& ext) {
    static const std::vector<std::string> bad = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".msi", ".com", ".pif",
        ".zip", ".rar", ".7z", ".gz"
    };
    return std::find(bad.begin(), bad.end(), lowerCopy(ext)) != bad.end();
}


static std::vector<std::string> readResourceAllowlist(const RuntimePaths& p) {
    std::vector<std::string> out;
    std::ifstream in(p.resourceAllowlist, std::ios::binary);
    std::string line;
    while (std::getline(in, line)) {
        line = trimCopy(line);
        if (line.empty() || line[0] == '#') continue;
        ParsedUrl u = parseUrl(line);
        std::string host = u.ok ? u.host : line;
        host = lowerCopy(trimCopy(host));
        if (!host.empty()) out.push_back(host);
    }
    return out;
}

static std::string resourceAllowlistText(const RuntimePaths& p) {
    std::ifstream in(p.resourceAllowlist, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static bool hostMatchesRule(const std::string& hostRaw, const std::string& ruleRaw) {
    std::string host = lowerCopy(hostRaw);
    std::string rule = lowerCopy(ruleRaw);
    if (host == rule) return true;
    if (host.size() > rule.size() && host.compare(host.size() - rule.size(), rule.size(), rule) == 0) {
        size_t dotpos = host.size() - rule.size();
        return dotpos > 0 && host[dotpos - 1] == '.';
    }
    return false;
}

static bool resourceAllowedByList(const RuntimePaths& p, const std::string& url, std::string& reason) {
    ParsedUrl u = parseUrl(url);
    if (!u.ok) {
        reason = "BAD_URL";
        return false;
    }
    auto list = readResourceAllowlist(p);
    if (list.empty()) {
        reason = "EMPTY_RESOURCE_ALLOWLIST";
        return false;
    }
    for (const auto& rule : list) {
        if (hostMatchesRule(u.host, rule)) {
            reason = "RESOURCE_ALLOWED:" + rule;
            return true;
        }
    }
    reason = "HOST_NOT_IN_RESOURCE_ALLOWLIST:" + u.host;
    return false;
}

#ifdef _WIN32
static std::wstring widenUtf8(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) {
        std::wstring w;
        for (unsigned char c : s) w.push_back((wchar_t)c);
        return w;
    }
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
static std::string narrowWide(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) {
        std::string s;
        for (wchar_t c : w) s.push_back((char)(c & 0xFF));
        return s;
    }
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
#endif


struct HttpRequest {
    std::string method;
    std::string target;
    std::string path;
    std::string query;
    std::string version;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string raw;
    std::string clientIp;
};

static std::map<std::string, std::string> parseQuery(const std::string& q) {
    std::map<std::string, std::string> m;
    std::string s = q;
    size_t start = 0;
    while (start <= s.size()) {
        size_t amp = s.find('&', start);
        std::string part = (amp == std::string::npos) ? s.substr(start) : s.substr(start, amp - start);
        if (!part.empty()) {
            size_t eq = part.find('=');
            if (eq == std::string::npos) {
                m[urlDecode(part)] = "";
            }
            else {
                m[urlDecode(part.substr(0, eq))] = urlDecode(part.substr(eq + 1));
            }
        }
        if (amp == std::string::npos) break;
        start = amp + 1;
    }
    return m;
}

struct StageResult {
    bool pass = true;
    GateVerdict verdict = GateVerdict::ADMIT;
    std::string reason = "OK";
};


enum UcmRunMode {
    UCM_MODE_MONITOR = 0,       // default: normal protection + normal alerts
    UCM_MODE_STRICT = 1,        // reserved hardening mode; current RC keeps same blocking path
    UCM_MODE_QUIET = 2,         // protection active; suppress balloons
    UCM_MODE_PAUSE_ALERTS = 3   // protection active; tray alerts paused, logs still written
};

static std::atomic<int> g_ucm_mode{ UCM_MODE_MONITOR };

static const char* ucmModeNameA(int mode) {
    switch (mode) {
    case UCM_MODE_MONITOR: return "MONITOR";
    case UCM_MODE_STRICT: return "STRICT";
    case UCM_MODE_QUIET: return "QUIET";
    case UCM_MODE_PAUSE_ALERTS: return "PAUSE_ALERTS";
    default: return "UNKNOWN";
    }
}

#ifdef _WIN32
static const wchar_t* ucmModeNameW(int mode) {
    switch (mode) {
    case UCM_MODE_MONITOR: return L"Monitor";
    case UCM_MODE_STRICT: return L"Strict";
    case UCM_MODE_QUIET: return L"Quiet";
    case UCM_MODE_PAUSE_ALERTS: return L"Pause alerts";
    default: return L"Unknown";
    }
}
#endif


#ifdef _WIN32
enum TrayState {
    TRAY_GREEN,
    TRAY_YELLOW,
    TRAY_RED
};

struct TrayEvent {
    GateVerdict verdict;
    std::string reason;
    std::string host;
};

static HWND g_hwnd = nullptr;
static UINT WM_UCM_TRAYICON = WM_APP + 77;
static UINT WM_UCM_TRAYEVENT = WM_APP + 78;
static NOTIFYICONDATAW g_nid{};
static std::queue<TrayEvent> g_tray_events;
static std::mutex g_tray_mtx;
static TrayState g_tray_state = TRAY_GREEN;

static void notifyTray(GateVerdict verdict, const std::string& reason, const std::string& host) {
    if (!g_hwnd) return;
    {
        std::lock_guard<std::mutex> lock(g_tray_mtx);
        g_tray_events.push({ verdict, reason, host });
    }
    PostMessageW(g_hwnd, WM_UCM_TRAYEVENT, 0, 0);
}
#else
static void notifyTray(GateVerdict, const std::string&, const std::string&) {}
#endif


// ================================================================
// UCM B2B ANTIVIRUS RC4 — STAGE 2.5 URL LEXICAL ANALYZER
// Computes visible/semantic/effective URL risk before fetch.
// No network access. STL-only.
// ================================================================
struct UrlLexResult {
    double visible_risk = 0.0;    // 0.0 .. 1.0
    double semantic_risk = 0.0;   // 0.0 .. 1.0
    double effective_risk = 0.0;  // weighted sum
    std::string reason = "URL_LEX_OK";
    GateVerdict verdict = GateVerdict::ADMIT;
};

static double clamp01(double x) {
    if (x < 0.0) return 0.0;
    if (x > 1.0) return 1.0;
    return x;
}

static bool isHexChar(char c) {
    return std::isxdigit((unsigned char)c) != 0;
}

static int countEncodedChars(const std::string& s) {
    int n = 0;
    for (size_t i = 0; i + 2 < s.size(); ++i) {
        if (s[i] == '%' && isHexChar(s[i + 1]) && isHexChar(s[i + 2])) ++n;
    }
    return n;
}

static std::vector<std::string> splitDots(const std::string& host) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : host) {
        if (c == '.') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        }
        else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static bool isIpv4Host(const std::string& host) {
    int dots = 0;
    if (host.empty()) return false;
    for (char c : host) {
        if (c == '.') ++dots;
        else if (!std::isdigit((unsigned char)c)) return false;
    }
    return dots == 3;
}

static bool hasRepeatedSubdomain(const std::string& host) {
    auto labels = splitDots(host);
    if (labels.size() < 4) return false;
    for (size_t i = 1; i < labels.size(); ++i) {
        if (!labels[i].empty() && labels[i] == labels[i - 1]) return true;
    }
    return false;
}

static std::string getTld(const std::string& host) {
    auto pos = host.rfind('.');
    if (pos == std::string::npos) return "";
    return host.substr(pos);
}

static bool suspiciousTld(const std::string& host) {
    static const std::vector<std::string> bad = {
        ".xyz", ".top", ".click", ".download",
        ".zip", ".loan", ".work", ".gq", ".ml",
        ".cf", ".tk", ".pw", ".icu", ".monster"
    };
    std::string tld = getTld(lowerCopy(host));
    return std::find(bad.begin(), bad.end(), tld) != bad.end();
}

static bool homoglyphSuspected(const std::string& hostRaw) {
    std::string h = lowerCopy(hostRaw);
    if (h.find("rn") != std::string::npos) return true;
    if (h.find("vv") != std::string::npos) return true;
    if (h.find("0o") != std::string::npos || h.find("o0") != std::string::npos) return true;
    if (h.find("1l") != std::string::npos || h.find("l1") != std::string::npos) return true;
    return false;
}

static int queryParamCount(const std::string& path) {
    auto q = path.find('?');
    if (q == std::string::npos) return 0;
    auto end = path.find('#', q + 1);
    std::string query = (end == std::string::npos) ? path.substr(q + 1) : path.substr(q + 1, end - q - 1);
    if (query.empty()) return 0;
    int count = 1;
    for (char c : query) if (c == '&') ++count;
    return count;
}

static bool fragmentWithPayload(const std::string& path) {
    auto h = path.find('#');
    if (h == std::string::npos) return false;
    std::string frag = path.substr(h + 1);
    if (frag.size() > 16) return true;
    return frag.find('=') != std::string::npos || frag.find('%') != std::string::npos || frag.find('/') != std::string::npos;
}

static bool containsAny(const std::string& s, const std::vector<std::string>& list, std::string* found = nullptr) {
    for (const auto& x : list) {
        if (s.find(x) != std::string::npos) {
            if (found) *found = x;
            return true;
        }
    }
    return false;
}

static UrlLexResult analyzeUrl(const std::string& url) {
    UrlLexResult r;
    ParsedUrl u = parseUrl(url);
    if (!u.ok) {
        r.visible_risk = 1.0;
        r.semantic_risk = 0.0;
        r.effective_risk = 0.4;
        r.reason = "URL_LEX_BAD_URL";
        r.verdict = GateVerdict::HOLD;
        return r;
    }

    double visible = 0.0;
    double semantic = 0.0;
    double hidden = 0.0;
    std::vector<std::pair<double, std::string>> reasons;

    auto addVisible = [&](double w, const std::string& why) {
        visible += w;
        reasons.push_back({ w, "VISIBLE:" + why });
        };
    auto addSemantic = [&](double w, const std::string& why) {
        semantic += w;
        reasons.push_back({ w, "SEMANTIC:" + why });
        };
    auto addHidden = [&](double w, const std::string& why) {
        hidden += w;
        reasons.push_back({ w, "HIDDEN:" + why });
        };

    std::string lurl = lowerCopy(url);
    std::string host = lowerCopy(u.host);

    // VISIBLE signals.
    if (url.size() > 100) addVisible(0.10, "url_length_gt_100");
    if (url.size() > 200) addVisible(0.20, "url_length_gt_200");
    if (isIpv4Host(host)) addVisible(0.35, "ip_as_host");
    if (u.port != "80" && u.port != "443") addVisible(0.15, "port_nonstandard:" + u.port);

    auto labels = splitDots(host);
    int subdomains = (labels.size() > 2) ? (int)labels.size() - 2 : 0;
    if (subdomains > 3) addVisible(0.20, "subdomain_count_gt_3");
    if (hasRepeatedSubdomain(host)) addVisible(0.25, "repeated_subdomain");
    if (suspiciousTld(host)) addVisible(0.30, "tld_suspicious:" + getTld(host));

    int encoded = countEncodedChars(url);
    if (encoded > 5) addVisible(0.15, "encoded_chars_gt_5");
    if (lurl.find("%25") != std::string::npos) addVisible(0.40, "double_encoded");

    // SEMANTIC signals.
    static const std::vector<std::string> keywords = {
        "login", "verify", "update", "secure",
        "account", "password", "wallet", "seed",
        "free", "download", "invoice", "payment",
        "urgent", "confirm", "suspended", "unusual"
    };

    double keywordRisk = 0.0;
    for (const auto& k : keywords) {
        if (lurl.find(k) != std::string::npos) {
            keywordRisk += 0.15;
            reasons.push_back({ 0.15, "SEMANTIC:keyword:" + k });
        }
    }
    if (keywordRisk > 0.60) keywordRisk = 0.60;
    semantic += keywordRisk;

    static const std::vector<std::string> doubleExt = {
        ".pdf.exe", ".doc.exe", ".pdf.zip",
        ".docx.exe", ".txt.bat"
    };
    std::string found;
    if (containsAny(lurl, doubleExt, &found)) addSemantic(0.60, "double_extension:" + found);

    if (homoglyphSuspected(host)) addSemantic(0.35, "homoglyph_suspected");

    // HIDDEN signals.
    if (host.find("xn--") != std::string::npos) addHidden(0.30, "punycode_domain");
    if (queryParamCount(u.path) > 8) addHidden(0.20, "query_param_count_gt_8");
    if (fragmentWithPayload(u.path)) addHidden(0.25, "fragment_with_payload");

    static const std::vector<std::string> redirects = {
        "redirect=", "url=", "goto=", "next=", "return="
    };
    if (containsAny(lurl, redirects, &found)) addHidden(0.30, "redirect_keyword:" + found);

    visible = clamp01(visible);
    semantic = clamp01(semantic);
    hidden = clamp01(hidden);

    r.visible_risk = visible;
    r.semantic_risk = semantic;
    r.effective_risk = clamp01(0.4 * visible + 0.4 * semantic + 0.2 * hidden);

    if (!reasons.empty()) {
        std::sort(reasons.begin(), reasons.end(),
            [](const auto& a, const auto& b) { return a.first > b.first; });
        r.reason = reasons.front().second;
    }
    else {
        r.reason = "URL_LEX_OK";
    }

    if (r.effective_risk < 0.25) r.verdict = GateVerdict::ADMIT;
    else if (r.effective_risk < 0.55) r.verdict = GateVerdict::HOLD;
    else r.verdict = GateVerdict::QUARANTINE;

    std::ostringstream reason;
    reason << r.reason
        << " visible=" << std::fixed << std::setprecision(3) << r.visible_risk
        << " semantic=" << r.semantic_risk
        << " effective=" << r.effective_risk;
    r.reason = reason.str();

    return r;
}


// ================================================================
// UCM B2B ANTIVIRUS RC4 — STAGE 3 V2
// Magic bytes + extension mismatch detection.
// Signatureless static sandbox guard: this is not AV signature DB,
// it is format/capability contradiction detection.
// ================================================================

// ================================================================
// UCM B2B ANTIVIRUS RC4 — STAGE 2.6 REDIRECT CHAIN ANALYZER
// Computes covert risk after fetch and before Stage 3.
// ================================================================
struct RedirectChainResult {
    double covert_risk = 0.0;   // 0.0 .. 1.0
    std::string reason = "REDIRECT_CHAIN_OK";
    GateVerdict verdict = GateVerdict::ADMIT;
};

static RedirectChainResult analyzeRedirectChain(
    const std::string& original_url,
    const std::string& final_url,
    int redirect_count,
    const std::string& content_type,
    const std::string& final_extension,
    bool original_trusted = false,
    bool final_trusted = true) {
    RedirectChainResult r;
    double covert = 0.0;
    std::vector<std::pair<double, std::string>> reasons;

    auto add = [&](double w, const std::string& why) {
        covert += w;
        reasons.push_back({ w, why });
        };

    ParsedUrl o = parseUrl(original_url);
    ParsedUrl f = parseUrl(final_url);
    std::string original_ext = urlPathExtension(original_url);
    std::string final_ext = lowerCopy(final_extension.empty() ? urlPathExtension(final_url) : final_extension);
    std::string ctype = lowerCopy(content_type);

    if (redirect_count > 3) add(0.20, "redirect_count_gt_3");
    if (redirect_count > 6) add(0.35, "redirect_count_gt_6");

    if (o.ok && f.ok && lowerCopy(o.host) != lowerCopy(f.host)) {
        add(0.30, "cross_domain_jump:" + o.host + "->" + f.host);
    }

    if (extensionIsDocumentIntent(original_ext) && extensionIsExecutableOrArchiveRisk(final_ext)) {
        add(0.40, "intent_mismatch:" + original_ext + "->" + final_ext);
    }

    if (extensionIsDocumentIntent(original_ext) &&
        (ctype.find("application/octet-stream") != std::string::npos ||
            ctype.find("application/x-msdownload") != std::string::npos ||
            ctype.find("application/x-msdos-program") != std::string::npos)) {
        add(0.35, "content_type_mismatch:" + ctype);
    }

    if (f.ok && suspiciousTld(f.host)) {
        add(0.25, "final_host_suspicious:" + getTld(lowerCopy(f.host)));
    }

    if (original_trusted && !final_trusted) {
        add(0.30, "original_trusted_final_not");
    }

    r.covert_risk = clamp01(covert);

    if (!reasons.empty()) {
        std::sort(reasons.begin(), reasons.end(),
            [](const auto& a, const auto& b) { return a.first > b.first; });
        r.reason = reasons.front().second;
    }

    if (r.covert_risk < 0.30) r.verdict = GateVerdict::ADMIT;
    else if (r.covert_risk < 0.60) r.verdict = GateVerdict::HOLD;
    else r.verdict = GateVerdict::QUARANTINE;

    std::ostringstream reason;
    reason << r.reason << " covert=" << std::fixed << std::setprecision(3) << r.covert_risk
        << " redirects=" << redirect_count
        << " final_ext=" << final_ext
        << " content_type=" << ctype;
    r.reason = reason.str();
    return r;
}

struct MagicSig {
    std::string label;
    size_t offset;
    std::vector<uint8_t> bytes;
    bool block_always;  // true = block regardless of extension
    // false = block only on extension mismatch
};

static const std::vector<MagicSig> KNOWN_MAGIC = {
    // Always block — executable formats
    {"PE_EXE",    0, {0x4D, 0x5A},                         true},
    {"ELF",       0, {0x7F, 0x45, 0x4C, 0x46},             true},
    {"MACH_O_32", 0, {0xCE, 0xFA, 0xED, 0xFE},             true},
    {"MACH_O_64", 0, {0xCF, 0xFA, 0xED, 0xFE},             true},
    {"MSI_OLE",   0, {0xD0, 0xCF, 0x11, 0xE0},             true},
    {"CLASS_JAR", 0, {0xCA, 0xFE, 0xBA, 0xBE},             true},

    // Mismatch-only — archives/scripts. Safe extension + archive/script body is contradiction.
    {"ZIP_JAR",   0, {0x50, 0x4B, 0x03, 0x04},             false},
    {"RAR4",      0, {0x52, 0x61, 0x72, 0x21},             false},
    {"RAR5",      0, {0x52, 0x61, 0x72, 0x1A},             false},
    {"7ZIP",      0, {0x37, 0x7A, 0xBC, 0xAF},             false},
    {"GZIP",      0, {0x1F, 0x8B},                         false},
    {"POWERSHELL",0, {0x23, 0x72, 0x65, 0x71},             false}, // #req
    {"SHEBANG",   0, {0x23, 0x21},                         false}  // #!
};

static const std::vector<std::string> SAFE_EXTENSIONS = {
    ".pdf", ".txt", ".md", ".csv", ".json",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".docx", ".xlsx", ".pptx"
};

static const std::vector<std::string> BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".scr", ".msi", ".com", ".pif",
    ".hta", ".wsf", ".reg"
};


// ================================================================
// UCM B2B ANTIVIRUS RC4 — STAGE 3+ ARCHIVE SHALLOW INSPECTOR
// ZIP central directory only. No extraction. No recursion.
// Non-ZIP archives: magic/header classification only.
// ================================================================
struct ArchiveInspectResult {
    bool is_archive = false;
    int file_count = 0;
    int max_nesting = 0;
    bool has_executable = false;
    bool has_nested_archive = false;
    bool name_mismatch = false;
    double covert_risk = 0.0;
    std::string reason = "ARCHIVE_NOT_DETECTED";
    GateVerdict verdict = GateVerdict::ADMIT;
};

static uint16_t readU16LE(const std::vector<uint8_t>& b, size_t off) {
    if (off + 1 >= b.size()) return 0;
    return (uint16_t)b[off] | ((uint16_t)b[off + 1] << 8);
}

static uint32_t readU32LE(const std::vector<uint8_t>& b, size_t off) {
    if (off + 3 >= b.size()) return 0;
    return (uint32_t)b[off] |
        ((uint32_t)b[off + 1] << 8) |
        ((uint32_t)b[off + 2] << 16) |
        ((uint32_t)b[off + 3] << 24);
}

static bool extInList(const std::string& extRaw, const std::vector<std::string>& list) {
    std::string ext = lowerCopy(extRaw);
    return std::find(list.begin(), list.end(), ext) != list.end();
}

static bool isArchiveExtension(const std::string& extRaw) {
    static const std::vector<std::string> archive = {
        ".zip", ".rar", ".7z", ".gz", ".tar", ".tgz"
    };
    return extInList(extRaw, archive);
}

static bool isExecutableInsideExtension(const std::string& extRaw) {
    static const std::vector<std::string> exec = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".jar", ".scr", ".msi", ".com", ".pif",
        ".hta", ".wsf", ".reg"
    };
    return extInList(extRaw, exec);
}

static bool isNestedArchiveExtension(const std::string& extRaw) {
    return isArchiveExtension(extRaw);
}

static int pathNestingDepth(const std::string& name) {
    int depth = 0;
    for (char c : name) if (c == '/' || c == '\\') ++depth;
    return depth;
}

static bool suspiciousArchiveEntryName(const std::string& nRaw) {
    std::string n = lowerCopy(nRaw);
    static const std::vector<std::string> bad = {
        "autorun", "install", "setup", "update", "patch", "loader"
    };
    for (const auto& b : bad) {
        if (n.find(b) != std::string::npos) return true;
    }
    return false;
}

static bool fileHasMagicAt0(const fs::path& file, const std::vector<uint8_t>& sig) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> buf(sig.size(), 0);
    in.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
    if ((size_t)in.gcount() < sig.size()) return false;
    return std::equal(sig.begin(), sig.end(), buf.begin());
}

static bool isZipByMagic(const fs::path& file) {
    return fileHasMagicAt0(file, { 0x50, 0x4B, 0x03, 0x04 });
}

static bool isNonZipArchiveByMagic(const fs::path& file) {
    return fileHasMagicAt0(file, { 0x52, 0x61, 0x72, 0x21 }) ||   // RAR
        fileHasMagicAt0(file, { 0x37, 0x7A, 0xBC, 0xAF }) ||   // 7Z
        fileHasMagicAt0(file, { 0x1F, 0x8B });                 // GZIP
}

static ArchiveInspectResult inspectArchiveShallow(const fs::path& file, const std::string& extRaw) {
    ArchiveInspectResult r;

    std::string ext = lowerCopy(extRaw.empty() ? file.extension().string() : extRaw);
    bool ext_archive = isArchiveExtension(ext);
    bool zip_magic = isZipByMagic(file);
    bool nonzip_magic = isNonZipArchiveByMagic(file);

    r.is_archive = ext_archive || zip_magic || nonzip_magic;
    if (!r.is_archive) {
        r.reason = "ARCHIVE_NOT_DETECTED";
        return r;
    }

    auto finish = [&](const std::vector<std::pair<double, std::string>>& rawReasons) -> ArchiveInspectResult {
        std::vector<std::pair<double, std::string>> reasons = rawReasons;
        r.covert_risk = clamp01(r.covert_risk);
        if (!reasons.empty()) {
            std::sort(reasons.begin(), reasons.end(),
                [](const auto& a, const auto& b) { return a.first > b.first; });
            r.reason = reasons.front().second;
        }
        if (r.covert_risk < 0.30) r.verdict = GateVerdict::ADMIT;
        else if (r.covert_risk < 0.55) r.verdict = GateVerdict::HOLD;
        else r.verdict = GateVerdict::QUARANTINE;

        std::ostringstream ss;
        ss << r.reason
            << " archive=1"
            << " files=" << r.file_count
            << " max_nesting=" << r.max_nesting
            << " exe=" << (r.has_executable ? 1 : 0)
            << " nested_archive=" << (r.has_nested_archive ? 1 : 0)
            << " mismatch=" << (r.name_mismatch ? 1 : 0)
            << " covert=" << std::fixed << std::setprecision(3) << r.covert_risk;
        r.reason = ss.str();
        return r;
        };

    std::vector<std::pair<double, std::string>> reasons;
    auto add = [&](double w, const std::string& why) {
        r.covert_risk += w;
        reasons.push_back({ w, why });
        };

    if (!zip_magic) {
        r.reason = nonzip_magic ? "NON_ZIP_ARCHIVE_HEADER_ONLY" : "ARCHIVE_EXT_HEADER_UNKNOWN";
        return finish(reasons);
    }

    std::error_code ec;
    uintmax_t size = fs::file_size(file, ec);
    if (ec || size < 22) {
        r.verdict = GateVerdict::HOLD;
        r.reason = "ARCHIVE_PARSE_FAILED:file_too_small_or_unreadable";
        return r;
    }

    const uintmax_t tailMax = 65536 + 22;
    size_t tailSize = (size_t)std::min<uintmax_t>(size, tailMax);
    uintmax_t tailStart = size - tailSize;

    std::ifstream in(file, std::ios::binary);
    if (!in) {
        r.verdict = GateVerdict::HOLD;
        r.reason = "ARCHIVE_PARSE_FAILED:open_failed";
        return r;
    }

    std::vector<uint8_t> tail(tailSize, 0);
    in.seekg((std::streamoff)tailStart, std::ios::beg);
    in.read(reinterpret_cast<char*>(tail.data()), (std::streamsize)tail.size());
    if ((size_t)in.gcount() < 22) {
        r.verdict = GateVerdict::HOLD;
        r.reason = "ARCHIVE_PARSE_FAILED:tail_read_failed";
        return r;
    }

    int64_t eocd = -1;
    for (int64_t i = (int64_t)tail.size() - 22; i >= 0; --i) {
        if (tail[(size_t)i] == 0x50 && tail[(size_t)i + 1] == 0x4B &&
            tail[(size_t)i + 2] == 0x05 && tail[(size_t)i + 3] == 0x06) {
            eocd = i;
            break;
        }
    }

    if (eocd < 0) {
        r.verdict = GateVerdict::HOLD;
        r.reason = "ARCHIVE_PARSE_FAILED:eocd_not_found";
        return r;
    }

    uint16_t total_entries = readU16LE(tail, (size_t)eocd + 10);
    uint32_t cd_size = readU32LE(tail, (size_t)eocd + 12);
    uint32_t cd_offset = readU32LE(tail, (size_t)eocd + 16);

    if (total_entries == 0xFFFF || cd_offset == 0xFFFFFFFFu || cd_size == 0xFFFFFFFFu) {
        r.verdict = GateVerdict::HOLD;
        r.reason = "ARCHIVE_PARSE_FAILED:zip64_unsupported";
        return r;
    }

    r.file_count = (int)total_entries;
    if (r.file_count > 100) add(0.20, "archive_file_count_gt_100");
    if (r.file_count > 500) add(0.40, "archive_file_count_gt_500");

    if ((uintmax_t)cd_offset >= size) {
        r.verdict = GateVerdict::HOLD;
        r.reason = "ARCHIVE_PARSE_FAILED:central_dir_offset_invalid";
        return r;
    }

    in.clear();
    in.seekg((std::streamoff)cd_offset, std::ios::beg);
    int parsed = 0;
    uint64_t maxUncompressed = 0;
    bool hugeSingle = false;
    bool compressionBomb = false;
    bool suspiciousName = false;

    const int maxEntriesToRead = std::min<int>((int)total_entries, 1000);
    for (int i = 0; i < maxEntriesToRead; ++i) {
        std::vector<uint8_t> hdr(46, 0);
        in.read(reinterpret_cast<char*>(hdr.data()), (std::streamsize)hdr.size());
        if ((size_t)in.gcount() != hdr.size()) break;

        uint32_t sig = readU32LE(hdr, 0);
        if (sig != 0x02014B50u) break;

        uint32_t comp = readU32LE(hdr, 20);
        uint32_t uncomp = readU32LE(hdr, 24);
        uint16_t nameLen = readU16LE(hdr, 28);
        uint16_t extraLen = readU16LE(hdr, 30);
        uint16_t commentLen = readU16LE(hdr, 32);

        std::string name(nameLen, '\0');
        if (nameLen > 0) in.read(&name[0], nameLen);
        if ((size_t)in.gcount() != nameLen && nameLen > 0) break;

        if (extraLen > 0) in.seekg(extraLen, std::ios::cur);
        if (commentLen > 0) in.seekg(commentLen, std::ios::cur);

        ++parsed;
        std::string entryExt = lowerCopy(fs::path(name).extension().string());
        int depth = pathNestingDepth(name);
        if (depth > r.max_nesting) r.max_nesting = depth;

        if (isExecutableInsideExtension(entryExt)) r.has_executable = true;
        if (isNestedArchiveExtension(entryExt)) r.has_nested_archive = true;
        if (suspiciousArchiveEntryName(name)) suspiciousName = true;

        if (comp > 0 && uncomp > 0) {
            double ratio = (double)uncomp / (double)comp;
            if (ratio > 100.0) compressionBomb = true;
        }
        if ((uint64_t)uncomp > maxUncompressed) maxUncompressed = uncomp;
    }

    if (parsed == 0 && total_entries > 0) {
        r.verdict = GateVerdict::HOLD;
        r.reason = "ARCHIVE_PARSE_FAILED:central_dir_parse_failed";
        return r;
    }

    if (total_entries == 1 && maxUncompressed > 500ull * 1024ull * 1024ull) hugeSingle = true;
    if (r.has_executable) add(0.55, "archive_has_executable");
    if (r.has_nested_archive) add(0.35, "archive_has_nested_archive");
    if (compressionBomb) add(0.40, "archive_compression_ratio_gt_100x");
    if (extInList(ext, SAFE_EXTENSIONS) && r.has_executable) {
        r.name_mismatch = true;
        add(0.50, "archive_name_mismatch_safe_ext_contains_executable");
    }
    if (hugeSingle) add(0.25, "archive_single_file_huge");
    if (suspiciousName) add(0.30, "archive_suspicious_name_inside");

    return finish(reasons);
}

class RateLimiter {
    std::mutex mu;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> perIp;
    std::deque<std::chrono::steady_clock::time_point> global;
    int maxPerSecondPerIp = 5;
    int maxPerSecondGlobal = 40;

public:
    StageResult allow(const std::string& ip) {
        using namespace std::chrono;
        auto now = steady_clock::now();
        std::lock_guard<std::mutex> lock(mu);

        auto trim = [&](auto& dq) {
            while (!dq.empty() && duration_cast<milliseconds>(now - dq.front()).count() > 1000) dq.pop_front();
            };

        trim(global);
        auto& q = perIp[ip];
        trim(q);

        if ((int)global.size() >= maxPerSecondGlobal) {
            return { false, GateVerdict::HOLD, "GLOBAL_RATE_LIMIT" };
        }
        if ((int)q.size() >= maxPerSecondPerIp) {
            return { false, GateVerdict::HOLD, "SOURCE_RATE_LIMIT" };
        }

        global.push_back(now);
        q.push_back(now);
        return { true, GateVerdict::ADMIT, "RATE_OK" };
    }
};

class SignaturelessAnalyzer {
public:
    StageResult stage1Ddos(const HttpRequest& req, RateLimiter& limiter) {
        if (req.raw.size() > 65536) {
            return { false, GateVerdict::REJECT, "REQUEST_TOO_LARGE" };
        }
        return limiter.allow(req.clientIp);
    }

    StageResult stage2UrlAndCapability(const std::string& url) {
        if (url.empty()) return { false, GateVerdict::REJECT, "EMPTY_URL" };

        std::string l = lowerCopy(url);
        ParsedUrl pu = parseUrl(url);

        if (!pu.ok) return { false, GateVerdict::REJECT, "BAD_URL_FORMAT" };
        if (pu.scheme != "http" && pu.scheme != "https") {
            return { false, GateVerdict::REJECT, "FORBIDDEN_SCHEME" };
        }

        if (pu.host == "localhost" || startsWith(pu.host, "127.") || startsWith(pu.host, "0.") ||
            startsWith(pu.host, "10.") || startsWith(pu.host, "192.168.") || startsWith(pu.host, "169.254.")) {
            return { false, GateVerdict::HOLD, "PRIVATE_OR_LOCAL_TARGET_REQUIRES_ARBITRATION" };
        }

        std::vector<std::string> hardBad = {
            "direct_core_write", "direct_memory_overwrite", "remote_exec",
            "core_reload", "body_control", "unauthorized_config_update",
            "persistence_install", "powershell", "cmd.exe", "wscript",
            "javascript:", "data:"
        };
        for (const auto& pat : hardBad) {
            if (l.find(pat) != std::string::npos) {
                return { false, GateVerdict::REJECT, "FORBIDDEN_CAPABILITY_PATTERN_" + pat };
            }
        }

        std::vector<std::string> suspicious = {
            "login", "verify", "password", "seed", "wallet", "free-download",
            "download-now", "update-browser", "enable-macro", "captcha",
            "redirect", "track", "adclick"
        };
        int score = 0;
        for (const auto& pat : suspicious) {
            if (l.find(pat) != std::string::npos) score++;
        }
        if (score >= 3) {
            return { true, GateVerdict::HOLD, "PHISHING_OR_ADWARE_CONTEXT_SUSPECTED" };
        }

        return { true, GateVerdict::ADMIT, "URL_CAPABILITY_OK" };
    }

    StageResult stage2ContentCapability(const std::string& content) {
        std::string l = lowerCopy(content);
        std::vector<std::string> forbidden = {
            "<script", "eval(", "document.cookie", "localstorage", "navigator.clipboard",
            "webassembly", ".wasm", "<iframe", "onerror=", "onload=", "autodownload",
            "window.location", "location.href", "createobject", "activexobject",
            "powershell", "cmd.exe", "wscript.shell", "direct_core_write",
            "direct_memory_overwrite", "core_reload"
        };

        int activeScore = 0;
        for (const auto& pat : forbidden) {
            if (l.find(pat) != std::string::npos) activeScore++;
        }

        if (activeScore >= 5) return { false, GateVerdict::QUARANTINE, "ACTIVE_WEB_CODE_HIGH_RISK" };
        if (activeScore >= 1) return { true, GateVerdict::HOLD, "ACTIVE_WEB_CODE_STRIPPED" };
        return { true, GateVerdict::ADMIT, "CONTENT_CAPABILITY_OK" };
    }

    StageResult stage3SandboxBehavior(const fs::path& file, const std::string& originalExt = "") {
        if (!fs::exists(file))
            return { false, GateVerdict::REJECT, "SANDBOX_INPUT_MISSING" };

        auto size = fs::file_size(file);
        if (size > 200ull * 1024ull * 1024ull)
            return { false, GateVerdict::REJECT, "FILE_TOO_LARGE" };

        // Zero-byte file check.
        if (size == 0)
            return { true, GateVerdict::HOLD, "EMPTY_FILE_HOLD" };

        // Extension check. For downloaded quarantine files, originalExt is the final URL extension.
        std::string ext = lowerCopy(originalExt.empty() ? file.extension().string() : originalExt);

        if (std::find(BLOCKED_EXTENSIONS.begin(),
            BLOCKED_EXTENSIONS.end(), ext)
            != BLOCKED_EXTENSIONS.end()) {
            return { false, GateVerdict::REJECT,
                    "BLOCKED_EXTENSION:" + ext };
        }

        // Stage 3+ archive shallow inspector. It runs before magic mismatch check.
        ArchiveInspectResult ar = inspectArchiveShallow(file, ext);
        if (ar.is_archive) {
            StageResult archiveResult;
            archiveResult.pass = (ar.verdict == GateVerdict::ADMIT);
            archiveResult.verdict = ar.verdict;
            archiveResult.reason = "STAGE3_ARCHIVE_INSPECT:" + ar.reason;
            if (ar.verdict == GateVerdict::QUARANTINE || ar.verdict == GateVerdict::HOLD) {
                return archiveResult;
            }
            // ADMIT archive continues through magic mismatch check.
        }

        // Read first 16 bytes.
        std::vector<uint8_t> magic(16, 0);
        {
            std::ifstream f(file, std::ios::binary);
            if (!f) {
                return { false, GateVerdict::QUARANTINE,
                        "CANNOT_READ_FILE" };
            }
            f.read(reinterpret_cast<char*>(magic.data()), (std::streamsize)magic.size());
        }

        bool ext_is_safe = std::find(SAFE_EXTENSIONS.begin(),
            SAFE_EXTENSIONS.end(), ext)
            != SAFE_EXTENSIONS.end();

        // Magic bytes matching.
        for (const auto& sig : KNOWN_MAGIC) {
            if (sig.offset + sig.bytes.size() > magic.size()) continue;

            bool match = std::equal(
                sig.bytes.begin(), sig.bytes.end(),
                magic.begin() + (std::ptrdiff_t)sig.offset
            );
            if (!match) continue;

            if (sig.block_always) {
                return { false, GateVerdict::QUARANTINE,
                        "MAGIC_BLOCKED:" + sig.label + " ext=" + ext };
            }

            // Mismatch: safe extension but archive/script magic.
            if (ext_is_safe) {
                return { false, GateVerdict::QUARANTINE,
                        "EXTENSION_MAGIC_MISMATCH:" + sig.label + " ext=" + ext };
            }
        }

        return { true, GateVerdict::ADMIT, ar.is_archive ? "STAGE3_ARCHIVE_INSPECT:" + ar.reason : "SANDBOX_STATIC_V2_OK" };
    }

    std::string sanitizeHtmlToSafeView(const std::string& html) {
        std::string out = html;
        auto flags = std::regex_constants::icase;
        try {
            out = std::regex_replace(out, std::regex("<script[\\s\\S]*?</script>", flags), "");
            out = std::regex_replace(out, std::regex("<iframe[\\s\\S]*?</iframe>", flags), "");
            out = std::regex_replace(out, std::regex("<form[\\s\\S]*?</form>", flags), "");
            out = std::regex_replace(out, std::regex("on[a-zA-Z]+\\s*=\\s*\"[^\"]*\"", flags), "");
            out = std::regex_replace(out, std::regex("on[a-zA-Z]+\\s*=\\s*'[^']*'", flags), "");
            out = std::regex_replace(out, std::regex("javascript:", flags), "");
        }
        catch (...) {
            return "<pre>" + htmlEscape(html) + "</pre>";
        }

        std::ostringstream safe;
        safe << "<!doctype html><html><head><meta charset=\"utf-8\">"
            << "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline';\">"
            << "<title>LOVE_AR Safe View</title></head><body>"
            << "<div style=\"font-family:Arial;padding:10px;border:1px solid #999;background:#eef\">"
            << "UCM_B2B SAFE VIEW: active content stripped. Browser sees local sanitized artifact only."
            << "</div>"
            << out
            << "</body></html>";
        return safe.str();
    }
};

class TokenStore {
    std::mutex mu;
    std::unordered_map<std::string, fs::path> tokenToFile;
    fs::path indexPath;

    void saveLocked() {
        if (indexPath.empty()) return;
        fs::create_directories(indexPath.parent_path());
        std::ofstream out(indexPath, std::ios::binary);
        out << "{\n  \"version\":\"LOVE_AR_UCM_TOKEN_INDEX_V1\",\n  \"tokens\":[\n";
        bool first = true;
        for (const auto& kv : tokenToFile) {
            if (!first) out << ",\n";
            first = false;
            out << "    {\"token\":\"" << jsonEscape(kv.first) << "\",\"path\":\"" << jsonEscape(kv.second.string()) << "\"}";
        }
        out << "\n  ]\n}\n";
    }

public:
    void load(const fs::path& p) {
        std::lock_guard<std::mutex> lock(mu);
        indexPath = p;
        tokenToFile.clear();

        if (!fs::exists(indexPath)) {
            saveLocked();
            return;
        }

        std::ifstream in(indexPath, std::ios::binary);
        std::ostringstream ss;
        ss << in.rdbuf();
        std::string data = ss.str();

        std::regex row("\\{\\s*\\\"token\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"\\s*,\\s*\\\"path\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"\\s*\\}");
        for (auto it = std::sregex_iterator(data.begin(), data.end(), row); it != std::sregex_iterator(); ++it) {
            std::string token = (*it)[1].str();
            std::string path = (*it)[2].str();
            tokenToFile[token] = fs::path(path);
        }
    }

    std::string makeToken() {
        static const char* alphabet = "0123456789abcdef";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> d(0, 15);
        std::string t;
        for (int i = 0; i < 32; ++i) t.push_back(alphabet[d(gen)]);
        return t;
    }

    void put(const std::string& token, const fs::path& p) {
        std::lock_guard<std::mutex> lock(mu);
        tokenToFile[token] = p;
        saveLocked();
    }

    bool get(const std::string& token, fs::path& out) {
        std::lock_guard<std::mutex> lock(mu);
        auto it = tokenToFile.find(token);
        if (it == tokenToFile.end()) return false;
        out = it->second;
        return true;
    }

    size_t size() {
        std::lock_guard<std::mutex> lock(mu);
        return tokenToFile.size();
    }
};

class ExternalFetcher {
public:
    struct FetchResult {
        bool ok = false;
        bool httpsUnsupported = false;
        int status_code = 0;
        int redirect_count = 0;
        std::string status;
        std::string body;
        std::string headers;
        std::string content_type;
        std::string redirect_location;
        std::string final_url;
    };


#ifdef _WIN32
    FetchResult fetchHttpsWinHttp(const std::string& url, size_t maxBytes = 1048576) {
        FetchResult r;
        ParsedUrl u = parseUrl(url);
        if (!u.ok) {
            r.status = "BAD_URL";
            return r;
        }
        if (u.scheme != "https") {
            r.status = "NOT_HTTPS";
            return r;
        }

        INTERNET_PORT port = 443;
        try { port = (INTERNET_PORT)std::stoi(u.port); }
        catch (...) { port = 443; }

        HINTERNET session = WinHttpOpen(L"UCM_B2B_ANTIVIRUS/4.0-FIX1",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!session) {
            r.status = "WINHTTP_OPEN_FAILED";
            return r;
        }

        WinHttpSetTimeouts(session, 10000, 10000, 30000, 30000);

        std::wstring whost = widenUtf8(u.host);
        std::wstring wpath = widenUtf8(u.path.empty() ? "/" : u.path);

        HINTERNET connect = WinHttpConnect(session, whost.c_str(), port, 0);
        if (!connect) {
            WinHttpCloseHandle(session);
            r.status = "WINHTTP_CONNECT_FAILED";
            return r;
        }

        HINTERNET request = WinHttpOpenRequest(connect,
            L"GET",
            wpath.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!request) {
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            r.status = "WINHTTP_OPEN_REQUEST_FAILED";
            return r;
        }

        DWORD disableRedirects = WINHTTP_DISABLE_REDIRECTS;
        WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disableRedirects, sizeof(disableRedirects));

        BOOL ok = WinHttpSendRequest(request,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0);
        if (ok) ok = WinHttpReceiveResponse(request, nullptr);

        if (!ok) {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            r.status = "WINHTTP_REQUEST_FAILED";
            return r;
        }

        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusSize,
            WINHTTP_NO_HEADER_INDEX);

        DWORD rawSize = 0;
        WinHttpQueryHeaders(request,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER,
            &rawSize,
            WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && rawSize > 0) {
            std::wstring rawHeaders(rawSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(request,
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &rawHeaders[0],
                &rawSize,
                WINHTTP_NO_HEADER_INDEX)) {
                while (!rawHeaders.empty() && rawHeaders.back() == L'\0') rawHeaders.pop_back();
                r.headers = narrowWide(rawHeaders);
            }
        }

        auto queryWinHttpHeaderString = [&](DWORD query) -> std::string {
            DWORD sz = 0;
            WinHttpQueryHeaders(request,
                query,
                WINHTTP_HEADER_NAME_BY_INDEX,
                WINHTTP_NO_OUTPUT_BUFFER,
                &sz,
                WINHTTP_NO_HEADER_INDEX);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sz == 0) return "";
            std::wstring w(sz / sizeof(wchar_t), L'\0');
            if (!WinHttpQueryHeaders(request,
                query,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &w[0],
                &sz,
                WINHTTP_NO_HEADER_INDEX)) {
                return "";
            }
            while (!w.empty() && w.back() == L'\0') w.pop_back();
            return narrowWide(w);
            };

        std::string directContentType = queryWinHttpHeaderString(WINHTTP_QUERY_CONTENT_TYPE);
        std::string directLocation = queryWinHttpHeaderString(WINHTTP_QUERY_LOCATION);

        std::ostringstream body;
        size_t total = 0;
        for (;;) {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request, &available)) break;
            if (available == 0) break;

            DWORD toRead = available;
            if (total + toRead > maxBytes) toRead = (DWORD)(maxBytes - total);
            if (toRead == 0) break;

            std::string chunk(toRead, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(request, &chunk[0], toRead, &read) || read == 0) break;
            chunk.resize(read);
            body << chunk;
            total += read;
            if (total >= maxBytes) break;
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);

        r.body = body.str();
        r.status_code = (int)statusCode;
        r.status = "HTTP_" + std::to_string(statusCode);
        r.content_type = headerValue(r.headers, "content-type");
        if (r.content_type.empty()) r.content_type = directContentType;
        r.redirect_location = headerValue(r.headers, "location");
        if (r.redirect_location.empty()) r.redirect_location = directLocation;
        r.final_url = url;
        r.ok = (statusCode >= 200 && statusCode < 400);
        return r;
    }
#endif

    FetchResult fetchExternalOnce(const std::string& url) {
        ParsedUrl u = parseUrl(url);
        if (!u.ok) {
            FetchResult r;
            r.status = "BAD_URL";
            return r;
        }
#ifdef _WIN32
        if (u.scheme == "https") return fetchHttpsWinHttp(url);
#endif
        return fetchHttpOnly(url);
    }

    FetchResult fetchExternal(const std::string& url) {
        std::string current = url;
        int redirects = 0;
        for (int i = 0; i < 8; ++i) {
            FetchResult r = fetchExternalOnce(current);
            if (r.final_url.empty()) r.final_url = current;
            r.redirect_count = redirects;

            if (r.status_code >= 300 && r.status_code < 400 && !r.redirect_location.empty()) {
                current = makeAbsoluteUrl(current, r.redirect_location);
                ++redirects;
                continue;
            }

            r.redirect_count = redirects;
            r.final_url = current;
            return r;
        }

        FetchResult r;
        r.ok = false;
        r.status = "TOO_MANY_REDIRECTS";
        r.redirect_count = redirects;
        r.final_url = current;
        return r;
    }

    FetchResult fetchHttpOnly(const std::string& url) {
        FetchResult r;
        ParsedUrl u = parseUrl(url);
        if (!u.ok) {
            r.status = "BAD_URL";
            return r;
        }
        if (u.scheme == "https") {
            r.httpsUnsupported = true;
            r.status = "HTTPS_CONNECTOR_NOT_COMPILED_IN_V1";
            return r;
        }
        if (u.scheme != "http") {
            r.status = "ONLY_HTTP_SUPPORTED_IN_BUILTIN_FETCHER";
            return r;
        }

        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        int gai = getaddrinfo(u.host.c_str(), u.port.c_str(), &hints, &res);
        if (gai != 0 || !res) {
            r.status = "DNS_OR_ADDRINFO_FAILED";
            return r;
        }

        socket_t s = INVALID_SOCKET_T;
        for (addrinfo* p = res; p; p = p->ai_next) {
            s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (s == INVALID_SOCKET_T) continue;
            if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
            close_socket(s);
            s = INVALID_SOCKET_T;
        }
        freeaddrinfo(res);

        if (s == INVALID_SOCKET_T) {
            r.status = "CONNECT_FAILED";
            return r;
        }

        std::ostringstream req;
        req << "GET " << u.path << " HTTP/1.0\r\n"
            << "Host: " << u.host << "\r\n"
            << "User-Agent: LOVE_AR_UCM/1.0\r\n"
            << "Accept: */*\r\n"
            << "Connection: close\r\n\r\n";
        std::string reqs = req.str();

        int sent = send(s, reqs.c_str(), (int)reqs.size(), 0);
        if (sent <= 0) {
            close_socket(s);
            r.status = "SEND_FAILED";
            return r;
        }

        std::vector<char> buf(65536);
        std::string response;
        while (true) {
            int n = recv(s, buf.data(), (int)buf.size(), 0);
            if (n <= 0) break;
            response.append(buf.data(), buf.data() + n);
            if (response.size() > 10 * 1024 * 1024) break;
        }
        close_socket(s);

        auto sep = response.find("\r\n\r\n");
        if (sep == std::string::npos) {
            r.headers = "";
            r.body = response;
        }
        else {
            r.headers = response.substr(0, sep);
            r.body = response.substr(sep + 4);
        }
        r.status_code = parseHttpStatusCode(r.headers);
        r.content_type = headerValue(r.headers, "content-type");
        r.redirect_location = headerValue(r.headers, "location");
        r.final_url = url;
        r.ok = (r.status_code >= 200 && r.status_code < 400);
        r.status = r.status_code ? ("HTTP_" + std::to_string(r.status_code)) : "FETCH_OK";
        return r;
    }
};

class UcmServer {
    RuntimePaths paths;
    RateLimiter limiter;
    SignaturelessAnalyzer analyzer;
    TokenStore tokens;
    ExternalFetcher fetcher;
    std::atomic<bool> running{ true };
    std::chrono::steady_clock::time_point lastCleanup = std::chrono::steady_clock::now() - std::chrono::minutes(10);

    std::string bindHost = "127.0.0.1";
    int port = 8888;

public:
    UcmServer() {
        ensureRuntime(paths);
        tokens.load(paths.tokenIndex);
        runStorageMaintenance(true);
        appendLog(paths, "BOOT UCM protocol_snapshot=" + paths.protocolJson.string());
        appendLog(paths, "BOOT token_index=" + paths.tokenIndex.string() + " tokens=" + std::to_string(tokens.size()));
    }

    void run() {
#ifdef _WIN32
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr << "WSAStartup failed\n";
            return;
        }
#endif
        socket_t server = socket(AF_INET, SOCK_STREAM, 0);
        if (server == INVALID_SOCKET_T) {
            std::cerr << "socket failed\n";
            return;
        }

        int opt = 1;
#ifdef _WIN32
        setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
        setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, bindHost.c_str(), &addr.sin_addr);

        if (bind(server, (sockaddr*)&addr, sizeof(addr)) != 0) {
            std::cerr << "bind failed on " << bindHost << ":" << port << "\n";
            close_socket(server);
            return;
        }
        if (listen(server, 64) != 0) {
            std::cerr << "listen failed\n";
            close_socket(server);
            return;
        }

        std::cout << "UCM_B2B_ANTIVIRUS_RC1 headless online: http://" << bindHost << ":" << port << " ; control from LOVE_AR panel on 127.0.0.1:7777\n";
        std::cout << "Protocol JSON created/loaded: " << paths.protocolJson << "\n";
        std::cout << "Keys template created/loaded: " << paths.keysEnv << "\n";

        while (running.load()) {
            sockaddr_in clientAddr{};
#ifdef _WIN32
            int clen = sizeof(clientAddr);
#else
            socklen_t clen = sizeof(clientAddr);
#endif
            socket_t client = accept(server, (sockaddr*)&clientAddr, &clen);
            if (client == INVALID_SOCKET_T) continue;

            char ipbuf[64] = { 0 };
            inet_ntop(AF_INET, &clientAddr.sin_addr, ipbuf, sizeof(ipbuf));
            std::string cip = ipbuf[0] ? ipbuf : "unknown";

            std::thread([this, client, cip]() {
                handleClient(client, cip);
                close_socket(client);
                }).detach();
        }

        close_socket(server);
#ifdef _WIN32
        WSACleanup();
#endif
    }

private:
    HttpRequest readRequest(socket_t client, const std::string& clientIp) {
        HttpRequest req;
        req.clientIp = clientIp;
        // FIX-BUFFER-2: read request headers and body up to 65536 bytes.
        std::string raw;
        raw.reserve(65536);
        char buf[4096];
        size_t totalRead = 0;
        size_t expectedTotal = 0;

        while (totalRead < 65536) {
            size_t remaining = 65536 - totalRead;
            int want = (int)std::min<size_t>(sizeof(buf), remaining);
            int n = recv(client, buf, want, 0);
            if (n <= 0) break;

            raw.append(buf, buf + n);
            totalRead += (size_t)n;

            size_t headerEnd = raw.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                if (expectedTotal == 0) {
                    std::string headersOnly = raw.substr(0, headerEnd);
                    std::string contentLength = headerValue(headersOnly, "Content-Length");
                    if (!contentLength.empty()) {
                        try {
                            size_t bodyLen = (size_t)std::stoull(contentLength);
                            expectedTotal = std::min<size_t>(65536, headerEnd + 4 + bodyLen);
                        }
                        catch (...) {
                            expectedTotal = headerEnd + 4;
                        }
                    }
                    else {
                        expectedTotal = headerEnd + 4;
                    }
                }
                if (raw.size() >= expectedTotal) break;
            }
        }
        req.raw = raw;
        size_t bodyPos = raw.find("\r\n\r\n");
        if (bodyPos != std::string::npos) req.body = raw.substr(bodyPos + 4);

        std::istringstream iss(raw);
        std::string line;
        if (std::getline(iss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            std::istringstream first(line);
            first >> req.method >> req.target >> req.version;
        }

        while (std::getline(iss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) break;
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                std::string k = lowerCopy(line.substr(0, colon));
                std::string v = line.substr(colon + 1);
                while (!v.empty() && std::isspace((unsigned char)v.front())) v.erase(v.begin());
                req.headers[k] = v;
            }
        }

        auto qpos = req.target.find('?');
        req.path = (qpos == std::string::npos) ? req.target : req.target.substr(0, qpos);
        req.query = (qpos == std::string::npos) ? "" : req.target.substr(qpos + 1);
        return req;
    }

    void sendResponse(socket_t client, const std::string& body, const std::string& type = "text/html; charset=utf-8", int code = 200, const std::string& status = "OK") {
        std::ostringstream out;
        out << "HTTP/1.1 " << code << " " << status << "\r\n"
            << "Content-Type: " << type << "\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "Connection: close\r\n"
            << "Access-Control-Allow-Origin: http://127.0.0.1:7777\r\n"
            << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            << "Access-Control-Allow-Headers: Content-Type, X-Love-Token\r\n"
            << "X-LOVE-AR-UCM: UDB8\r\n"
            << "\r\n"
            << body;
        std::string s = out.str();
        send(client, s.c_str(), (int)s.size(), 0);
    }


    bool loveTokenValid(const HttpRequest& req, std::string& reason) {
        fs::path tokenPath = discoverLoveTokenPath(paths);
        if (tokenPath.empty()) {
            reason = "LOVE_TOKEN_FILE_NOT_FOUND";
            return false;
        }
        std::string expected = readTextFileTrim(tokenPath);
        if (expected.empty()) {
            reason = "LOVE_TOKEN_EMPTY";
            return false;
        }
        auto it = req.headers.find("x-love-token");
        if (it == req.headers.end()) {
            reason = "X_LOVE_TOKEN_MISSING";
            return false;
        }
        if (it->second != expected) {
            reason = "X_LOVE_TOKEN_INVALID";
            return false;
        }
        reason = "AUTH_OK";
        return true;
    }

    bool commandRouteRequiresAuth(const std::string& path) {
        return path == "/resources/save" || path == "/open" || path == "/download";
    }

    void sendAuthReject(socket_t client, const std::string& reason) {
        appendLog(paths, "AUTH_REJECT reason=" + reason);
        sendResponse(client, blockPage("AUTH_REJECT_" + reason), "text/html; charset=utf-8", 403, "Forbidden");
    }

    void runStorageMaintenance(bool force = false) {
        auto now = std::chrono::steady_clock::now();
        if (!force && std::chrono::duration_cast<std::chrono::seconds>(now - lastCleanup).count() < 60) return;
        lastCleanup = now;

        cleanupOldAndRotate(paths.quarantine, 7, 512ull * 1024ull * 1024ull);
        cleanupOldAndRotate(paths.safe, 7, 512ull * 1024ull * 1024ull);
        appendLog(paths, "STORAGE_MAINTENANCE quarantine_bytes=" + std::to_string(directoryBytes(paths.quarantine)) +
            " safe_bytes=" + std::to_string(directoryBytes(paths.safe)));
    }

    void handleClient(socket_t client, const std::string& clientIp) {
        runStorageMaintenance(false);
        HttpRequest req = readRequest(client, clientIp);
        if (req.method == "OPTIONS") {
            sendResponse(client, "", "text/plain; charset=utf-8", 204, "No Content");
            return;
        }

        StageResult st1 = analyzer.stage1Ddos(req, limiter);
        if (!st1.pass) {
            appendLog(paths, "STAGE1_BLOCK ip=" + clientIp + " reason=" + st1.reason);
            sendResponse(client, blockPage(st1.reason), "text/html; charset=utf-8", 429, "Too Many Requests");
            return;
        }

        if (commandRouteRequiresAuth(req.path)) {
            std::string authReason;
            if (!loveTokenValid(req, authReason)) {
                sendAuthReject(client, authReason);
                return;
            }
        }

        if (req.path == "/" || req.path.empty()) {
            sendResponse(client, controlPanel());
        }
        else if (req.path == "/status") {
            sendResponse(client, statusJson(), "application/json");
        }
        else if (req.path == "/proxy.pac") {
            sendResponse(client, proxyPac(), "application/x-ns-proxy-autoconfig");
        }
        else if (req.path == "/resources") {
            sendResponse(client, resourceAllowlistText(paths), "text/plain; charset=utf-8");
        }
        else if (req.path == "/resources/save") {
            handleResourcesSave(client, req);
        }
        else if (req.path == "/open") {
            handleOpen(client, req);
        }
        else if (req.path == "/download") {
            handleDownload(client, req);
        }
        else if (startsWith(req.path, "/safe/view/")) {
            serveSafeView(client, req.path.substr(std::string("/safe/view/").size()));
        }
        else if (startsWith(req.path, "/safe/file/")) {
            serveSafeFile(client, req.path.substr(std::string("/safe/file/").size()));
        }
        else {
            sendResponse(client, blockPage("UNKNOWN_ROUTE"), "text/html; charset=utf-8", 404, "Not Found");
        }
    }

    std::string controlPanel() {
        std::ostringstream h;
        h << "<!doctype html><html><head><meta charset=\"utf-8\"><title>KeelCore Labs UCM B2B ANTIVIRUS RC4</title>"
            << "<style>body{font-family:Arial;margin:24px;max-width:900px}.ok{color:green}.small{font-size:12px;color:#555}"
            << "code{background:#eee;padding:2px 4px}</style></head><body>"
            << "<h1>KeelCore Labs — UCM B2B ANTIVIRUS RC4</h1>"
            << "<p class='ok'>Independent lightweight B2B online-monitor is running.</p>"
            << "<p>Local admin endpoint is active on this service.</p>"
            << "<p><code>http://127.0.0.1:8888/status</code> · <code>http://127.0.0.1:8888/resources</code></p>"
            << "<p class='small'>KeelCore Labs reference: <a href='https://keelcore.org/'>https://keelcore.org/</a></p>"
            << "<p><a href='/status'>status</a> · <a href='/resources'>resource allowlist</a></p>"
            << "</body></html>";
        return h.str();
    }

    std::string statusJson() {
        std::ostringstream s;
        s << "{\n"
            << "  \"module\":\"UCM_B2B_ANTIVIRUS\",\n"
            << "  \"vendor\":\"" << PRODUCT_VENDOR << "\",\n"
            << "  \"reference_url\":\"" << PRODUCT_REFERENCE_URL << "\",\n"
            << "  \"version\":\"4.0-RC4-ARCHIVE-INSPECTOR\",\n"
            << "  \"module_class\":\"INDEPENDENT_B2B_ONLINE_MONITOR\",\n"
            << "  \"organ\":\"ONLINE_SECURITY_GATEWAY\",\n"
            << "  \"port_name\":\"UDB8\",\n"
            << "  \"bind\":\"" << bindHost << ":" << port << "\",\n"
            << "  \"controlled_by\":\"LOCAL_ADMIN_PANEL_AND_TRAY\",\n"
            << "  \"firewall\":\"ACTIVE\",\n"
            << "  \"signatureless_antivirus\":\"ACTIVE\",\n"
            << "  \"stage25_url_lexical_analyzer\":\"ACTIVE\",\n"
            << "  \"redirect_chain_analyzer\":\"ACTIVE\",\n"
            << "  \"tray_wrapper\":\"WINDOWS_SHELL_NOTIFYICON\",\n"
            << "  \"tray_mode\":\"" << ucmModeNameA(g_ucm_mode.load()) << "\",\n"
            << "  \"archive_shallow_inspector\":\"ACTIVE\",\n"
            << "  \"ddos_shield\":\"ACTIVE\",\n"
            << "  \"sandbox\":\"STATIC_V2_MAGIC_MISMATCH_READY\",\n"
            << "  \"quarantine\":\"" << paths.quarantine.string() << "\",\n"
            << "  \"safe_storage\":\"" << paths.safe.string() << "\",\n"
            << "  \"protocol_json\":\"" << paths.protocolJson.string() << "\",\n"
            << "  \"resource_allowlist\":\"" << paths.resourceAllowlist.string() << "\",\n"
            << "  \"resource_allowlist_count\":" << readResourceAllowlist(paths).size() << ",\n"
            << "  \"keys_env\":\"" << paths.keysEnv.string() << "\",\n"
            << "  \"token_index\":\"" << paths.tokenIndex.string() << "\",\n"
            << "  \"token_count\":" << tokens.size() << ",\n"
            << "  \"love_token_path\":\"" << discoverLoveTokenPath(paths).string() << "\",\n"
            << "  \"quarantine_bytes\":" << directoryBytes(paths.quarantine) << ",\n"
            << "  \"safe_bytes\":" << directoryBytes(paths.safe) << ",\n"
            << "  \"cleanup_policy\":\"AGE_7_DAYS_AND_512MB_ROTATION\",\n"
            << "  \"https_connector\":\"WINHTTP_HTTPS_GET_ON_WINDOWS\",\n"
            << "  \"drive_api\":\"ADAPTER_REQUIRED\"\n"
            << "}\n";
        return s.str();
    }

    std::string proxyPac() {
        std::ostringstream p;
        p << "function FindProxyForURL(url, host) {\n"
            << "  if (isPlainHostName(host) || shExpMatch(host, \"127.*\") || host == \"localhost\") return \"DIRECT\";\n"
            << "  return \"PROXY 127.0.0.1:" << port << "\";\n"
            << "}\n";
        return p.str();
    }

    std::string blockPage(const std::string& reason) {
        std::ostringstream h;
        h << "<!doctype html><html><head><meta charset=\"utf-8\"><title>Blocked</title></head><body>"
            << "<h1>UCM B2B BLOCKED / HOLD</h1>"
            << "<p>Reason: <b>" << htmlEscape(reason) << "</b></p>"
            << "<p>Raw external object was not released.</p>"
            << "</body></html>";
        return h.str();
    }


    void handleResourcesSave(socket_t client, const HttpRequest& req) {
        if (req.method != "POST") {
            sendResponse(client, blockPage("METHOD_NOT_ALLOWED"), "text/html; charset=utf-8", 405, "Method Not Allowed");
            return;
        }
        auto body = parseQuery(req.body);
        std::string list = body.count("list") ? body["list"] : "";
        if (list.size() > 65536) {
            sendResponse(client, blockPage("RESOURCE_LIST_TOO_LARGE"), "text/html; charset=utf-8", 413, "Payload Too Large");
            return;
        }
        {
            std::ofstream out(paths.resourceAllowlist, std::ios::binary);
            out << list;
        }
        appendLog(paths, "RESOURCE_ALLOWLIST_UPDATED count=" + std::to_string(readResourceAllowlist(paths).size()));
        std::ostringstream h;
        h << "<!doctype html><html><body><h1>RESOURCE LIST SAVED</h1>"
            << "<p>Allowed hosts: " << readResourceAllowlist(paths).size() << "</p>"
            << "<p><a href='/'>back</a></p>"
            << "</body></html>";
        sendResponse(client, h.str());
    }

    void handleOpen(socket_t client, const HttpRequest& req) {
        auto q = parseQuery(req.query);
        std::string url = q.count("url") ? q["url"] : "";
        std::string allowReason;
        if (!resourceAllowedByList(paths, url, allowReason)) {
            appendLog(paths, "OPEN_RESOURCE_REJECT url=" + urlEncode(url) + " reason=" + allowReason);
            sendResponse(client, blockPage(allowReason));
            return;
        }
        StageResult st2 = analyzer.stage2UrlAndCapability(url);
        appendLog(paths, "OPEN_REQUEST ip=" + req.clientIp + " url=" + urlEncode(url) + " stage2=" + st2.reason);

        if (!st2.pass && st2.verdict == GateVerdict::REJECT) {
            sendResponse(client, blockPage(st2.reason));
            return;
        }

        UrlLexResult lex = analyzeUrl(url);
        appendLog(paths, "STAGE25_URL_LEX_OPEN url=" + urlEncode(url) +
            " verdict=" + verdictToString(lex.verdict) +
            " reason=" + lex.reason);
        if (lex.verdict == GateVerdict::QUARANTINE) {
            notifyTray(lex.verdict, lex.reason, parseUrl(url).host);
            sendResponse(client, blockPage("STAGE25_URL_QUARANTINE_" + lex.reason));
            return;
        }

        ExternalFetcher::FetchResult fr = fetcher.fetchExternal(url);
        bool originalTrusted = false;
        bool finalTrusted = false;
        std::string trustReason;
        originalTrusted = resourceAllowedByList(paths, url, trustReason);
        finalTrusted = resourceAllowedByList(paths, fr.final_url.empty() ? url : fr.final_url, trustReason);

        RedirectChainResult rc = analyzeRedirectChain(
            url,
            fr.final_url.empty() ? url : fr.final_url,
            fr.redirect_count,
            fr.content_type,
            urlPathExtension(fr.final_url.empty() ? url : fr.final_url),
            originalTrusted,
            finalTrusted
        );
        appendLog(paths, "STAGE25_REDIRECT_CHAIN_OPEN url=" + urlEncode(url) +
            " final=" + urlEncode(fr.final_url.empty() ? url : fr.final_url) +
            " verdict=" + verdictToString(rc.verdict) +
            " reason=" + rc.reason);
        if (rc.verdict == GateVerdict::QUARANTINE) {
            notifyTray(rc.verdict, rc.reason, parseUrl(fr.final_url.empty() ? url : fr.final_url).host);
            sendResponse(client, blockPage("STAGE25_REDIRECT_CHAIN_QUARANTINE_" + rc.reason));
            return;
        }
        if (rc.verdict == GateVerdict::HOLD) {
            notifyTray(rc.verdict, rc.reason, parseUrl(fr.final_url.empty() ? url : fr.final_url).host);
        }

        std::string safeHtml;

        if (fr.ok) {
            StageResult content = analyzer.stage2ContentCapability(fr.body);
            safeHtml = analyzer.sanitizeHtmlToSafeView(fr.body);
            appendLog(paths, "CONTENT_ANALYSIS url=" + urlEncode(url) + " result=" + content.reason);
        }
        else if (fr.httpsUnsupported) {
            safeHtml =
                "<!doctype html><html><head><meta charset='utf-8'></head><body>"
                "<h1>UCM B2B SAFE HOLD</h1>"
                "<p>HTTPS resource accepted into route logic, but built-in V1 fetcher has no TLS connector.</p>"
                "<p>On Windows, WinHTTP HTTPS GET is active. On non-Windows, connect TLS/libcurl adapter.</p>"
                "<p>Original URL is not opened directly by browser.</p>"
                "<pre>" + htmlEscape(url) + "</pre></body></html>";
        }
        else {
            safeHtml =
                "<!doctype html><html><head><meta charset='utf-8'></head><body>"
                "<h1>UCM B2B HOLD</h1><p>Fetch failed: " + htmlEscape(fr.status) + "</p>"
                "<pre>" + htmlEscape(url) + "</pre></body></html>";
        }

        std::string token = tokens.makeToken();
        fs::path out = paths.safe / (token + ".html");
        {
            std::ofstream f(out, std::ios::binary);
            f << safeHtml;
        }
        tokens.put(token, out);
        appendLog(paths, "SAFE_VIEW_CREATED token=" + token + " path=" + out.string());

        std::ostringstream h;
        h << "<!doctype html><html><head><meta charset=\"utf-8\"></head><body>"
            << "<h1>SAFE VIEW READY</h1>"
            << "<p>Browser must open internal local artifact only:</p>"
            << "<p><a href=\"/safe/view/" << token << "\">/safe/view/" << token << "</a></p>"
            << "<p>Stage2 verdict: " << htmlEscape(st2.reason) << "</p>"
            << "</body></html>";
        sendResponse(client, h.str());
    }

    void handleDownload(socket_t client, const HttpRequest& req) {
        auto q = parseQuery(req.query);
        std::string url = q.count("url") ? q["url"] : "";
        std::string allowReason;
        if (!resourceAllowedByList(paths, url, allowReason)) {
            appendLog(paths, "DOWNLOAD_RESOURCE_REJECT url=" + urlEncode(url) + " reason=" + allowReason);
            sendResponse(client, blockPage(allowReason));
            return;
        }
        StageResult st2 = analyzer.stage2UrlAndCapability(url);
        if (!st2.pass && st2.verdict == GateVerdict::REJECT) {
            appendLog(paths, "DOWNLOAD_REJECT url=" + urlEncode(url) + " reason=" + st2.reason);
            sendResponse(client, blockPage(st2.reason));
            return;
        }

        UrlLexResult lex = analyzeUrl(url);
        appendLog(paths, "STAGE25_URL_LEX_DOWNLOAD url=" + urlEncode(url) +
            " verdict=" + verdictToString(lex.verdict) +
            " reason=" + lex.reason);
        if (lex.verdict == GateVerdict::QUARANTINE) {
            notifyTray(lex.verdict, lex.reason, parseUrl(url).host);
            sendResponse(client, blockPage("STAGE25_URL_QUARANTINE_" + lex.reason));
            return;
        }

        ExternalFetcher::FetchResult fr = fetcher.fetchExternal(url);

        bool originalTrusted = false;
        bool finalTrusted = false;
        std::string trustReason;
        originalTrusted = resourceAllowedByList(paths, url, trustReason);
        finalTrusted = resourceAllowedByList(paths, fr.final_url.empty() ? url : fr.final_url, trustReason);

        RedirectChainResult rc = analyzeRedirectChain(
            url,
            fr.final_url.empty() ? url : fr.final_url,
            fr.redirect_count,
            fr.content_type,
            urlPathExtension(fr.final_url.empty() ? url : fr.final_url),
            originalTrusted,
            finalTrusted
        );
        appendLog(paths, "STAGE25_REDIRECT_CHAIN_DOWNLOAD url=" + urlEncode(url) +
            " final=" + urlEncode(fr.final_url.empty() ? url : fr.final_url) +
            " verdict=" + verdictToString(rc.verdict) +
            " reason=" + rc.reason);
        if (rc.verdict == GateVerdict::QUARANTINE) {
            notifyTray(rc.verdict, rc.reason, parseUrl(fr.final_url.empty() ? url : fr.final_url).host);
            sendResponse(client, blockPage("STAGE25_REDIRECT_CHAIN_QUARANTINE_" + rc.reason));
            return;
        }
        if (rc.verdict == GateVerdict::HOLD) {
            notifyTray(rc.verdict, rc.reason, parseUrl(fr.final_url.empty() ? url : fr.final_url).host);
        }

        std::string token = tokens.makeToken();
        fs::path qfile = paths.quarantine / (token + ".bin");

        if (!fr.ok) {
            std::ofstream f(qfile.string() + ".hold.txt", std::ios::binary);
            f << "DOWNLOAD HOLD\nURL=" << url << "\nSTATUS=" << fr.status << "\n";
            appendLog(paths, "DOWNLOAD_HOLD token=" + token + " status=" + fr.status);
            sendResponse(client, blockPage("DOWNLOAD_HOLD_" + fr.status));
            return;
        }

        // FIX-BUFFER-1: check quarantine limits BEFORE writing.
        {
            std::error_code ec;
            int qcount = 0;
            for (auto& e : fs::directory_iterator(paths.quarantine, ec)) {
                if (ec) break;
                if (e.is_regular_file(ec)) ++qcount;
            }

            uintmax_t qbytes = directoryBytes(paths.quarantine);

            if (qcount >= 64) {
                appendLog(paths, "QUARANTINE_FULL_COUNT url=" + urlEncode(url));
                notifyTray(GateVerdict::HOLD, "QUARANTINE_FULL_COUNT", parseUrl(url).host);
                sendResponse(client, blockPage("QUARANTINE_FULL_COUNT"),
                    "text/html; charset=utf-8", 503, "Service Unavailable");
                return;
            }
            if (qbytes >= 512ull * 1024ull * 1024ull) {
                appendLog(paths, "QUARANTINE_FULL_SIZE url=" + urlEncode(url));
                notifyTray(GateVerdict::HOLD, "QUARANTINE_FULL_SIZE", parseUrl(url).host);
                sendResponse(client, blockPage("QUARANTINE_FULL_SIZE"),
                    "text/html; charset=utf-8", 503, "Service Unavailable");
                return;
            }
        }

        {
            std::ofstream f(qfile, std::ios::binary);
            f << fr.body;
        }

        StageResult st3 = analyzer.stage3SandboxBehavior(qfile, urlPathExtension(fr.final_url.empty() ? url : fr.final_url));
        appendLog(paths, "DOWNLOAD_STAGE3 token=" + token + " verdict=" + verdictToString(st3.verdict) + " reason=" + st3.reason);
        if (st3.reason.find("STAGE3_ARCHIVE_INSPECT") != std::string::npos) {
            appendLog(paths, "STAGE3_ARCHIVE_INSPECT token=" + token + " verdict=" + verdictToString(st3.verdict) + " reason=" + st3.reason);
        }

        if (st3.verdict == GateVerdict::ADMIT) {
            fs::path safeFile = paths.safe / (token + ".safe.bin");
            fs::copy_file(qfile, safeFile, fs::copy_options::overwrite_existing);
            tokens.put(token, safeFile);
            std::ostringstream h;
            h << "<!doctype html><html><body><h1>SAFE FILE READY</h1>"
                << "<p><a href=\"/safe/file/" << token << "\">/safe/file/" << token << "</a></p>"
                << "<p>Original external URL was fetched by UCM, not by browser.</p>"
                << "</body></html>";
            sendResponse(client, h.str());
        }
        else {
            notifyTray(st3.verdict, st3.reason, parseUrl(fr.final_url.empty() ? url : fr.final_url).host);
            sendResponse(client, blockPage("FILE_NOT_ADMITTED_" + st3.reason));
        }
    }

    void serveSafeView(socket_t client, const std::string& token) {
        fs::path file;
        if (!tokens.get(token, file) || !fs::exists(file)) {
            sendResponse(client, blockPage("SAFE_VIEW_TOKEN_NOT_FOUND"), "text/html; charset=utf-8", 404, "Not Found");
            return;
        }
        std::ifstream in(file, std::ios::binary);
        std::ostringstream ss;
        ss << in.rdbuf();
        sendResponse(client, ss.str(), "text/html; charset=utf-8");
    }

    void serveSafeFile(socket_t client, const std::string& token) {
        fs::path file;
        if (!tokens.get(token, file) || !fs::exists(file)) {
            sendResponse(client, blockPage("SAFE_FILE_TOKEN_NOT_FOUND"), "text/html; charset=utf-8", 404, "Not Found");
            return;
        }
        std::ifstream in(file, std::ios::binary);
        std::ostringstream ss;
        ss << in.rdbuf();
        sendResponse(client, ss.str(), "application/octet-stream");
    }
};


#ifdef _WIN32
static HICON makeTrayIcon(COLORREF color) {
    HDC hdc = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP colorBmp = CreateCompatibleBitmap(hdc, 16, 16);
    HBITMAP oldBmp = (HBITMAP)SelectObject(mem, colorBmp);

    HBRUSH bg = CreateSolidBrush(RGB(20, 20, 20));
    RECT rc{ 0, 0, 16, 16 };
    FillRect(mem, &rc, bg);
    DeleteObject(bg);

    HBRUSH brush = CreateSolidBrush(color);
    HBRUSH oldBrush = (HBRUSH)SelectObject(mem, brush);
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
    HPEN oldPen = (HPEN)SelectObject(mem, pen);
    Ellipse(mem, 2, 2, 14, 14);

    SelectObject(mem, oldPen);
    SelectObject(mem, oldBrush);
    DeleteObject(pen);
    DeleteObject(brush);
    SelectObject(mem, oldBmp);
    DeleteDC(mem);

    HBITMAP maskBmp = CreateBitmap(16, 16, 1, 1, nullptr);
    ICONINFO ii{};
    ii.fIcon = TRUE;
    ii.hbmColor = colorBmp;
    ii.hbmMask = maskBmp;
    HICON icon = CreateIconIndirect(&ii);

    DeleteObject(colorBmp);
    DeleteObject(maskBmp);
    ReleaseDC(nullptr, hdc);
    return icon;
}

static void updateTrayIcon(TrayState state, const std::wstring& tip = L"UCM B2B running") {
    g_tray_state = state;
    if (!g_hwnd) return;

    HICON icon = nullptr;
    if (state == TRAY_GREEN) icon = makeTrayIcon(RGB(0, 180, 70));
    else if (state == TRAY_YELLOW) icon = makeTrayIcon(RGB(220, 180, 0));
    else icon = makeTrayIcon(RGB(210, 40, 40));

    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_UCM_TRAYICON;
    g_nid.hIcon = icon;
    wcsncpy_s(g_nid.szTip, tip.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    DestroyIcon(icon);
}

static void showTrayBalloon(const std::wstring& title, const std::wstring& msg, DWORD infoFlags = NIIF_WARNING) {
    if (!g_hwnd) return;
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_INFO;
    wcsncpy_s(g_nid.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(g_nid.szInfo, msg.c_str(), _TRUNCATE);
    g_nid.dwInfoFlags = infoFlags;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void drainTrayEvents() {
    std::queue<TrayEvent> local;
    {
        std::lock_guard<std::mutex> lock(g_tray_mtx);
        std::swap(local, g_tray_events);
    }

    while (!local.empty()) {
        TrayEvent e = local.front();
        local.pop();
        int mode = g_ucm_mode.load();
        bool suppressBalloons = (mode == UCM_MODE_QUIET || mode == UCM_MODE_PAUSE_ALERTS);

        if (e.verdict == GateVerdict::ADMIT) {
            updateTrayIcon(TRAY_GREEN);
        }
        else if (e.verdict == GateVerdict::HOLD) {
            updateTrayIcon(TRAY_YELLOW, L"UCM B2B: HOLD event");
        }
        else if (e.verdict == GateVerdict::QUARANTINE) {
            updateTrayIcon(TRAY_RED, L"UCM B2B: threat quarantined");
            if (!suppressBalloons) showTrayBalloon(L"UCM: Threat blocked", widenUtf8(e.reason), NIIF_WARNING);
        }
        else if (e.verdict == GateVerdict::REJECT) {
            updateTrayIcon(TRAY_RED, L"UCM B2B: blocked");
            if (!suppressBalloons) showTrayBalloon(L"UCM: Blocked", widenUtf8(e.reason), NIIF_ERROR);
        }
        else if (e.verdict == GateVerdict::DETACH_SOURCE) {
            updateTrayIcon(TRAY_RED, L"UCM B2B: source detached");
            if (!suppressBalloons) showTrayBalloon(L"UCM: Source detached", widenUtf8(e.host), NIIF_ERROR);
        }
    }
}

static void openLogFile() {
    fs::path log = RuntimePaths().immuneLog;
    ShellExecuteW(nullptr, L"open", widenUtf8(log.string()).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

static void showStatusBalloon() {
    std::wstring state = L"GREEN";
    if (g_tray_state == TRAY_YELLOW) state = L"YELLOW";
    if (g_tray_state == TRAY_RED) state = L"RED";
    showTrayBalloon(L"UCM B2B Status", L"UCM B2B — running\\nTray state: " + state, NIIF_INFO);
}

static LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_UCM_TRAYEVENT) {
        drainTrayEvents();
        return 0;
    }

    if (msg == WM_UCM_TRAYICON) {
        if (lParam == WM_RBUTTONUP) {
            HMENU menu = CreatePopupMenu();
            HMENU modeMenu = CreatePopupMenu();
            int mode = g_ucm_mode.load();

            AppendMenuW(modeMenu, MF_STRING | (mode == UCM_MODE_MONITOR ? MF_CHECKED : 0), 1101, L"Monitor");
            AppendMenuW(modeMenu, MF_STRING | (mode == UCM_MODE_STRICT ? MF_CHECKED : 0), 1102, L"Strict");
            AppendMenuW(modeMenu, MF_STRING | (mode == UCM_MODE_QUIET ? MF_CHECKED : 0), 1103, L"Quiet");
            AppendMenuW(modeMenu, MF_STRING | (mode == UCM_MODE_PAUSE_ALERTS ? MF_CHECKED : 0), 1104, L"Pause alerts");

            AppendMenuW(menu, MF_STRING | MF_DISABLED, 1000, L"KeelCore Labs — UCM B2B running");
            AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(menu, MF_POPUP, (UINT_PTR)modeMenu, L"Modes");
            AppendMenuW(menu, MF_STRING, 1001, L"Open log...");
            AppendMenuW(menu, MF_STRING, 1002, L"Status");
            AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(menu, MF_STRING, 1003, L"Exit");

            POINT pt;
            GetCursorPos(&pt);
            SetForegroundWindow(hwnd);
            int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(menu);

            if (cmd == 1001) openLogFile();
            else if (cmd == 1002) showStatusBalloon();
            else if (cmd == 1101 || cmd == 1102 || cmd == 1103 || cmd == 1104) {
                int newMode = UCM_MODE_MONITOR;
                if (cmd == 1102) newMode = UCM_MODE_STRICT;
                else if (cmd == 1103) newMode = UCM_MODE_QUIET;
                else if (cmd == 1104) newMode = UCM_MODE_PAUSE_ALERTS;
                g_ucm_mode.store(newMode);
                showTrayBalloon(L"UCM B2B Mode", std::wstring(L"Mode: ") + ucmModeNameW(newMode), NIIF_INFO);
            }
            else if (cmd == 1003) {
                Shell_NotifyIconW(NIM_DELETE, &g_nid);
                PostQuitMessage(0);
                ExitProcess(0);
            }
            return 0;
        }
    }

    if (msg == WM_DESTROY) {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static int runTrayApp(HINSTANCE hInstance) {
    const wchar_t* cls = L"UCM_B2B_TRAY_WINDOW";
    WNDCLASSW wc{};
    wc.lpfnWndProc = TrayWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = cls;
    RegisterClassW(&wc);

    g_hwnd = CreateWindowExW(0, cls, L"KeelCore Labs UCM B2B", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, hInstance, nullptr);
    if (!g_hwnd) return 1;

    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_UCM_TRAYICON;
    g_nid.hIcon = makeTrayIcon(RGB(0, 180, 70));
    wcsncpy_s(g_nid.szTip, L"KeelCore Labs UCM B2B — running", _TRUNCATE);
    Shell_NotifyIconW(NIM_ADD, &g_nid);
    DestroyIcon(g_nid.hIcon);

    std::thread([]() {
        try {
            UcmServer server;
            server.run();
        }
        catch (...) {
            notifyTray(GateVerdict::REJECT, "UCM_SERVER_FATAL_EXCEPTION", "localhost");
        }
        }).detach();

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
#endif


int main() {
    try {
        UcmServer server;
        server.run();
    }
    catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

#ifdef _WIN32
// UCM_WINMAIN_COMPAT_ENTRY:
// Visual Studio Windows-subsystem projects look for WinMain/wWinMain.
// The UCM server logic stays in main(); this wrapper only forwards startup.
int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE, _In_ PWSTR, _In_ int) {
    return runTrayApp(hInstance);
}
#endif


