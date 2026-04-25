#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <cstdlib>
#include <cerrno>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_handle = int;
static constexpr socket_handle invalid_socket_handle = -1;

#define XXH_INLINE_ALL
#include <xxhash.hpp>

namespace fs = std::filesystem;

namespace {

constexpr std::uint64_t max_memory_package_size = 128ull * 1024ull * 1024ull;
constexpr std::size_t max_request_bytes = 16 * 1024;
constexpr int listen_backlog = 32;
constexpr int socket_timeout_seconds = 15;
constexpr int max_connections_per_ip = 8;
constexpr int max_requests_per_minute = 180;
constexpr int max_package_requests_per_minute = 90;

struct Config {
    fs::path root = "client-root";
    fs::path cache = "cache";
    std::string host = "0.0.0.0";
    std::uint16_t port = 1919;
    std::string version = "v1.0.0";
};

struct FileEntry {
    std::string relative_path;
    fs::path absolute_path;
    std::uint64_t size = 0;
    std::uint64_t package_size = 0;
    std::string sha256;
    std::string xxh3_64;
    std::string package_sha256;
    std::string package_xxh3_64;
};

struct MarkRule {
    std::string relative_path;
    std::string version;
    bool force_delete_excess = true;
};

struct MarkedTreeBundle {
    std::string relative_path;
    std::string version;
    std::string archive_name;
    std::string archive_url;
    fs::path archive_path;
    std::string tree_sha256;
    std::string tree_xxh3_64;
    std::string package_sha256;
    std::string package_xxh3_64;
    std::uint64_t package_size = 0;
    std::size_t file_count = 0;
    bool force_delete_excess = true;
};

enum class RouteKind {
    health,
    version_toon,
    checksum_toon,
    package,
    mark_archive,
    static_file
};

struct HttpRequestHead {
    std::string method;
    std::string target;
    std::string http_version;
};

struct ResponseSpec {
    int status = 200;
    std::string reason = "OK";
    std::string content_type = "text/plain; charset=utf-8";
    std::string body_text;
    std::vector<std::uint8_t> body_bytes;
    std::string cache_control = "no-store";
};

struct RouteTarget {
    RouteKind kind = RouteKind::health;
    std::string value;
};

std::string trim_ascii(std::string value);
bool path_has_cache_segment(const fs::path& path);
bool path_is_default_excluded(std::string_view relative_path);

std::string quote(std::string_view value) {
    std::ostringstream out;
    out << '"';
    for (char ch : value) {
        if (ch == '"' || ch == '\\') {
            out << '\\';
        }
        out << ch;
    }
    out << '"';
    return out.str();
}

std::string json_escape(std::string_view value) {
    std::ostringstream out;
    for (unsigned char ch : value) {
        switch (ch) {
        case '\\': out << "\\\\"; break;
        case '"': out << "\\\""; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (ch < 0x20) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << int(ch);
            } else {
                out << ch;
            }
        }
    }
    return out.str();
}

bool is_hex_hash(std::string_view value) {
    if (value.size() != 16 && value.size() != 64) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

bool is_safe_relative_path(std::string_view value) {
    if (value.empty() || value.front() == '/' || value.find('\\') != std::string_view::npos) {
        return false;
    }

    std::size_t start = 0;
    while (start < value.size()) {
        const std::size_t end = value.find('/', start);
        const std::string_view segment = value.substr(start, end == std::string_view::npos ? value.size() - start
                                                                                            : end - start);
        if (segment.empty() || segment == "." || segment == ".." || segment.find(':') != std::string_view::npos) {
            return false;
        }
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1;
    }

    return true;
}

std::string path_to_url_path(const fs::path& path) {
    return path.generic_string();
}

std::string normalize_mark_path(std::string value) {
    value = trim_ascii(std::move(value));
    while (!value.empty() && value.front() == '/') {
        value.erase(value.begin());
    }
    while (!value.empty() && value.back() == '/') {
        value.pop_back();
    }
    if (!is_safe_relative_path(value)) {
        throw std::runtime_error("mark path must be a safe relative directory");
    }
    if (path_has_cache_segment(fs::path(value))) {
        throw std::runtime_error("mark path must not contain cache");
    }
    if (path_is_default_excluded(value)) {
        throw std::runtime_error("mark path is excluded from the fast validation manifest");
    }
    return value;
}

std::string url_decode(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2 < value.size()) {
            const std::string hex{value.substr(i + 1, 2)};
            char* end = nullptr;
            const long decoded = std::strtol(hex.c_str(), &end, 16);
            if (end != hex.c_str() + 2) {
                throw std::runtime_error("bad percent escape");
            }
            result.push_back(static_cast<char>(decoded));
            i += 2;
        } else if (value[i] == '+') {
            result.push_back(' ');
        } else {
            result.push_back(value[i]);
        }
    }
    return result;
}

std::string trim_ascii(std::string value) {
    auto not_space = [](unsigned char ch) { return std::isspace(ch) == 0; };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

bool starts_with_slash(std::string_view value) {
    return !value.empty() && value.front() == '/';
}

bool path_has_cache_segment(const fs::path& path) {
    for (const auto& part : path) {
        auto text = part.generic_string();
        std::ranges::transform(text, text.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        if (text.find("cache") != std::string::npos || text.ends_with(".tmp")) {
            return true;
        }
    }
    return false;
}

std::string normalize_relative_path_text(std::string value) {
    std::ranges::replace(value, '\\', '/');
    while (!value.empty() && value.front() == '/') {
        value.erase(value.begin());
    }
    while (!value.empty() && value.back() == '/') {
        value.pop_back();
    }
    std::ranges::transform(value, value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool path_is_under(std::string_view relative_path, std::string_view root) {
    return relative_path == root
        || (relative_path.size() > root.size()
            && relative_path.starts_with(root)
            && relative_path[root.size()] == '/');
}

bool path_is_default_excluded(std::string_view relative_path) {
    static constexpr std::array<std::string_view, 6> excluded_roots = {
        "csgo/expressions",
        "csgo/maps/workshop",
        "csgo/materials",
        "csgo/models",
        "csgo/sounds",
        "platform"
    };

    const std::string normalized = normalize_relative_path_text(std::string(relative_path));
    for (std::string_view root : excluded_roots) {
        if (path_is_under(normalized, root)) {
            return true;
        }
    }
    return false;
}

bool is_inside(const fs::path& child, const fs::path& parent) {
    const auto child_norm = fs::weakly_canonical(child);
    const auto parent_norm = fs::weakly_canonical(parent);
    auto child_it = child_norm.begin();
    auto parent_it = parent_norm.begin();
    for (; parent_it != parent_norm.end(); ++parent_it, ++child_it) {
        if (child_it == child_norm.end() || *child_it != *parent_it) {
            return false;
        }
    }
    return true;
}

std::string shell_quote(const fs::path& path) {
    const std::string value = path.string();
    std::string escaped = "'";
    for (char ch : value) {
        if (ch == '\'') {
            escaped += "'\\''";
        } else {
            escaped += ch;
        }
    }
    escaped += "'";
    return escaped;
}

std::string timestamp_utc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t raw = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
    gmtime_r(&raw, &utc);
    std::ostringstream out;
    out << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

std::string xxh3_digest_to_hex(XXH64_hash_t digest) {
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << digest;
    return out.str();
}

std::string xxh3_bytes(std::string_view bytes) {
    return xxh3_digest_to_hex(XXH3_64bits(bytes.data(), bytes.size()));
}

std::string xxh3_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("could not open " + path.string());
    }

    XXH3_state_t* state = XXH3_createState();
    if (state == nullptr) {
        throw std::runtime_error("could not allocate xxHash state");
    }

    XXH3_64bits_reset(state);
    std::array<char, 1024 * 1024> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto read = input.gcount();
        if (read > 0 && XXH3_64bits_update(state, buffer.data(), static_cast<std::size_t>(read)) == XXH_ERROR) {
            XXH3_freeState(state);
            throw std::runtime_error("xxHash failed for " + path.string());
        }
    }

    const XXH64_hash_t digest = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    return xxh3_digest_to_hex(digest);
}

std::vector<std::uint8_t> read_file_bytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("could not open " + path.string());
    }
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(bytes.data()), size);
    return bytes;
}

std::string read_text_file_if_exists(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }

    std::ostringstream out;
    out << input.rdbuf();
    return out.str();
}

void write_text_file(const fs::path& path, std::string_view text) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("could not write " + path.string());
    }
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
}

std::string sanitize_token(std::string value) {
    for (char& ch : value) {
        const bool keep = std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '.' || ch == '-' || ch == '_';
        if (!keep) {
            ch = '_';
        }
    }
    return value;
}

bool command_exists_7z() {
    return std::system("command -v 7z >/dev/null 2>&1") == 0;
}

class PackageCache {
public:
    std::optional<std::vector<std::uint8_t>> get(const std::string& sha) {
        std::scoped_lock lock(mutex_);
        auto found = entries_.find(sha);
        if (found == entries_.end()) {
            return std::nullopt;
        }
        ++hits_;
        return found->second;
    }

    void put(const std::string& sha, std::vector<std::uint8_t> bytes) {
        if (bytes.size() > max_memory_package_size) {
            return;
        }
        std::scoped_lock lock(mutex_);
        memory_bytes_ -= entries_[sha].size();
        memory_bytes_ += bytes.size();
        entries_[sha] = std::move(bytes);
    }

    void record_miss() {
        std::scoped_lock lock(mutex_);
        ++misses_;
    }

    void clear() {
        std::scoped_lock lock(mutex_);
        entries_.clear();
        memory_bytes_ = 0;
        hits_ = 0;
        misses_ = 0;
    }

    std::string status() const {
        std::scoped_lock lock(mutex_);
        std::ostringstream out;
        out << "memory packages: " << entries_.size()
            << ", bytes: " << memory_bytes_
            << ", hits: " << hits_
            << ", misses: " << misses_;
        return out.str();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::vector<std::uint8_t>> entries_;
    std::uint64_t memory_bytes_ = 0;
    std::uint64_t hits_ = 0;
    std::uint64_t misses_ = 0;
};

class ContentIndex {
public:
    explicit ContentIndex(Config config) : config_(std::move(config)) {
        load_marks();
        load_existing_manifests();
    }

    const Config& config() const {
        return config_;
    }

    void regenerate(std::optional<std::string> version = std::nullopt) {
        std::scoped_lock regen_lock(regen_mutex_);
        regenerating_.store(true);
        struct RegenGuard {
            std::atomic<bool>& value;
            ~RegenGuard() { value = false; }
        } guard{regenerating_};
        if (version) {
            std::scoped_lock lock(mutex_);
            config_.version = *version;
        }
        const auto active_version = version_value();
        fs::create_directories(config_.root);
        fs::create_directories(files_cache_dir());
        fs::create_directories(marks_cache_dir());

        const std::vector<MarkRule> marks_snapshot = current_marks();
        const std::vector<MarkedTreeBundle> next_marked_bundles = build_marked_bundles(active_version, marks_snapshot);

        std::vector<FileEntry> next_entries;
        const fs::path canonical_root = fs::weakly_canonical(config_.root);
        for (auto iterator = fs::recursive_directory_iterator(config_.root);
             iterator != fs::recursive_directory_iterator();
             ++iterator) {
            const auto& item = *iterator;
            const auto absolute = fs::weakly_canonical(item.path());
            const auto relative = fs::relative(absolute, canonical_root);
            const auto relative_path = path_to_url_path(relative);

            if (item.is_directory()) {
                if (path_has_cache_segment(relative) || path_is_default_excluded(relative_path)) {
                    iterator.disable_recursion_pending();
                }
                continue;
            }
            if (!item.is_regular_file()) {
                continue;
            }
            if (path_has_cache_segment(relative)) {
                continue;
            }
            const auto name = relative.filename().generic_string();
            if (name == "version.toon" || name == "checksum.toon") {
                continue;
            }
            if (path_is_default_excluded(relative_path)) {
                continue;
            }
            if (is_under_mark(relative_path, marks_snapshot)) {
                continue;
            }

            FileEntry entry;
            entry.absolute_path = absolute;
            entry.relative_path = relative_path;
            entry.size = item.file_size();
            entry.xxh3_64 = xxh3_file(absolute);
            load_package_metadata_if_present(entry);
            next_entries.push_back(std::move(entry));
        }

        std::ranges::sort(next_entries, {}, &FileEntry::relative_path);
        const auto version_text = build_version_toon(next_entries, active_version);
        const auto checksum_text = build_checksum_toon(next_entries, next_marked_bundles, active_version);
        write_text_file(config_.root / "version.toon", version_text);
        write_text_file(config_.root / "checksum.toon", checksum_text);
        write_text_file(config_.cache / "version.toon", version_text);
        write_text_file(config_.cache / "checksum.toon", checksum_text);

        std::scoped_lock lock(mutex_);
        entries_ = std::move(next_entries);
        marked_bundles_ = next_marked_bundles;
        version_toon_ = version_text;
        checksum_toon_ = checksum_text;
        generated_at_ = std::chrono::system_clock::now();
    }

    std::vector<FileEntry> entries() const {
        std::scoped_lock lock(mutex_);
        return entries_;
    }

    std::string version_toon() const {
        std::scoped_lock lock(mutex_);
        return version_toon_;
    }

    std::string checksum_toon() const {
        std::scoped_lock lock(mutex_);
        return checksum_toon_;
    }

    bool checksum_ready() const {
        std::scoped_lock lock(mutex_);
        return !checksum_toon_.empty();
    }

    bool regenerating() const {
        return regenerating_.load();
    }

    std::string version_value() const {
        std::scoped_lock lock(mutex_);
        return config_.version;
    }

    std::optional<FileEntry> package_entry(const std::string& sha) const {
        std::scoped_lock lock(mutex_);
        auto found = std::ranges::find(entries_, sha, &FileEntry::xxh3_64);
        if (found == entries_.end()) {
            found = std::ranges::find(entries_, sha, &FileEntry::sha256);
        }
        if (found == entries_.end()) {
            return std::nullopt;
        }
        return *found;
    }

    std::optional<FileEntry> ensure_package_ready(const std::string& sha) {
        auto entry = package_entry(sha);
        if (!entry) {
            return std::nullopt;
        }

        ensure_package(*entry);

        std::scoped_lock lock(mutex_);
        auto found = std::ranges::find(entries_, sha, &FileEntry::sha256);
        if (found != entries_.end()) {
            found->package_size = entry->package_size;
            found->package_sha256 = entry->package_sha256;
        }
        return entry;
    }

    std::optional<MarkedTreeBundle> mark_bundle(const std::string& archive_name) const {
        std::scoped_lock lock(mutex_);
        auto found = std::ranges::find(marked_bundles_, archive_name, &MarkedTreeBundle::archive_name);
        if (found == marked_bundles_.end()) {
            return std::nullopt;
        }
        return *found;
    }

    std::optional<MarkedTreeBundle> ensure_mark_bundle_ready(const std::string& archive_name) {
        auto bundle = mark_bundle(archive_name);
        if (!bundle) {
            return std::nullopt;
        }

        ensure_mark_bundle(*bundle);

        std::scoped_lock lock(mutex_);
        auto found = std::ranges::find(marked_bundles_, archive_name, &MarkedTreeBundle::archive_name);
        if (found != marked_bundles_.end()) {
            found->package_size = bundle->package_size;
            found->package_sha256 = bundle->package_sha256;
        }
        return bundle;
    }

    void add_mark(const std::string& raw_path,
                  std::optional<std::string> version,
                  bool force_delete_excess) {
        const std::string relative_path = normalize_mark_path(raw_path);
        const fs::path absolute = fs::weakly_canonical(config_.root / fs::path(relative_path));
        if (!fs::exists(absolute) || !fs::is_directory(absolute) || !is_inside(absolute, fs::weakly_canonical(config_.root))) {
            throw std::runtime_error("marked path must point at an existing directory under the root");
        }

        std::scoped_lock lock(mutex_);
        for (const MarkRule& mark : marks_) {
            if (mark.relative_path == relative_path) {
                continue;
            }
            if (relative_path.starts_with(mark.relative_path + "/")
                || mark.relative_path.starts_with(relative_path + "/")) {
                throw std::runtime_error("marked paths cannot overlap");
            }
        }

        auto found = std::ranges::find(marks_, relative_path, &MarkRule::relative_path);
        if (found == marks_.end()) {
            marks_.push_back(MarkRule{relative_path, version.value_or(""), force_delete_excess});
        } else {
            if (version) {
                found->version = *version;
            }
            found->force_delete_excess = force_delete_excess;
        }
        std::ranges::sort(marks_, {}, &MarkRule::relative_path);
        save_marks_locked();
    }

    fs::path package_path(const std::string& sha) const {
        return files_cache_dir() / (sha + ".7z");
    }

    std::string status() const {
        std::scoped_lock lock(mutex_);
        std::uint64_t source_bytes = 0;
        std::uint64_t package_bytes = 0;
        for (const auto& entry : entries_) {
            source_bytes += entry.size;
            package_bytes += entry.package_size;
        }
        std::ostringstream out;
        out << "root: " << fs::absolute(config_.root).string() << '\n'
            << "cache: " << fs::absolute(config_.cache).string() << '\n'
            << "listen: " << config_.host << ':' << config_.port << '\n'
            << "version: " << config_.version << '\n'
            << "checksum: " << (regenerating_.load() ? "running" : "idle") << '\n'
            << "marks: " << marks_.size() << '\n'
            << "marked bundles: " << marked_bundles_.size() << '\n'
            << "files: " << entries_.size() << '\n'
            << "source bytes: " << source_bytes << '\n'
            << "package bytes: " << package_bytes;
        return out.str();
    }

private:
    fs::path files_cache_dir() const {
        return config_.cache / "files";
    }

    fs::path marks_cache_dir() const {
        return config_.cache / "marks";
    }

    fs::path marks_config_path() const {
        return config_.cache / "marks.toon";
    }

    std::vector<MarkRule> current_marks() const {
        std::scoped_lock lock(mutex_);
        return marks_;
    }

    static bool is_under_mark(std::string_view relative_path, const std::vector<MarkRule>& marks) {
        for (const MarkRule& mark : marks) {
            if (relative_path == mark.relative_path) {
                return true;
            }
            if (relative_path.size() > mark.relative_path.size()
                && relative_path.starts_with(mark.relative_path)
                && relative_path[mark.relative_path.size()] == '/') {
                return true;
            }
        }
        return false;
    }

    std::vector<FileEntry> collect_mark_files(const MarkRule& mark) const {
        std::vector<FileEntry> files;
        const fs::path mark_root = fs::weakly_canonical(config_.root / fs::path(mark.relative_path));
        const fs::path canonical_root = fs::weakly_canonical(config_.root);
        for (auto iterator = fs::recursive_directory_iterator(mark_root);
             iterator != fs::recursive_directory_iterator();
             ++iterator) {
            const auto& item = *iterator;
            const auto absolute = fs::weakly_canonical(item.path());
            const auto relative = path_to_url_path(fs::relative(absolute, canonical_root));

            if (item.is_directory()) {
                if (path_has_cache_segment(fs::path(relative)) || path_is_default_excluded(relative)) {
                    iterator.disable_recursion_pending();
                }
                continue;
            }
            if (!item.is_regular_file()) {
                continue;
            }
            if (!is_safe_relative_path(relative)) {
                continue;
            }
            if (path_has_cache_segment(fs::path(relative))) {
                continue;
            }
            if (path_is_default_excluded(relative)) {
                continue;
            }
            FileEntry entry;
            entry.absolute_path = absolute;
            entry.relative_path = relative;
            entry.size = item.file_size();
            entry.xxh3_64 = xxh3_file(absolute);
            files.push_back(std::move(entry));
        }
        std::ranges::sort(files, {}, &FileEntry::relative_path);
        return files;
    }

    std::string compute_tree_xxh3_64(const std::vector<FileEntry>& files) const {
        std::ostringstream payload;
        for (const FileEntry& entry : files) {
            payload << entry.relative_path << '\t' << entry.size << '\t' << entry.xxh3_64 << '\n';
        }
        return xxh3_bytes(payload.str());
    }

    fs::path mark_archive_path(std::string_view relative_path, std::string_view tree_sha256) const {
        const std::string slug = sanitize_token(std::string(relative_path));
        return marks_cache_dir() / (slug + "-" + std::string(tree_sha256.substr(0, 16)) + ".7z");
    }

    void ensure_mark_bundle(MarkedTreeBundle& bundle) {
        if (!command_exists_7z()) {
            throw std::runtime_error("7z was not found on PATH; install 7-Zip or add 7z to PATH");
        }
        if (!fs::exists(bundle.archive_path)) {
            fs::create_directories(bundle.archive_path.parent_path());
            const std::string command = "cd " + shell_quote(config_.root)
                + " && 7z a -t7z -mx=9 -bd -y "
                + shell_quote(bundle.archive_path) + " "
                + shell_quote(bundle.relative_path);
            const int code = std::system(command.c_str());
            if (code != 0) {
                throw std::runtime_error("7z failed while packing marked tree " + bundle.relative_path);
            }
        }

        bundle.package_size = fs::file_size(bundle.archive_path);
        bundle.package_xxh3_64 = xxh3_file(bundle.archive_path);
        bundle.archive_name = bundle.archive_path.filename().string();
        bundle.archive_url = "/marks/" + bundle.archive_name;
    }

    void load_mark_bundle_metadata_if_present(MarkedTreeBundle& bundle) const {
        bundle.archive_name = bundle.archive_path.filename().string();
        bundle.archive_url = "/marks/" + bundle.archive_name;
        if (!fs::exists(bundle.archive_path)) {
            return;
        }
        bundle.package_size = fs::file_size(bundle.archive_path);
        bundle.package_xxh3_64 = xxh3_file(bundle.archive_path);
    }

    std::vector<MarkedTreeBundle> build_marked_bundles(std::string_view version, const std::vector<MarkRule>& marks) {
        std::vector<MarkedTreeBundle> bundles;
        for (const MarkRule& mark : marks) {
            const std::vector<FileEntry> files = collect_mark_files(mark);
            if (files.empty()) {
                continue;
            }

            MarkedTreeBundle bundle;
            bundle.relative_path = mark.relative_path;
            bundle.version = mark.version.empty() ? std::string(version) : mark.version;
            bundle.force_delete_excess = mark.force_delete_excess;
            bundle.file_count = files.size();
            bundle.tree_xxh3_64 = compute_tree_xxh3_64(files);
            bundle.archive_path = mark_archive_path(mark.relative_path, bundle.tree_xxh3_64);
            load_mark_bundle_metadata_if_present(bundle);
            bundles.push_back(std::move(bundle));
        }
        std::ranges::sort(bundles, {}, &MarkedTreeBundle::relative_path);
        return bundles;
    }

    void ensure_package(FileEntry& entry) {
        if (!command_exists_7z()) {
            throw std::runtime_error("7z was not found on PATH; install 7-Zip or add 7z to PATH");
        }
        const auto package = package_path(entry.xxh3_64.empty() ? entry.sha256 : entry.xxh3_64);
        if (!fs::exists(package)) {
            const auto tmp = package;
            fs::create_directories(tmp.parent_path());
            const std::string command = "7z a -t7z -mx=9 -bd -y "
                + shell_quote(tmp) + " " + shell_quote(entry.absolute_path);
            const int code = std::system(command.c_str());
            if (code != 0) {
                throw std::runtime_error("7z failed while packing " + entry.relative_path);
            }
        }
        entry.package_size = fs::file_size(package);
        entry.package_xxh3_64 = xxh3_file(package);
    }

    void load_package_metadata_if_present(FileEntry& entry) const {
        const auto package = package_path(entry.xxh3_64.empty() ? entry.sha256 : entry.xxh3_64);
        if (!fs::exists(package)) {
            return;
        }
        entry.package_size = fs::file_size(package);
        entry.package_xxh3_64 = xxh3_file(package);
    }

    std::string build_version_toon(const std::vector<FileEntry>& entries, std::string_view version) const {
        std::ostringstream out;
        out << "version: " << version << '\n';
        out << "generated_at: " << timestamp_utc() << '\n';
        out << "file_count: " << entries.size() << '\n';
        out << "checksum_url: /checksum.toon\n";
        return out.str();
    }

    std::string build_checksum_toon(const std::vector<FileEntry>& entries,
                                    const std::vector<MarkedTreeBundle>& marked_bundles,
                                    std::string_view version) const {
        std::ostringstream out;
        out << "schema: 1\n";
        out << "version: " << version << '\n';
        out << "generated_at: " << timestamp_utc() << '\n';
        out << "root: .\n\n";
        out << "files:\n";
        for (const auto& entry : entries) {
            out << "  - path: " << entry.relative_path << '\n'
                << "    size: " << entry.size << '\n'
                << "    xxh3_64: " << entry.xxh3_64 << '\n'
                << "    package: files/" << entry.xxh3_64 << ".7z\n"
                << "    package_size: " << entry.package_size << '\n'
                << "    package_xxh3_64: " << entry.package_xxh3_64 << '\n';
            if (!entry.sha256.empty()) {
                out << "    sha256: " << entry.sha256 << '\n';
            }
            if (!entry.package_sha256.empty()) {
                out << "    package_sha256: " << entry.package_sha256 << '\n';
            }
            out << "    memory_eligible: unknown\n";
        }
        out << "\nmarks:\n";
        for (const MarkedTreeBundle& bundle : marked_bundles) {
            out << "  - path: " << bundle.relative_path << '\n'
                << "    version: " << bundle.version << '\n'
                << "    package: marks/" << bundle.archive_name << '\n'
                << "    package_size: " << bundle.package_size << '\n'
                << "    package_xxh3_64: " << bundle.package_xxh3_64 << '\n'
                << "    tree_xxh3_64: " << bundle.tree_xxh3_64 << '\n'
                << "    file_count: " << bundle.file_count << '\n'
                << "    force_delete_excess: " << (bundle.force_delete_excess ? "true" : "false") << '\n';
            if (!bundle.package_sha256.empty()) {
                out << "    package_sha256: " << bundle.package_sha256 << '\n';
            }
            if (!bundle.tree_sha256.empty()) {
                out << "    tree_sha256: " << bundle.tree_sha256 << '\n';
            }
        }
        return out.str();
    }

    void load_marks() {
        std::ifstream input(marks_config_path(), std::ios::binary);
        if (!input) {
            return;
        }

        std::string line;
        MarkRule current;
        bool in_marks = false;
        bool has_current = false;
        while (std::getline(input, line)) {
            line = trim_ascii(line);
            if (line.empty() || line.starts_with('#')) {
                continue;
            }
            if (line == "marks:") {
                in_marks = true;
                continue;
            }
            if (!in_marks) {
                continue;
            }
            if (line.starts_with("- ")) {
                if (has_current && !current.relative_path.empty()) {
                    marks_.push_back(current);
                }
                current = {};
                current.force_delete_excess = true;
                has_current = true;
                line = trim_ascii(line.substr(2));
            }

            const auto split = line.find(':');
            if (split == std::string::npos) {
                continue;
            }
            const std::string key = trim_ascii(line.substr(0, split));
            std::string value = trim_ascii(line.substr(split + 1));
            if (!value.empty() && value.front() == '"' && value.back() == '"' && value.size() >= 2) {
                value = value.substr(1, value.size() - 2);
            }

            if (key == "path") {
                current.relative_path = normalize_mark_path(value);
            } else if (key == "version") {
                current.version = value;
            } else if (key == "force_delete_excess") {
                current.force_delete_excess = value != "false";
            }
        }

        if (has_current && !current.relative_path.empty()) {
            marks_.push_back(current);
        }

        std::ranges::sort(marks_, {}, &MarkRule::relative_path);
        marks_.erase(std::unique(marks_.begin(), marks_.end(), [](const MarkRule& lhs, const MarkRule& rhs) {
            return lhs.relative_path == rhs.relative_path;
        }), marks_.end());
    }

    void save_marks_locked() const {
        std::ostringstream out;
        out << "marks:\n";
        for (const MarkRule& mark : marks_) {
            out << "  - path: " << mark.relative_path << '\n'
                << "    version: " << quote(mark.version) << '\n'
                << "    force_delete_excess: " << (mark.force_delete_excess ? "true" : "false") << '\n';
        }
        write_text_file(marks_config_path(), out.str());
    }

    void load_existing_manifests() {
        std::string version_text = read_text_file_if_exists(config_.root / "version.toon");
        std::string checksum_text = read_text_file_if_exists(config_.root / "checksum.toon");

        if (version_text.empty()) {
            version_text = read_text_file_if_exists(config_.cache / "version.toon");
        }
        if (checksum_text.empty()) {
            checksum_text = read_text_file_if_exists(config_.cache / "checksum.toon");
        }

        if (version_text.empty() && checksum_text.empty()) {
            return;
        }

        std::scoped_lock lock(mutex_);
        version_toon_ = std::move(version_text);
        checksum_toon_ = std::move(checksum_text);
    }

    mutable std::mutex mutex_;
    std::mutex regen_mutex_;
    std::atomic<bool> regenerating_ = false;
    Config config_;
    std::vector<FileEntry> entries_;
    std::vector<MarkRule> marks_;
    std::vector<MarkedTreeBundle> marked_bundles_;
    std::string version_toon_;
    std::string checksum_toon_;
    std::chrono::system_clock::time_point generated_at_{};
};

void close_socket(socket_handle socket) {
    close(socket);
}

bool send_all(socket_handle socket, const std::uint8_t* data, std::size_t size) {
    while (size > 0) {
        const auto sent = send(socket, reinterpret_cast<const char*>(data), static_cast<int>(std::min<std::size_t>(size, 64 * 1024)), 0);
        if (sent <= 0) {
            return false;
        }
        data += sent;
        size -= static_cast<std::size_t>(sent);
    }
    return true;
}

bool send_all(socket_handle socket, std::string_view text) {
    return send_all(socket, reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

// Keep slow or wedged clients from pinning a worker forever.
void set_socket_timeouts(socket_handle socket) {
    timeval timeout{};
    timeout.tv_sec = socket_timeout_seconds;
    timeout.tv_usec = 0;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

std::string socket_peer_ip(const sockaddr_in& peer) {
    std::array<char, INET_ADDRSTRLEN> buffer{};
    if (inet_ntop(AF_INET, &peer.sin_addr, buffer.data(), static_cast<socklen_t>(buffer.size())) == nullptr) {
        return "unknown";
    }
    return buffer.data();
}

bool is_supported_http_version(std::string_view value) {
    return value == "HTTP/1.1" || value == "HTTP/1.0";
}

std::optional<HttpRequestHead> parse_request_head(const std::string& raw_request) {
    std::istringstream stream(raw_request);
    HttpRequestHead request;
    if (!(stream >> request.method >> request.target >> request.http_version)) {
        return std::nullopt;
    }
    return request;
}

ResponseSpec make_text_response(int status,
                                std::string reason,
                                std::string body,
                                std::string cache_control = "no-store")
{
    ResponseSpec response;
    response.status = status;
    response.reason = std::move(reason);
    response.content_type = "text/plain; charset=utf-8";
    response.body_text = std::move(body);
    response.cache_control = std::move(cache_control);
    return response;
}

ResponseSpec make_binary_response(std::string content_type,
                                  std::vector<std::uint8_t> body,
                                  std::string cache_control)
{
    ResponseSpec response;
    response.content_type = std::move(content_type);
    response.body_bytes = std::move(body);
    response.cache_control = std::move(cache_control);
    return response;
}

std::string mime_type(const fs::path& path) {
    const auto extension = path.extension().string();
    if (extension == ".html" || extension == ".htm") return "text/html; charset=utf-8";
    if (extension == ".css") return "text/css; charset=utf-8";
    if (extension == ".js") return "application/javascript";
    if (extension == ".json") return "application/json";
    if (extension == ".png") return "image/png";
    if (extension == ".jpg" || extension == ".jpeg") return "image/jpeg";
    if (extension == ".gif") return "image/gif";
    if (extension == ".7z") return "application/x-7z-compressed";
    if (extension == ".toon" || extension == ".txt") return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

class RateLimiter {
public:
    // Small rolling budgets are enough here because the service only exposes a
    // handful of GET endpoints and should degrade predictably under abuse.
    bool allow(const std::string& ip, RouteKind route_kind) {
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(mutex_);
        trim_old(now);

        auto& state = states_[ip];
        if (state.active_connections >= max_connections_per_ip) {
            return false;
        }

        const int budget = route_kind == RouteKind::package
                || route_kind == RouteKind::mark_archive
            ? max_package_requests_per_minute
            : max_requests_per_minute;

        if (static_cast<int>(state.request_times.size()) >= budget) {
            return false;
        }

        state.request_times.push_back(now);
        ++state.active_connections;
        return true;
    }

    void release(const std::string& ip) {
        std::scoped_lock lock(mutex_);
        auto found = states_.find(ip);
        if (found == states_.end()) {
            return;
        }
        if (found->second.active_connections > 0) {
            --found->second.active_connections;
        }
    }

private:
    struct ClientState {
        std::deque<std::chrono::steady_clock::time_point> request_times;
        int active_connections = 0;
    };

    void trim_old(std::chrono::steady_clock::time_point now) {
        const auto cutoff = now - std::chrono::minutes(1);
        for (auto it = states_.begin(); it != states_.end();) {
            auto& queue = it->second.request_times;
            while (!queue.empty() && queue.front() < cutoff) {
                queue.pop_front();
            }
            if (queue.empty() && it->second.active_connections == 0) {
                it = states_.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::mutex mutex_;
    std::unordered_map<std::string, ClientState> states_;
};

class HttpServer {
public:
    HttpServer(ContentIndex& index, PackageCache& package_cache)
        : index_(index), package_cache_(package_cache) {}

    void start() {
        running_ = true;
        worker_ = std::thread([this] { run(); });
    }

    void stop() {
        running_ = false;
        if (listen_socket_ != invalid_socket_handle) {
            shutdown(listen_socket_, SHUT_RDWR);
            close_socket(listen_socket_);
            listen_socket_ = invalid_socket_handle;
        }
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    ~HttpServer() {
        stop();
    }

    int active_sends() const {
        return active_sends_.load();
    }

private:
    static RouteTarget classify_route(std::string target) {
        const auto query_at = target.find('?');
        if (query_at != std::string::npos) {
            target.resize(query_at);
        }

        if (target == "/health") {
            return {RouteKind::health, {}};
        }
        if (target == "/version.toon") {
            return {RouteKind::version_toon, {}};
        }
        if (target == "/checksum.toon") {
            return {RouteKind::checksum_toon, {}};
        }
        if (target.starts_with("/packages/")) {
            return {RouteKind::package, std::move(target)};
        }
        if (target.starts_with("/marks/")) {
            return {RouteKind::mark_archive, std::move(target)};
        }
        return {RouteKind::static_file, std::move(target)};
    }

    void run() {
        listen_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_socket_ == invalid_socket_handle) {
            throw std::runtime_error("could not create listening socket");
        }

        int reuse = 1;
        setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(index_.config().port);
        if (inet_pton(AF_INET, index_.config().host.c_str(), &address.sin_addr) != 1) {
            throw std::runtime_error("invalid --host value; use an IPv4 address");
        }
        if (bind(listen_socket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            throw std::runtime_error("could not bind HTTP socket");
        }
        if (listen(listen_socket_, listen_backlog) != 0) {
            throw std::runtime_error("could not listen on HTTP socket");
        }

        while (running_) {
            sockaddr_in peer{};
            socklen_t peer_size = sizeof(peer);
            const auto client = accept(listen_socket_, reinterpret_cast<sockaddr*>(&peer), &peer_size);
            if (client == invalid_socket_handle) {
                if (running_ && errno != EINTR) {
                    std::cerr << "accept failed: " << std::strerror(errno) << '\n';
                }
                continue;
            }
            set_socket_timeouts(client);
            std::thread([this, client, peer] {
                handle_client(client, peer);
                close_socket(client);
            }).detach();
        }
    }

    void handle_client(socket_handle client, const sockaddr_in& peer) {
        const std::string ip = socket_peer_ip(peer);
        std::string request;
        std::array<char, 8192> buffer{};
        while (request.find("\r\n\r\n") == std::string::npos && request.size() < max_request_bytes) {
            const auto received = recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
            if (received <= 0) {
                return;
            }
            request.append(buffer.data(), static_cast<std::size_t>(received));
        }

        if (request.find("\r\n\r\n") == std::string::npos) {
            send_response(client, make_text_response(413, "Payload Too Large", "Request headers are too large.\n"));
            return;
        }

        const auto parsed = parse_request_head(request);
        if (!parsed) {
            send_response(client, make_text_response(400, "Bad Request", "Malformed request line.\n"));
            return;
        }
        if (parsed->method != "GET") {
            send_response(client, make_text_response(405, "Method Not Allowed", "Only GET is supported.\n"));
            return;
        }
        if (!is_supported_http_version(parsed->http_version)) {
            send_response(client, make_text_response(505, "HTTP Version Not Supported", "Only HTTP/1.0 and HTTP/1.1 are supported.\n"));
            return;
        }
        if (!starts_with_slash(parsed->target)) {
            send_response(client, make_text_response(400, "Bad Request", "Request target must start with '/'.\n"));
            return;
        }
        if (parsed->target.size() > 2048) {
            send_response(client, make_text_response(414, "URI Too Long", "Request target is too long.\n"));
            return;
        }

        const RouteTarget route_target = classify_route(parsed->target);
        if (!rate_limiter_.allow(ip, route_target.kind)) {
            send_response(client, make_text_response(429, "Too Many Requests", "Rate limit exceeded.\n"));
            return;
        }
        struct RateGuard {
            RateLimiter& limiter;
            std::string ip;
            ~RateGuard() { limiter.release(ip); }
        } rate_guard{rate_limiter_, ip};

        try {
            route(client, route_target, ip);
        } catch (const std::exception& error) {
            send_response(client, make_text_response(500, "Internal Server Error", std::string(error.what()) + "\n"));
        }
    }

    void route(socket_handle client, const RouteTarget& target, const std::string& ip) {
        if (target.kind == RouteKind::health) {
            const auto entries = index_.entries();
            std::ostringstream body;
            body << "{\"ok\":true,\"files\":" << entries.size()
                 << ",\"version\":\"" << json_escape(index_.version_value()) << "\""
                 << ",\"checksum_ready\":" << (index_.checksum_ready() ? "true" : "false")
                 << ",\"regenerating\":" << (index_.regenerating() ? "true" : "false")
                 << "}\n";
            ResponseSpec response;
            response.content_type = "application/json";
            response.body_text = body.str();
            send_response(client, response);
            return;
        }
        if (target.kind == RouteKind::version_toon) {
            if (!index_.checksum_ready()) {
                send_response(client, make_text_response(503, "Service Unavailable", "Checksum is still generating.\n"));
                return;
            }
            ResponseSpec response;
            response.body_text = index_.version_toon();
            send_response(client, response);
            return;
        }
        if (target.kind == RouteKind::checksum_toon) {
            if (!index_.checksum_ready()) {
                send_response(client, make_text_response(503, "Service Unavailable", "Checksum is still generating.\n"));
                return;
            }
            ResponseSpec response;
            response.body_text = index_.checksum_toon();
            send_response(client, response);
            return;
        }
        if (target.kind == RouteKind::package) {
            send_package(client, target.value, ip);
            return;
        }
        if (target.kind == RouteKind::mark_archive) {
            send_mark_archive(client, target.value, ip);
            return;
        }
        send_static_file(client, target.value);
    }

    void send_package(socket_handle client, const std::string& target, const std::string& ip) {
        const std::string prefix = "/packages/";
        const std::string suffix = ".7z";
        if (!target.ends_with(suffix)) {
            send_response(client, make_text_response(404, "Not Found", "Package not found.\n"));
            return;
        }
        const auto sha = target.substr(prefix.size(), target.size() - prefix.size() - suffix.size());
        if (!is_hex_hash(sha)) {
            send_response(client, make_text_response(404, "Not Found", "Package not found.\n"));
            return;
        }

        const auto entry = index_.ensure_package_ready(sha);
        if (!entry) {
            send_response(client, make_text_response(404, "Not Found", "Package not found.\n"));
            return;
        }

        ++active_sends_;
        struct SendGuard {
            std::atomic<int>& value;
            ~SendGuard() { --value; }
        } guard{active_sends_};

        if (const auto cached = package_cache_.get(sha)) {
            std::cout << ip << " sending " << sha << ".7z from RAM\n";
            send_response(client, make_binary_response("application/x-7z-compressed", *cached, "public, max-age=300, immutable"));
            return;
        }

        const auto path = index_.package_path(sha);
        const auto size = fs::file_size(path);
        if (size <= max_memory_package_size) {
            auto bytes = read_file_bytes(path);
            package_cache_.put(sha, bytes);
            package_cache_.record_miss();
            std::cout << ip << " sending " << sha << ".7z from disk into RAM cache\n";
            send_response(client, make_binary_response("application/x-7z-compressed", std::move(bytes), "public, max-age=300, immutable"));
            return;
        }

        package_cache_.record_miss();
        std::cout << ip << " streaming " << sha << ".7z from disk\n";
        send_file_stream(client, path, "application/x-7z-compressed", "public, max-age=300, immutable");
    }

    void send_mark_archive(socket_handle client, const std::string& target, const std::string& ip) {
        const std::string prefix = "/marks/";
        const std::string archive_name = target.substr(prefix.size());
        if (archive_name.empty() || archive_name.find('/') != std::string::npos || archive_name.find('\\') != std::string::npos) {
            send_response(client, make_text_response(404, "Not Found", "Marked archive not found.\n"));
            return;
        }

        const auto bundle = index_.ensure_mark_bundle_ready(archive_name);
        if (!bundle) {
            send_response(client, make_text_response(404, "Not Found", "Marked archive not found.\n"));
            return;
        }

        ++active_sends_;
        struct SendGuard {
            std::atomic<int>& value;
            ~SendGuard() { --value; }
        } guard{active_sends_};

        if (bundle->package_size <= max_memory_package_size) {
            if (const auto cached = package_cache_.get(bundle->package_sha256)) {
                std::cout << ip << " sending mark " << bundle->relative_path << " from RAM\n";
                send_response(client, make_binary_response("application/x-7z-compressed", *cached, "public, max-age=300, immutable"));
                return;
            }

            auto bytes = read_file_bytes(bundle->archive_path);
            package_cache_.put(bundle->package_sha256, bytes);
            package_cache_.record_miss();
            std::cout << ip << " sending mark " << bundle->relative_path << " from disk into RAM cache\n";
            send_response(client, make_binary_response("application/x-7z-compressed", std::move(bytes), "public, max-age=300, immutable"));
            return;
        }

        package_cache_.record_miss();
        std::cout << ip << " streaming mark " << bundle->relative_path << " from disk\n";
        send_file_stream(client, bundle->archive_path, "application/x-7z-compressed", "public, max-age=300, immutable");
    }

    void send_static_file(socket_handle client, const std::string& target) {
        const auto decoded = url_decode(target);
        if (!decoded.starts_with('/') || decoded.find('\\') != std::string::npos || decoded.find('\0') != std::string::npos) {
            send_response(client, make_text_response(400, "Bad Request", "Bad path.\n"));
            return;
        }

        fs::path relative = decoded.substr(1);
        if (relative.empty()) {
            relative = "index.html";
        }
        for (const auto& part : relative) {
            if (part == "..") {
                send_response(client, make_text_response(403, "Forbidden", "Path traversal rejected.\n"));
                return;
            }
        }
        if (path_has_cache_segment(relative)) {
            send_response(client, make_text_response(403, "Forbidden", "Cache paths are not served from root.\n"));
            return;
        }

        const auto root = fs::weakly_canonical(index_.config().root);
        const auto resolved = fs::weakly_canonical(root / relative);
        if (!is_inside(resolved, root) || !fs::is_regular_file(resolved)) {
            send_response(client, make_text_response(404, "Not Found", "File not found.\n"));
            return;
        }
        send_file_stream(client, resolved, mime_type(resolved), "public, max-age=60");
    }

    void send_response(socket_handle client, const ResponseSpec& response) {
        const std::size_t body_size = response.body_bytes.empty()
            ? response.body_text.size()
            : response.body_bytes.size();
        std::ostringstream headers;
        headers << "HTTP/1.1 " << response.status << ' ' << response.reason << "\r\n"
                << "Content-Type: " << response.content_type << "\r\n"
                << "Content-Length: " << body_size << "\r\n"
                << "Cache-Control: " << response.cache_control << "\r\n"
                << "X-Content-Type-Options: nosniff\r\n"
                << "X-Frame-Options: DENY\r\n"
                << "Referrer-Policy: no-referrer\r\n"
                << "Content-Security-Policy: default-src 'none'\r\n"
                << "Connection: close\r\n\r\n";
        send_all(client, headers.str());
        if (!response.body_bytes.empty()) {
            send_all(client, response.body_bytes.data(), response.body_bytes.size());
        } else {
            send_all(client, response.body_text);
        }
    }

    void send_file_stream(socket_handle client,
                          const fs::path& path,
                          std::string_view content_type,
                          std::string_view cache_control) {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            send_response(client, make_text_response(404, "Not Found", "File not found.\n"));
            return;
        }
        const auto size = fs::file_size(path);
        std::ostringstream headers;
        headers << "HTTP/1.1 200 OK\r\n"
                << "Content-Type: " << content_type << "\r\n"
                << "Content-Length: " << size << "\r\n"
                << "Cache-Control: " << cache_control << "\r\n"
                << "X-Content-Type-Options: nosniff\r\n"
                << "X-Frame-Options: DENY\r\n"
                << "Referrer-Policy: no-referrer\r\n"
                << "Content-Security-Policy: default-src 'none'\r\n"
                << "Connection: close\r\n\r\n";
        send_all(client, headers.str());

        std::array<std::uint8_t, 64 * 1024> bytes{};
        while (input) {
            input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            const auto read = input.gcount();
            if (read > 0 && !send_all(client, bytes.data(), static_cast<std::size_t>(read))) {
                return;
            }
        }
    }

    ContentIndex& index_;
    PackageCache& package_cache_;
    RateLimiter rate_limiter_;
    std::atomic<bool> running_ = false;
    std::atomic<int> active_sends_ = 0;
    socket_handle listen_socket_ = invalid_socket_handle;
    std::thread worker_;
};

Config parse_args(int argc, char** argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto require_value = [&](std::string_view name) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error(std::string(name) + " requires a value");
            }
            return argv[++i];
        };

        if (arg == "--root") {
            config.root = require_value(arg);
        } else if (arg == "--cache") {
            config.cache = require_value(arg);
        } else if (arg == "--host") {
            config.host = require_value(arg);
        } else if (arg == "--port") {
            const auto port = std::stoi(require_value(arg));
            if (port <= 0 || port > 65535) {
                throw std::runtime_error("--port must be between 1 and 65535");
            }
            config.port = static_cast<std::uint16_t>(port);
        } else if (arg == "--version") {
            config.version = require_value(arg);
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: lieuMt [--root DIR] [--cache DIR] [--host IPv4] [--port PORT] [--version VALUE]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + arg);
        }
    }
    return config;
}

std::optional<std::string> parse_regen_version(const std::string& line) {
    const auto marker = line.find("-version");
    if (marker == std::string::npos) {
        return std::nullopt;
    }
    auto value = trim_ascii(line.substr(marker + 8));
    if (value.starts_with('"') && value.ends_with('"') && value.size() >= 2) {
        value = value.substr(1, value.size() - 2);
    }
    if (value.empty()) {
        throw std::runtime_error("regen -version requires a value");
    }
    return value;
}

struct ParsedMarkCommand {
    std::string relative_path;
    std::optional<std::string> version;
    bool force_delete_excess = false;
};

ParsedMarkCommand parse_mark_command(const std::string& line) {
    std::istringstream stream(line);
    std::string command;
    ParsedMarkCommand parsed;
    stream >> command >> parsed.relative_path;
    if (command != "mark" || parsed.relative_path.empty()) {
        throw std::runtime_error("mark requires a directory path");
    }

    std::string token;
    while (stream >> token) {
        if (token == "--force-delete-excess") {
            parsed.force_delete_excess = true;
            continue;
        }
        if (token == "-version") {
            std::string value;
            if (!(stream >> value)) {
                throw std::runtime_error("mark -version requires a value");
            }
            value = trim_ascii(value);
            if (value.starts_with('"') && !value.ends_with('"')) {
                std::string tail;
                while (stream >> tail) {
                    value += " " + tail;
                    if (!tail.empty() && tail.ends_with('"')) {
                        break;
                    }
                }
            }
            if (value.starts_with('"') && value.ends_with('"') && value.size() >= 2) {
                value = value.substr(1, value.size() - 2);
            }
            if (value.empty()) {
                throw std::runtime_error("mark -version requires a value");
            }
            parsed.version = value;
            continue;
        }
        throw std::runtime_error("unknown mark option: " + token);
    }

    return parsed;
}

std::chrono::system_clock::time_point next_local_noon() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t raw = std::chrono::system_clock::to_time_t(now);
    std::tm local{};
    localtime_r(&raw, &local);
    local.tm_hour = 12;
    local.tm_min = 0;
    local.tm_sec = 0;
    auto noon = std::chrono::system_clock::from_time_t(std::mktime(&local));
    if (noon <= now) {
        local.tm_mday += 1;
        noon = std::chrono::system_clock::from_time_t(std::mktime(&local));
    }
    return noon;
}

void print_help() {
    std::cout
        << "Commands:\n"
        << "  status                    Show root, cache, version, and file counts\n"
        << "  regen                     Rebuild version.toon and checksum.toon\n"
        << "  regen -version \"v1.1.6\"   Set version and rebuild .toon files\n"
        << "  mark /bin/ --force-delete-excess\n"
        << "                           Mark a subtree for whole-archive replacement\n"
        << "  mark /bin/ -version \"v1.1.6\" --force-delete-excess\n"
        << "                           Mark a subtree, store a label, and regenerate\n"
        << "  cache                     Show RAM package cache stats\n"
        << "  cache clear               Empty the RAM package cache\n"
        << "  help                      Show this help\n"
        << "  quit                      Stop the server\n";
}

void console_loop(ContentIndex& index, PackageCache& cache, HttpServer& server, std::atomic<bool>& running) {
    print_help();
    std::string line;
    while (running && std::getline(std::cin, line)) {
        try {
            if (line == "status") {
                std::cout << index.status() << '\n'
                          << "active sends: " << server.active_sends() << '\n';
            } else if (line == "regen" || line.starts_with("regen ")) {
                const auto version = parse_regen_version(line);
                index.regenerate(version);
                std::cout << "Regenerated manifests and packages.\n";
            } else if (line.starts_with("mark ")) {
                const ParsedMarkCommand mark = parse_mark_command(line);
                index.add_mark(mark.relative_path, mark.version, mark.force_delete_excess);
                index.regenerate(mark.version);
                std::cout << "Marked " << normalize_mark_path(mark.relative_path)
                          << " for subtree replacement and regenerated manifests.\n";
            } else if (line == "cache") {
                std::cout << cache.status() << '\n';
            } else if (line == "cache clear") {
                cache.clear();
                std::cout << "RAM package cache cleared.\n";
            } else if (line == "help") {
                print_help();
            } else if (line == "quit" || line == "exit") {
                running = false;
                break;
            } else if (!line.empty()) {
                std::cout << "Unknown command. Type help.\n";
            }
        } catch (const std::exception& error) {
            std::cout << "Error: " << error.what() << '\n';
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        auto config = parse_args(argc, argv);

        ContentIndex index(std::move(config));
        PackageCache cache;
        HttpServer server(index, cache);
        server.start();

        std::cout << "lieuMt listening on http://" << index.config().host << ':' << index.config().port << '\n';
        std::cout << "Serving root " << fs::absolute(index.config().root).string() << '\n';

        std::atomic<bool> running = true;
        std::thread initial_regen([&] {
            try {
                std::cout << "Initial checksum regen starting...\n";
                index.regenerate();
                std::cout << "Initial checksum regen finished.\n";
            } catch (const std::exception& error) {
                std::cout << "Initial checksum regen failed: " << error.what() << '\n';
            }
        });
        std::thread daily_regen([&] {
            auto next = next_local_noon();
            while (running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                if (!running || std::chrono::system_clock::now() < next) {
                    continue;
                }
                try {
                    std::cout << "\nDaily 12:00 regen starting...\n";
                    index.regenerate();
                    std::cout << "Daily regen finished.\n";
                } catch (const std::exception& error) {
                    std::cout << "Daily regen failed: " << error.what() << '\n';
                }
                next = next_local_noon();
            }
        });
        console_loop(index, cache, server, running);
        running = false;
        if (initial_regen.joinable()) {
            initial_regen.join();
        }
        if (daily_regen.joinable()) {
            daily_regen.join();
        }
        server.stop();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal: " << error.what() << '\n';
        return 1;
    }
}
