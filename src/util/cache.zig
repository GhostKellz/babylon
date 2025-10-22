const std = @import("std");
const zcrypto = @import("zcrypto");
const zpack = @import("zpack");

fn ArrayListManaged(comptime T: type) type {
    return std.array_list.AlignedManaged(T, null);
}

/// Content-addressed storage system for Babylon packages
/// Uses SHA-256 hashes as keys for deterministic, deduplicated storage
pub const ContentAddressedStorage = struct {
    allocator: std.mem.Allocator,
    cache_dir: []const u8,

    const Self = @This();

    pub const ObjectInfo = struct {
        hash: []u8,
        size: u64,

        pub fn deinit(self: *ObjectInfo, allocator: std.mem.Allocator) void {
            allocator.free(self.hash);
        }
    };

    /// Initialize CAS with cache directory
    pub fn init(allocator: std.mem.Allocator, cache_dir: ?[]const u8) !Self {
        // Use XDG_CACHE_HOME/babylon/objects or fallback to ~/.cache/babylon/objects
        const cache_path = if (cache_dir) |dir|
            try allocator.dupe(u8, dir)
        else
            try getDefaultCacheDir(allocator);

        // Ensure cache directory exists
        std.fs.cwd().makePath(cache_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return Self{
            .allocator = allocator,
            .cache_dir = cache_path,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.cache_dir);
    }

    /// Store content in CAS and return its SHA-256 hash
    pub fn store(self: *Self, content: []const u8) ![]const u8 {
        // Calculate SHA-256 hash
        const hash = try self.calculateHash(content);
        defer self.allocator.free(hash);

        // Create object path: cache_dir/objects/ab/cdef1234...
        const object_path = try self.getObjectPath(hash);
        defer self.allocator.free(object_path);

        // Check if already exists
        if (self.exists(hash)) {
            return self.allocator.dupe(u8, hash);
        }

        // Ensure subdirectory exists
        const dir_path = std.fs.path.dirname(object_path) orelse return error.InvalidPath;
        std.fs.cwd().makePath(dir_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        // Write content to temporary file first (atomic operation)
        const temp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{object_path});
        defer self.allocator.free(temp_path);

        {
            const temp_file = try std.fs.cwd().createFile(temp_path, .{});
            defer temp_file.close();
            try temp_file.writeAll(content);
        }

        // Atomically move to final location
        try std.fs.cwd().rename(temp_path, object_path);

        return self.allocator.dupe(u8, hash);
    }

    /// Store compressed content (useful for large packages)
    pub fn storeCompressed(self: *Self, content: []const u8) ![]const u8 {
        // Compress content using zpack
        const compressed = try self.compress(content);
        defer self.allocator.free(compressed);

        return self.store(compressed);
    }

    /// Retrieve content by hash
    pub fn retrieve(self: *Self, hash: []const u8) ![]const u8 {
        if (!self.isValidHash(hash)) {
            return error.InvalidHash;
        }

        const object_path = try self.getObjectPath(hash);
        defer self.allocator.free(object_path);

        const file = std.fs.cwd().openFile(object_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.ObjectNotFound,
            else => return err,
        };
        defer file.close();

        // Read file content
        const file_size = try file.getEndPos();
        if (file_size > 100 * 1024 * 1024) return error.FileTooLarge;

        const content = try self.allocator.alloc(u8, file_size);
        _ = try file.readAll(content);

        // Verify integrity
        const calculated_hash = try self.calculateHash(content);
        defer self.allocator.free(calculated_hash);

        if (!std.mem.eql(u8, hash, calculated_hash)) {
            self.allocator.free(content);
            return error.CorruptedObject;
        }

        return content;
    }

    /// Retrieve and decompress content
    pub fn retrieveDecompressed(self: *Self, hash: []const u8) ![]const u8 {
        const compressed = try self.retrieve(hash);
        defer self.allocator.free(compressed);

        return self.decompress(compressed);
    }

    /// Check if object exists in cache
    pub fn exists(self: *Self, hash: []const u8) bool {
        if (!self.isValidHash(hash)) return false;

        const object_path = self.getObjectPath(hash) catch return false;
        defer self.allocator.free(object_path);

        std.fs.cwd().access(object_path, .{}) catch return false;
        return true;
    }

    /// Get size of cached object
    pub fn getSize(self: *Self, hash: []const u8) !u64 {
        const object_path = try self.getObjectPath(hash);
        defer self.allocator.free(object_path);

        const file = try std.fs.cwd().openFile(object_path, .{});
        defer file.close();

        const stat = try file.stat();
        return stat.size;
    }

    /// Delete object from cache
    pub fn delete(self: *Self, hash: []const u8) !void {
        const object_path = try self.getObjectPath(hash);
        defer self.allocator.free(object_path);

        try std.fs.cwd().deleteFile(object_path);
    }

    /// Clean up cache (remove unreferenced objects older than days)
    pub fn cleanup(self: *Self, days: u32) !void {
        _ = self;
        _ = days;
        // TODO: Implement cache cleanup
        // - Walk through cache directory
        // - Check file modification times
        // - Remove objects older than specified days
        // - Could also implement LRU cleanup based on access times
    }

    /// Get cache statistics
    pub fn getStats(self: *Self) !CacheStats {
        var stats = CacheStats{};

        // Walk cache directory and collect statistics
        const cache_dir = try std.fs.cwd().openDir(self.cache_dir, .{ .iterate = true });
        var walker = try cache_dir.walk(self.allocator);
        defer walker.deinit();

        while (try walker.next()) |entry| {
            if (entry.kind == .file) {
                stats.object_count += 1;
                const file = try entry.dir.openFile(entry.basename, .{});
                defer file.close();
                const stat = try file.stat();
                stats.total_size += stat.size;
            }
        }

        return stats;
    }

    pub fn listObjects(self: *Self, allocator: std.mem.Allocator) !ArrayListManaged(ObjectInfo) {
        var list = ArrayListManaged(ObjectInfo).init(allocator);
        errdefer {
            for (list.items) |*info| info.deinit(allocator);
            list.deinit();
        }

        const objects_path = try std.fmt.allocPrint(allocator, "{s}/objects", .{self.cache_dir});
        defer allocator.free(objects_path);

        var objects_dir = std.fs.cwd().openDir(objects_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return list,
            else => return err,
        };
        defer objects_dir.close();

        var sub_iter = objects_dir.iterate();
        while (try sub_iter.next()) |entry| {
            if (entry.kind != .directory or entry.name.len != 2) continue;

            {
                var subdir = try objects_dir.openDir(entry.name, .{ .iterate = true });
                defer subdir.close();

                var file_iter = subdir.iterate();
                while (try file_iter.next()) |file_entry| {
                    if (file_entry.kind != .file or file_entry.name.len != 62) continue;

                    const object_file = try subdir.openFile(file_entry.name, .{});
                    defer object_file.close();
                    const stat = try object_file.stat();

                    var hash_buf = try allocator.alloc(u8, 64);
                    errdefer allocator.free(hash_buf);
                    @memcpy(hash_buf[0..2], entry.name);
                    @memcpy(hash_buf[2..], file_entry.name);

                    try list.append(.{ .hash = hash_buf, .size = stat.size });
                }
            }
        }

        return list;
    }

    // Private helper methods

    fn calculateHash(self: *Self, content: []const u8) ![]const u8 {
        // Use zcrypto for SHA-256 hashing
        var hash_buffer: [32]u8 = undefined;

        // TODO: Use actual zcrypto SHA-256 implementation
        // For now, use a simple hash placeholder
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(content);
        hasher.final(&hash_buffer);

        // Convert to hex string
        var hex_buffer: [64]u8 = undefined;
        const hex_str = std.fmt.bytesToHex(&hash_buffer, .lower);
        @memcpy(&hex_buffer, &hex_str);

        return self.allocator.dupe(u8, &hex_buffer);
    }

    fn getObjectPath(self: *Self, hash: []const u8) ![]const u8 {
        if (hash.len < 4) return error.InvalidHash;

        // Split hash into subdirectory structure: ab/cdef1234...
        const subdir = hash[0..2];
        const filename = hash[2..];

        return std.fmt.allocPrint(self.allocator, "{s}/objects/{s}/{s}", .{ self.cache_dir, subdir, filename });
    }

    fn isValidHash(self: *Self, hash: []const u8) bool {
        _ = self;
        // SHA-256 hashes are 64 hex characters
        if (hash.len != 64) return false;

        for (hash) |c| {
            if (!std.ascii.isHex(c)) return false;
        }

        return true;
    }

    pub fn normalizeHashInput(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
        var start: usize = 0;
        if (std.mem.indexOfScalar(u8, value, ':')) |idx| {
            start = idx + 1;
        } else if (std.mem.indexOfScalar(u8, value, '-')) |idx| {
            start = idx + 1;
        } else if (value.len > 6 and std.mem.startsWith(u8, value, "sha256")) {
            start = 6;
        }

        const hex = value[start..];
        if (hex.len != 64) return error.InvalidHash;

        const normalized = try allocator.alloc(u8, 64);
        errdefer allocator.free(normalized);

        for (hex, 0..) |byte, idx| {
            if (!std.ascii.isHex(byte)) return error.InvalidHash;
            normalized[idx] = std.ascii.toLower(byte);
        }

        return normalized;
    }

    pub const PruneStats = struct {
        removed: usize = 0,
        kept: usize = 0,
        dry_run: bool = false,
    };

    pub fn prune(self: *Self, allocator: std.mem.Allocator, required_hashes: []const []const u8, dry_run: bool) !PruneStats {
        var stats = PruneStats{ .dry_run = dry_run };

        var required_map = std.AutoHashMap([64]u8, void).init(allocator);
        defer required_map.deinit();

        for (required_hashes) |hash| {
            if (hash.len != 64) continue;
            var key: [64]u8 = undefined;
            @memcpy(key[0..hash.len], hash);
            try required_map.put(key, {});
        }

        const objects_path = try std.fmt.allocPrint(allocator, "{s}/objects", .{self.cache_dir});
        defer allocator.free(objects_path);

        var objects_dir = std.fs.cwd().openDir(objects_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return stats,
            else => return err,
        };
        defer objects_dir.close();

        var sub_iter = objects_dir.iterate();
        while (try sub_iter.next()) |entry| {
            if (entry.kind != .directory) continue;
            if (entry.name.len != 2) continue;

            var keep_dir = false;
            var subdir = try objects_dir.openDir(entry.name, .{ .iterate = true });
            {
                defer subdir.close();
                var file_iter = subdir.iterate();
                while (try file_iter.next()) |file_entry| {
                    if (file_entry.kind != .file) continue;
                    if (file_entry.name.len != 62) continue;

                    var hash_buf: [64]u8 = undefined;
                    @memcpy(hash_buf[0..2], entry.name);
                    @memcpy(hash_buf[2..], file_entry.name);

                    if (required_map.contains(hash_buf)) {
                        stats.kept += 1;
                        keep_dir = true;
                        continue;
                    }

                    stats.removed += 1;
                    if (!dry_run) {
                        try subdir.deleteFile(file_entry.name);
                    }
                }
            }

            if (!keep_dir and !dry_run) {
                objects_dir.deleteDir(entry.name) catch {};
            }
        }

        return stats;
    }

    fn compress(self: *Self, content: []const u8) ![]const u8 {
        // TODO: Use zpack for compression
        // For now, just return original content
        return self.allocator.dupe(u8, content);
    }

    fn decompress(self: *Self, compressed: []const u8) ![]const u8 {
        // TODO: Use zpack for decompression
        // For now, just return original content
        return self.allocator.dupe(u8, compressed);
    }

    fn getDefaultCacheDir(allocator: std.mem.Allocator) ![]const u8 {
        // Try XDG_CACHE_HOME first
        if (std.process.getEnvVarOwned(allocator, "XDG_CACHE_HOME")) |xdg_cache| {
            defer allocator.free(xdg_cache);
            return std.fmt.allocPrint(allocator, "{s}/babylon/objects", .{xdg_cache});
        } else |_| {}

        // Fallback to HOME/.cache
        if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
            defer allocator.free(home);
            return std.fmt.allocPrint(allocator, "{s}/.cache/babylon/objects", .{home});
        } else |_| {}

        // Last resort fallback
        return allocator.dupe(u8, "/tmp/babylon/objects");
    }
};

/// Cache statistics
pub const CacheStats = struct {
    object_count: u64 = 0,
    total_size: u64 = 0,

    pub fn format(self: CacheStats, allocator: std.mem.Allocator) ![]const u8 {
        const size_mb = @as(f64, @floatFromInt(self.total_size)) / (1024.0 * 1024.0);
        return std.fmt.allocPrint(allocator, "Objects: {d}, Total size: {d:.2} MB", .{ self.object_count, size_mb });
    }
};

/// Package cache entry with metadata
pub const PackageEntry = struct {
    hash: []const u8,
    name: []const u8,
    version: []const u8,
    size: u64,
    compressed: bool = false,

    pub fn deinit(self: *PackageEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.hash);
        allocator.free(self.name);
        allocator.free(self.version);
    }
};

/// High-level package cache interface
pub const PackageCache = struct {
    storage: ContentAddressedStorage,
    index: std.StringHashMap(PackageEntry), // package_name:version -> entry

    const Self = @This();

    pub const StoreOptions = struct {
        compressed: bool = false,
        expected_hash: ?[]const u8 = null,
    };

    pub fn init(allocator: std.mem.Allocator, cache_dir: ?[]const u8) !Self {
        return Self{
            .storage = try ContentAddressedStorage.init(allocator, cache_dir),
            .index = std.StringHashMap(PackageEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.index.iterator();
        while (iter.next()) |entry| {
            var pkg_entry = entry.value_ptr;
            pkg_entry.deinit(self.storage.allocator);
            self.storage.allocator.free(entry.key_ptr.*);
        }
        self.index.deinit();
        self.storage.deinit();
    }

    /// Store package content and associate with name/version
    pub fn storePackage(self: *Self, name: []const u8, version: []const u8, content: []const u8, options: StoreOptions) ![]const u8 {
        const hash = if (options.compressed)
            try self.storage.storeCompressed(content)
        else
            try self.storage.store(content);

        errdefer self.storage.allocator.free(hash);

        var normalized_expected: ?[]const u8 = null;
        defer if (normalized_expected) |value| self.storage.allocator.free(value);

        if (options.expected_hash) |expected| {
            normalized_expected = try ContentAddressedStorage.normalizeHashInput(self.storage.allocator, expected);
            if (!std.mem.eql(u8, normalized_expected.?, hash)) {
                self.storage.delete(hash) catch {};
                return error.HashMismatch;
            }
        }

        const key = try std.fmt.allocPrint(self.storage.allocator, "{s}:{s}", .{ name, version });
        defer self.storage.allocator.free(key);

        if (self.index.fetchRemove(key)) |existing| {
            var old_entry = existing.value;
            old_entry.deinit(self.storage.allocator);
            self.storage.allocator.free(existing.key);
        }

        const entry = PackageEntry{
            .hash = try self.storage.allocator.dupe(u8, hash),
            .name = try self.storage.allocator.dupe(u8, name),
            .version = try self.storage.allocator.dupe(u8, version),
            .size = content.len,
            .compressed = options.compressed,
        };

        const stored_key = try self.storage.allocator.dupe(u8, key);
        try self.index.put(stored_key, entry);
        return hash;
    }

    /// Retrieve package content by name and version
    pub fn retrievePackage(self: *Self, name: []const u8, version: []const u8) ![]const u8 {
        const key = try std.fmt.allocPrint(self.storage.allocator, "{s}:{s}", .{ name, version });
        defer self.storage.allocator.free(key);

        const entry = self.index.get(key) orelse return error.PackageNotFound;

        return if (entry.compressed)
            self.storage.retrieveDecompressed(entry.hash)
        else
            self.storage.retrieve(entry.hash);
    }

    /// Check if package exists in cache
    pub fn hasPackage(self: *Self, name: []const u8, version: []const u8) bool {
        const key = std.fmt.allocPrint(self.storage.allocator, "{s}:{s}", .{ name, version }) catch return false;
        defer self.storage.allocator.free(key);

        return self.index.contains(key);
    }
};

// Tests
test "content addressed storage" {
    const allocator = std.testing.allocator;

    var storage = try ContentAddressedStorage.init(allocator, "/tmp/babylon_test");
    defer storage.deinit();

    const test_content = "Hello, Babylon package manager!";

    // Store content
    const hash = try storage.store(test_content);
    defer allocator.free(hash);

    // Verify it exists
    try std.testing.expect(storage.exists(hash));

    // Retrieve and verify
    const retrieved = try storage.retrieve(hash);
    defer allocator.free(retrieved);

    try std.testing.expectEqualStrings(test_content, retrieved);

    // Clean up
    try storage.delete(hash);
    try std.testing.expect(!storage.exists(hash));
}

test "content addressed storage listObjects enumerates entries" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const cache_path = try std.fs.path.join(allocator, &.{ tmp_path, "cas" });
    defer allocator.free(cache_path);

    var storage = try ContentAddressedStorage.init(allocator, cache_path);
    defer storage.deinit();

    const hash_a = try storage.store("alpha");
    defer allocator.free(hash_a);
    const hash_b = try storage.store("bravo");
    defer allocator.free(hash_b);

    var objects = try storage.listObjects(allocator);
    defer {
        for (objects.items) |*info| info.deinit(allocator);
        objects.deinit();
    }

    try std.testing.expectEqual(@as(usize, 2), objects.items.len);

    var seen_alpha = false;
    var seen_bravo = false;
    for (objects.items) |info| {
        if (std.mem.eql(u8, info.hash, hash_a)) seen_alpha = true;
        if (std.mem.eql(u8, info.hash, hash_b)) seen_bravo = true;
    }
    try std.testing.expect(seen_alpha);
    try std.testing.expect(seen_bravo);
}

test "package cache" {
    const allocator = std.testing.allocator;

    var cache = try PackageCache.init(allocator, "/tmp/babylon_test_pkg");
    defer cache.deinit();

    const package_content = "package content for testing";

    // Store package
    const hash = try cache.storePackage("test-pkg", "1.0.0", package_content, .{});
    defer allocator.free(hash);

    // Check if exists
    try std.testing.expect(cache.hasPackage("test-pkg", "1.0.0"));

    // Retrieve package
    const retrieved = try cache.retrievePackage("test-pkg", "1.0.0");
    defer allocator.free(retrieved);

    try std.testing.expectEqualStrings(package_content, retrieved);
}

test "content addressed storage prune removes unreferenced objects" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const cache_path = try std.fs.path.join(allocator, &.{ tmp_path, "cache" });
    defer allocator.free(cache_path);

    var storage = try ContentAddressedStorage.init(allocator, cache_path);
    defer storage.deinit();

    const hash_keep = try storage.store("keep this");
    defer allocator.free(hash_keep);
    const hash_remove = try storage.store("remove this");
    defer allocator.free(hash_remove);

    const required = [_][]const u8{hash_keep};
    const stats = try storage.prune(allocator, required[0..], false);
    try std.testing.expectEqual(@as(usize, 1), stats.kept);
    try std.testing.expectEqual(@as(usize, 1), stats.removed);
    try std.testing.expect(storage.exists(hash_keep));
    try std.testing.expect(!storage.exists(hash_remove));
}

test "package cache validates expected hash" {
    const allocator = std.testing.allocator;

    var cache = try PackageCache.init(allocator, "/tmp/babylon_test_pkg_verify");
    defer cache.deinit();

    const content = "tarball bytes";

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
    const hex = std.fmt.bytesToHex(&digest, .lower);
    const expected = try std.fmt.allocPrint(allocator, "sha256:{s}", .{hex[0..]});
    defer allocator.free(expected);

    const stored = try cache.storePackage("pkg", "0.1.0", content, .{ .expected_hash = expected });
    defer allocator.free(stored);
    try std.testing.expectEqualStrings(hex[0..], stored);

    var bad_hex = hex;
    bad_hex[0] = if (bad_hex[0] == 'a') 'b' else 'a';
    const wrong_expected = try std.fmt.allocPrint(allocator, "sha256:{s}", .{bad_hex[0..]});
    defer allocator.free(wrong_expected);

    try std.testing.expectError(error.HashMismatch, cache.storePackage("pkg", "0.2.0", content, .{ .expected_hash = wrong_expected }));
}
