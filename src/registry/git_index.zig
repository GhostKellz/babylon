const std = @import("std");
const semver = @import("../util/semver.zig");
const registry = @import("registry.zig");

fn ArrayListManaged(comptime T: type) type {
    return std.array_list.AlignedManaged(T, null);
}

pub const GitIndexBackend = struct {
    allocator: std.mem.Allocator,
    registry_id: []const u8,
    index_url: []const u8,
    cache_root: []const u8,
    work_path: []const u8,
    work_path_owned: bool,
    is_local: bool,
    auto_update: bool,

    package_cache: std.StringHashMap(PackageCacheEntry),
    package_names: ArrayListManaged([]const u8),
    packages_enumerated: bool = false,

    const PackageCacheEntry = struct {
        versions: std.ArrayListUnmanaged(CachedVersion) = .{},
        summary: ?[]const u8 = null,

        fn deinit(self: *PackageCacheEntry, allocator: std.mem.Allocator) void {
            for (self.versions.items) |*entry| entry.deinit(allocator);
            self.versions.deinit(allocator);
            if (self.summary) |value| if (value.len != 0) allocator.free(value);
            self.* = undefined;
        }
    };

    const CachedVersion = struct {
        version: semver.SemanticVersion,
        metadata: registry.PackageMetadata,

        fn deinit(self: *CachedVersion, allocator: std.mem.Allocator) void {
            self.version.deinit(allocator);
            self.metadata.deinit(allocator);
            self.* = undefined;
        }
    };

    pub const Options = struct {
        registry_id: []const u8,
        index_url: []const u8,
        cache_root: []const u8,
        auto_update: bool = true,
    };

    pub fn init(allocator: std.mem.Allocator, options: Options) !GitIndexBackend {
        var backend = GitIndexBackend{
            .allocator = allocator,
            .registry_id = try allocator.dupe(u8, options.registry_id),
            .index_url = try allocator.dupe(u8, options.index_url),
            .cache_root = try allocator.dupe(u8, options.cache_root),
            .work_path = &[_]u8{},
            .work_path_owned = false,
            .is_local = false,
            .auto_update = options.auto_update,
            .package_cache = std.StringHashMap(PackageCacheEntry).init(allocator),
            .package_names = ArrayListManaged([]const u8).init(allocator),
            .packages_enumerated = false,
        };
        errdefer backend.deinit();

        backend.is_local = detectLocal(options.index_url);
        if (backend.is_local) {
            if (std.mem.startsWith(u8, backend.index_url, "file://")) {
                const slice = backend.index_url["file://".len..];
                backend.work_path = try backend.allocator.dupe(u8, slice);
                backend.work_path_owned = true;
            } else {
                backend.work_path = backend.index_url;
            }
        } else {
            backend.work_path = try backend.computeWorkPath();
            backend.work_path_owned = true;
        }

        try backend.ensureReady();

        return backend;
    }

    pub fn deinit(self: *GitIndexBackend) void {
        var cache_it = self.package_cache.iterator();
        while (cache_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
            if (entry.key_ptr.*.len != 0) self.allocator.free(entry.key_ptr.*);
        }
        self.package_cache.deinit();

        for (self.package_names.items) |name| {
            if (name.len != 0) self.allocator.free(name);
        }
        self.package_names.deinit();

        if (self.work_path_owned and self.work_path.len != 0) {
            self.allocator.free(self.work_path);
        }

        if (self.registry_id.len != 0) self.allocator.free(self.registry_id);
        if (self.index_url.len != 0) self.allocator.free(self.index_url);
        if (self.cache_root.len != 0) self.allocator.free(self.cache_root);

        self.* = undefined;
    }

    pub fn asBackend(self: *GitIndexBackend) registry.Backend {
        return .{
            .context = self,
            .vtable = &vtable,
        };
    }

    fn computeWorkPath(self: *GitIndexBackend) ![]const u8 {
        const hash = try hashUrl(self.allocator, self.index_url);
        errdefer self.allocator.free(hash);

        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.cache_root, hash });
        errdefer self.allocator.free(path);

        self.allocator.free(hash);
        return path;
    }

    fn ensureReady(self: *GitIndexBackend) !void {
        if (self.is_local) {
            if (!pathExists(self.work_path)) return error.GitIndexNotFound;
            return;
        }

        var git_exists = false;
        if (pathExists(self.work_path)) {
            const git_path = std.fs.path.join(self.allocator, &[_][]const u8{ self.work_path, ".git" }) catch return error.OutOfMemory;
            defer self.allocator.free(git_path);
            git_exists = pathExists(git_path);
        }

        if (!git_exists) {
            try self.cloneRepository();
            return;
        }

        if (self.auto_update) {
            try self.updateRepository();
        }
    }

    fn pathExists(path: []const u8) bool {
        var dir = std.fs.cwd().openDir(path) catch return false;
        dir.close();
        return true;
    }

    fn ensureCacheRoot(self: *GitIndexBackend) !void {
        try std.fs.createDirAbsolute(self.cache_root) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    fn cloneRepository(self: *GitIndexBackend) !void {
        try self.ensureCacheRoot();

        if (pathExists(self.work_path)) {
            try std.fs.deleteTreeAbsolute(self.work_path);
        }

        var argv = ArrayListManaged([]const u8).init(self.allocator);
        defer argv.deinit();

        try argv.appendSlice(&[_][]const u8{
            "git",
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            self.index_url,
            self.work_path,
        });

        try runCommand(self.allocator, argv.items, null);
    }

    fn updateRepository(self: *GitIndexBackend) !void {
        var argv_fetch = [_][]const u8{ "git", "-C", self.work_path, "fetch", "--depth", "1" };
        try runCommand(self.allocator, &argv_fetch, null);

        var argv_reset = [_][]const u8{ "git", "-C", self.work_path, "reset", "--hard", "origin/HEAD" };
        try runCommand(self.allocator, &argv_reset, null);
    }

    fn runCommand(allocator: std.mem.Allocator, argv: [][]const u8, cwd: ?[]const u8) !void {
        var child = std.process.Child.init(argv, allocator);
        defer child.deinit();
        child.cwd = cwd;
        try child.spawn();
        const term = try child.wait();
        switch (term) {
            .Exited => |code| if (code != 0) return error.CommandFailed,
            else => return error.CommandFailed,
        }
    }

    fn detectLocal(url: []const u8) bool {
        return std.mem.startsWith(u8, url, "file://") or std.mem.indexOfScalar(u8, url, ':') == null;
    }

    fn hashUrl(allocator: std.mem.Allocator, url: []const u8) ![]const u8 {
        var hasher = std.hash.Fnv1a64.init();
        hasher.update(url);
        const digest = hasher.final();
        return try std.fmt.allocPrint(allocator, "{x:0>16}", .{digest});
    }

    const vtable = registry.Backend.VTable{
        .listVersions = listVersions,
        .getMetadata = getMetadata,
        .fetchArtifact = fetchArtifact,
        .search = search,
        .packageInfo = packageInfo,
    };

    fn getSelf(context: *anyopaque) *GitIndexBackend {
        return @as(*GitIndexBackend, @ptrCast(context));
    }

    fn listVersions(context: *anyopaque, allocator: std.mem.Allocator, package_name: []const u8) anyerror![]semver.SemanticVersion {
        const self = getSelf(context);
        const cache_entry = self.loadPackage(package_name) catch |err| switch (err) {
            error.PackageNotFound => return error.PackageNotFound,
            else => return err,
        };

        var versions = try allocator.alloc(semver.SemanticVersion, cache_entry.versions.items.len);
        errdefer allocator.free(versions);

        for (cache_entry.versions.items, 0..) |entry, idx| {
            versions[idx] = try entry.version.clone(allocator);
        }

        return versions;
    }

    fn getMetadata(context: *anyopaque, allocator: std.mem.Allocator, package_name: []const u8, version: semver.SemanticVersion) anyerror!registry.PackageMetadata {
        const self = getSelf(context);
        const cache_entry = self.loadPackage(package_name) catch |err| switch (err) {
            error.PackageNotFound => return error.PackageNotFound,
            else => return err,
        };

        for (cache_entry.versions.items) |entry| {
            if (entry.version.order(version) == .eq) {
                return try cloneMetadataForExport(allocator, &entry.metadata);
            }
        }

        return error.PackageNotFound;
    }

    fn fetchArtifact(context: *anyopaque, allocator: std.mem.Allocator, package_name: []const u8, version: semver.SemanticVersion) anyerror!registry.Artifact {
        _ = context;
        _ = allocator;
        _ = package_name;
        _ = version;
        return error.ArtifactUnavailable;
    }

    fn search(context: *anyopaque, allocator: std.mem.Allocator, query: []const u8) anyerror![]registry.SearchResult {
        const self = getSelf(context);
        try self.ensurePackageNames();

        var results = ArrayListManaged(registry.SearchResult).init(allocator);
        errdefer {
            for (results.items) |*item| item.deinit();
            results.deinit();
        }

        for (self.package_names.items) |name| {
            if (query.len != 0 and !registry.containsCaseInsensitive(name, query)) continue;
            const cache_entry = try self.loadPackage(name);
            const latest = cache_entry.versions.items[0];

            var summary_copy: ?[]const u8 = null;
            var summary_owned = false;
            if (cache_entry.summary) |summary| {
                summary_copy = try allocator.dupe(u8, summary);
                summary_owned = true;
            }
            errdefer if (summary_owned) {
                if (summary_copy) |value| allocator.free(value);
            };

            var latest_clone: ?semver.SemanticVersion = try latest.version.clone(allocator);
            var latest_owned = true;
            errdefer if (latest_owned) {
                if (latest_clone) |*v| v.deinit(allocator);
            };

            const registry_copy = try allocator.dupe(u8, self.registry_id);
            var registry_owned = true;
            errdefer if (registry_owned and registry_copy.len != 0) allocator.free(registry_copy);

            const name_copy = try allocator.dupe(u8, name);
            var name_owned = true;
            errdefer if (name_owned and name_copy.len != 0) allocator.free(name_copy);

            const result = registry.SearchResult{
                .registry = registry_copy,
                .name = name_copy,
                .summary = summary_copy,
                .latest_version = latest_clone,
                .allocator = allocator,
            };

            try results.append(result);
            summary_owned = false;
            latest_owned = false;
            registry_owned = false;
            name_owned = false;
            summary_copy = null;
            latest_clone = null;
        }

        return try results.toOwnedSlice();
    }

    fn packageInfo(context: *anyopaque, allocator: std.mem.Allocator, package_name: []const u8) anyerror!registry.PackageInfo {
        const self = getSelf(context);
        const cache_entry = self.loadPackage(package_name) catch |err| switch (err) {
            error.PackageNotFound => return error.PackageNotFound,
            else => return err,
        };

        var versions = try allocator.alloc(semver.SemanticVersion, cache_entry.versions.items.len);
        errdefer allocator.free(versions);

        for (cache_entry.versions.items, 0..) |entry, idx| {
            versions[idx] = try entry.version.clone(allocator);
        }

        var metadata = try cloneMetadataForExport(allocator, &cache_entry.versions.items[0].metadata);
        errdefer metadata.deinit(allocator);

        const registry_copy = try allocator.dupe(u8, self.registry_id);
        errdefer allocator.free(registry_copy);

        return registry.PackageInfo{
            .registry = registry_copy,
            .metadata = metadata,
            .versions = versions,
            .allocator = allocator,
        };
    }

    fn ensurePackageNames(self: *GitIndexBackend) !void {
        if (self.packages_enumerated) return;

        try self.ensureReady();

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const scratch = arena.allocator();

        const packages_path = try std.fs.path.join(scratch, &[_][]const u8{ self.work_path, "packages" });
        defer scratch.free(packages_path);

        var dir = try std.fs.cwd().openDir(packages_path, .{ .iterate = true });
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".json")) continue;
            const name = try self.allocator.dupe(u8, entry.name[0 .. entry.name.len - 5]);
            try self.package_names.append(name);
        }

        self.packages_enumerated = true;
    }

    fn loadPackage(self: *GitIndexBackend, package_name: []const u8) !*PackageCacheEntry {
        try self.ensureReady();

        if (self.package_cache.get(package_name)) |entry| {
            return entry;
        }

        const key = try self.allocator.dupe(u8, package_name);
        errdefer self.allocator.free(key);

        var entry_value = try self.readPackage(package_name);
        errdefer entry_value.deinit(self.allocator);

        const gop = try self.package_cache.getOrPut(key);
        if (!gop.found_existing) {
            gop.value_ptr.* = entry_value;
            return gop.value_ptr;
        }

        self.allocator.free(key);
        entry_value.deinit(self.allocator);
        return gop.value_ptr;
    }

    fn readPackage(self: *GitIndexBackend, package_name: []const u8) !PackageCacheEntry {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const scratch = arena.allocator();

        const sanitized = try sanitizeFileName(scratch, package_name);
        defer scratch.free(sanitized);

        const file_name = try std.fmt.allocPrint(scratch, "{s}.json", .{sanitized});
        defer scratch.free(file_name);

        const file_path = try std.fs.path.join(scratch, &[_][]const u8{ self.work_path, "packages", file_name });
        defer scratch.free(file_path);

        const contents = blk: {
            var file = try std.fs.cwd().openFile(file_path, .{});
            defer file.close();
            const bytes = try file.readToEndAlloc(self.allocator, max_index_size);
            break :blk bytes;
        };
        defer self.allocator.free(contents);

        const parsed = try parseIndex(self.allocator, contents);
        defer parsed.deinit();

        return try self.materializePackage(parsed);
    }

    fn materializePackage(self: *GitIndexBackend, parsed: IndexPackage) !PackageCacheEntry {
        var entry = PackageCacheEntry{};
        errdefer entry.deinit(self.allocator);

        try entry.versions.ensureTotalCapacity(self.allocator, parsed.versions.len);

        for (parsed.versions) |version_spec| {
            var cached = try self.buildCachedVersion(parsed.name, version_spec);
            errdefer cached.deinit(self.allocator);
            try entry.versions.append(self.allocator, cached);
        }

        sortCachedVersions(entry.versions.items);

        if (parsed.versions.len != 0) {
            if (versionHasSummary(parsed.versions[0])) |summary| {
                entry.summary = try self.allocator.dupe(u8, summary);
            }
        }

        return entry;
    }

    fn buildCachedVersion(self: *GitIndexBackend, package_name: []const u8, version_spec: IndexVersion) !CachedVersion {
        var sem = try semver.SemanticVersion.parse(self.allocator, version_spec.version);
        errdefer sem.deinit(self.allocator);

        const spec = try version_spec.toPackageSpec(self.allocator, package_name);
        defer spec.deinit(self.allocator);

        var metadata = try version_spec.toPackageMetadata(spec);
        errdefer metadata.deinit(self.allocator);

        return CachedVersion{
            .version = sem,
            .metadata = metadata,
        };
    }

    const max_index_size = 4 * 1024 * 1024; // 4 MiB

    const IndexPackage = struct {
        name: []const u8,
        versions: []IndexVersion,

        fn deinit(self: IndexPackage, allocator: std.mem.Allocator) void {
            allocator.free(self.name);
            for (self.versions) |version| version.deinit(allocator);
            allocator.free(self.versions);
        }
    };

    const IndexVersion = struct {
        allocator: std.mem.Allocator,
        version: []const u8,
        checksum: ?[]const u8,
        source: IndexSource,
        dependencies: []IndexDependency,
        summary: ?[]const u8,
        artifact: ?[]const u8,

        fn deinit(self: IndexVersion, allocator: std.mem.Allocator) void {
            allocator.free(self.version);
            if (self.checksum) |value| allocator.free(value);
            self.source.deinit(allocator);
            for (self.dependencies) |dep| dep.deinit(allocator);
            allocator.free(self.dependencies);
            if (self.summary) |value| allocator.free(value);
            if (self.artifact) |value| allocator.free(value);
        }

        fn toPackageSpec(self: IndexVersion, allocator: std.mem.Allocator, package_name: []const u8) !PackageSpecWrapper {
            return try PackageSpecWrapper.init(allocator, package_name, self);
        }

        fn toPackageMetadata(self: IndexVersion, spec: PackageSpecWrapper) !registry.PackageMetadata {
            return try materializeMetadata(self.allocator, spec);
        }
    };

    const IndexSource = union(enum) {
        git: Git,
        path: []const u8,
        registry: RegistryRef,
        tarball: Tarball,

        const Git = struct {
            url: []const u8,
            reference_type: registry.GitReferenceType,
            reference: []const u8,
        };

        const RegistryRef = struct {
            registry: []const u8,
            name: []const u8,
            version: []const u8,
        };

        const Tarball = struct {
            url: []const u8,
            hash: ?[]const u8,
        };

        fn deinit(self: IndexSource, allocator: std.mem.Allocator) void {
            switch (self) {
                .git => |git| {
                    allocator.free(git.url);
                    allocator.free(git.reference);
                },
                .path => |value| allocator.free(value),
                .registry => |reg| {
                    allocator.free(reg.registry);
                    allocator.free(reg.name);
                    allocator.free(reg.version);
                },
                .tarball => |tarball| {
                    allocator.free(tarball.url);
                    if (tarball.hash) |hash| allocator.free(hash);
                },
            }
        }
    };

    const IndexDependency = struct {
        name: []const u8,
        constraint: []const u8,
        source: ?IndexSource = null,

        fn deinit(self: IndexDependency, allocator: std.mem.Allocator) void {
            allocator.free(self.name);
            allocator.free(self.constraint);
            if (self.source) |src| src.deinit(allocator);
        }
    };

    const PackageSpecWrapper = struct {
        allocator: std.mem.Allocator,
        spec: registry.PackageSpec,
        deps: []registry.DependencySpec,

        fn init(allocator: std.mem.Allocator, package_name: []const u8, version: IndexVersion) !PackageSpecWrapper {
            const name_copy = try allocator.dupe(u8, package_name);
            errdefer allocator.free(name_copy);

            const deps = try convertDependencies(allocator, version.dependencies);
            errdefer freeDependencySpecs(allocator, deps);

            const spec = registry.PackageSpec{
                .name = name_copy,
                .version = try allocator.dupe(u8, version.version),
                .checksum = if (version.checksum) |value| try allocator.dupe(u8, value) else null,
                .source = try convertSource(allocator, version.source),
                .dependencies = deps,
                .artifact = if (version.artifact) |value| try allocator.dupe(u8, value) else null,
            };

            return PackageSpecWrapper{
                .allocator = allocator,
                .spec = spec,
                .deps = deps,
            };
        }

        fn deinit(self: PackageSpecWrapper, allocator: std.mem.Allocator) void {
            allocator.free(self.spec.name);
            allocator.free(self.spec.version);
            if (self.spec.checksum) |value| allocator.free(value);
            freeSource(allocator, self.spec.source);
            freeDependencySpecs(allocator, self.deps);
            if (self.spec.artifact) |value| allocator.free(value);
        }
    };

    fn convertDependencies(allocator: std.mem.Allocator, deps: []IndexDependency) ![]registry.DependencySpec {
        if (deps.len == 0) return try allocator.alloc(registry.DependencySpec, 0);

        var out = try allocator.alloc(registry.DependencySpec, deps.len);
        errdefer allocator.free(out);

        for (deps, 0..) |dep, idx| {
            out[idx] = try convertDependency(allocator, dep);
        }

        return out;
    }

    fn convertDependency(allocator: std.mem.Allocator, dep: IndexDependency) !registry.DependencySpec {
        var source: ?registry.PackageSourceSpec = null;
        if (dep.source) |src| {
            source = try convertSource(allocator, src);
        }

        return registry.DependencySpec{
            .name = try allocator.dupe(u8, dep.name),
            .constraint = try allocator.dupe(u8, dep.constraint),
            .source = source,
        };
    }

    fn freeDependencySpecs(allocator: std.mem.Allocator, deps: []registry.DependencySpec) void {
        for (deps) |dep| {
            allocator.free(dep.name);
            allocator.free(dep.constraint);
            if (dep.source) |source| freeSource(allocator, source);
        }
        allocator.free(deps);
    }

    fn convertSource(allocator: std.mem.Allocator, source: IndexSource) !registry.PackageSourceSpec {
        return switch (source) {
            .git => |git| registry.PackageSourceSpec{ .git = .{
                .url = try allocator.dupe(u8, git.url),
                .reference_type = git.reference_type,
                .reference = try allocator.dupe(u8, git.reference),
            } },
            .path => |value| registry.PackageSourceSpec{ .path = try allocator.dupe(u8, value) },
            .registry => |reg| registry.PackageSourceSpec{ .registry = .{
                .registry = try allocator.dupe(u8, reg.registry),
                .name = try allocator.dupe(u8, reg.name),
                .version = try allocator.dupe(u8, reg.version),
            } },
            .tarball => |tarball| registry.PackageSourceSpec{ .tarball = .{
                .url = try allocator.dupe(u8, tarball.url),
                .hash = if (tarball.hash) |hash| try allocator.dupe(u8, hash) else null,
            } },
        };
    }

    fn freeSource(allocator: std.mem.Allocator, source: registry.PackageSourceSpec) void {
        switch (source) {
            .git => |git| {
                allocator.free(git.url);
                allocator.free(git.reference);
            },
            .path => |value| allocator.free(value),
            .registry => |reg| {
                allocator.free(reg.registry);
                allocator.free(reg.name);
                allocator.free(reg.version);
            },
            .tarball => |tarball| {
                allocator.free(tarball.url);
                if (tarball.hash) |hash| allocator.free(hash);
            },
        }
    }

    fn materializeMetadata(allocator: std.mem.Allocator, wrapper: PackageSpecWrapper) !registry.PackageMetadata {
        return try registry.materializeMetadataFromSpec(allocator, wrapper.spec);
    }

    fn cloneMetadataForExport(allocator: std.mem.Allocator, metadata: *const registry.PackageMetadata) !registry.PackageMetadata {
        return try registry.cloneMetadataForExport(allocator, metadata);
    }

    fn sanitizeFileName(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
        var buf = try allocator.alloc(u8, name.len);
        errdefer allocator.free(buf);
        for (name, 0..) |c, idx| {
            switch (c) {
                'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => buf[idx] = c,
                else => buf[idx] = '_',
            }
        }
        return buf;
    }

    fn parseIndex(allocator: std.mem.Allocator, contents: []const u8) !IndexPackage {
        var parser = std.json.Parser.init(allocator);
        defer parser.deinit();

        var tree = try parser.parse(contents);
        errdefer tree.deinit();

        return try decodeIndex(allocator, tree.root);
    }

    fn decodeIndex(allocator: std.mem.Allocator, node: std.json.Value) !IndexPackage {
        if (node != .object) return error.InvalidIndex;
        const obj = node.object;

        const name_node = obj.get("name") orelse return error.InvalidIndex;
        if (name_node != .string) return error.InvalidIndex;
        const name = try allocator.dupe(u8, name_node.string);
        errdefer allocator.free(name);

        const versions_node = obj.get("versions") orelse return error.InvalidIndex;
        if (versions_node != .array) return error.InvalidIndex;

        var versions = try allocator.alloc(IndexVersion, versions_node.array.len);
        errdefer allocator.free(versions);

        var idx: usize = 0;
        while (idx < versions_node.array.len) : (idx += 1) {
            versions[idx] = try decodeVersion(allocator, versions_node.array.items[idx]);
        }

        return IndexPackage{ .name = name, .versions = versions };
    }

    fn decodeVersion(allocator: std.mem.Allocator, node: std.json.Value) !IndexVersion {
        if (node != .object) return error.InvalidIndex;
        const obj = node.object;

        const version_str = try requireString(allocator, obj, "version");
        errdefer allocator.free(version_str);

        const checksum = try optionalString(allocator, obj, "checksum");
        errdefer if (checksum) |value| allocator.free(value);

        const source_node = obj.get("source") orelse return error.InvalidIndex;
        const source = try decodeSource(allocator, source_node);
        errdefer source.deinit(allocator);

        const deps_node = obj.get("dependencies");
        const deps = try decodeDependencies(allocator, deps_node);
        errdefer {
            for (deps) |dep| dep.deinit(allocator);
            allocator.free(deps);
        }

        const summary = try optionalString(allocator, obj, "summary");
        errdefer if (summary) |value| allocator.free(value);

        const artifact = try optionalString(allocator, obj, "artifact");
        errdefer if (artifact) |value| allocator.free(value);

        return IndexVersion{
            .allocator = allocator,
            .version = version_str,
            .checksum = checksum,
            .source = source,
            .dependencies = deps,
            .summary = summary,
            .artifact = artifact,
        };
    }

    fn decodeDependencies(allocator: std.mem.Allocator, node_opt: ?std.json.Value) ![]IndexDependency {
        if (node_opt) |node| {
            if (node != .array) return error.InvalidIndex;
            const arr = node.array;
            var list = ArrayListManaged(IndexDependency).init(allocator);
            errdefer {
                for (list.items) |dep| dep.deinit(allocator);
                list.deinit();
            }

            try list.ensureTotalCapacity(arr.len);
            for (arr.items) |item| {
                const dep = try decodeDependency(allocator, item);
                try list.append(dep);
            }

            return try list.toOwnedSlice();
        }
        return allocator.alloc(IndexDependency, 0);
    }

    fn decodeDependency(allocator: std.mem.Allocator, node: std.json.Value) !IndexDependency {
        if (node != .object) return error.InvalidIndex;
        const obj = node.object;

        const name = try requireString(allocator, obj, "name");
        errdefer allocator.free(name);

        const constraint = try requireString(allocator, obj, "constraint");
        errdefer allocator.free(constraint);

        const source_node = obj.get("source");
        var source: ?IndexSource = null;
        if (source_node) |value| {
            source = try decodeSource(allocator, value);
        }

        return IndexDependency{
            .name = name,
            .constraint = constraint,
            .source = source,
        };
    }

    fn decodeSource(allocator: std.mem.Allocator, node: std.json.Value) !IndexSource {
        if (node != .object) return error.InvalidIndex;
        const obj = node.object;

        const kind_node = obj.get("type") orelse return error.InvalidIndex;
        if (kind_node != .string) return error.InvalidIndex;

        const tag = kind_node.string;

        if (std.mem.eql(u8, tag, "git")) {
            const url = try requireString(allocator, obj, "url");
            errdefer allocator.free(url);

            const reference = try requireString(allocator, obj, "reference");
            errdefer allocator.free(reference);

            const reference_type = try parseGitReference(obj.get("reference_type"));

            return IndexSource{ .git = .{
                .url = url,
                .reference_type = reference_type,
                .reference = reference,
            } };
        } else if (std.mem.eql(u8, tag, "path")) {
            const path = try requireString(allocator, obj, "path");
            return IndexSource{ .path = path };
        } else if (std.mem.eql(u8, tag, "registry")) {
            const registry_name = try requireString(allocator, obj, "registry");
            errdefer allocator.free(registry_name);

            const package_name = try requireString(allocator, obj, "name");
            errdefer allocator.free(package_name);

            const version = try requireString(allocator, obj, "version");
            errdefer allocator.free(version);

            return IndexSource{ .registry = .{
                .registry = registry_name,
                .name = package_name,
                .version = version,
            } };
        } else if (std.mem.eql(u8, tag, "tarball")) {
            const url = try requireString(allocator, obj, "url");
            errdefer allocator.free(url);

            const hash = try optionalString(allocator, obj, "hash");
            errdefer if (hash) |value| allocator.free(value);

            return IndexSource{ .tarball = .{ .url = url, .hash = hash } };
        }

        return error.UnsupportedSource;
    }

    fn parseGitReference(node_opt: ?std.json.Value) !registry.GitReferenceType {
        if (node_opt) |node| {
            if (node != .string) return error.InvalidIndex;
            const value = node.string;
            if (std.mem.eql(u8, value, "branch")) return .branch;
            if (std.mem.eql(u8, value, "tag")) return .tag;
            if (std.mem.eql(u8, value, "commit")) return .commit;
            return error.InvalidIndex;
        }
        return .tag;
    }

    fn requireString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
        const node = obj.get(key) orelse return error.InvalidIndex;
        if (node != .string) return error.InvalidIndex;
        return allocator.dupe(u8, node.string);
    }

    fn optionalString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
        const node = obj.get(key) orelse return null;
        if (node == .null) return null;
        if (node != .string) return error.InvalidIndex;
        return allocator.dupe(u8, node.string);
    }

    fn sortCachedVersions(versions: []CachedVersion) void {
        std.sort.heap(CachedVersion, versions, {}, struct {
            fn lessThan(_: void, a: CachedVersion, b: CachedVersion) bool {
                return a.version.order(b.version) == .gt;
            }
        }.lessThan);
    }

    fn versionHasSummary(version: IndexVersion) ?[]const u8 {
        return version.summary;
    }
};

pub fn destroyBackend(context: *anyopaque, allocator: std.mem.Allocator) void {
    const backend = @as(*GitIndexBackend, @ptrCast(context));
    backend.deinit();
    allocator.destroy(backend);
}

pub const GitIndexError = error{
    GitIndexNotFound,
    UnsupportedSource,
    InvalidIndex,
    CommandFailed,
} || std.mem.Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError;
