const std = @import("std");
const semver = @import("../util/semver.zig");

fn ArrayListManaged(comptime T: type) type {
    return std.array_list.AlignedManaged(T, null);
}

const LOCAL_REGISTRY_ID = "local";

pub const PackageSource = union(enum) {
    git: Git,
    path: []const u8,
    registry: RegistryLocation,
    tarball: Tarball,

    pub fn deinit(self: *PackageSource, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .git => |*git| {
                if (git.url.len != 0) allocator.free(git.url);
                if (git.reference.len != 0) allocator.free(git.reference);
            },
            .path => |path| if (path.len != 0) allocator.free(path),
            .registry => |*reg| {
                if (reg.registry.len != 0) allocator.free(reg.registry);
                if (reg.name.len != 0) allocator.free(reg.name);
                if (reg.version.len != 0) allocator.free(reg.version);
            },
            .tarball => |*tarball| {
                if (tarball.url.len != 0) allocator.free(tarball.url);
                if (tarball.hash) |hash| if (hash.len != 0) allocator.free(hash);
            },
        }
        self.* = undefined;
    }
};

pub const Git = struct {
    url: []const u8,
    reference_type: GitReferenceType,
    reference: []const u8,
};

pub const GitReferenceType = enum { branch, tag, commit };

pub const RegistryLocation = struct {
    registry: []const u8,
    name: []const u8,
    version: []const u8,
};

pub const Tarball = struct {
    url: []const u8,
    hash: ?[]const u8 = null,
};

pub const Dependency = struct {
    name: []const u8,
    constraint: semver.VersionConstraint,
    raw_constraint: ?[]const u8,
    source: ?PackageSource,

    pub fn deinit(self: *Dependency, allocator: std.mem.Allocator) void {
        if (self.name.len != 0) allocator.free(self.name);
        self.constraint.deinit(allocator);
        if (self.raw_constraint) |raw| allocator.free(raw);
        if (self.source) |*src| src.deinit(allocator);
        self.* = undefined;
    }
};

pub const PackageMetadata = struct {
    name: []const u8,
    version: semver.SemanticVersion,
    checksum: ?[]const u8,
    source: PackageSource,
    dependencies: []Dependency,

    pub fn deinit(self: *PackageMetadata, allocator: std.mem.Allocator) void {
        if (self.name.len != 0) allocator.free(self.name);
        self.version.deinit(allocator);
        if (self.checksum) |checksum| allocator.free(checksum);
        self.source.deinit(allocator);
        for (self.dependencies) |*dep| dep.deinit(allocator);
        if (self.dependencies.len != 0) allocator.free(self.dependencies);
        self.* = undefined;
    }
};

pub const PackageSpec = struct {
    name: []const u8,
    version: []const u8,
    checksum: ?[]const u8 = null,
    source: PackageSourceSpec,
    dependencies: []const DependencySpec = &[_]DependencySpec{},
    artifact: ?[]const u8 = null,
};

pub const PackageSourceSpec = union(enum) {
    git: GitSpec,
    path: []const u8,
    registry: RegistrySpec,
    tarball: TarballSpec,
};

pub const GitSpec = struct {
    url: []const u8,
    reference_type: GitReferenceType,
    reference: []const u8,
};

pub const RegistrySpec = struct {
    registry: []const u8,
    name: []const u8,
    version: []const u8,
};

pub const TarballSpec = struct {
    url: []const u8,
    hash: ?[]const u8 = null,
};

pub const DependencySpec = struct {
    name: []const u8,
    constraint: []const u8,
    source: ?PackageSourceSpec = null,
};

pub const Artifact = struct {
    registry: []const u8 = &[_]u8{},
    bytes: []u8,
    checksum: ?[]const u8 = null,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Artifact) void {
        if (self.registry.len != 0) self.allocator.free(self.registry);
        if (self.bytes.len != 0) self.allocator.free(self.bytes);
        if (self.checksum) |hash| if (hash.len != 0) self.allocator.free(hash);
        self.* = undefined;
    }
};

pub const SearchResult = struct {
    registry: []const u8,
    name: []const u8,
    summary: ?[]const u8 = null,
    latest_version: ?semver.SemanticVersion = null,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *SearchResult) void {
        if (self.registry.len != 0) self.allocator.free(self.registry);
        if (self.name.len != 0) self.allocator.free(self.name);
        if (self.summary) |value| if (value.len != 0) self.allocator.free(value);
        if (self.latest_version) |*vers| vers.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const PackageInfo = struct {
    registry: []const u8,
    metadata: PackageMetadata,
    versions: []semver.SemanticVersion,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PackageInfo) void {
        if (self.registry.len != 0) self.allocator.free(self.registry);
        self.metadata.deinit(self.allocator);
        for (self.versions) |*vers| vers.deinit(self.allocator);
        if (self.versions.len != 0) self.allocator.free(self.versions);
        self.* = undefined;
    }
};

pub const Backend = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        listVersions: *const fn (context: *anyopaque, allocator: std.mem.Allocator, package_name: []const u8) anyerror![]semver.SemanticVersion,
        getMetadata: *const fn (context: *anyopaque, allocator: std.mem.Allocator, package_name: []const u8, version: semver.SemanticVersion) anyerror!PackageMetadata,
        fetchArtifact: *const fn (context: *anyopaque, allocator: std.mem.Allocator, package_name: []const u8, version: semver.SemanticVersion) anyerror!Artifact,
        search: *const fn (context: *anyopaque, allocator: std.mem.Allocator, query: []const u8) anyerror![]SearchResult,
        packageInfo: *const fn (context: *anyopaque, allocator: std.mem.Allocator, package_name: []const u8) anyerror!PackageInfo,
    };
};

pub const BackendRegistration = struct {
    id: []const u8,
    backend: Backend,
    priority: u32 = 10,
    owned: bool = false,
    context_allocator: ?std.mem.Allocator = null,
    deinitFn: ?*const fn (context: *anyopaque, allocator: std.mem.Allocator) void = null,
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    packages: std.StringHashMap(PackageRecord),
    backends: ArrayListManaged(BackendEntry),

    pub const PackageRecord = struct {
        versions: ArrayListManaged(Entry),

        pub fn deinit(self: *PackageRecord, allocator: std.mem.Allocator) void {
            for (self.versions.items) |*entry| entry.deinit(allocator);
            self.versions.deinit();
            self.* = undefined;
        }

        pub fn init(allocator: std.mem.Allocator) PackageRecord {
            return .{ .versions = ArrayListManaged(Entry).init(allocator) };
        }
    };

    const BackendEntry = struct {
        id: []const u8,
        priority: u32,
        backend: Backend,
        owned: bool,
        context_allocator: std.mem.Allocator,
        deinitFn: ?*const fn (context: *anyopaque, allocator: std.mem.Allocator) void,
    };

    pub const Entry = struct {
        version: semver.SemanticVersion,
        metadata: PackageMetadata,
        artifact: ?[]u8 = null,

        pub fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
            self.version.deinit(allocator);
            self.metadata.deinit(allocator);
            if (self.artifact) |bytes| if (bytes.len != 0) allocator.free(bytes);
            self.* = undefined;
        }
    };

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{
            .allocator = allocator,
            .packages = std.StringHashMap(PackageRecord).init(allocator),
            .backends = ArrayListManaged(BackendEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Registry) void {
        var it = self.packages.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.packages.deinit();

        for (self.backends.items) |entry| {
            if (entry.owned) {
                if (entry.deinitFn) |func| {
                    func(entry.backend.context, entry.context_allocator);
                }
            }
            if (entry.id.len != 0) self.allocator.free(entry.id);
        }
        self.backends.deinit();
        self.* = undefined;
    }

    pub fn registerBackend(self: *Registry, registration: BackendRegistration) !void {
        const context_allocator = registration.context_allocator orelse self.allocator;

        if (self.findBackendIndex(registration.id)) |idx| {
            var entry = &self.backends.items[idx];

            if (entry.owned and entry.deinitFn) |func| {
                func(entry.backend.context, entry.context_allocator);
            }

            if (entry.id.len != 0) self.allocator.free(entry.id);

            entry.id = try self.allocator.dupe(u8, registration.id);
            entry.priority = registration.priority;
            entry.backend = registration.backend;
            entry.owned = registration.owned;
            entry.context_allocator = context_allocator;
            entry.deinitFn = registration.deinitFn;

            self.sortBackends();
            return;
        }

        const id_copy = try self.allocator.dupe(u8, registration.id);
        errdefer self.allocator.free(id_copy);

        try self.backends.append(.{
            .id = id_copy,
            .priority = registration.priority,
            .backend = registration.backend,
            .owned = registration.owned,
            .context_allocator = context_allocator,
            .deinitFn = registration.deinitFn,
        });

        self.sortBackends();
    }

    fn findBackendIndex(self: *Registry, id: []const u8) ?usize {
        for (self.backends.items, 0..) |entry, idx| {
            if (std.mem.eql(u8, entry.id, id)) {
                return idx;
            }
        }
        return null;
    }

    fn sortBackends(self: *Registry) void {
        std.sort.heap(BackendEntry, self.backends.items, {}, struct {
            fn lessThan(_: void, a: BackendEntry, b: BackendEntry) bool {
                return a.priority < b.priority;
            }
        }.lessThan);
    }

    pub fn addPackage(self: *Registry, spec: PackageSpec) !void {
        var metadata = try self.cloneMetadata(spec);
        errdefer metadata.deinit(self.allocator);

        const key = try self.allocator.dupe(u8, metadata.name);
        errdefer self.allocator.free(key);

        const result = try self.packages.getOrPut(key);
        if (!result.found_existing) {
            result.value_ptr.* = PackageRecord.init(self.allocator);
        } else {
            self.allocator.free(key);
        }

        var entry = Entry{
            .version = try metadata.version.clone(self.allocator),
            .metadata = metadata,
            .artifact = if (spec.artifact) |blob| try cloneOwnedBytes(self.allocator, blob) else null,
        };
        errdefer entry.deinit(self.allocator);

        const versions = &result.value_ptr.versions;
        const existing_index = findEntryIndex(versions.items, entry.version);
        if (existing_index) |idx| {
            versions.items[idx].deinit(self.allocator);
            versions.items[idx] = entry;
        } else {
            try versions.append(entry);
            sortEntries(versions.items);
        }
    }

    pub fn getPackageVersions(self: *Registry, allocator: std.mem.Allocator, package_name: []const u8) ![]semver.SemanticVersion {
        if (self.packages.get(package_name)) |record| {
            if (record.versions.items.len == 0) return error.PackageNotFound;
            var out = try allocator.alloc(semver.SemanticVersion, record.versions.items.len);
            errdefer allocator.free(out);
            for (record.versions.items, 0..) |entry, idx| {
                out[idx] = try entry.version.clone(allocator);
            }
            return out;
        }

        for (self.backends.items) |entry| {
            const versions = entry.backend.vtable.listVersions(entry.backend.context, allocator, package_name) catch |err| switch (err) {
                error.PackageNotFound => continue,
                else => return err,
            };

            if (versions.len != 0) {
                return versions;
            } else {
                allocator.free(versions);
            }
        }

        return error.PackageNotFound;
    }

    pub fn getPackageMetadata(self: *Registry, allocator: std.mem.Allocator, package_name: []const u8, version: semver.SemanticVersion) !PackageMetadata {
        if (self.packages.get(package_name)) |record| {
            for (record.versions.items) |entry| {
                if (entry.version.order(version) == .eq) {
                    return try cloneMetadataForExport(allocator, &entry.metadata);
                }
            }
        }

        for (self.backends.items) |entry| {
            const metadata = entry.backend.vtable.getMetadata(entry.backend.context, allocator, package_name, version) catch |err| switch (err) {
                error.PackageNotFound => continue,
                else => return err,
            };
            return metadata;
        }

        return error.PackageNotFound;
    }

    pub fn fetchArtifact(self: *Registry, allocator: std.mem.Allocator, package_name: []const u8, version: semver.SemanticVersion) !Artifact {
        if (self.packages.get(package_name)) |record| {
            for (record.versions.items) |entry| {
                if (entry.version.order(version) == .eq) {
                    if (entry.artifact) |blob| {
                        const bytes = try allocator.dupe(u8, blob);
                        errdefer if (bytes.len != 0) allocator.free(bytes);

                        const checksum = try cloneOptional(allocator, entry.metadata.checksum);
                        errdefer if (checksum) |value| if (value.len != 0) allocator.free(value);

                        const registry_copy = try allocator.dupe(u8, LOCAL_REGISTRY_ID);
                        errdefer if (registry_copy.len != 0) allocator.free(registry_copy);

                        return Artifact{
                            .registry = registry_copy,
                            .bytes = bytes,
                            .checksum = checksum,
                            .allocator = allocator,
                        };
                    }
                    break;
                }
            }
        }

        for (self.backends.items) |entry_desc| {
            var artifact = entry_desc.backend.vtable.fetchArtifact(entry_desc.backend.context, allocator, package_name, version) catch |err| switch (err) {
                error.PackageNotFound => continue,
                error.ArtifactUnavailable => continue,
                else => return err,
            };

            if (artifact.registry.len != 0) {
                if (!std.mem.eql(u8, artifact.registry, entry_desc.id)) {
                    artifact.allocator.free(artifact.registry);
                    artifact.registry = try allocator.dupe(u8, entry_desc.id);
                }
            } else {
                artifact.registry = try allocator.dupe(u8, entry_desc.id);
            }

            artifact.allocator = allocator;
            return artifact;
        }

        return error.PackageNotFound;
    }

    pub fn search(self: *Registry, allocator: std.mem.Allocator, query: []const u8) ![]SearchResult {
        var results = ArrayListManaged(SearchResult).init(allocator);
        errdefer {
            for (results.items) |*item| item.deinit();
            results.deinit();
        }

        var it = self.packages.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            if (query.len != 0 and !containsCaseInsensitive(name, query)) continue;

            const registry_copy = try allocator.dupe(u8, LOCAL_REGISTRY_ID);
            var registry_owned = true;
            errdefer if (registry_owned and registry_copy.len != 0) allocator.free(registry_copy);

            const name_copy = try allocator.dupe(u8, name);
            var name_owned = true;
            errdefer if (name_owned and name_copy.len != 0) allocator.free(name_copy);

            var latest_version: ?semver.SemanticVersion = null;
            if (entry.value_ptr.versions.items.len != 0) {
                latest_version = try entry.value_ptr.versions.items[0].version.clone(allocator);
            }

            if (latest_version) |*vers| {
                errdefer vers.deinit(allocator);
            }

            const result = SearchResult{
                .registry = registry_copy,
                .name = name_copy,
                .summary = null,
                .latest_version = latest_version,
                .allocator = allocator,
            };

            try results.append(result);
            latest_version = null;
            registry_owned = false;
            name_owned = false;
        }

        for (self.backends.items) |entry_desc| {
            const backend_results = entry_desc.backend.vtable.search(entry_desc.backend.context, allocator, query) catch |err| switch (err) {
                error.SearchUnsupported => continue,
                error.PackageNotFound => continue,
                else => return err,
            };

            const base_len = results.items.len;
            for (backend_results) |res| {
                try results.append(res);
            }

            allocator.free(backend_results);

            for (results.items[base_len..]) |*res_ptr| {
                if (!std.mem.eql(u8, res_ptr.registry, entry_desc.id)) {
                    if (res_ptr.registry.len != 0) res_ptr.allocator.free(res_ptr.registry);
                    res_ptr.registry = try res_ptr.allocator.dupe(u8, entry_desc.id);
                }
            }
        }

        return try results.toOwnedSlice();
    }

    pub fn packageInfo(self: *Registry, allocator: std.mem.Allocator, package_name: []const u8) !PackageInfo {
        if (self.packages.get(package_name)) |record| {
            if (record.versions.items.len == 0) return error.PackageNotFound;

            var metadata = try cloneMetadataForExport(allocator, &record.versions.items[0].metadata);
            errdefer metadata.deinit(allocator);

            var versions = try allocator.alloc(semver.SemanticVersion, record.versions.items.len);
            errdefer allocator.free(versions);
            var version_count: usize = 0;
            errdefer {
                var i: usize = 0;
                while (i < version_count) : (i += 1) {
                    versions[i].deinit(allocator);
                }
            }

            for (record.versions.items, 0..) |entry, idx| {
                versions[idx] = try entry.version.clone(allocator);
                version_count = idx + 1;
            }

            const registry_copy = try allocator.dupe(u8, LOCAL_REGISTRY_ID);
            errdefer allocator.free(registry_copy);

            return PackageInfo{
                .registry = registry_copy,
                .metadata = metadata,
                .versions = versions,
                .allocator = allocator,
            };
        }

        for (self.backends.items) |entry_desc| {
            var info = entry_desc.backend.vtable.packageInfo(entry_desc.backend.context, allocator, package_name) catch |err| switch (err) {
                error.PackageNotFound => continue,
                error.InfoUnsupported => try self.derivePackageInfoFromBackend(allocator, entry_desc, package_name),
                else => return err,
            };

            if (!std.mem.eql(u8, info.registry, entry_desc.id)) {
                if (info.registry.len != 0) info.allocator.free(info.registry);
                info.registry = try allocator.dupe(u8, entry_desc.id);
            }

            info.allocator = allocator;
            return info;
        }

        return error.PackageNotFound;
    }

    fn derivePackageInfoFromBackend(self: *Registry, allocator: std.mem.Allocator, entry_desc: BackendEntry, package_name: []const u8) !PackageInfo {
        _ = self;

        const backend_versions = entry_desc.backend.vtable.listVersions(entry_desc.backend.context, allocator, package_name) catch |err| switch (err) {
            error.PackageNotFound => return err,
            else => return err,
        };
        defer {
            for (backend_versions) |*vers| vers.deinit(allocator);
            allocator.free(backend_versions);
        }

        if (backend_versions.len == 0) {
            return error.PackageNotFound;
        }

        const selected_version = backend_versions[0];

        var metadata = entry_desc.backend.vtable.getMetadata(entry_desc.backend.context, allocator, package_name, selected_version) catch |err| switch (err) {
            error.PackageNotFound => return err,
            else => return err,
        };
        errdefer metadata.deinit(allocator);

        var versions = try allocator.alloc(semver.SemanticVersion, backend_versions.len);
        errdefer allocator.free(versions);
        var clone_count: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < clone_count) : (i += 1) {
                versions[i].deinit(allocator);
            }
        }

        for (backend_versions, 0..) |version, idx| {
            versions[idx] = try version.clone(allocator);
            clone_count = idx + 1;
        }

        const registry_copy = try allocator.dupe(u8, entry_desc.id);
        errdefer allocator.free(registry_copy);

        return PackageInfo{
            .registry = registry_copy,
            .metadata = metadata,
            .versions = versions,
            .allocator = allocator,
        };
    }

    fn cloneMetadata(self: *Registry, spec: PackageSpec) !PackageMetadata {
        const name = try cloneSlice(self.allocator, spec.name);
        errdefer if (name.len != 0) self.allocator.free(name);

        var version = try semver.SemanticVersion.parse(self.allocator, spec.version);
        errdefer version.deinit(self.allocator);

        const checksum = try cloneOptional(self.allocator, spec.checksum);
        errdefer if (checksum) |value| if (value.len != 0) self.allocator.free(value);

        var source = try self.cloneSource(spec.source);
        errdefer source.deinit(self.allocator);

        const deps = try self.cloneDependencies(spec.dependencies);
        errdefer self.freeDependencies(deps);

        return PackageMetadata{
            .name = name,
            .version = version,
            .checksum = checksum,
            .source = source,
            .dependencies = deps,
        };
    }

    fn cloneSource(self: *Registry, spec: PackageSourceSpec) !PackageSource {
        return switch (spec) {
            .git => |git| PackageSource{ .git = .{
                .url = try cloneSlice(self.allocator, git.url),
                .reference_type = git.reference_type,
                .reference = try cloneSlice(self.allocator, git.reference),
            } },
            .path => |path| PackageSource{ .path = try cloneSlice(self.allocator, path) },
            .registry => |reg| PackageSource{ .registry = .{
                .registry = try cloneSlice(self.allocator, reg.registry),
                .name = try cloneSlice(self.allocator, reg.name),
                .version = try cloneSlice(self.allocator, reg.version),
            } },
            .tarball => |tarball| PackageSource{ .tarball = .{
                .url = try cloneSlice(self.allocator, tarball.url),
                .hash = if (tarball.hash) |value| try cloneSlice(self.allocator, value) else null,
            } },
        };
    }

    fn cloneDependencies(self: *Registry, deps: []const DependencySpec) ![]Dependency {
        if (deps.len == 0) return &[_]Dependency{};
        var out = try self.allocator.alloc(Dependency, deps.len);
        errdefer self.freeDependencies(out);
        for (deps, 0..) |spec, idx| out[idx] = try self.cloneDependency(spec);
        return out;
    }

    fn cloneDependency(self: *Registry, spec: DependencySpec) !Dependency {
        const name = try cloneSlice(self.allocator, spec.name);
        errdefer if (name.len != 0) self.allocator.free(name);

        var parsed = try semver.VersionConstraint.parseRaw(self.allocator, spec.constraint);
        var guard = true;
        defer if (guard) parsed.deinit(self.allocator);

        var source: ?PackageSource = null;
        if (spec.source) |source_spec| {
            source = try self.cloneSource(source_spec);
        }

        const dep = Dependency{
            .name = name,
            .constraint = parsed.constraint,
            .raw_constraint = parsed.raw,
            .source = source,
        };
        parsed.raw = null;
        guard = false;
        return dep;
    }

    fn freeDependencies(self: *Registry, deps: []Dependency) void {
        for (deps) |*dep| dep.deinit(self.allocator);
        if (deps.len != 0 and deps.ptr != null) self.allocator.free(deps);
    }
};

pub fn materializeMetadataFromSpec(allocator: std.mem.Allocator, spec: PackageSpec) !PackageMetadata {
    var temp = Registry.init(allocator);
    defer temp.deinit();
    return temp.cloneMetadata(spec);
}

pub fn cloneMetadataForExport(allocator: std.mem.Allocator, metadata: *const PackageMetadata) !PackageMetadata {
    const name = try allocator.dupe(u8, metadata.name);
    errdefer allocator.free(name);

    var version = try metadata.version.clone(allocator);
    errdefer version.deinit(allocator);

    const checksum = try cloneOptional(allocator, metadata.checksum);
    errdefer if (checksum) |value| allocator.free(value);

    var source = try cloneSourceForExport(allocator, metadata.source);
    errdefer source.deinit(allocator);

    var deps = try allocator.alloc(Dependency, metadata.dependencies.len);
    errdefer freeExportDependencies(allocator, deps);
    for (metadata.dependencies, 0..) |dep, idx| {
        deps[idx] = try cloneDependencyForExport(allocator, dep);
    }

    return PackageMetadata{
        .name = name,
        .version = version,
        .checksum = checksum,
        .source = source,
        .dependencies = deps,
    };
}

fn cloneSourceForExport(allocator: std.mem.Allocator, source: PackageSource) !PackageSource {
    return switch (source) {
        .git => |git| PackageSource{ .git = .{
            .url = try allocator.dupe(u8, git.url),
            .reference_type = git.reference_type,
            .reference = try allocator.dupe(u8, git.reference),
        } },
        .path => |path| PackageSource{ .path = try allocator.dupe(u8, path) },
        .registry => |reg| PackageSource{ .registry = .{
            .registry = try allocator.dupe(u8, reg.registry),
            .name = try allocator.dupe(u8, reg.name),
            .version = try allocator.dupe(u8, reg.version),
        } },
        .tarball => |tarball| PackageSource{ .tarball = .{
            .url = try allocator.dupe(u8, tarball.url),
            .hash = if (tarball.hash) |value| try allocator.dupe(u8, value) else null,
        } },
    };
}

fn cloneDependencyForExport(allocator: std.mem.Allocator, dep: Dependency) !Dependency {
    const name = try allocator.dupe(u8, dep.name);
    errdefer allocator.free(name);

    var constraint = try dep.constraint.clone(allocator);
    errdefer constraint.deinit(allocator);

    const raw_constraint = try cloneOptional(allocator, dep.raw_constraint);
    errdefer if (raw_constraint) |value| allocator.free(value);

    var source: ?PackageSource = null;
    if (dep.source) |src| {
        source = try cloneSourceForExport(allocator, src);
    }

    return Dependency{
        .name = name,
        .constraint = constraint,
        .raw_constraint = raw_constraint,
        .source = source,
    };
}

fn freeExportDependencies(allocator: std.mem.Allocator, deps: []Dependency) void {
    for (deps) |*dep| dep.deinit(allocator);
    if (deps.len != 0) allocator.free(deps);
}

fn findEntryIndex(entries: []Registry.Entry, version: semver.SemanticVersion) ?usize {
    for (entries, 0..) |entry, idx| {
        if (entry.version.order(version) == .eq) return idx;
    }
    return null;
}

fn sortEntries(entries: []Registry.Entry) void {
    std.sort.heap(Registry.Entry, entries, {}, struct {
        fn lessThan(_: void, a: Registry.Entry, b: Registry.Entry) bool {
            // sort newest first
            return a.version.order(b.version) == .gt;
        }
    }.lessThan);
}

fn cloneSlice(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    if (value.len == 0) return &[_]u8{};
    return try allocator.dupe(u8, value);
}

fn cloneOptional(allocator: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    if (value) |slice| {
        return try cloneSlice(allocator, slice);
    }
    return null;
}

fn cloneOwnedBytes(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    if (value.len == 0) return &[_]u8{};
    return try allocator.dupe(u8, value);
}

pub fn containsCaseInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }

    return false;
}

test "registry add and retrieve package" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.addPackage(.{
        .name = "core",
        .version = "1.2.3",
        .checksum = "sha256-abc",
        .source = .{ .git = .{
            .url = "https://example.com/core.git",
            .reference_type = .tag,
            .reference = "v1.2.3",
        } },
        .dependencies = &[_]DependencySpec{
            .{ .name = "util", .constraint = "^0.5.0" },
        },
    });

    try registry.addPackage(.{
        .name = "core",
        .version = "1.3.0",
        .source = .{ .git = .{
            .url = "https://example.com/core.git",
            .reference_type = .tag,
            .reference = "v1.3.0",
        } },
    });

    const versions = try registry.getPackageVersions(allocator, "core");
    defer {
        for (versions) |*ver| ver.deinit(allocator);
        allocator.free(versions);
    }
    try std.testing.expectEqual(@as(usize, 2), versions.len);
    try std.testing.expect(versions[0].order(versions[1]) == .gt);

    const metadata = try registry.getPackageMetadata(allocator, "core", versions[0]);
    defer metadata.deinit(allocator);
    try std.testing.expectEqualStrings("core", metadata.name);
    try std.testing.expect(metadata.dependencies.len == 1);
}

test "registry add dependency with source" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.addPackage(.{
        .name = "app",
        .version = "0.1.0",
        .source = .{ .path = "../app" },
        .dependencies = &[_]DependencySpec{
            .{
                .name = "lib",
                .constraint = "^1.0.0",
                .source = .{ .tarball = .{ .url = "https://example.com/lib-1.0.0.tar.gz" } },
            },
        },
    });

    const versions = try registry.getPackageVersions(allocator, "app");
    defer {
        for (versions) |*ver| ver.deinit(allocator);
        allocator.free(versions);
    }

    const metadata = try registry.getPackageMetadata(allocator, "app", versions[0]);
    defer metadata.deinit(allocator);
    try std.testing.expect(metadata.dependencies.len == 1);
    const dep = metadata.dependencies[0];
    try std.testing.expect(dep.source != null);
}
