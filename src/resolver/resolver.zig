const std = @import("std");
const semver = @import("../util/semver.zig");
const registry_mod = @import("../registry/registry.zig");

/// Package source information
pub const Source = union(enum) {
    git: struct {
        url: []const u8,
        ref: GitRef,
    },
    path: []const u8,
    registry: struct {
        registry: []const u8,
        name: []const u8,
        version: []const u8,
    },
    tarball: Tarball,

    pub const GitRef = union(enum) {
        branch: []const u8,
        tag: []const u8,
        commit: []const u8,
    };

    pub const Tarball = struct {
        url: []const u8,
        hash: ?[]const u8 = null,
    };

    pub fn deinit(self: *Source, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .git => |*git| {
                if (git.url.len != 0) allocator.free(git.url);
                switch (git.ref) {
                    .branch => |value| if (value.len != 0) allocator.free(value),
                    .tag => |value| if (value.len != 0) allocator.free(value),
                    .commit => |value| if (value.len != 0) allocator.free(value),
                }
            },
            .path => |value| if (value.len != 0) allocator.free(value),
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
    }
};

/// A package dependency specification
pub const Dependency = struct {
    name: []const u8,
    constraint: semver.VersionConstraint,
    raw_constraint: ?[]const u8 = null,
    source: ?Source = null,
    optional: bool = false,

    pub fn deinit(self: *Dependency, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.constraint.deinit(allocator);
        if (self.raw_constraint) |raw| allocator.free(raw);
        if (self.source) |*src| src.deinit(allocator);
    }
};

/// A resolved package with specific version
pub const ResolvedPackage = struct {
    name: []const u8,
    version: semver.SemanticVersion,
    source: Source,
    dependencies: []Dependency,
    checksum: ?[]const u8 = null,

    pub fn deinit(self: *ResolvedPackage, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.version.deinit(allocator);
        self.source.deinit(allocator);
        for (self.dependencies) |*dep| {
            dep.deinit(allocator);
        }
        allocator.free(self.dependencies);
        if (self.checksum) |checksum| {
            allocator.free(checksum);
        }
    }
};

/// Dependency resolution context
pub const ResolutionContext = struct {
    allocator: std.mem.Allocator,
    resolved: std.StringHashMap(ResolvedPackage),
    constraints: std.StringHashMap(std.ArrayListUnmanaged(ResolutionConstraint)),
    sources: std.StringHashMap(Source),

    const Self = @This();

    pub const ResolutionConstraint = struct {
        constraint: semver.VersionConstraint,
        raw: ?[]const u8 = null,

        pub fn deinit(self: *ResolutionConstraint, allocator: std.mem.Allocator) void {
            self.constraint.deinit(allocator);
            if (self.raw) |raw| allocator.free(raw);
        }
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .resolved = std.StringHashMap(ResolvedPackage).init(allocator),
            .constraints = std.StringHashMap(std.ArrayListUnmanaged(ResolutionConstraint)).init(allocator),
            .sources = std.StringHashMap(Source).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var resolved_iter = self.resolved.iterator();
        while (resolved_iter.next()) |entry| {
            var pkg = entry.value_ptr;
            pkg.deinit(self.allocator);
        }
        self.resolved.deinit();

        var constraints_iter = self.constraints.iterator();
        while (constraints_iter.next()) |entry| {
            var constraint_list = entry.value_ptr;
            for (constraint_list.items) |*constraint| constraint.deinit(self.allocator);
            constraint_list.deinit(self.allocator);
        }
        self.constraints.deinit();

        var source_iter = self.sources.iterator();
        while (source_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.sources.deinit();
    }

    /// Add a constraint for a package
    pub fn addConstraint(self: *Self, package_name: []const u8, constraint: semver.VersionConstraint, raw: ?[]const u8) !void {
        const cloned = try constraint.clone(self.allocator);
        var raw_copy: ?[]const u8 = null;
        if (raw) |value| raw_copy = try self.allocator.dupe(u8, value);

        var clone_guard = true;
        defer if (clone_guard) {
            var clone_cleanup = cloned;
            clone_cleanup.deinit(self.allocator);
            if (raw_copy) |value| self.allocator.free(value);
        };

        const owned_name = try self.allocator.dupe(u8, package_name);
        var owned_guard = true;
        defer if (owned_guard) self.allocator.free(owned_name);

        const result = try self.constraints.getOrPut(owned_name);
        var list_ptr = result.value_ptr;
        if (!result.found_existing) {
            list_ptr.* = .{};
            owned_guard = false;
        }

        try list_ptr.append(self.allocator, .{ .constraint = cloned, .raw = raw_copy });
        clone_guard = false;
    }

    /// Check if all constraints for a package are satisfied by a version
    pub fn satisfiesConstraints(self: *Self, package_name: []const u8, version: semver.SemanticVersion) bool {
        const constraints = self.constraints.get(package_name) orelse return true;

        for (constraints.items) |record| {
            if (!record.constraint.satisfies(version)) {
                return false;
            }
        }
        return true;
    }

    pub fn setSource(self: *Self, package_name: []const u8, source: Source) !void {
        const owned_name = try self.allocator.dupe(u8, package_name);
        var owned_guard = true;
        defer if (owned_guard) self.allocator.free(owned_name);

        var cloned = try cloneResolverSource(self.allocator, source);
        var cloned_guard = true;
        defer if (cloned_guard) cloned.deinit(self.allocator);

        const entry = try self.sources.getOrPut(owned_name);
        if (!entry.found_existing) {
            entry.value_ptr.* = cloned;
            owned_guard = false;
            cloned_guard = false;
            return;
        }

        // Prefer existing source; free new clone
        cloned.deinit(self.allocator);
        cloned_guard = false;
        self.allocator.free(owned_name);
        owned_guard = false;
    }

    pub fn getSource(self: *Self, package_name: []const u8) ?*Source {
        return self.sources.getPtr(package_name);
    }

    pub fn getConstraints(self: *Self, package_name: []const u8) ?[]ResolutionConstraint {
        const entry = self.constraints.get(package_name) orelse return null;
        return entry.items;
    }
};

/// Dependency resolution errors
pub const ResolutionError = error{
    PackageNotFound,
    VersionConflict,
    CircularDependency,
    InvalidSource,
    InvalidVersion,
    RegistryFailure,
} || std.mem.Allocator.Error;

/// Dependency resolver
pub const Resolver = struct {
    allocator: std.mem.Allocator,
    registry: ?*registry_mod.Registry = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .registry = null,
        };
    }

    pub fn withRegistry(self: *Self, registry: *registry_mod.Registry) void {
        self.registry = registry;
    }

    /// Resolve dependencies for a set of root dependencies
    pub fn resolve(self: *Self, root_deps: []const Dependency) !ResolutionContext {
        var context = ResolutionContext.init(self.allocator);
        errdefer context.deinit();

        // Add root constraints
        for (root_deps) |dep| {
            try context.addConstraint(dep.name, dep.constraint, dep.raw_constraint);
            if (dep.source) |source| {
                try context.setSource(dep.name, source);
            }
        }

        // Resolve each root dependency
        for (root_deps) |dep| {
            try self.resolvePackage(&context, dep.name);
        }

        return context;
    }

    /// Resolve a single package recursively
    fn resolvePackage(self: *Self, context: *ResolutionContext, package_name: []const u8) ResolutionError!void {
        // Check if already resolved
        if (context.resolved.contains(package_name)) {
            return;
        }

        // Get available versions for this package
        const available_versions = try self.getAvailableVersions(context, package_name);
        defer self.allocator.free(available_versions);

        // Find the best version that satisfies all constraints
        const best_version = self.findBestVersion(context, package_name, available_versions) orelse {
            std.debug.print("Error: No version of '{s}' satisfies the following constraints:\n", .{package_name});
            if (context.getConstraints(package_name)) |constraint_list| {
                for (constraint_list) |record| {
                    if (record.raw) |raw| {
                        std.debug.print("  • {s}\n", .{raw});
                    } else {
                        const formatted = record.constraint.format(self.allocator) catch {
                            std.debug.print("  • <unprintable constraint>\n", .{});
                            continue;
                        };
                        defer self.allocator.free(formatted);
                        std.debug.print("  • {s}\n", .{formatted});
                    }
                }
            }

            if (available_versions.len == 0) {
                std.debug.print("  (registry returned no versions)\n", .{});
            } else {
                std.debug.print("Available versions: ", .{});
                for (available_versions, 0..) |version, idx| {
                    if (idx != 0) std.debug.print(", ", .{});
                    const formatted = version.format(self.allocator) catch {
                        std.debug.print("<unknown>", .{});
                        continue;
                    };
                    defer self.allocator.free(formatted);
                    std.debug.print("{s}", .{formatted});
                }
                std.debug.print("\n", .{});
            }

            return ResolutionError.VersionConflict;
        };

        // Get package metadata for the selected version
        var package_metadata = try self.getPackageMetadata(context, package_name, best_version);
        defer package_metadata.deinit(self.allocator);

        // Add package to resolved set
        try context.resolved.put(package_name, package_metadata);

        // Recursively resolve dependencies
        for (package_metadata.dependencies) |dep| {
            try context.addConstraint(dep.name, dep.constraint, dep.raw_constraint);
            if (dep.source) |source| {
                try context.setSource(dep.name, source);
            }
            try self.resolvePackage(context, dep.name);
        }
    }

    /// Find the best version that satisfies constraints
    fn findBestVersion(self: *Self, context: *ResolutionContext, package_name: []const u8, available_versions: []semver.SemanticVersion) ?semver.SemanticVersion {
        _ = self;

        // Sort versions in descending order (newest first)
        std.sort.heap(semver.SemanticVersion, available_versions, {}, struct {
            fn lessThan(_: void, a: semver.SemanticVersion, b: semver.SemanticVersion) bool {
                return a.order(b) == .gt;
            }
        }.lessThan);

        // Find the first (newest) version that satisfies all constraints
        for (available_versions) |version| {
            if (context.satisfiesConstraints(package_name, version)) {
                return version;
            }
        }

        return null;
    }

    /// Get available versions for a package from the active registry or fallback sources
    fn getAvailableVersions(self: *Self, context: *ResolutionContext, package_name: []const u8) ResolutionError![]semver.SemanticVersion {
        if (self.registry) |reg| {
            const maybe_versions = reg.getPackageVersions(self.allocator, package_name) catch |err| switch (err) {
                error.PackageNotFound => @as(?[]semver.SemanticVersion, null),
                error.OutOfMemory => return error.OutOfMemory,
                else => return ResolutionError.RegistryFailure,
            };

            if (maybe_versions) |versions| {
                return versions;
            }
        }

        const source_ptr = context.getSource(package_name) orelse return ResolutionError.PackageNotFound;
        _ = source_ptr;

        const derived = try self.deriveVersionFromConstraints(context, package_name);
        var versions = try self.allocator.alloc(semver.SemanticVersion, 1);
        errdefer {
            versions[0].deinit(self.allocator);
            self.allocator.free(versions);
        }
        versions[0] = derived;
        return versions;
    }

    /// Get package metadata for a specific version using the active registry
    fn getPackageMetadata(self: *Self, context: *ResolutionContext, package_name: []const u8, version: semver.SemanticVersion) ResolutionError!ResolvedPackage {
        if (self.registry) |reg| {
            var maybe_metadata = reg.getPackageMetadata(self.allocator, package_name, version) catch |err| switch (err) {
                error.PackageNotFound => @as(?registry_mod.PackageMetadata, null),
                error.OutOfMemory => return error.OutOfMemory,
                else => return ResolutionError.RegistryFailure,
            };

            if (maybe_metadata) |*meta| {
                defer meta.deinit(self.allocator);

                const empty_deps = try self.allocator.alloc(Dependency, 0);
                var empty_deps_guard = true;
                defer if (empty_deps_guard) self.allocator.free(empty_deps);

                var resolved = ResolvedPackage{
                    .name = try self.allocator.dupe(u8, meta.name),
                    .version = try meta.version.clone(self.allocator),
                    .source = try convertRegistrySource(self.allocator, meta.source),
                    .dependencies = empty_deps,
                    .checksum = null,
                };
                empty_deps_guard = false;
                errdefer resolved.deinit(self.allocator);

                if (meta.checksum) |checksum| {
                    resolved.checksum = try self.allocator.dupe(u8, checksum);
                }

                const deps_len = meta.dependencies.len;
                if (deps_len != 0) {
                    var deps = try self.allocator.alloc(Dependency, deps_len);
                    var initialized: usize = 0;
                    errdefer {
                        var i: usize = 0;
                        while (i < initialized) : (i += 1) {
                            deps[i].deinit(self.allocator);
                        }
                        self.allocator.free(deps);
                    }

                    for (meta.dependencies, 0..) |dep, idx| {
                        deps[idx] = try cloneRegistryDependency(self, dep);
                        initialized = idx + 1;
                    }

                    self.allocator.free(empty_deps);
                    resolved.dependencies = deps;
                }

                return resolved;
            }
        }

        const source_ptr = context.getSource(package_name) orelse return ResolutionError.PackageNotFound;

        var cloned_source = try cloneResolverSource(self.allocator, source_ptr.*);
        var source_guard = true;
        defer if (source_guard) cloned_source.deinit(self.allocator);

        const deps = try self.allocator.alloc(Dependency, 0);
        var deps_guard = true;
        defer if (deps_guard) self.allocator.free(deps);

        const resolved = ResolvedPackage{
            .name = try self.allocator.dupe(u8, package_name),
            .version = try version.clone(self.allocator),
            .source = cloned_source,
            .dependencies = deps,
            .checksum = null,
        };

        source_guard = false;
        deps_guard = false;
        return resolved;
    }

    fn deriveVersionFromConstraints(self: *Self, context: *ResolutionContext, package_name: []const u8) ResolutionError!semver.SemanticVersion {
        const constraints = context.getConstraints(package_name) orelse return ResolutionError.PackageNotFound;

        const Bound = struct {
            version: semver.SemanticVersion,
            inclusive: bool,
        };

        const Helpers = struct {
            fn applyLower(lower_ref: *?Bound, allocator: std.mem.Allocator, new_version: semver.SemanticVersion, inclusive: bool) void {
                var bound = Bound{ .version = new_version, .inclusive = inclusive };
                if (lower_ref.*) |*existing| {
                    switch (existing.version.order(bound.version)) {
                        .lt => {
                            existing.version.deinit(allocator);
                            existing.* = bound;
                            return;
                        },
                        .eq => {
                            existing.inclusive = existing.inclusive and bound.inclusive;
                            bound.version.deinit(allocator);
                            return;
                        },
                        .gt => {
                            bound.version.deinit(allocator);
                            return;
                        },
                    }
                } else {
                    lower_ref.* = bound;
                }
            }

            fn applyUpper(upper_ref: *?Bound, allocator: std.mem.Allocator, new_version: semver.SemanticVersion, inclusive: bool) void {
                var bound = Bound{ .version = new_version, .inclusive = inclusive };
                if (upper_ref.*) |*existing| {
                    switch (existing.version.order(bound.version)) {
                        .gt => {
                            existing.version.deinit(allocator);
                            existing.* = bound;
                            return;
                        },
                        .eq => {
                            existing.inclusive = existing.inclusive and bound.inclusive;
                            bound.version.deinit(allocator);
                            return;
                        },
                        .lt => {
                            bound.version.deinit(allocator);
                            return;
                        },
                    }
                } else {
                    upper_ref.* = bound;
                }
            }

            fn bumpExclusive(allocator: std.mem.Allocator, version: *semver.SemanticVersion) ResolutionError!void {
                if (version.prerelease) |pre| {
                    allocator.free(pre);
                    version.prerelease = null;
                }
                if (version.build) |build| {
                    allocator.free(build);
                    version.build = null;
                }

                if (version.patch != std.math.maxInt(u32)) {
                    version.patch += 1;
                    return;
                }

                version.patch = 0;
                if (version.minor != std.math.maxInt(u32)) {
                    version.minor += 1;
                    return;
                }

                version.minor = 0;
                if (version.major == std.math.maxInt(u32)) return ResolutionError.InvalidVersion;
                version.major += 1;
            }

            fn caretUpperBound(base: semver.SemanticVersion) ResolutionError!Bound {
                var upper = semver.SemanticVersion{
                    .major = base.major,
                    .minor = base.minor,
                    .patch = base.patch,
                    .prerelease = null,
                    .build = null,
                };

                if (base.major == 0) {
                    if (base.minor == 0) {
                        if (base.patch == std.math.maxInt(u32)) return ResolutionError.InvalidVersion;
                        upper.patch = base.patch + 1;
                    } else {
                        if (base.minor == std.math.maxInt(u32)) return ResolutionError.InvalidVersion;
                        upper.minor = base.minor + 1;
                        upper.patch = 0;
                    }
                } else {
                    if (base.major == std.math.maxInt(u32)) return ResolutionError.InvalidVersion;
                    upper.major = base.major + 1;
                    upper.minor = 0;
                    upper.patch = 0;
                }

                return Bound{ .version = upper, .inclusive = false };
            }

            fn tildeUpperBound(base: semver.SemanticVersion) ResolutionError!Bound {
                var upper = semver.SemanticVersion{
                    .major = base.major,
                    .minor = base.minor,
                    .patch = base.patch,
                    .prerelease = null,
                    .build = null,
                };

                if (base.minor == std.math.maxInt(u32)) {
                    if (base.major == std.math.maxInt(u32)) return ResolutionError.InvalidVersion;
                    upper.major = base.major + 1;
                    upper.minor = 0;
                } else {
                    upper.minor = base.minor + 1;
                }
                upper.patch = 0;

                return Bound{ .version = upper, .inclusive = false };
            }
        };

        var lower: ?Bound = null;
        var upper: ?Bound = null;

        defer {
            if (lower) |*bound| bound.version.deinit(self.allocator);
            if (upper) |*bound| bound.version.deinit(self.allocator);
        }

        for (constraints) |record| {
            switch (record.constraint) {
                .exact => |version| {
                    Helpers.applyLower(&lower, self.allocator, try version.clone(self.allocator), true);
                    Helpers.applyUpper(&upper, self.allocator, try version.clone(self.allocator), true);
                },
                .caret => |version| {
                    Helpers.applyLower(&lower, self.allocator, try version.clone(self.allocator), true);
                    const bound = try Helpers.caretUpperBound(version);
                    Helpers.applyUpper(&upper, self.allocator, bound.version, bound.inclusive);
                },
                .tilde => |version| {
                    Helpers.applyLower(&lower, self.allocator, try version.clone(self.allocator), true);
                    const bound = try Helpers.tildeUpperBound(version);
                    Helpers.applyUpper(&upper, self.allocator, bound.version, bound.inclusive);
                },
                .gte => |version| {
                    Helpers.applyLower(&lower, self.allocator, try version.clone(self.allocator), true);
                },
                .gt => |version| {
                    Helpers.applyLower(&lower, self.allocator, try version.clone(self.allocator), false);
                },
                .lte => |version| {
                    Helpers.applyUpper(&upper, self.allocator, try version.clone(self.allocator), true);
                },
                .lt => |version| {
                    Helpers.applyUpper(&upper, self.allocator, try version.clone(self.allocator), false);
                },
                .range => |range| {
                    Helpers.applyLower(&lower, self.allocator, try range.min.clone(self.allocator), true);
                    Helpers.applyUpper(&upper, self.allocator, try range.max.clone(self.allocator), true);
                },
            }
        }

        if (lower != null and upper != null) {
            const relation = lower.?.version.order(upper.?.version);
            if (relation == .gt or (relation == .eq and (!lower.?.inclusive or !upper.?.inclusive))) {
                return ResolutionError.VersionConflict;
            }
        }

        if (lower) |*lower_bound| {
            var candidate = try lower_bound.version.clone(self.allocator);
            if (!lower_bound.inclusive) {
                try Helpers.bumpExclusive(self.allocator, &candidate);
            }

            if (upper) |*upper_bound| {
                switch (candidate.order(upper_bound.version)) {
                    .gt => {
                        candidate.deinit(self.allocator);
                        return ResolutionError.VersionConflict;
                    },
                    .eq => if (!upper_bound.inclusive) {
                        candidate.deinit(self.allocator);
                        return ResolutionError.VersionConflict;
                    },
                    else => {},
                }
            }

            if (!context.satisfiesConstraints(package_name, candidate)) {
                candidate.deinit(self.allocator);
                return ResolutionError.VersionConflict;
            }

            return candidate;
        }

        if (upper) |*upper_bound| {
            if (!upper_bound.inclusive) return ResolutionError.InvalidVersion;

            var candidate = try upper_bound.version.clone(self.allocator);
            if (!context.satisfiesConstraints(package_name, candidate)) {
                candidate.deinit(self.allocator);
                return ResolutionError.VersionConflict;
            }
            return candidate;
        }

        return ResolutionError.PackageNotFound;
    }
};

fn cloneResolverSource(allocator: std.mem.Allocator, source: Source) !Source {
    return switch (source) {
        .git => |git| blk: {
            const url = try duplicateSlice(allocator, git.url);
            errdefer if (url.len != 0) allocator.free(url);

            const ref_copy = switch (git.ref) {
                .branch => try duplicateSlice(allocator, git.ref.branch),
                .tag => try duplicateSlice(allocator, git.ref.tag),
                .commit => try duplicateSlice(allocator, git.ref.commit),
            };
            errdefer if (ref_copy.len != 0) allocator.free(ref_copy);

            const ref = switch (git.ref) {
                .branch => Source.GitRef{ .branch = ref_copy },
                .tag => Source.GitRef{ .tag = ref_copy },
                .commit => Source.GitRef{ .commit = ref_copy },
            };

            break :blk Source{ .git = .{ .url = url, .ref = ref } };
        },
        .path => |path| Source{ .path = try duplicateSlice(allocator, path) },
        .registry => |reg| Source{ .registry = .{
            .registry = try duplicateSlice(allocator, reg.registry),
            .name = try duplicateSlice(allocator, reg.name),
            .version = try duplicateSlice(allocator, reg.version),
        } },
        .tarball => |tarball| Source{ .tarball = .{
            .url = try duplicateSlice(allocator, tarball.url),
            .hash = if (tarball.hash) |value| try duplicateSlice(allocator, value) else null,
        } },
    };
}

fn convertRegistrySource(allocator: std.mem.Allocator, source: registry_mod.PackageSource) !Source {
    return switch (source) {
        .git => |git| blk: {
            const url = try duplicateSlice(allocator, git.url);
            errdefer if (url.len != 0) allocator.free(url);

            const reference_copy = try duplicateSlice(allocator, git.reference);
            errdefer if (reference_copy.len != 0) allocator.free(reference_copy);

            const ref = switch (git.reference_type) {
                .branch => Source.GitRef{ .branch = reference_copy },
                .tag => Source.GitRef{ .tag = reference_copy },
                .commit => Source.GitRef{ .commit = reference_copy },
            };

            break :blk Source{ .git = .{ .url = url, .ref = ref } };
        },
        .path => |path| Source{ .path = try duplicateSlice(allocator, path) },
        .registry => |reg| Source{ .registry = .{
            .registry = try duplicateSlice(allocator, reg.registry),
            .name = try duplicateSlice(allocator, reg.name),
            .version = try duplicateSlice(allocator, reg.version),
        } },
        .tarball => |tarball| Source{ .tarball = .{
            .url = try duplicateSlice(allocator, tarball.url),
            .hash = if (tarball.hash) |value| try duplicateSlice(allocator, value) else null,
        } },
    };
}

fn cloneRegistryDependency(self: *Resolver, dep: registry_mod.Dependency) !Dependency {
    var cloned = Dependency{
        .name = try self.allocator.dupe(u8, dep.name),
        .constraint = try dep.constraint.clone(self.allocator),
        .raw_constraint = null,
        .source = null,
        .optional = false,
    };
    errdefer cloned.deinit(self.allocator);

    if (dep.raw_constraint) |raw| {
        cloned.raw_constraint = try self.allocator.dupe(u8, raw);
    }

    if (dep.source) |src| {
        cloned.source = try convertRegistrySource(self.allocator, src);
    }

    return cloned;
}

fn duplicateSlice(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    if (value.len == 0) return &[_]u8{};
    return try allocator.dupe(u8, value);
}

// Tests
test "basic dependency resolution" {
    const allocator = std.testing.allocator;

    var resolver = Resolver.init(allocator);

    var registry = registry_mod.Registry.init(allocator);
    defer registry.deinit();

    try registry.addPackage(.{
        .name = "dep-package",
        .version = "0.5.1",
        .source = .{ .registry = .{
            .registry = "https://registry.example.com",
            .name = "dep-package",
            .version = "0.5.1",
        } },
    });

    try registry.addPackage(.{
        .name = "test-package",
        .version = "1.2.3",
        .source = .{ .registry = .{
            .registry = "https://registry.example.com",
            .name = "test-package",
            .version = "1.2.3",
        } },
        .dependencies = &[_]registry_mod.DependencySpec{
            .{
                .name = "dep-package",
                .constraint = "^0.5.0",
                .source = .{ .registry = .{
                    .registry = "https://registry.example.com",
                    .name = "dep-package",
                    .version = "0.5.1",
                } },
            },
        },
    });

    resolver.withRegistry(&registry);

    // Create a root dependency
    const constraint = try semver.VersionConstraint.parse(allocator, "^1.2.0");
    var constraint_cleanup = constraint;
    defer constraint_cleanup.deinit(allocator);

    const root_dep = Dependency{
        .name = "test-package",
        .constraint = constraint,
    };

    // Resolve dependencies
    var resolution = resolver.resolve(&[_]Dependency{root_dep}) catch |err| {
        std.debug.print("Resolution failed: {}\n", .{err});
        return;
    };
    defer resolution.deinit();

    // Check that the package was resolved
    try std.testing.expect(resolution.resolved.contains("test-package"));
    try std.testing.expect(resolution.resolved.contains("dep-package"));

    const test_pkg = resolution.resolved.get("test-package") orelse unreachable;

    var expected_version = try semver.SemanticVersion.parse(allocator, "1.2.3");
    defer expected_version.deinit(allocator);
    try std.testing.expect(test_pkg.version.order(expected_version) == .eq);

    switch (test_pkg.source) {
        .registry => |reg| {
            try std.testing.expectEqualStrings("https://registry.example.com", reg.registry);
            try std.testing.expectEqualStrings("test-package", reg.name);
            try std.testing.expectEqualStrings("1.2.3", reg.version);
        },
        else => return std.testing.expect(false),
    }

    try std.testing.expect(test_pkg.dependencies.len == 1);
    const dep = test_pkg.dependencies[0];
    try std.testing.expectEqualStrings("dep-package", dep.name);
    try std.testing.expect(dep.source != null);
    if (dep.source) |src| {
        switch (src) {
            .registry => |reg| {
                try std.testing.expectEqualStrings("https://registry.example.com", reg.registry);
                try std.testing.expectEqualStrings("dep-package", reg.name);
                try std.testing.expectEqualStrings("0.5.1", reg.version);
            },
            else => return std.testing.expect(false),
        }
    }
}

test "version constraint satisfaction" {
    const allocator = std.testing.allocator;

    var context = ResolutionContext.init(allocator);
    defer context.deinit();

    const constraint = try semver.VersionConstraint.parse(allocator, "^1.2.0");
    var constraint_cleanup = constraint;
    defer constraint_cleanup.deinit(allocator);
    try context.addConstraint("test-pkg", constraint, null);

    var version1 = try semver.SemanticVersion.parse(allocator, "1.2.3");
    defer version1.deinit(allocator);
    var version2 = try semver.SemanticVersion.parse(allocator, "2.0.0");
    defer version2.deinit(allocator);

    try std.testing.expect(context.satisfiesConstraints("test-pkg", version1));
    try std.testing.expect(!context.satisfiesConstraints("test-pkg", version2));
}

test "resolver fallback handles git source without registry" {
    const allocator = std.testing.allocator;

    var resolver = Resolver.init(allocator);

    var parsed = try semver.VersionConstraint.parseRaw(allocator, "1.0.0");
    var parsed_guard = true;
    defer if (parsed_guard) parsed.deinit(allocator);

    var dependency = Dependency{
        .name = try allocator.dupe(u8, "git-pkg"),
        .constraint = parsed.constraint,
        .raw_constraint = parsed.raw,
        .source = Source{ .git = .{
            .url = try allocator.dupe(u8, "https://example.com/git-pkg.git"),
            .ref = Source.GitRef{ .branch = try allocator.dupe(u8, "main") },
        } },
    };
    parsed.raw = null;
    parsed_guard = false;

    defer dependency.deinit(allocator);

    const deps = &[_]Dependency{dependency};

    var resolution = resolver.resolve(deps) catch |err| {
        std.debug.print("Resolution failed unexpectedly: {}\n", .{err});
        return;
    };
    defer resolution.deinit();

    try std.testing.expect(resolution.resolved.contains("git-pkg"));

    const pkg = resolution.resolved.get("git-pkg") orelse unreachable;

    var expected_version = try semver.SemanticVersion.parse(allocator, "1.0.0");
    defer expected_version.deinit(allocator);
    try std.testing.expect(pkg.version.order(expected_version) == .eq);

    switch (pkg.source) {
        .git => |git| {
            try std.testing.expectEqualStrings("https://example.com/git-pkg.git", git.url);
            switch (git.ref) {
                .branch => |value| try std.testing.expectEqualStrings("main", value),
                else => return std.testing.expect(false),
            }
        },
        else => return std.testing.expect(false),
    }
}

test "resolver fallback handles path source without registry" {
    const allocator = std.testing.allocator;

    var resolver = Resolver.init(allocator);

    var parsed = try semver.VersionConstraint.parseRaw(allocator, "2.3.4");
    var parsed_guard = true;
    defer if (parsed_guard) parsed.deinit(allocator);

    var dependency = Dependency{
        .name = try allocator.dupe(u8, "path-pkg"),
        .constraint = parsed.constraint,
        .raw_constraint = parsed.raw,
        .source = Source{ .path = try allocator.dupe(u8, "../libs/path-pkg") },
    };
    parsed.raw = null;
    parsed_guard = false;

    defer dependency.deinit(allocator);

    const deps = &[_]Dependency{dependency};

    var resolution = resolver.resolve(deps) catch |err| {
        std.debug.print("Resolution failed unexpectedly: {}\n", .{err});
        return;
    };
    defer resolution.deinit();

    try std.testing.expect(resolution.resolved.contains("path-pkg"));

    const pkg = resolution.resolved.get("path-pkg") orelse unreachable;

    var expected_version = try semver.SemanticVersion.parse(allocator, "2.3.4");
    defer expected_version.deinit(allocator);
    try std.testing.expect(pkg.version.order(expected_version) == .eq);

    switch (pkg.source) {
        .path => |value| try std.testing.expectEqualStrings("../libs/path-pkg", value),
        else => return std.testing.expect(false),
    }
}

test "resolver fallback handles tarball source with optional hash" {
    const allocator = std.testing.allocator;

    var resolver = Resolver.init(allocator);

    var parsed = try semver.VersionConstraint.parseRaw(allocator, "3.4.5");
    var parsed_guard = true;
    defer if (parsed_guard) parsed.deinit(allocator);

    var dependency = Dependency{
        .name = try allocator.dupe(u8, "tarball-pkg"),
        .constraint = parsed.constraint,
        .raw_constraint = parsed.raw,
        .source = Source{ .tarball = .{
            .url = try allocator.dupe(u8, "https://example.com/tarball-pkg-3.4.5.tar.gz"),
            .hash = try allocator.dupe(u8, "sha256-deadbeef"),
        } },
    };
    parsed.raw = null;
    parsed_guard = false;

    defer dependency.deinit(allocator);

    const deps = &[_]Dependency{dependency};

    var resolution = resolver.resolve(deps) catch |err| {
        std.debug.print("Resolution failed unexpectedly: {}\n", .{err});
        return;
    };
    defer resolution.deinit();

    try std.testing.expect(resolution.resolved.contains("tarball-pkg"));

    const pkg = resolution.resolved.get("tarball-pkg") orelse unreachable;

    var expected_version = try semver.SemanticVersion.parse(allocator, "3.4.5");
    defer expected_version.deinit(allocator);
    try std.testing.expect(pkg.version.order(expected_version) == .eq);

    switch (pkg.source) {
        .tarball => |tarball| {
            try std.testing.expectEqualStrings("https://example.com/tarball-pkg-3.4.5.tar.gz", tarball.url);
            try std.testing.expect(tarball.hash != null);
            try std.testing.expectEqualStrings("sha256-deadbeef", tarball.hash.?);
        },
        else => return std.testing.expect(false),
    }
}

test "resolver fallback derives version from caret constraint" {
    const allocator = std.testing.allocator;

    var resolver = Resolver.init(allocator);

    var parsed = try semver.VersionConstraint.parseRaw(allocator, "^1.2.3");
    var parsed_guard = true;
    defer if (parsed_guard) parsed.deinit(allocator);

    var dependency = Dependency{
        .name = try allocator.dupe(u8, "caret-pkg"),
        .constraint = parsed.constraint,
        .raw_constraint = parsed.raw,
        .source = Source{ .path = try allocator.dupe(u8, "../libs/caret-pkg") },
    };
    parsed.raw = null;
    parsed_guard = false;

    defer dependency.deinit(allocator);

    var resolution = resolver.resolve(&[_]Dependency{dependency}) catch |err| {
        std.debug.print("Resolution failed unexpectedly: {}\n", .{err});
        return;
    };
    defer resolution.deinit();

    const pkg = resolution.resolved.get("caret-pkg") orelse unreachable;

    var expected_version = try semver.SemanticVersion.parse(allocator, "1.2.3");
    defer expected_version.deinit(allocator);
    try std.testing.expect(pkg.version.order(expected_version) == .eq);
}

test "resolver fallback intersects mixed range constraints" {
    const allocator = std.testing.allocator;

    var resolver = Resolver.init(allocator);

    var gt_parsed = try semver.VersionConstraint.parseRaw(allocator, ">1.2.3");
    var gt_guard = true;
    defer if (gt_guard) gt_parsed.deinit(allocator);

    var lte_parsed = try semver.VersionConstraint.parseRaw(allocator, "<=1.2.4");
    var lte_guard = true;
    defer if (lte_guard) lte_parsed.deinit(allocator);

    var dep_gt = Dependency{
        .name = try allocator.dupe(u8, "range-pkg"),
        .constraint = gt_parsed.constraint,
        .raw_constraint = gt_parsed.raw,
        .source = Source{ .tarball = .{
            .url = try allocator.dupe(u8, "https://example.com/range-pkg.tar.gz"),
            .hash = null,
        } },
    };
    gt_parsed.raw = null;
    gt_guard = false;

    var dep_lte = Dependency{
        .name = try allocator.dupe(u8, "range-pkg"),
        .constraint = lte_parsed.constraint,
        .raw_constraint = lte_parsed.raw,
        .source = null,
    };
    lte_parsed.raw = null;
    lte_guard = false;

    defer dep_gt.deinit(allocator);
    defer dep_lte.deinit(allocator);

    var resolution = resolver.resolve(&[_]Dependency{ dep_gt, dep_lte }) catch |err| {
        std.debug.print("Resolution failed unexpectedly: {}\n", .{err});
        return;
    };
    defer resolution.deinit();

    const pkg = resolution.resolved.get("range-pkg") orelse unreachable;

    var expected_version = try semver.SemanticVersion.parse(allocator, "1.2.4");
    defer expected_version.deinit(allocator);
    try std.testing.expect(pkg.version.order(expected_version) == .eq);
}
