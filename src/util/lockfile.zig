const std = @import("std");
const Manifest = @import("manifest.zig").Manifest;
const Resolver = @import("../resolver/resolver.zig");
const semver = @import("semver.zig");

const testing = std.testing;
const GitReferenceType = Manifest.GitReferenceType;

const max_lockfile_bytes = 8 * 1024 * 1024;

fn ArrayListManaged(comptime T: type) type {
    return std.array_list.AlignedManaged(T, null);
}

const ArrayListWriter = struct {
    list: *ArrayListManaged(u8),

    fn writeAll(self: *ArrayListWriter, bytes: []const u8) std.mem.Allocator.Error!void {
        try self.list.appendSlice(bytes);
    }

    fn writeByte(self: *ArrayListWriter, byte: u8) std.mem.Allocator.Error!void {
        try self.list.append(byte);
    }
};

pub const Lockfile = struct {
    allocator: std.mem.Allocator,
    zig_version: []const u8,
    targets: std.ArrayListUnmanaged([]const u8),
    packages: std.ArrayListUnmanaged(Package),

    pub const format_version: u32 = 1;

    pub const PersistError = std.mem.Allocator.Error || error{
        Io,
        ParseError,
        MissingField,
        UnsupportedVersion,
        DuplicatePackage,
        InvalidSource,
        FileTooLarge,
    };

    pub const Package = struct {
        name: []const u8,
        version: []const u8,
        checksum: ?[]const u8,
        source: Source,
        dependencies: []Dependency,

        pub fn deinit(self: *Package, allocator: std.mem.Allocator) void {
            if (self.name.len != 0) allocator.free(self.name);
            if (self.version.len != 0) allocator.free(self.version);
            if (self.checksum) |checksum| if (checksum.len != 0) allocator.free(checksum);
            self.source.deinit(allocator);
            for (self.dependencies) |*dep| dep.deinit(allocator);
            if (self.dependencies.len != 0) allocator.free(self.dependencies);
            self.* = undefined;
        }
    };

    pub const Dependency = struct {
        name: []const u8,
        version: []const u8,
        checksum: ?[]const u8,

        pub fn deinit(self: *Dependency, allocator: std.mem.Allocator) void {
            if (self.name.len != 0) allocator.free(self.name);
            if (self.version.len != 0) allocator.free(self.version);
            if (self.checksum) |checksum| if (checksum.len != 0) allocator.free(checksum);
            self.* = undefined;
        }
    };

    pub const Source = union(enum) {
        git: Git,
        path: []const u8,
        registry: Registry,
        tarball: Tarball,

        pub fn deinit(self: *Source, allocator: std.mem.Allocator) void {
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

    pub const Registry = struct {
        registry: []const u8,
        name: []const u8,
        version: []const u8,
    };

    pub const PackageSpec = struct {
        name: []const u8,
        version: []const u8,
        checksum: ?[]const u8 = null,
        source: SourceSpec,
        dependencies: []const DependencySpec = &[_]DependencySpec{},
    };

    pub const SourceSpec = union(enum) {
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

    pub const Tarball = struct {
        url: []const u8,
        hash: ?[]const u8 = null,
    };

    pub const TarballSpec = struct {
        url: []const u8,
        hash: ?[]const u8 = null,
    };

    pub const DependencySpec = struct {
        name: []const u8,
        version: []const u8,
        checksum: ?[]const u8 = null,
    };

    pub fn init(allocator: std.mem.Allocator, zig_version: []const u8, targets: []const []const u8) !Lockfile {
        var lockfile = Lockfile{
            .allocator = allocator,
            .zig_version = &[_]u8{},
            .targets = .{},
            .packages = .{},
        };

        lockfile.zig_version = try cloneSlice(allocator, zig_version);
        errdefer if (lockfile.zig_version.len != 0) allocator.free(lockfile.zig_version);

        if (targets.len != 0) {
            try lockfile.targets.ensureTotalCapacity(allocator, targets.len);
            errdefer lockfile.freeTargets();
            for (targets) |target| {
                const cloned = try cloneSlice(allocator, target);
                lockfile.targets.appendAssumeCapacity(cloned);
            }
        }

        return lockfile;
    }

    pub fn deinit(self: *Lockfile) void {
        if (self.zig_version.len != 0) self.allocator.free(self.zig_version);
        self.freeTargets();
        self.freePackages();
        self.* = undefined;
    }

    pub fn zigVersion(self: *const Lockfile) []const u8 {
        return self.zig_version;
    }

    pub fn setZigVersion(self: *Lockfile, version: []const u8) !void {
        if (self.zig_version.len != 0) self.allocator.free(self.zig_version);
        self.zig_version = try cloneSlice(self.allocator, version);
    }

    pub fn targetsSlice(self: *const Lockfile) []const []const u8 {
        return self.targets.items;
    }

    pub fn packagesSlice(self: *const Lockfile) []const Package {
        return self.packages.items;
    }

    pub fn putPackage(self: *Lockfile, spec: PackageSpec) !void {
        var package = try self.clonePackage(spec);
        errdefer package.deinit(self.allocator);

        if (self.findPackageIndex(spec.name)) |idx| {
            self.packages.items[idx].deinit(self.allocator);
            self.packages.items[idx] = package;
        } else {
            try self.packages.append(self.allocator, package);
        }
    }

    pub fn getPackage(self: *const Lockfile, name: []const u8) ?*const Package {
        if (self.findPackageIndex(name)) |idx| return &self.packages.items[idx];
        return null;
    }

    pub fn removePackage(self: *Lockfile, name: []const u8) bool {
        if (self.findPackageIndex(name)) |idx| {
            self.packages.items[idx].deinit(self.allocator);
            _ = self.packages.swapRemove(idx);
            return true;
        }
        return false;
    }

    pub fn render(self: *const Lockfile, allocator: std.mem.Allocator) PersistError![]u8 {
        var buffer = ArrayListManaged(u8).init(allocator);
        errdefer buffer.deinit();
        var writer = ArrayListWriter{ .list = &buffer };

        var line_buf: [64]u8 = undefined;
        const formatted = std.fmt.bufPrint(&line_buf, "version = {d}\n", .{format_version}) catch unreachable;
        try writer.writeAll(formatted);
        try writer.writeAll("zig = ");
        try writeQuoted(&writer, self.zig_version);
        try writer.writeByte('\n');

        try writer.writeAll("targets = [");
        const targets_len = self.targets.items.len;
        if (targets_len != 0) {
            const targets_copy = try allocator.alloc([]const u8, targets_len);
            defer allocator.free(targets_copy);
            @memcpy(targets_copy, self.targets.items);
            std.sort.heap([]const u8, targets_copy, {}, lessThanStrings);

            for (targets_copy, 0..) |target, idx| {
                if (idx != 0) try writer.writeAll(", ");
                try writeQuoted(&writer, target);
            }
        }
        try writer.writeAll("]\n\n");

        if (self.packages.items.len != 0) {
            const indices = try allocator.alloc(usize, self.packages.items.len);
            defer allocator.free(indices);
            for (indices, 0..) |*idx, pos| idx.* = pos;
            std.sort.heap(usize, indices, self, struct {
                fn lessThan(lockfile: *const Lockfile, a: usize, b: usize) bool {
                    return std.mem.lessThan(u8, lockfile.packages.items[a].name, lockfile.packages.items[b].name);
                }
            }.lessThan);

            for (indices, 0..) |pkg_index, idx| {
                const pkg = self.packages.items[pkg_index];
                if (idx != 0) try writer.writeByte('\n');
                try writer.writeAll("[[packages]]\n");
                try writer.writeAll("name = ");
                try writeQuoted(&writer, pkg.name);
                try writer.writeByte('\n');
                try writer.writeAll("version = ");
                try writeQuoted(&writer, pkg.version);
                try writer.writeByte('\n');
                if (pkg.checksum) |checksum| {
                    try writer.writeAll("checksum = ");
                    try writeQuoted(&writer, checksum);
                    try writer.writeByte('\n');
                }
                try writer.writeAll("source = ");
                try renderSource(&writer, pkg.source);
                try writer.writeByte('\n');

                if (pkg.dependencies.len != 0) {
                    const dep_indices = try allocator.alloc(usize, pkg.dependencies.len);
                    defer allocator.free(dep_indices);
                    for (dep_indices, 0..) |*dep_idx, pos| dep_idx.* = pos;
                    std.sort.heap(usize, dep_indices, pkg.dependencies, struct {
                        fn lessThan(deps: []const Dependency, a: usize, b: usize) bool {
                            return std.mem.lessThan(u8, deps[a].name, deps[b].name);
                        }
                    }.lessThan);

                    for (dep_indices) |dep_idx| {
                        const dep = pkg.dependencies[dep_idx];
                        try writer.writeAll("[[packages.dependencies]]\n");
                        try writer.writeAll("name = ");
                        try writeQuoted(&writer, dep.name);
                        try writer.writeByte('\n');
                        try writer.writeAll("version = ");
                        try writeQuoted(&writer, dep.version);
                        try writer.writeByte('\n');
                        if (dep.checksum) |checksum| {
                            try writer.writeAll("checksum = ");
                            try writeQuoted(&writer, checksum);
                            try writer.writeByte('\n');
                        }
                        try writer.writeByte('\n');
                    }
                }
            }
        }

        return buffer.toOwnedSlice();
    }

    pub fn writeToFile(self: *const Lockfile, allocator: std.mem.Allocator, path: []const u8) PersistError!void {
        const rendered = try self.render(allocator);
        defer allocator.free(rendered);

        var file = std.fs.cwd().createFile(path, .{ .truncate = true, .read = false }) catch {
            return PersistError.Io;
        };
        defer file.close();

        file.writeAll(rendered) catch {
            return PersistError.Io;
        };
    }

    pub fn load(allocator: std.mem.Allocator, path: []const u8) PersistError!Lockfile {
        const contents = std.fs.cwd().readFileAlloc(path, allocator, std.Io.Limit.limited(max_lockfile_bytes)) catch |err| switch (err) {
            error.StreamTooLong => return PersistError.FileTooLarge,
            error.FileNotFound => return PersistError.Io,
            error.NotDir => return PersistError.Io,
            error.AccessDenied => return PersistError.Io,
            else => return PersistError.Io,
        };
        defer allocator.free(contents);

        return parseLockfile(allocator, contents);
    }

    pub fn fromResolution(allocator: std.mem.Allocator, resolution: *Resolver.ResolutionContext, zig_version: []const u8, targets: []const []const u8) PersistError!Lockfile {
        var lockfile = try Lockfile.init(allocator, zig_version, targets);
        errdefer lockfile.deinit();

        var names = ArrayListManaged([]const u8).init(allocator);
        defer names.deinit();

        var iter = resolution.resolved.iterator();
        while (iter.next()) |entry| {
            try names.append(entry.key_ptr.*);
        }

        std.sort.heap([]const u8, names.items, {}, lessThanStrings);

        for (names.items) |name| {
            const pkg = resolution.resolved.get(name) orelse continue;
            const version_str = try pkg.version.format(allocator);
            defer allocator.free(version_str);

            const source_spec = try sourceSpecFromResolver(pkg.source);

            var dep_specs = ArrayListManaged(DependencySpec).init(allocator);
            defer dep_specs.deinit();

            var allocated_versions = ArrayListManaged([]const u8).init(allocator);
            defer {
                for (allocated_versions.items) |item| allocator.free(item);
                allocated_versions.deinit();
            }

            for (pkg.dependencies) |dep| {
                const version_value = dep.raw_constraint orelse blk: {
                    const formatted = try dep.constraint.format(allocator);
                    try allocated_versions.append(formatted);
                    break :blk formatted;
                };

                try dep_specs.append(.{
                    .name = dep.name,
                    .version = version_value,
                    .checksum = null,
                });
            }

            try lockfile.putPackage(.{
                .name = pkg.name,
                .version = version_str,
                .checksum = pkg.checksum,
                .source = source_spec,
                .dependencies = dep_specs.items,
            });
        }

        return lockfile;
    }

    fn clonePackage(self: *Lockfile, spec: PackageSpec) !Package {
        const name = try cloneSlice(self.allocator, spec.name);
        errdefer if (name.len != 0) self.allocator.free(name);

        const version = try cloneSlice(self.allocator, spec.version);
        errdefer if (version.len != 0) self.allocator.free(version);

        const checksum = try cloneOptional(self.allocator, spec.checksum);
        errdefer if (checksum) |value| if (value.len != 0) self.allocator.free(value);

        var source = try self.cloneSource(spec.source);
        errdefer source.deinit(self.allocator);

        const deps = try self.cloneDependencies(spec.dependencies);
        errdefer self.freeDependencySlice(deps);

        return Package{
            .name = name,
            .version = version,
            .checksum = checksum,
            .source = source,
            .dependencies = deps,
        };
    }

    fn cloneSource(self: *Lockfile, spec: SourceSpec) !Source {
        return switch (spec) {
            .git => |git| Source{ .git = .{
                .url = try cloneSlice(self.allocator, git.url),
                .reference_type = git.reference_type,
                .reference = try cloneSlice(self.allocator, git.reference),
            } },
            .path => |path| Source{ .path = try cloneSlice(self.allocator, path) },
            .registry => |reg| Source{ .registry = .{
                .registry = try cloneSlice(self.allocator, reg.registry),
                .name = try cloneSlice(self.allocator, reg.name),
                .version = try cloneSlice(self.allocator, reg.version),
            } },
            .tarball => |tarball| Source{ .tarball = .{
                .url = try cloneSlice(self.allocator, tarball.url),
                .hash = if (tarball.hash) |value| try cloneSlice(self.allocator, value) else null,
            } },
        };
    }

    fn cloneDependencies(self: *Lockfile, specs: []const DependencySpec) ![]Dependency {
        if (specs.len == 0) return &[_]Dependency{};

        var deps = try self.allocator.alloc(Dependency, specs.len);
        errdefer self.freeDependencySlice(deps);

        for (specs, 0..) |spec, idx| deps[idx] = try self.cloneDependency(spec);
        return deps;
    }

    fn cloneDependency(self: *Lockfile, spec: DependencySpec) !Dependency {
        const name = try cloneSlice(self.allocator, spec.name);
        errdefer if (name.len != 0) self.allocator.free(name);

        const version = try cloneSlice(self.allocator, spec.version);
        errdefer if (version.len != 0) self.allocator.free(version);

        const checksum = try cloneOptional(self.allocator, spec.checksum);
        errdefer if (checksum) |value| if (value.len != 0) self.allocator.free(value);

        return Dependency{ .name = name, .version = version, .checksum = checksum };
    }

    fn freeTargets(self: *Lockfile) void {
        for (self.targets.items) |target| if (target.len != 0) self.allocator.free(target);
        self.targets.deinit(self.allocator);
    }

    fn freePackages(self: *Lockfile) void {
        for (self.packages.items) |*pkg| pkg.deinit(self.allocator);
        self.packages.deinit(self.allocator);
    }

    fn freeDependencySlice(self: *Lockfile, deps: []Dependency) void {
        for (deps) |*dep| dep.deinit(self.allocator);
        if (deps.len != 0) self.allocator.free(deps);
    }

    fn findPackageIndex(self: *const Lockfile, name: []const u8) ?usize {
        for (self.packages.items, 0..) |pkg, idx| {
            if (std.mem.eql(u8, pkg.name, name)) return idx;
        }
        return null;
    }
};

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

fn lessThanStrings(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn writeQuoted(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        const c = value[i];
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeByte('"');
}

fn renderSource(writer: anytype, source: Lockfile.Source) !void {
    try writer.writeAll("{ ");
    switch (source) {
        .git => |git| {
            try writer.writeAll("kind = \"git\", url = ");
            try writeQuoted(writer, git.url);
            try writer.writeAll(", reference_type = ");
            try writeQuoted(writer, @tagName(git.reference_type));
            try writer.writeAll(", reference = ");
            try writeQuoted(writer, git.reference);
        },
        .path => |path| {
            try writer.writeAll("kind = \"path\", path = ");
            try writeQuoted(writer, path);
        },
        .registry => |reg| {
            try writer.writeAll("kind = \"registry\", registry = ");
            try writeQuoted(writer, reg.registry);
            try writer.writeAll(", name = ");
            try writeQuoted(writer, reg.name);
            try writer.writeAll(", version = ");
            try writeQuoted(writer, reg.version);
        },
        .tarball => |tarball| {
            try writer.writeAll("kind = \"tarball\", url = ");
            try writeQuoted(writer, tarball.url);
            if (tarball.hash) |hash| {
                try writer.writeAll(", hash = ");
                try writeQuoted(writer, hash);
            }
        },
    }
    try writer.writeAll(" }");
}

fn parseLockfile(allocator: std.mem.Allocator, contents: []const u8) Lockfile.PersistError!Lockfile {
    var parser = Parser.init(allocator);
    defer parser.deinit();

    var index: usize = 0;
    while (index < contents.len) {
        const line_end = std.mem.indexOfScalarPos(u8, contents, index, '\n') orelse contents.len;
        const line = contents[index..line_end];
        index = if (line_end < contents.len) line_end + 1 else contents.len;
        try parser.processLine(line);
    }

    try parser.finish();
    return parser.build();
}

const Parser = struct {
    allocator: std.mem.Allocator,
    version: ?u32 = null,
    zig_version: ?[]const u8 = null,
    targets: std.ArrayListUnmanaged([]const u8) = .{},
    packages: std.ArrayListUnmanaged(Lockfile.Package) = .{},
    state: State = .top,
    current_package: ?PackageBuilder = null,
    current_dependency: ?DependencyBuilder = null,
    transferred: bool = false,

    const State = enum { top, package, dependency };

    fn init(allocator: std.mem.Allocator) Parser {
        return Parser{ .allocator = allocator };
    }

    fn deinit(self: *Parser) void {
        if (self.transferred) return;
        if (self.zig_version) |zig_version| if (zig_version.len != 0) self.allocator.free(zig_version);
        for (self.targets.items) |target| if (target.len != 0) self.allocator.free(target);
        self.targets.deinit(self.allocator);
        for (self.packages.items) |*pkg| pkg.deinit(self.allocator);
        self.packages.deinit(self.allocator);
        if (self.current_dependency) |*dep| dep.deinit();
        if (self.current_package) |*pkg| pkg.deinit();
    }

    fn processLine(self: *Parser, raw_line: []const u8) !void {
        const trimmed_comment = stripInlineComment(raw_line);
        const line = std.mem.trim(u8, trimmed_comment, " \t\r");
        if (line.len == 0) {
            try self.flushDependency();
            return;
        }

        if (std.mem.eql(u8, line, "[[packages]]")) {
            try self.flushDependency();
            try self.flushPackage();
            self.current_package = PackageBuilder.init(self.allocator);
            self.state = .package;
            return;
        }

        if (std.mem.eql(u8, line, "[[packages.dependencies]]")) {
            if (self.state == .top or self.current_package == null) return Lockfile.PersistError.ParseError;
            try self.flushDependency();
            self.current_dependency = DependencyBuilder.init(self.allocator);
            self.state = .dependency;
            return;
        }

        if (line.len >= 2 and line[0] == '[' and line[1] == '[') {
            return Lockfile.PersistError.ParseError;
        }

        try self.parseKeyValue(line);
    }

    fn finish(self: *Parser) !void {
        try self.flushDependency();
        try self.flushPackage();
        self.state = .top;
    }

    fn build(self: *Parser) Lockfile.PersistError!Lockfile {
        const format_version = self.version orelse return Lockfile.PersistError.MissingField;
        if (format_version != Lockfile.format_version) return Lockfile.PersistError.UnsupportedVersion;
        const zig_version = self.zig_version orelse return Lockfile.PersistError.MissingField;

        const lockfile = Lockfile{
            .allocator = self.allocator,
            .zig_version = zig_version,
            .targets = self.targets,
            .packages = self.packages,
        };

        self.targets = .{};
        self.packages = .{};
        self.zig_version = null;
        self.transferred = true;
        return lockfile;
    }

    fn parseKeyValue(self: *Parser, line: []const u8) !void {
        const eq_index = std.mem.indexOfScalar(u8, line, '=') orelse return Lockfile.PersistError.ParseError;
        const key = std.mem.trim(u8, line[0..eq_index], " \t");
        const value = std.mem.trim(u8, line[eq_index + 1 ..], " \t");
        if (value.len == 0) return Lockfile.PersistError.ParseError;

        switch (self.state) {
            .top => try self.assignTopLevel(key, value),
            .package => try self.assignPackageField(key, value),
            .dependency => try self.assignDependencyField(key, value),
        }
    }

    fn assignTopLevel(self: *Parser, key: []const u8, value: []const u8) !void {
        if (std.mem.eql(u8, key, "version")) {
            if (self.version != null) return Lockfile.PersistError.DuplicatePackage;
            self.version = std.fmt.parseInt(u32, value, 10) catch return Lockfile.PersistError.ParseError;
        } else if (std.mem.eql(u8, key, "zig")) {
            if (self.zig_version != null) {
                if (self.zig_version.?.len != 0) self.allocator.free(self.zig_version.?);
            }
            self.zig_version = try parseStringAlloc(self.allocator, value);
        } else if (std.mem.eql(u8, key, "targets")) {
            try self.assignTargets(value);
        } else {
            return Lockfile.PersistError.ParseError;
        }
    }

    fn assignPackageField(self: *Parser, key: []const u8, value: []const u8) !void {
        const builder = blk: {
            if (self.current_package) |*pkg| break :blk pkg;
            return Lockfile.PersistError.ParseError;
        };
        switch (key.len) {
            4 => {
                if (std.mem.eql(u8, key, "name")) {
                    const parsed = try parseStringAlloc(self.allocator, value);
                    errdefer if (parsed.len != 0) self.allocator.free(parsed);
                    builder.setName(parsed);
                    return;
                }
            },
            7 => {
                if (std.mem.eql(u8, key, "version")) {
                    const parsed = try parseStringAlloc(self.allocator, value);
                    errdefer if (parsed.len != 0) self.allocator.free(parsed);
                    builder.setVersion(parsed);
                    return;
                }
            },
            8 => {
                if (std.mem.eql(u8, key, "checksum")) {
                    const parsed = try parseStringAlloc(self.allocator, value);
                    errdefer if (parsed.len != 0) self.allocator.free(parsed);
                    builder.setChecksum(parsed);
                    return;
                }
            },
            6 => {
                if (std.mem.eql(u8, key, "source")) {
                    const source = try parseInlineSource(self.allocator, value);
                    try builder.setSource(source);
                    return;
                }
            },
            else => {},
        }
        return Lockfile.PersistError.ParseError;
    }

    fn assignDependencyField(self: *Parser, key: []const u8, value: []const u8) !void {
        const dep_ptr = blk: {
            if (self.current_dependency) |*dep| break :blk dep;
            return Lockfile.PersistError.ParseError;
        };
        switch (key.len) {
            4 => {
                if (std.mem.eql(u8, key, "name")) {
                    const parsed = try parseStringAlloc(self.allocator, value);
                    errdefer if (parsed.len != 0) self.allocator.free(parsed);
                    dep_ptr.setName(parsed);
                    return;
                }
            },
            7 => {
                if (std.mem.eql(u8, key, "version")) {
                    const parsed = try parseStringAlloc(self.allocator, value);
                    errdefer if (parsed.len != 0) self.allocator.free(parsed);
                    dep_ptr.setVersion(parsed);
                    return;
                }
            },
            8 => {
                if (std.mem.eql(u8, key, "checksum")) {
                    const parsed = try parseStringAlloc(self.allocator, value);
                    errdefer if (parsed.len != 0) self.allocator.free(parsed);
                    dep_ptr.setChecksum(parsed);
                    return;
                }
            },
            else => {},
        }
        return Lockfile.PersistError.ParseError;
    }

    fn assignTargets(self: *Parser, raw: []const u8) !void {
        if (raw.len < 2 or raw[0] != '[' or raw[raw.len - 1] != ']') return Lockfile.PersistError.ParseError;
        for (self.targets.items) |target| if (target.len != 0) self.allocator.free(target);
        self.targets.deinit(self.allocator);
        self.targets = .{};
        const inner = std.mem.trim(u8, raw[1 .. raw.len - 1], " \t");
        if (inner.len == 0) return;

        var index: usize = 0;
        var start: usize = 0;
        var in_string = false;
        while (index <= inner.len) : (index += 1) {
            if (index == inner.len or (inner[index] == ',' and !in_string)) {
                const part = std.mem.trim(u8, inner[start..index], " \t");
                if (part.len == 0) return Lockfile.PersistError.ParseError;
                const item = try parseStringAlloc(self.allocator, part);
                errdefer if (item.len != 0) self.allocator.free(item);
                try self.targets.append(self.allocator, item);
                start = index + 1;
            } else if (inner[index] == '"' and (index == 0 or inner[index - 1] != '\\')) {
                in_string = !in_string;
            }
        }
        if (in_string) return Lockfile.PersistError.ParseError;
    }

    fn flushPackage(self: *Parser) !void {
        try self.flushDependency();
        if (self.current_package) |*builder| {
            var package = try builder.finalize();
            errdefer package.deinit(self.allocator);
            try self.packages.append(self.allocator, package);
            self.current_package = null;
        }
        self.state = .top;
    }

    fn flushDependency(self: *Parser) !void {
        if (self.current_dependency) |*builder| {
            var dependency = try builder.finalize();
            errdefer dependency.deinit(self.allocator);
            const pkg_ptr = blk: {
                if (self.current_package) |*pkg| break :blk pkg;
                return Lockfile.PersistError.ParseError;
            };
            try pkg_ptr.appendDependency(dependency);
            self.current_dependency = null;
        }
        if (self.state == .dependency) self.state = .package;
    }
};

const PackageBuilder = struct {
    allocator: std.mem.Allocator,
    name: ?[]const u8 = null,
    version: ?[]const u8 = null,
    checksum: ?[]const u8 = null,
    source: ?Lockfile.Source = null,
    dependencies: std.ArrayListUnmanaged(Lockfile.Dependency) = .{},

    fn init(allocator: std.mem.Allocator) PackageBuilder {
        return PackageBuilder{ .allocator = allocator };
    }

    fn deinit(self: *PackageBuilder) void {
        if (self.name) |name| if (name.len != 0) self.allocator.free(name);
        if (self.version) |version| if (version.len != 0) self.allocator.free(version);
        if (self.checksum) |checksum| if (checksum.len != 0) self.allocator.free(checksum);
        if (self.source) |*src| src.deinit(self.allocator);
        for (self.dependencies.items) |*dep| dep.deinit(self.allocator);
        self.dependencies.deinit(self.allocator);
    }

    fn setName(self: *PackageBuilder, value: []const u8) void {
        if (self.name) |existing| if (existing.len != 0) self.allocator.free(existing);
        self.name = value;
    }

    fn setVersion(self: *PackageBuilder, value: []const u8) void {
        if (self.version) |existing| if (existing.len != 0) self.allocator.free(existing);
        self.version = value;
    }

    fn setChecksum(self: *PackageBuilder, value: []const u8) void {
        if (self.checksum) |existing| if (existing.len != 0) self.allocator.free(existing);
        self.checksum = value;
    }

    fn setSource(self: *PackageBuilder, source: Lockfile.Source) !void {
        if (self.source) |*existing| existing.deinit(self.allocator);
        self.source = source;
    }

    fn appendDependency(self: *PackageBuilder, dependency: Lockfile.Dependency) !void {
        try self.dependencies.append(self.allocator, dependency);
    }

    fn finalize(self: *PackageBuilder) Lockfile.PersistError!Lockfile.Package {
        const name = self.name orelse return Lockfile.PersistError.MissingField;
        const version = self.version orelse return Lockfile.PersistError.MissingField;
        const source = self.source orelse return Lockfile.PersistError.MissingField;
        const deps_slice = try self.dependencies.toOwnedSlice(self.allocator);
        self.dependencies = .{};
        const pkg = Lockfile.Package{
            .name = name,
            .version = version,
            .checksum = self.checksum,
            .source = source,
            .dependencies = deps_slice,
        };
        self.name = null;
        self.version = null;
        self.checksum = null;
        self.source = null;
        return pkg;
    }
};

const DependencyBuilder = struct {
    allocator: std.mem.Allocator,
    name: ?[]const u8 = null,
    version: ?[]const u8 = null,
    checksum: ?[]const u8 = null,

    fn init(allocator: std.mem.Allocator) DependencyBuilder {
        return DependencyBuilder{ .allocator = allocator };
    }

    fn deinit(self: *DependencyBuilder) void {
        if (self.name) |name| if (name.len != 0) self.allocator.free(name);
        if (self.version) |version| if (version.len != 0) self.allocator.free(version);
        if (self.checksum) |checksum| if (checksum.len != 0) self.allocator.free(checksum);
    }

    fn setName(self: *DependencyBuilder, value: []const u8) void {
        if (self.name) |existing| if (existing.len != 0) self.allocator.free(existing);
        self.name = value;
    }

    fn setVersion(self: *DependencyBuilder, value: []const u8) void {
        if (self.version) |existing| if (existing.len != 0) self.allocator.free(existing);
        self.version = value;
    }

    fn setChecksum(self: *DependencyBuilder, value: []const u8) void {
        if (self.checksum) |existing| if (existing.len != 0) self.allocator.free(existing);
        self.checksum = value;
    }

    fn finalize(self: *DependencyBuilder) Lockfile.PersistError!Lockfile.Dependency {
        const name = self.name orelse return Lockfile.PersistError.MissingField;
        const version = self.version orelse return Lockfile.PersistError.MissingField;
        const dep = Lockfile.Dependency{
            .name = name,
            .version = version,
            .checksum = self.checksum,
        };
        self.name = null;
        self.version = null;
        self.checksum = null;
        return dep;
    }
};

fn stripInlineComment(input: []const u8) []const u8 {
    var in_string = false;
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const c = input[i];
        if (c == '"' and (i == 0 or input[i - 1] != '\\')) {
            in_string = !in_string;
        } else if (c == '#' and !in_string) {
            return input[0..i];
        }
    }
    return input;
}

fn parseStringAlloc(allocator: std.mem.Allocator, raw: []const u8) Lockfile.PersistError![]const u8 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return Lockfile.PersistError.ParseError;
    var builder = ArrayListManaged(u8).init(allocator);
    errdefer builder.deinit();
    var i: usize = 1;
    while (i < raw.len - 1) : (i += 1) {
        const c = raw[i];
        if (c == '\\') {
            i += 1;
            if (i >= raw.len - 1) return Lockfile.PersistError.ParseError;
            switch (raw[i]) {
                '"' => try builder.append('"'),
                '\\' => try builder.append('\\'),
                'n' => try builder.append('\n'),
                'r' => try builder.append('\r'),
                't' => try builder.append('\t'),
                else => return Lockfile.PersistError.ParseError,
            }
        } else {
            try builder.append(c);
        }
    }
    return builder.toOwnedSlice();
}

fn parseInlineSource(allocator: std.mem.Allocator, raw: []const u8) Lockfile.PersistError!Lockfile.Source {
    if (raw.len < 2 or raw[0] != '{' or raw[raw.len - 1] != '}') return Lockfile.PersistError.ParseError;
    const inner = std.mem.trim(u8, raw[1 .. raw.len - 1], " \t");
    if (inner.len == 0) return Lockfile.PersistError.ParseError;

    var kind: ?[]const u8 = null;
    var url: ?[]const u8 = null;
    var reference_type_raw: ?[]const u8 = null;
    var reference_value: ?[]const u8 = null;
    var path_value: ?[]const u8 = null;
    var registry_url: ?[]const u8 = null;
    var registry_name: ?[]const u8 = null;
    var registry_version: ?[]const u8 = null;
    var hash_value: ?[]const u8 = null;

    errdefer {
        if (url) |value| if (value.len != 0) allocator.free(value);
        if (reference_value) |value| if (value.len != 0) allocator.free(value);
        if (path_value) |value| if (value.len != 0) allocator.free(value);
        if (registry_url) |value| if (value.len != 0) allocator.free(value);
        if (registry_name) |value| if (value.len != 0) allocator.free(value);
        if (registry_version) |value| if (value.len != 0) allocator.free(value);
        if (hash_value) |value| if (value.len != 0) allocator.free(value);
    }

    var index: usize = 0;
    var start: usize = 0;
    var in_string = false;
    while (index <= inner.len) : (index += 1) {
        if (index == inner.len or (inner[index] == ',' and !in_string)) {
            const segment = std.mem.trim(u8, inner[start..index], " \t");
            if (segment.len == 0) return Lockfile.PersistError.ParseError;
            const eq_index = std.mem.indexOfScalar(u8, segment, '=') orelse return Lockfile.PersistError.ParseError;
            const key = std.mem.trim(u8, segment[0..eq_index], " \t");
            const value = std.mem.trim(u8, segment[eq_index + 1 ..], " \t");
            const parsed = try parseStringAlloc(allocator, value);
            errdefer allocator.free(parsed);

            if (std.mem.eql(u8, key, "kind")) {
                if (kind) |existing| allocator.free(existing);
                kind = parsed;
                start = index + 1;
                continue;
            } else if (std.mem.eql(u8, key, "url")) {
                if (url) |existing| allocator.free(existing);
                url = parsed;
                start = index + 1;
                continue;
            } else if (std.mem.eql(u8, key, "reference_type")) {
                if (reference_type_raw) |existing| allocator.free(existing);
                reference_type_raw = parsed;
                start = index + 1;
                continue;
            } else if (std.mem.eql(u8, key, "reference")) {
                if (reference_value) |existing| allocator.free(existing);
                reference_value = parsed;
                start = index + 1;
                continue;
            } else if (std.mem.eql(u8, key, "path")) {
                if (path_value) |existing| allocator.free(existing);
                path_value = parsed;
                start = index + 1;
                continue;
            } else if (std.mem.eql(u8, key, "registry")) {
                if (registry_url) |existing| allocator.free(existing);
                registry_url = parsed;
                start = index + 1;
                continue;
            } else if (std.mem.eql(u8, key, "name")) {
                if (registry_name) |existing| allocator.free(existing);
                registry_name = parsed;
                start = index + 1;
                continue;
            } else if (std.mem.eql(u8, key, "version")) {
                if (registry_version) |existing| allocator.free(existing);
                registry_version = parsed;
                start = index + 1;
                continue;
            } else if (std.mem.eql(u8, key, "hash")) {
                if (hash_value) |existing| allocator.free(existing);
                hash_value = parsed;
                start = index + 1;
                continue;
            } else {
                allocator.free(parsed);
                return Lockfile.PersistError.ParseError;
            }
        } else if (inner[index] == '"' and (index == 0 or inner[index - 1] != '\\')) {
            in_string = !in_string;
        }
    }
    if (in_string) return Lockfile.PersistError.ParseError;

    const kind_value = kind orelse return Lockfile.PersistError.MissingField;
    defer allocator.free(kind_value);

    if (std.mem.eql(u8, kind_value, "git")) {
        const url_value = url orelse return Lockfile.PersistError.MissingField;
        url = null;
        const ref_type_raw = reference_type_raw orelse return Lockfile.PersistError.MissingField;
        defer allocator.free(ref_type_raw);
        const ref_value = reference_value orelse return Lockfile.PersistError.MissingField;
        reference_value = null;

        const ref_type = std.meta.stringToEnum(GitReferenceType, ref_type_raw) orelse return Lockfile.PersistError.InvalidSource;
        return Lockfile.Source{ .git = .{
            .url = url_value,
            .reference_type = ref_type,
            .reference = ref_value,
        } };
    } else if (std.mem.eql(u8, kind_value, "path")) {
        const path = path_value orelse return Lockfile.PersistError.MissingField;
        path_value = null;
        return Lockfile.Source{ .path = path };
    } else if (std.mem.eql(u8, kind_value, "registry")) {
        const reg_url = registry_url orelse return Lockfile.PersistError.MissingField;
        const reg_name = registry_name orelse return Lockfile.PersistError.MissingField;
        const reg_version = registry_version orelse return Lockfile.PersistError.MissingField;
        registry_url = null;
        registry_name = null;
        registry_version = null;
        return Lockfile.Source{ .registry = .{
            .registry = reg_url,
            .name = reg_name,
            .version = reg_version,
        } };
    } else if (std.mem.eql(u8, kind_value, "tarball")) {
        const url_value = url orelse return Lockfile.PersistError.MissingField;
        url = null;
        const hash = hash_value;
        hash_value = null;
        return Lockfile.Source{ .tarball = .{
            .url = url_value,
            .hash = hash,
        } };
    } else {
        return Lockfile.PersistError.InvalidSource;
    }
}

fn sourceSpecFromResolver(source: Resolver.Source) Lockfile.PersistError!Lockfile.SourceSpec {
    return switch (source) {
        .git => |git| .{ .git = .{
            .url = git.url,
            .reference_type = switch (git.ref) {
                .branch => .branch,
                .tag => .tag,
                .commit => .commit,
            },
            .reference = switch (git.ref) {
                .branch => |value| value,
                .tag => |value| value,
                .commit => |value| value,
            },
        } },
        .path => |path| .{ .path = path },
        .registry => |registry| .{ .registry = .{
            .registry = registry.registry,
            .name = registry.name,
            .version = registry.version,
        } },
        .tarball => |tarball| .{ .tarball = .{
            .url = tarball.url,
            .hash = tarball.hash,
        } },
    };
}

fn sampleGitSpec() Lockfile.GitSpec {
    return .{ .url = "https://example.com/foo.git", .reference_type = .tag, .reference = "v1.0.0" };
}

fn sampleDependencySpec(name: []const u8, version: []const u8) Lockfile.DependencySpec {
    return .{ .name = name, .version = version };
}

test "lockfile init clones version and targets" {
    var lockfile = try Lockfile.init(testing.allocator, "0.16.0", &[_][]const u8{"x86_64-linux-gnu"});
    defer lockfile.deinit();

    try testing.expectEqualStrings("0.16.0", lockfile.zigVersion());
    try testing.expectEqual(@as(usize, 1), lockfile.targetsSlice().len);
    try testing.expectEqualStrings("x86_64-linux-gnu", lockfile.targetsSlice()[0]);
}

test "sourceSpecFromResolver preserves registry url" {
    const source = Resolver.Source{ .registry = .{
        .registry = "https://registry.example.com",
        .name = "demo",
        .version = "1.0.0",
    } };

    const spec = try sourceSpecFromResolver(source);
    switch (spec) {
        .registry => |reg| {
            try testing.expectEqualStrings("https://registry.example.com", reg.registry);
            try testing.expectEqualStrings("demo", reg.name);
            try testing.expectEqualStrings("1.0.0", reg.version);
        },
        else => return testing.expect(false),
    }
}

test "lockfile putPackage inserts and replaces" {
    var lockfile = try Lockfile.init(testing.allocator, "0.16.0", &[_][]const u8{});
    defer lockfile.deinit();

    const first_spec = Lockfile.PackageSpec{
        .name = "core",
        .version = "1.0.0",
        .checksum = "abc123",
        .source = .{ .git = sampleGitSpec() },
        .dependencies = &[_]Lockfile.DependencySpec{
            sampleDependencySpec("dep", "0.5.0"),
        },
    };

    try lockfile.putPackage(first_spec);
    const stored_first = lockfile.getPackage("core") orelse return error.PackageMissing;
    try testing.expectEqualStrings("1.0.0", stored_first.version);
    try testing.expect(stored_first.checksum != null);
    try testing.expectEqual(@as(usize, 1), stored_first.dependencies.len);

    const second_spec = Lockfile.PackageSpec{
        .name = "core",
        .version = "1.1.0",
        .source = .{ .path = "../core" },
    };

    try lockfile.putPackage(second_spec);
    const stored_second = lockfile.getPackage("core") orelse return error.PackageMissing;
    try testing.expectEqualStrings("1.1.0", stored_second.version);
    try testing.expect(stored_second.checksum == null);
    try testing.expectEqual(@as(usize, 0), stored_second.dependencies.len);
}

test "lockfile removePackage" {
    var lockfile = try Lockfile.init(testing.allocator, "0.16.0", &[_][]const u8{});
    defer lockfile.deinit();

    try lockfile.putPackage(.{
        .name = "util",
        .version = "0.1.0",
        .source = .{ .tarball = .{ .url = "https://example.com/util.tar.gz" } },
    });

    try testing.expect(lockfile.removePackage("util"));
    try testing.expect(lockfile.getPackage("util") == null);
    try testing.expect(!lockfile.removePackage("util"));
}

test "lockfile render and load roundtrip" {
    var allocator = testing.allocator;
    var lockfile = try Lockfile.init(allocator, "0.16.0", &[_][]const u8{ "x86_64-linux-gnu", "aarch64-macos" });
    defer lockfile.deinit();

    try lockfile.putPackage(.{
        .name = "core",
        .version = "1.0.0",
        .source = .{ .git = sampleGitSpec() },
        .dependencies = &[_]Lockfile.DependencySpec{
            sampleDependencySpec("dep-one", "^0.5"),
            sampleDependencySpec("dep-two", "1.2.3"),
        },
    });

    try lockfile.putPackage(.{
        .name = "archive",
        .version = "2.0.0",
        .source = .{ .tarball = .{ .url = "https://example.com/archive-2.0.0.tar.gz", .hash = "sha256-ff00" } },
    });

    try lockfile.putPackage(.{
        .name = "helper",
        .version = "0.2.0",
        .checksum = "sha256-123",
        .source = .{ .path = "../helper" },
    });

    const rendered = try lockfile.render(allocator);
    defer allocator.free(rendered);

    var loaded = try parseLockfile(allocator, rendered);
    defer loaded.deinit();

    try testing.expectEqualStrings(lockfile.zigVersion(), loaded.zigVersion());
    try testing.expectEqual(lockfile.targetsSlice().len, loaded.targetsSlice().len);
    try testing.expectEqual(lockfile.packagesSlice().len, loaded.packagesSlice().len);

    const archive_pkg = loaded.getPackage("archive") orelse return error.PackageMissing;
    switch (archive_pkg.source) {
        .tarball => |tarball| {
            try testing.expectEqualStrings("https://example.com/archive-2.0.0.tar.gz", tarball.url);
            try testing.expect(tarball.hash != null);
            try testing.expectEqualStrings("sha256-ff00", tarball.hash.?);
        },
        else => return error.PackageMissing,
    }
}

test "lockfile from resolution" {
    var allocator = testing.allocator;
    var context = Resolver.ResolutionContext.init(allocator);
    defer context.deinit();

    const version = try semver.SemanticVersion.parse(allocator, "1.2.3");
    const git_source = Resolver.Source{ .git = .{
        .url = try allocator.dupe(u8, "https://example.com/core.git"),
        .ref = Resolver.Source.GitRef{ .tag = try allocator.dupe(u8, "v1.2.3") },
    } };

    const resolved = Resolver.ResolvedPackage{
        .name = try allocator.dupe(u8, "core"),
        .version = version,
        .source = git_source,
        .dependencies = &[_]Resolver.Dependency{},
        .checksum = null,
    };

    try context.resolved.put("core", resolved);

    const tarball_source = Resolver.Source{ .tarball = .{
        .url = try allocator.dupe(u8, "https://example.com/archive-2.0.0.tar.gz"),
        .hash = try allocator.dupe(u8, "sha256-deadbeef"),
    } };

    const tarball_version = try semver.SemanticVersion.parse(allocator, "2.0.0");

    const tarball_pkg = Resolver.ResolvedPackage{
        .name = try allocator.dupe(u8, "archive"),
        .version = tarball_version,
        .source = tarball_source,
        .dependencies = &[_]Resolver.Dependency{},
        .checksum = null,
    };

    try context.resolved.put("archive", tarball_pkg);

    var lockfile = try Lockfile.fromResolution(allocator, &context, "0.16.0", &[_][]const u8{"x86_64-linux-gnu"});
    defer lockfile.deinit();

    try testing.expectEqual(@as(usize, 2), lockfile.packagesSlice().len);

    const pkg_core = lockfile.getPackage("core") orelse return error.PackageMissing;
    try testing.expect(std.mem.eql(u8, pkg_core.source.git.url, "https://example.com/core.git"));

    const pkg_archive = lockfile.getPackage("archive") orelse return error.PackageMissing;
    switch (pkg_archive.source) {
        .tarball => |tarball| {
            try testing.expectEqualStrings("https://example.com/archive-2.0.0.tar.gz", tarball.url);
            try testing.expect(tarball.hash != null);
            try testing.expectEqualStrings("sha256-deadbeef", tarball.hash.?);
        },
        else => return error.PackageMissing,
    }
}
