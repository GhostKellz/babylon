const std = @import("std");
const testing = std.testing;

pub const Manifest = struct {
    allocator: std.mem.Allocator,
    source_buffer: []u8,
    source_len: usize,
    tree: std.zig.Ast,
    root_node: std.zig.Ast.Node.Index,
    name: []const u8,
    version: []const u8,
    minimum_zig_version: []const u8,
    dependencies: []Dependency,
    entries: []DependencyEntry,
    dependencies_node: ?std.zig.Ast.Node.Index,

    pub const filename = "build.zig.zon";

    pub const GitReferenceType = enum { branch, tag, commit };

    pub const Dependency = struct {
        name: []const u8,
        constraint: ?[]const u8,
        source: Source,

        pub fn initGit(
            allocator: std.mem.Allocator,
            name: []const u8,
            constraint: []const u8,
            url: []const u8,
            reference_type: GitReferenceType,
            reference: []const u8,
        ) !Dependency {
            return .{
                .name = try allocator.dupe(u8, name),
                .constraint = try allocator.dupe(u8, constraint),
                .source = .{ .git = try Git.init(allocator, url, reference_type, reference) },
            };
        }

        pub fn initPath(
            allocator: std.mem.Allocator,
            name: []const u8,
            constraint: ?[]const u8,
            location: []const u8,
        ) !Dependency {
            var constraint_copy: ?[]const u8 = null;
            if (constraint) |value| constraint_copy = try allocator.dupe(u8, value);

            return .{
                .name = try allocator.dupe(u8, name),
                .constraint = constraint_copy,
                .source = .{ .path = try Path.init(allocator, location) },
            };
        }

        pub fn initTarball(
            allocator: std.mem.Allocator,
            name: []const u8,
            constraint: []const u8,
            url: []const u8,
            hash: ?[]const u8,
        ) !Dependency {
            return .{
                .name = try allocator.dupe(u8, name),
                .constraint = try allocator.dupe(u8, constraint),
                .source = .{ .tarball = try Tarball.init(allocator, url, hash) },
            };
        }

        pub fn deinit(self: *Dependency, allocator: std.mem.Allocator) void {
            allocator.free(self.name);
            if (self.constraint) |value| allocator.free(value);
            self.source.deinit(allocator);
        }
    };

    pub const Source = union(enum) {
        git: Git,
        path: Path,
        tarball: Tarball,

        pub fn deinit(self: *Source, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .git => |*git| git.deinit(allocator),
                .path => |*path| path.deinit(allocator),
                .tarball => |*tarball| tarball.deinit(allocator),
            }
        }
    };

    pub const Git = struct {
        url: []const u8,
        reference_type: GitReferenceType,
        reference: []const u8,

        pub fn init(
            allocator: std.mem.Allocator,
            url: []const u8,
            reference_type: GitReferenceType,
            reference: []const u8,
        ) !Git {
            return .{
                .url = try allocator.dupe(u8, url),
                .reference_type = reference_type,
                .reference = try allocator.dupe(u8, reference),
            };
        }

        pub fn deinit(self: *Git, allocator: std.mem.Allocator) void {
            allocator.free(self.url);
            allocator.free(self.reference);
        }
    };

    pub const Path = struct {
        location: []const u8,

        pub fn init(allocator: std.mem.Allocator, location: []const u8) !Path {
            return .{ .location = try allocator.dupe(u8, location) };
        }

        pub fn deinit(self: *Path, allocator: std.mem.Allocator) void {
            allocator.free(self.location);
        }
    };

    pub const Tarball = struct {
        url: []const u8,
        hash: ?[]const u8,

        pub fn init(allocator: std.mem.Allocator, url: []const u8, hash: ?[]const u8) !Tarball {
            return .{
                .url = try allocator.dupe(u8, url),
                .hash = if (hash) |value| try allocator.dupe(u8, value) else null,
            };
        }

        pub fn deinit(self: *Tarball, allocator: std.mem.Allocator) void {
            allocator.free(self.url);
            if (self.hash) |value| allocator.free(value);
        }
    };

    const DependencyEntry = struct {
        index: ?usize,
        name: []const u8,
        owns_name: bool,
        span_start: usize,
        span_end: usize,
        trailing_comma: bool,
    };

    fn renderDependencyFromData(
        self: *Manifest,
        entry_prefix: []const u8,
        trailing_indent: []const u8,
        name: []const u8,
        dep: Manifest.Dependency,
        include_trailing_comma: bool,
    ) ![]u8 {
        return switch (dep.source) {
            .git => |git| blk: {
                const constraint = dep.constraint orelse return error.ManifestInvalidDependency;
                break :blk try self.renderGitDependencySnippet(
                    entry_prefix,
                    trailing_indent,
                    name,
                    constraint,
                    git.url,
                    git.reference_type,
                    git.reference,
                    include_trailing_comma,
                );
            },
            .path => |path| try self.renderPathDependencySnippet(
                entry_prefix,
                trailing_indent,
                name,
                dep.constraint,
                path.location,
                include_trailing_comma,
            ),
            .tarball => |tarball| blk: {
                const constraint = dep.constraint orelse return error.ManifestInvalidDependency;
                break :blk try self.renderTarballDependencySnippet(
                    entry_prefix,
                    trailing_indent,
                    name,
                    constraint,
                    tarball.url,
                    tarball.hash,
                    include_trailing_comma,
                );
            },
        };
    }

    fn renderGitDependencySnippet(
        self: *Manifest,
        entry_prefix: []const u8,
        trailing_indent: []const u8,
        name: []const u8,
        constraint: []const u8,
        url: []const u8,
        reference_type: GitReferenceType,
        reference: []const u8,
        include_trailing_comma: bool,
    ) ![]u8 {
        var list = std.ArrayList(u8).empty;
        errdefer list.deinit(self.allocator);

        const indent = if (entry_prefix.len != 0 and entry_prefix[entry_prefix.len - 1] == '.')
            entry_prefix[0 .. entry_prefix.len - 1]
        else
            entry_prefix;

        try list.appendSlice(self.allocator, entry_prefix);
        try list.appendSlice(self.allocator, name);
        try list.appendSlice(self.allocator, " = .{\n");

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "    .constraint = \"");
        try list.appendSlice(self.allocator, constraint);
        try list.appendSlice(self.allocator, "\",\n");

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "    .git = .{\n");

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "        .url = \"");
        try list.appendSlice(self.allocator, url);
        try list.appendSlice(self.allocator, "\",\n");

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "        .reference_type = \"");
        try list.appendSlice(self.allocator, @tagName(reference_type));
        try list.appendSlice(self.allocator, "\",\n");

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "        .reference = \"");
        try list.appendSlice(self.allocator, reference);
        try list.appendSlice(self.allocator, "\",\n");

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "    },\n");

        try list.appendSlice(self.allocator, indent);
        if (include_trailing_comma) {
            try list.appendSlice(self.allocator, "},\n");
        } else {
            try list.appendSlice(self.allocator, "}\n");
        }

        try list.appendSlice(self.allocator, trailing_indent);

        const result = try list.toOwnedSlice(self.allocator);
        list.deinit(self.allocator);
        return result;
    }

    fn renderTarballDependencySnippet(
        self: *Manifest,
        entry_prefix: []const u8,
        trailing_indent: []const u8,
        name: []const u8,
        constraint: []const u8,
        url: []const u8,
        hash: ?[]const u8,
        include_trailing_comma: bool,
    ) ![]u8 {
        var list = std.ArrayList(u8).empty;
        errdefer list.deinit(self.allocator);

        const indent = if (entry_prefix.len != 0 and entry_prefix[entry_prefix.len - 1] == '.')
            entry_prefix[0 .. entry_prefix.len - 1]
        else
            entry_prefix;

        try list.appendSlice(self.allocator, entry_prefix);
        try list.appendSlice(self.allocator, name);
        try list.appendSlice(self.allocator, " = .{\n");

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "    .constraint = ");
        try list.appendSlice(self.allocator, "\"");
        try list.appendSlice(self.allocator, constraint);
        try list.appendSlice(self.allocator, "\",\n");

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "    .tarball = .{\n");

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "        .url = ");
        try list.appendSlice(self.allocator, "\"");
        try list.appendSlice(self.allocator, url);
        try list.appendSlice(self.allocator, "\",\n");

        if (hash) |hash_value| {
            try list.appendSlice(self.allocator, indent);
            try list.appendSlice(self.allocator, "        .hash = ");
            try list.appendSlice(self.allocator, "\"");
            try list.appendSlice(self.allocator, hash_value);
            try list.appendSlice(self.allocator, "\",\n");
        }

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "    },\n");

        try list.appendSlice(self.allocator, indent);
        if (include_trailing_comma) {
            try list.appendSlice(self.allocator, "},\n");
        } else {
            try list.appendSlice(self.allocator, "}\n");
        }

        try list.appendSlice(self.allocator, trailing_indent);

        const result = try list.toOwnedSlice(self.allocator);
        list.deinit(self.allocator);
        return result;
    }

    fn renderPathDependencySnippet(
        self: *Manifest,
        entry_prefix: []const u8,
        trailing_indent: []const u8,
        name: []const u8,
        constraint: ?[]const u8,
        path: []const u8,
        include_trailing_comma: bool,
    ) ![]u8 {
        var list = std.ArrayList(u8).empty;
        errdefer list.deinit(self.allocator);

        const indent = if (entry_prefix.len != 0 and entry_prefix[entry_prefix.len - 1] == '.')
            entry_prefix[0 .. entry_prefix.len - 1]
        else
            entry_prefix;

        try list.appendSlice(self.allocator, entry_prefix);
        try list.appendSlice(self.allocator, name);
        try list.appendSlice(self.allocator, " = .{\n");

        if (constraint) |value| {
            try list.appendSlice(self.allocator, indent);
            try list.appendSlice(self.allocator, "    .constraint = \"");
            try list.appendSlice(self.allocator, value);
            try list.appendSlice(self.allocator, "\",\n");
        }

        try list.appendSlice(self.allocator, indent);
        try list.appendSlice(self.allocator, "    .path = \"");
        try list.appendSlice(self.allocator, path);
        try list.appendSlice(self.allocator, "\",\n");

        try list.appendSlice(self.allocator, indent);
        if (include_trailing_comma) {
            try list.appendSlice(self.allocator, "},\n");
        } else {
            try list.appendSlice(self.allocator, "}\n");
        }

        try list.appendSlice(self.allocator, trailing_indent);

        const result = try list.toOwnedSlice(self.allocator);
        list.deinit(self.allocator);
        return result;
    }

    const SpanRange = struct {
        start: usize,
        end: usize,
        trailing_comma: bool,
    };

    const DependenciesInfo = struct {
        lbrace_token: std.zig.Ast.TokenIndex,
        rbrace_token: std.zig.Ast.TokenIndex,
        entry_indent: []const u8,
        closing_indent: []const u8,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        name: []const u8,
        version: []const u8,
        zig_version: []const u8,
    ) !Manifest {
        const template =
            \\.{{
            \\    .name = .{s},
            \\    .version = "{s}",
            \\    .minimum_zig_version = "{s}",
            \\    .dependencies = .{{
            \\    }},
            \\}}
        ;
        const content = try std.fmt.allocPrint(allocator, template, .{ name, version, zig_version });
        defer allocator.free(content);
        return Manifest.parse(allocator, content);
    }

    pub fn load(allocator: std.mem.Allocator, path: []const u8) !Manifest {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const stat = try file.stat();
        if (stat.size > 1024 * 1024) return error.FileTooBig;

        const size: usize = @intCast(stat.size);
        var buffer = try allocator.alloc(u8, size + 1);

        const read = try file.readAll(buffer[0..size]);
        if (read != stat.size) return error.UnexpectedEndOfFile;

        buffer[size] = 0;
        return try initFromOwnedBuffer(allocator, buffer, size);
    }

    pub fn parse(allocator: std.mem.Allocator, content: []const u8) !Manifest {
        var buffer = try allocator.alloc(u8, content.len + 1);
        @memcpy(buffer[0..content.len], content);
        buffer[content.len] = 0;
        return try initFromOwnedBuffer(allocator, buffer, content.len);
    }

    fn initFromOwnedBuffer(
        allocator: std.mem.Allocator,
        buffer: []u8,
        source_len: usize,
    ) !Manifest {
        const sentinel_slice: [:0]const u8 = buffer[0..source_len :0];
        const tree = std.zig.Ast.parse(allocator, sentinel_slice, .zon) catch |err| {
            allocator.free(buffer);
            return err;
        };

        var manifest = Manifest{
            .allocator = allocator,
            .source_buffer = buffer,
            .source_len = source_len,
            .tree = tree,
            .root_node = undefined,
            .name = &[_]u8{},
            .version = &[_]u8{},
            .minimum_zig_version = &[_]u8{},
            .dependencies = &[_]Dependency{},
            .entries = &[_]DependencyEntry{},
            .dependencies_node = null,
        };
        errdefer manifest.deinit();

        try manifest.populate();
        return manifest;
    }

    pub fn deinit(self: *Manifest) void {
        for (self.dependencies) |*dep| dep.deinit(self.allocator);
        if (self.dependencies.len != 0) self.allocator.free(self.dependencies);

        for (self.entries) |entry| {
            if (entry.owns_name) self.allocator.free(entry.name);
        }
        if (self.entries.len != 0) self.allocator.free(self.entries);

        if (self.name.len != 0) self.allocator.free(self.name);
        if (self.version.len != 0) self.allocator.free(self.version);
        if (self.minimum_zig_version.len != 0) self.allocator.free(self.minimum_zig_version);

        self.tree.deinit(self.allocator);
        self.allocator.free(self.source_buffer);

        self.* = undefined;
    }

    pub fn source(self: *const Manifest) []const u8 {
        return self.source_buffer[0..self.source_len];
    }

    pub fn render(self: *const Manifest, allocator: std.mem.Allocator) ![]u8 {
        return allocator.dupe(u8, self.source());
    }

    pub fn save(self: *const Manifest, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(self.source());
    }

    pub fn upsertDependency(
        self: *Manifest,
        allocator: std.mem.Allocator,
        name: []const u8,
        constraint: []const u8,
        url: []const u8,
        reference_type: GitReferenceType,
        reference: []const u8,
    ) !void {
        _ = allocator;

        const info = try self.dependenciesInfo();

        if (self.findEntryIndex(name)) |entry_idx| {
            const entry = self.entries[entry_idx];
            const entry_prefix = self.entryPrefix(entry.span_start);
            const trailing_indent = self.trailingIndentAfterEntry(entry_idx, info);
            const include_comma = entry.trailing_comma;
            const snippet = try self.renderGitDependencySnippet(
                entry_prefix,
                trailing_indent,
                name,
                constraint,
                url,
                reference_type,
                reference,
                include_comma,
            );
            defer self.allocator.free(snippet);

            const updated = try self.buildUpdatedSource(
                entry.span_start,
                entry.span_end,
                snippet,
            );
            defer self.allocator.free(updated);

            try self.rebuildWithSource(updated);
        } else {
            const entry_prefix_buf = try self.allocateNewEntryPrefix(info);
            defer self.allocator.free(entry_prefix_buf);
            const trailing_indent = info.closing_indent;
            const snippet = try self.renderGitDependencySnippet(
                entry_prefix_buf,
                trailing_indent,
                name,
                constraint,
                url,
                reference_type,
                reference,
                true,
            );
            defer self.allocator.free(snippet);

            const insert_pos = self.tree.tokenStart(info.rbrace_token);
            const updated = try self.buildUpdatedSource(insert_pos, insert_pos, snippet);
            defer self.allocator.free(updated);

            try self.rebuildWithSource(updated);
        }
    }

    pub fn upsertTarballDependency(
        self: *Manifest,
        allocator: std.mem.Allocator,
        name: []const u8,
        constraint: []const u8,
        url: []const u8,
        hash: ?[]const u8,
    ) !void {
        _ = allocator;

        const info = try self.dependenciesInfo();

        if (self.findEntryIndex(name)) |entry_idx| {
            const entry = self.entries[entry_idx];
            const entry_prefix = self.entryPrefix(entry.span_start);
            const trailing_indent = self.trailingIndentAfterEntry(entry_idx, info);
            const include_comma = entry.trailing_comma;
            const snippet = try self.renderTarballDependencySnippet(
                entry_prefix,
                trailing_indent,
                name,
                constraint,
                url,
                hash,
                include_comma,
            );
            defer self.allocator.free(snippet);

            const updated = try self.buildUpdatedSource(entry.span_start, entry.span_end, snippet);
            defer self.allocator.free(updated);

            try self.rebuildWithSource(updated);
        } else {
            const entry_prefix_buf = try self.allocateNewEntryPrefix(info);
            defer self.allocator.free(entry_prefix_buf);
            const trailing_indent = info.closing_indent;
            const snippet = try self.renderTarballDependencySnippet(
                entry_prefix_buf,
                trailing_indent,
                name,
                constraint,
                url,
                hash,
                true,
            );
            defer self.allocator.free(snippet);

            const insert_pos = self.tree.tokenStart(info.rbrace_token);
            const updated = try self.buildUpdatedSource(insert_pos, insert_pos, snippet);
            defer self.allocator.free(updated);

            try self.rebuildWithSource(updated);
        }
    }

    pub fn setLocalPath(
        self: *Manifest,
        allocator: std.mem.Allocator,
        name: []const u8,
        path: []const u8,
        constraint: ?[]const u8,
    ) !void {
        _ = allocator;

        const info = try self.dependenciesInfo();

        if (self.findEntryIndex(name)) |entry_idx| {
            const entry = self.entries[entry_idx];
            const entry_prefix = self.entryPrefix(entry.span_start);
            const trailing_indent = self.trailingIndentAfterEntry(entry_idx, info);
            const snippet = try self.renderPathDependencySnippet(
                entry_prefix,
                trailing_indent,
                name,
                constraint,
                path,
                entry.trailing_comma,
            );
            defer self.allocator.free(snippet);

            const updated = try self.buildUpdatedSource(entry.span_start, entry.span_end, snippet);
            defer self.allocator.free(updated);

            try self.rebuildWithSource(updated);
        } else {
            const entry_prefix_buf = try self.allocateNewEntryPrefix(info);
            defer self.allocator.free(entry_prefix_buf);
            const trailing_indent = info.closing_indent;
            const snippet = try self.renderPathDependencySnippet(
                entry_prefix_buf,
                trailing_indent,
                name,
                constraint,
                path,
                true,
            );
            defer self.allocator.free(snippet);

            const insert_pos = self.tree.tokenStart(info.rbrace_token);
            const updated = try self.buildUpdatedSource(insert_pos, insert_pos, snippet);
            defer self.allocator.free(updated);

            try self.rebuildWithSource(updated);
        }
    }

    pub fn renameDependency(
        self: *Manifest,
        allocator: std.mem.Allocator,
        from: []const u8,
        to: []const u8,
    ) !bool {
        _ = allocator;

        const entry_idx = self.findEntryIndex(from) orelse return false;
        const info = self.dependenciesInfo() catch return false;
        const entry = self.entries[entry_idx];
        const dep_index = entry.index orelse return false;

        const entry_prefix = self.entryPrefix(entry.span_start);
        const trailing_indent = self.trailingIndentAfterEntry(entry_idx, info);

        const snippet = try self.renderDependencyFromData(
            entry_prefix,
            trailing_indent,
            to,
            self.dependencies[dep_index],
            entry.trailing_comma,
        );
        defer self.allocator.free(snippet);

        const updated = try self.buildUpdatedSource(entry.span_start, entry.span_end, snippet);
        defer self.allocator.free(updated);

        try self.rebuildWithSource(updated);
        return true;
    }

    pub fn normalize(self: *Manifest) !void {
        const snapshot = try self.render(self.allocator);
        defer self.allocator.free(snapshot);
        try self.rebuildWithSource(snapshot);
    }

    pub fn removeDependency(self: *Manifest, allocator: std.mem.Allocator, name: []const u8) bool {
        _ = allocator;
        const entry_idx = self.findEntryIndex(name) orelse return false;

        const info = self.dependenciesInfo() catch return false;
        const trailing_indent = self.trailingIndentAfterEntry(entry_idx, info);

        const updated = self.buildUpdatedSource(
            self.entries[entry_idx].span_start,
            self.entries[entry_idx].span_end,
            trailing_indent,
        ) catch return false;
        defer self.allocator.free(updated);

        self.rebuildWithSource(updated) catch return false;
        return true;
    }

    fn populate(self: *Manifest) !void {
        var buffer: [2]std.zig.Ast.Node.Index = undefined;
        const root_container = self.tree.containerDeclRoot();
        if (root_container.ast.members.len == 0) return error.ManifestInvalidRoot;

        self.root_node = root_container.ast.members[0];
        const root_struct = self.tree.fullStructInit(&buffer, self.root_node) orelse return error.ManifestInvalidRoot;

        var name_value: ?[]const u8 = null;
        var version_node: ?[]u8 = null;
        var zig_node: ?[]u8 = null;
        errdefer if (version_node) |slice| self.allocator.free(slice);
        errdefer if (zig_node) |slice| self.allocator.free(slice);
        var deps_node: ?std.zig.Ast.Node.Index = null;

        for (root_struct.ast.fields) |field_node| {
            const field_name = self.fieldName(field_node);
            if (std.mem.eql(u8, field_name, "name")) {
                name_value = try self.parseEnumLiteral(field_node);
            } else if (std.mem.eql(u8, field_name, "version")) {
                version_node = try self.parseStringLiteralAlloc(field_node);
            } else if (std.mem.eql(u8, field_name, "minimum_zig_version")) {
                zig_node = try self.parseStringLiteralAlloc(field_node);
            } else if (std.mem.eql(u8, field_name, "dependencies")) {
                deps_node = field_node;
            }
        }

        const final_name = name_value orelse return error.ManifestMissingName;
        const final_version = version_node orelse return error.ManifestMissingVersion;
        const final_zig = zig_node orelse return error.ManifestMissingZigVersion;

        errdefer self.allocator.free(final_version);
        errdefer self.allocator.free(final_zig);

        self.name = try self.allocator.dupe(u8, final_name);
        self.version = final_version;
        version_node = null;
        self.minimum_zig_version = final_zig;
        zig_node = null;
        self.dependencies_node = deps_node;

        if (deps_node) |node| {
            try self.parseDependencies(node);
        } else {
            self.dependencies = &[_]Dependency{};
            self.entries = &[_]DependencyEntry{};
        }
    }

    fn parseDependencies(self: *Manifest, node: std.zig.Ast.Node.Index) !void {
        var deps = std.ArrayList(Dependency).empty;
        errdefer {
            for (deps.items) |*dep| dep.deinit(self.allocator);
            deps.deinit(self.allocator);
        }

        var entries = std.ArrayList(DependencyEntry).empty;
        errdefer {
            for (entries.items) |entry| if (entry.owns_name) self.allocator.free(entry.name);
            entries.deinit(self.allocator);
        }

        var buffer: [2]std.zig.Ast.Node.Index = undefined;
        const deps_init = self.tree.fullStructInit(&buffer, node) orelse return error.ManifestInvalidDependencies;

        for (deps_init.ast.fields) |field_node| {
            const name_slice = self.fieldName(field_node);
            const span = try self.computeDependencySpan(field_node);

            var entry = DependencyEntry{
                .index = null,
                .name = &[_]u8{},
                .owns_name = false,
                .span_start = span.start,
                .span_end = span.end,
                .trailing_comma = span.trailing_comma,
            };

            if (try self.parseDependency(field_node, name_slice)) |dep| {
                const idx = deps.items.len;
                try deps.append(self.allocator, dep);
                entry.index = idx;
                entry.name = deps.items[idx].name;
            } else {
                entry.name = try self.allocator.dupe(u8, name_slice);
                entry.owns_name = true;
            }

            try entries.append(self.allocator, entry);
        }

        self.dependencies = try deps.toOwnedSlice(self.allocator);
        deps.deinit(self.allocator);

        self.entries = try entries.toOwnedSlice(self.allocator);
        entries.deinit(self.allocator);
    }

    fn parseDependency(
        self: *Manifest,
        node: std.zig.Ast.Node.Index,
        name_slice: []const u8,
    ) !?Dependency {
        if (try self.parseGitDependency(node, name_slice)) |dep| return dep;
        if (try self.parsePathDependency(node, name_slice)) |dep| return dep;
        if (try self.parseTarballDependency(node, name_slice)) |dep| return dep;
        return null;
    }

    fn parseGitDependency(
        self: *Manifest,
        node: std.zig.Ast.Node.Index,
        name_slice: []const u8,
    ) !?Dependency {
        var buffer: [2]std.zig.Ast.Node.Index = undefined;
        const value_struct = self.tree.fullStructInit(&buffer, node) orelse return null;

        var constraint_node: ?std.zig.Ast.Node.Index = null;
        var git_node: ?std.zig.Ast.Node.Index = null;

        for (value_struct.ast.fields) |field_node| {
            const field_name = self.fieldName(field_node);
            if (std.mem.eql(u8, field_name, "constraint")) {
                constraint_node = field_node;
            } else if (std.mem.eql(u8, field_name, "git")) {
                git_node = field_node;
            }
        }

        if (constraint_node == null or git_node == null) return null;

        const constraint = try self.parseStringLiteralAlloc(constraint_node.?);
        defer self.allocator.free(constraint);

        const git_struct = self.tree.fullStructInit(&buffer, git_node.?) orelse return null;

        var url_node: ?std.zig.Ast.Node.Index = null;
        var reference_type_node: ?std.zig.Ast.Node.Index = null;
        var reference_node: ?std.zig.Ast.Node.Index = null;

        for (git_struct.ast.fields) |field_node| {
            const field_name = self.fieldName(field_node);
            if (std.mem.eql(u8, field_name, "url")) {
                url_node = field_node;
            } else if (std.mem.eql(u8, field_name, "reference_type")) {
                reference_type_node = field_node;
            } else if (std.mem.eql(u8, field_name, "reference")) {
                reference_node = field_node;
            }
        }

        if (url_node == null or reference_type_node == null or reference_node == null) return null;

        const url = try self.parseStringLiteralAlloc(url_node.?);
        defer self.allocator.free(url);

        const reference_type_raw = try self.parseStringLiteralAlloc(reference_type_node.?);
        defer self.allocator.free(reference_type_raw);

        const reference_value = try self.parseStringLiteralAlloc(reference_node.?);
        defer self.allocator.free(reference_value);

        const reference_type = std.meta.stringToEnum(GitReferenceType, reference_type_raw) orelse return null;

        const dep = try Dependency.initGit(
            self.allocator,
            name_slice,
            constraint,
            url,
            reference_type,
            reference_value,
        );

        return dep;
    }

    fn parsePathDependency(
        self: *Manifest,
        node: std.zig.Ast.Node.Index,
        name_slice: []const u8,
    ) !?Dependency {
        var buffer: [2]std.zig.Ast.Node.Index = undefined;
        const value_struct = self.tree.fullStructInit(&buffer, node) orelse return null;

        var path_node: ?std.zig.Ast.Node.Index = null;
        var constraint_node: ?std.zig.Ast.Node.Index = null;

        for (value_struct.ast.fields) |field_node| {
            const field_name = self.fieldName(field_node);
            if (std.mem.eql(u8, field_name, "path")) {
                path_node = field_node;
            } else if (std.mem.eql(u8, field_name, "constraint")) {
                constraint_node = field_node;
            }
        }

        if (path_node == null) return null;

        const path_value = try self.parseStringLiteralAlloc(path_node.?);
        defer self.allocator.free(path_value);

        var constraint_buffer: ?[]u8 = null;
        defer if (constraint_buffer) |buf| self.allocator.free(buf);

        var constraint_value: ?[]const u8 = null;
        if (constraint_node) |cn| {
            constraint_buffer = try self.parseStringLiteralAlloc(cn);
            constraint_value = constraint_buffer.?;
        }

        const dep = try Dependency.initPath(
            self.allocator,
            name_slice,
            constraint_value,
            path_value,
        );

        return dep;
    }

    fn parseTarballDependency(
        self: *Manifest,
        node: std.zig.Ast.Node.Index,
        name_slice: []const u8,
    ) !?Dependency {
        var buffer: [2]std.zig.Ast.Node.Index = undefined;
        const value_struct = self.tree.fullStructInit(&buffer, node) orelse return null;

        var tarball_node: ?std.zig.Ast.Node.Index = null;
        var constraint_node: ?std.zig.Ast.Node.Index = null;

        for (value_struct.ast.fields) |field_node| {
            const field_name = self.fieldName(field_node);
            if (std.mem.eql(u8, field_name, "tarball")) {
                tarball_node = field_node;
            } else if (std.mem.eql(u8, field_name, "constraint")) {
                constraint_node = field_node;
            }
        }

        if (tarball_node == null or constraint_node == null) return null;

        const constraint_value = try self.parseStringLiteralAlloc(constraint_node.?);
        defer self.allocator.free(constraint_value);

        const tarball_struct = self.tree.fullStructInit(&buffer, tarball_node.?) orelse return null;

        var url_node: ?std.zig.Ast.Node.Index = null;
        var hash_node: ?std.zig.Ast.Node.Index = null;

        for (tarball_struct.ast.fields) |field_node| {
            const field_name = self.fieldName(field_node);
            if (std.mem.eql(u8, field_name, "url")) {
                url_node = field_node;
            } else if (std.mem.eql(u8, field_name, "hash")) {
                hash_node = field_node;
            }
        }

        if (url_node == null) return null;

        const url_value = try self.parseStringLiteralAlloc(url_node.?);
        defer self.allocator.free(url_value);

        var hash_buffer: ?[]u8 = null;
        defer if (hash_buffer) |buf| self.allocator.free(buf);

        if (hash_node) |hn| {
            hash_buffer = try self.parseStringLiteralAlloc(hn);
        }

        const dep = try Dependency.initTarball(
            self.allocator,
            name_slice,
            constraint_value,
            url_value,
            if (hash_buffer) |buf| buf else null,
        );

        return dep;
    }

    fn computeDependencySpan(self: *Manifest, node: std.zig.Ast.Node.Index) !SpanRange {
        const src = self.source();
        const first_token = self.tree.firstToken(node);
        var search = first_token;
        var equal_token: ?std.zig.Ast.TokenIndex = null;

        while (search > 0) {
            search -= 1;
            if (self.tree.tokenTag(search) == .equal) {
                equal_token = search;
                break;
            }
        }

        const eq_token = equal_token orelse return error.ManifestInvalidDependency;
        const ident_token = eq_token - 1;
        const dot_token = ident_token - 1;

        const start_pos = findLineStart(src, self.tree.tokenStart(dot_token));

        var end_token = self.tree.lastToken(node);
        var trailing_comma = false;
        if (end_token + 1 < self.tree.tokens.len) {
            const next = end_token + 1;
            if (self.tree.tokenTag(next) == .comma) {
                trailing_comma = true;
                end_token = next;
            }
        }

        const end_pos = self.tree.tokenStart(end_token) + self.tree.tokenSlice(end_token).len;

        return .{
            .start = start_pos,
            .end = end_pos,
            .trailing_comma = trailing_comma,
        };
    }

    fn dependenciesInfo(self: *Manifest) !DependenciesInfo {
        const node = self.dependencies_node orelse return error.ManifestInvalidDependencies;
        var buffer: [2]std.zig.Ast.Node.Index = undefined;
        const deps_init = self.tree.fullStructInit(&buffer, node) orelse return error.ManifestInvalidDependencies;
        const lbrace_token = deps_init.ast.lbrace;
        const rbrace_token = self.tree.lastToken(node);

        const lbrace_slice = self.tree.tokenSlice(lbrace_token);
        const entry_indent = blk: {
            if (std.mem.lastIndexOfScalar(u8, lbrace_slice, '\n')) |idx| {
                break :blk lbrace_slice[idx + 1 ..];
            } else {
                break :blk lbrace_slice;
            }
        };

        const close_start = self.tree.tokenStart(rbrace_token);
        const indent_start = findLineStart(self.source(), close_start);
        const closing_indent = self.source()[indent_start..close_start];

        return .{
            .lbrace_token = lbrace_token,
            .rbrace_token = rbrace_token,
            .entry_indent = entry_indent,
            .closing_indent = closing_indent,
        };
    }

    fn trailingIndentAfterEntry(self: *Manifest, entry_index: usize, info: DependenciesInfo) []const u8 {
        if (entry_index + 1 < self.entries.len) {
            return self.entryIndent(self.entries[entry_index + 1].span_start);
        }
        return info.closing_indent;
    }

    fn entryPrefix(self: *Manifest, pos: usize) []const u8 {
        const src = self.source();
        const line_start = findLineStart(src, pos);
        var i = line_start;
        while (i < src.len) : (i += 1) {
            const ch = src[i];
            if (ch != ' ' and ch != '\t') break;
        }
        if (i < src.len and src[i] == '.') i += 1;
        return src[line_start..i];
    }

    fn entryIndent(self: *Manifest, pos: usize) []const u8 {
        const prefix = self.entryPrefix(pos);
        if (prefix.len == 0) return prefix;
        if (prefix[prefix.len - 1] == '.') return prefix[0 .. prefix.len - 1];
        return prefix;
    }

    fn allocateNewEntryPrefix(self: *Manifest, info: DependenciesInfo) ![]u8 {
        const base = info.closing_indent;
        const indent_len = base.len + 5;
        var buffer = try self.allocator.alloc(u8, indent_len);
        @memcpy(buffer[0..base.len], base);
        for (buffer[base.len .. base.len + 4]) |*ch| ch.* = ' ';
        buffer[indent_len - 1] = '.';
        return buffer;
    }

    fn findEntryIndex(self: *Manifest, name: []const u8) ?usize {
        for (self.entries, 0..) |entry, idx| {
            if (std.mem.eql(u8, entry.name, name)) return idx;
        }
        return null;
    }

    fn buildUpdatedSource(self: *Manifest, start: usize, end: usize, insert: []const u8) ![]u8 {
        const src = self.source();
        const new_len = src.len - (end - start) + insert.len;
        var buffer = try self.allocator.alloc(u8, new_len);
        errdefer self.allocator.free(buffer);

        @memcpy(buffer[0..start], src[0..start]);
        @memcpy(buffer[start .. start + insert.len], insert);
        @memcpy(buffer[start + insert.len ..], src[end..]);

        return buffer;
    }

    fn rebuildWithSource(self: *Manifest, new_source: []const u8) !void {
        var replacement = try Manifest.parse(self.allocator, new_source);
        std.mem.swap(Manifest, self, &replacement);
        replacement.deinit();
    }

    fn parseEnumLiteral(self: *Manifest, node: std.zig.Ast.Node.Index) ![]const u8 {
        if (self.tree.nodeTag(node) != .enum_literal) return error.ExpectedEnumLiteral;
        const token = self.tree.nodeMainToken(node);
        const raw = std.mem.trim(u8, self.tree.tokenSlice(token), " \t\r\n,");
        if (raw.len == 0) return error.ExpectedEnumLiteral;

        if (raw[0] == '.') {
            return raw[1..];
        }

        if (token > 0 and self.tree.tokenTag(token - 1) == .period) {
            return raw;
        }

        return error.ExpectedEnumLiteral;
    }

    fn parseStringLiteralAlloc(self: *Manifest, node: std.zig.Ast.Node.Index) ![]u8 {
        if (self.tree.nodeTag(node) != .string_literal) return error.ExpectedStringLiteral;
        const token = self.tree.nodeMainToken(node);
        const raw = self.tree.tokenSlice(token);
        if (raw.len < 2 or raw[0] != '"') return error.ExpectedStringLiteral;
        const trimmed = std.mem.trim(u8, raw, " \t\r\n,");
        if (trimmed.len < 2 or trimmed[0] != '"' or trimmed[trimmed.len - 1] != '"') return error.ExpectedStringLiteral;
        return try std.zig.string_literal.parseAlloc(self.allocator, trimmed);
    }

    fn fieldName(self: *Manifest, value_node: std.zig.Ast.Node.Index) []const u8 {
        var token_index = self.tree.firstToken(value_node);
        while (token_index > 0) {
            token_index -= 1;
            if (self.tree.tokenTag(token_index) == .equal) {
                const ident_token = token_index - 1;
                const raw = self.tree.tokenSlice(ident_token);
                return std.mem.trim(u8, raw, " \t\r\n");
            }
        }
        return "";
    }
};

fn findLineStart(source: []const u8, pos: usize) usize {
    var i = pos;
    while (i > 0) {
        if (source[i - 1] == '\n') break;
        i -= 1;
    }
    return i;
}

fn findDependency(deps: []Manifest.Dependency, name: []const u8) ?usize {
    for (deps, 0..) |dep, idx| {
        if (std.mem.eql(u8, dep.name, name)) return idx;
    }
    return null;
}

test "upsertDependency adds git entry and preserves comments" {
    const base_manifest =
        \\.{
        \\    // header comment
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{
        \\        // keep me
        \\        .keep = .{
        \\            .constraint = ">=1.0.0",
        \\            .git = .{
        \\                .url = "https://example.com/keep.git",
        \\                .reference_type = "branch",
        \\                .reference = "main",
        \\            },
        \\        },
        \\    },
        \\}
    ;

    var manifest = try Manifest.parse(testing.allocator, base_manifest);
    defer manifest.deinit();

    try manifest.upsertDependency(
        testing.allocator,
        "newdep",
        "^1.2.3",
        "https://example.com/newdep.git",
        .tag,
        "v1.2.3",
    );

    try testing.expectEqual(@as(usize, 2), manifest.entries.len);
    try testing.expectEqual(@as(usize, 2), manifest.dependencies.len);

    const rendered = try manifest.render(testing.allocator);
    defer testing.allocator.free(rendered);

    try testing.expect(std.mem.indexOf(u8, rendered, "// header comment") != null);
    try testing.expect(std.mem.indexOf(u8, rendered, "// keep me") != null);
    try testing.expect(std.mem.indexOf(u8, rendered, ".newdep = .{") != null);
}

test "upsertTarballDependency adds tarball entry" {
    var manifest = try Manifest.init(testing.allocator, "example", "0.0.1", "0.16.0");
    defer manifest.deinit();

    try manifest.upsertTarballDependency(
        testing.allocator,
        "tarball-dep",
        "3.2.1",
        "https://example.com/tarball-dep-3.2.1.tar.gz",
        "sha256-cafebabe",
    );

    try testing.expectEqual(@as(usize, 1), manifest.entries.len);
    try testing.expectEqual(@as(usize, 1), manifest.dependencies.len);

    const rendered = try manifest.render(testing.allocator);
    defer testing.allocator.free(rendered);

    try testing.expect(std.mem.indexOf(u8, rendered, ".tarball-dep = .{") != null);
    try testing.expect(std.mem.indexOf(u8, rendered, ".tarball = .{") != null);
    try testing.expect(std.mem.indexOf(u8, rendered, "sha256-cafebabe") != null);
}

test "removeDependency deletes entry and keeps structure" {
    const base_manifest =
        \\.{
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{
        \\        .keep = .{
        \\            .constraint = ">=1.0.0",
        \\            .git = .{
        \\                .url = "https://example.com/keep.git",
        \\                .reference_type = "branch",
        \\                .reference = "main",
        \\            },
        \\        },
        \\    },
        \\}
    ;

    var manifest = try Manifest.parse(testing.allocator, base_manifest);
    defer manifest.deinit();

    try testing.expect(manifest.removeDependency(testing.allocator, "keep"));
    try testing.expectEqual(@as(usize, 0), manifest.entries.len);
    try testing.expectEqual(@as(usize, 0), manifest.dependencies.len);

    const rendered = try manifest.render(testing.allocator);
    defer testing.allocator.free(rendered);

    try testing.expect(std.mem.indexOf(u8, rendered, ".keep") == null);
    try testing.expect(std.mem.indexOf(u8, rendered, ".dependencies = .{") != null);
}

test "parse captures manifest metadata" {
    const manifest_source =
        \\// ensure enum literals and strings survive formatting
        \\.{
        \\    .name =
        \\        .example,
        \\    .version = "1.2.3"
        \\        ,
        \\    .minimum_zig_version = "0.16.0" // trailing text should be ignored
        \\        ,
        \\}
    ;

    var manifest = try Manifest.parse(testing.allocator, manifest_source);
    defer manifest.deinit();

    try testing.expectEqualStrings("example", manifest.name);
    try testing.expectEqualStrings("1.2.3", manifest.version);
    try testing.expectEqualStrings("0.16.0", manifest.minimum_zig_version);
}

test "parse handles manifest without dependencies" {
    const source =
        \\// manifest without dependency block should still parse
        \\.{
        \\    .name = .solo,
        \\    .version = "0.9.0",
        \\    .minimum_zig_version = "0.16.0",
        \\}
    ;

    var manifest = try Manifest.parse(testing.allocator, source);
    defer manifest.deinit();

    try testing.expectEqual(@as(usize, 0), manifest.dependencies.len);
    try testing.expectEqual(@as(usize, 0), manifest.entries.len);

    const rendered = try manifest.render(testing.allocator);
    defer testing.allocator.free(rendered);

    try testing.expectEqualStrings(source, rendered);
}

test "roundtrip preserves comments and trailing commas" {
    const source =
        \\// header comment stays intact
        \\.{
        \\    // dependency list with trailing comma
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{
        \\        // keep trailing comma and comment
        \\        .foo = .{
        \\            .constraint = "^1.0.0",
        \\        },
        \\    },
        \\},
    ;

    var manifest = try Manifest.parse(testing.allocator, source);
    defer manifest.deinit();

    const rendered = try manifest.render(testing.allocator);
    defer testing.allocator.free(rendered);

    try testing.expectEqualStrings(source, rendered);
    try testing.expect(std.mem.indexOf(u8, rendered, "// header comment") != null);
    try testing.expect(std.mem.indexOf(u8, rendered, ".foo = .{") != null);
}

test "parse errors when required fields missing" {
    const missing_name =
        \\.{
        \\    .version = "0.0.1",
        \\    .minimum_zig_version = "0.16.0",
        \\}
    ;
    const missing_version =
        \\.{
        \\    .name = .example,
        \\    .minimum_zig_version = "0.16.0",
        \\}
    ;
    const missing_zig =
        \\.{
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\}
    ;

    try testing.expectError(error.ManifestMissingName, Manifest.parse(testing.allocator, missing_name));
    try testing.expectError(error.ManifestMissingVersion, Manifest.parse(testing.allocator, missing_version));
    try testing.expectError(error.ManifestMissingZigVersion, Manifest.parse(testing.allocator, missing_zig));
}

test "upsertDependency updates existing entry" {
    const base_manifest =
        \\.{
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{
        \\        .lib = .{
        \\            .constraint = "^1.0.0",
        \\            .git = .{
        \\                .url = "https://example.com/lib.git",
        \\                .reference_type = "branch",
        \\                .reference = "main",
        \\            },
        \\        },
        \\    },
        \\}
    ;

    var manifest = try Manifest.parse(testing.allocator, base_manifest);
    defer manifest.deinit();

    try manifest.upsertDependency(
        testing.allocator,
        "lib",
        "^2.0.0",
        "https://example.com/lib.git",
        .tag,
        "v2.0.0",
    );

    try testing.expectEqual(@as(usize, 1), manifest.dependencies.len);
    const dep = manifest.dependencies[0];
    try testing.expectEqualStrings("lib", dep.name);
    try testing.expect(dep.constraint != null);
    try testing.expectEqualStrings("^2.0.0", dep.constraint.?);
    switch (dep.source) {
        .git => |git| {
            try testing.expectEqualStrings("https://example.com/lib.git", git.url);
            try testing.expectEqualStrings("v2.0.0", git.reference);
            try testing.expectEqual(git.reference_type, Manifest.GitReferenceType.tag);
        },
        else => return error.TestUnexpectedResult,
    }

    const rendered = try manifest.render(testing.allocator);
    defer testing.allocator.free(rendered);
    try testing.expect(std.mem.indexOf(u8, rendered, ".reference_type = \"tag\"") != null);
    try testing.expect(std.mem.indexOf(u8, rendered, ".constraint = \"^2.0.0\"") != null);
}

test "setLocalPath inserts path dependency" {
    const base_manifest =
        \\.{
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{
        \\        // placeholder comment
        \\    },
        \\}
    ;

    var manifest = try Manifest.parse(testing.allocator, base_manifest);
    defer manifest.deinit();

    try manifest.setLocalPath(testing.allocator, "local", "../local", null);

    try testing.expectEqual(@as(usize, 1), manifest.dependencies.len);
    const dep = manifest.dependencies[0];
    try testing.expect(dep.constraint == null);
    switch (dep.source) {
        .path => |path| try testing.expectEqualStrings("../local", path.location),
        else => return error.TestUnexpectedResult,
    }

    const rendered = try manifest.render(testing.allocator);
    defer testing.allocator.free(rendered);
    try testing.expect(std.mem.indexOf(u8, rendered, ".path = \"../local\"") != null);
    try testing.expect(std.mem.indexOf(u8, rendered, "    .constraint = ") == null);
}

test "renameDependency updates dependency name" {
    const base_manifest =
        \\.{
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{
        \\        .core = .{
        \\            .constraint = "^1.0.0",
        \\            .git = .{
        \\                .url = "https://example.com/core.git",
        \\                .reference_type = "branch",
        \\                .reference = "main",
        \\            },
        \\        },
        \\    },
        \\}
    ;

    var manifest = try Manifest.parse(testing.allocator, base_manifest);
    defer manifest.deinit();

    try testing.expect(try manifest.renameDependency(testing.allocator, "core", "core_renamed"));

    try testing.expectEqual(@as(usize, 1), manifest.dependencies.len);
    try testing.expectEqualStrings("core_renamed", manifest.dependencies[0].name);

    const rendered = try manifest.render(testing.allocator);
    defer testing.allocator.free(rendered);
    try testing.expect(std.mem.indexOf(u8, rendered, ".core_renamed = .{") != null);
    try testing.expect(std.mem.indexOf(u8, rendered, ".core = .{") == null);
}

test "upsertDependency converts path to git" {
    const base_manifest =
        \\.{
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{
        \\        .shared = .{
        \\            .path = "../shared",
        \\        },
        \\    },
        \\}
    ;

    var manifest = try Manifest.parse(testing.allocator, base_manifest);
    defer manifest.deinit();

    try manifest.upsertDependency(
        testing.allocator,
        "shared",
        "^1.1.0",
        "https://example.com/shared.git",
        .commit,
        "deadbeef",
    );

    try testing.expectEqual(@as(usize, 1), manifest.dependencies.len);
    switch (manifest.dependencies[0].source) {
        .git => {},
        else => return error.TestUnexpectedResult,
    }

    const rendered = try manifest.render(testing.allocator);
    defer testing.allocator.free(rendered);
    try testing.expect(std.mem.indexOf(u8, rendered, ".git = .{") != null);
    try testing.expect(std.mem.indexOf(u8, rendered, ".path =") == null);
}

test "normalize leaves manifest unchanged" {
    const base_manifest =
        \\// comments should persist
        \\.{
        \\    .name = .example,
        \\    .version = "0.0.1",
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{
        \\        .pkg = .{
        \\            .constraint = "^1.0.0",
        \\            .git = .{
        \\                .url = "https://example.com/pkg.git",
        \\                .reference_type = "branch",
        \\                .reference = "main",
        \\            },
        \\        },
        \\    },
        \\}
    ;

    var manifest = try Manifest.parse(testing.allocator, base_manifest);
    defer manifest.deinit();

    const before = try manifest.render(testing.allocator);
    defer testing.allocator.free(before);

    try manifest.normalize();

    const after = try manifest.render(testing.allocator);
    defer testing.allocator.free(after);

    try testing.expectEqualStrings(before, after);
}
