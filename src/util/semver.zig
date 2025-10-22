const std = @import("std");

/// Semantic version structure following semver.org specification
pub const SemanticVersion = struct {
    major: u32,
    minor: u32,
    patch: u32,
    prerelease: ?[]const u8,
    build: ?[]const u8,

    const Self = @This();

    /// Parse a semantic version string like "1.2.3", "1.2.3-alpha.1", "1.2.3+build.1"
    pub fn parse(allocator: std.mem.Allocator, version_str: []const u8) !Self {
        var parts = std.mem.splitSequence(u8, version_str, "+");
        const version_part = parts.first();
        const build_part = parts.next();

        var pre_parts = std.mem.splitSequence(u8, version_part, "-");
        const core_version = pre_parts.first();

        // Collect prerelease parts by slicing original string to avoid ArrayList API differences
        var prerelease: ?[]const u8 = null;
        if (pre_parts.next()) |_| {
            const pre_start = core_version.len + 1;
            if (pre_start > version_part.len) return error.InvalidVersion;
            prerelease = try allocator.dupe(u8, version_part[pre_start..]);
        }

        // Parse major.minor.patch
        var version_parts = std.mem.splitSequence(u8, core_version, ".");
        const major_str = version_parts.next() orelse return error.InvalidVersion;
        const minor_str = version_parts.next() orelse return error.InvalidVersion;
        const patch_str = version_parts.next() orelse return error.InvalidVersion;

        if (version_parts.next() != null) return error.InvalidVersion; // Too many parts

        const major = std.fmt.parseInt(u32, major_str, 10) catch return error.InvalidVersion;
        const minor = std.fmt.parseInt(u32, minor_str, 10) catch return error.InvalidVersion;
        const patch = std.fmt.parseInt(u32, patch_str, 10) catch return error.InvalidVersion;

        var build_metadata: ?[]const u8 = null;
        if (build_part) |build| {
            build_metadata = try allocator.dupe(u8, build);
        }

        return Self{
            .major = major,
            .minor = minor,
            .patch = patch,
            .prerelease = prerelease,
            .build = build_metadata,
        };
    }

    /// Format version as string
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]const u8 {
        var result = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}", .{ self.major, self.minor, self.patch });

        if (self.prerelease) |pre| {
            const updated = try std.fmt.allocPrint(allocator, "{s}-{s}", .{ result, pre });
            allocator.free(result);
            result = updated;
        }

        if (self.build) |build| {
            const updated = try std.fmt.allocPrint(allocator, "{s}+{s}", .{ result, build });
            allocator.free(result);
            result = updated;
        }

        return result;
    }

    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        return Self{
            .major = self.major,
            .minor = self.minor,
            .patch = self.patch,
            .prerelease = if (self.prerelease) |pre| try allocator.dupe(u8, pre) else null,
            .build = if (self.build) |build| try allocator.dupe(u8, build) else null,
        };
    }

    /// Compare two semantic versions following semver precedence rules
    pub fn order(self: Self, other: Self) std.math.Order {
        // Compare major.minor.patch
        if (self.major != other.major) return std.math.order(self.major, other.major);
        if (self.minor != other.minor) return std.math.order(self.minor, other.minor);
        if (self.patch != other.patch) return std.math.order(self.patch, other.patch);

        // Prerelease versions have lower precedence than normal versions
        if (self.prerelease == null and other.prerelease != null) return .gt;
        if (self.prerelease != null and other.prerelease == null) return .lt;
        if (self.prerelease == null and other.prerelease == null) return .eq;

        // Compare prerelease versions lexically
        return std.mem.order(u8, self.prerelease.?, other.prerelease.?);
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.prerelease) |pre| allocator.free(pre);
        if (self.build) |build| allocator.free(build);
    }
};

/// Version constraint types for dependency resolution
pub const VersionConstraint = union(enum) {
    exact: SemanticVersion, // 1.2.3
    caret: SemanticVersion, // ^1.2.3 (compatible within major version)
    tilde: SemanticVersion, // ~1.2.3 (compatible within minor version)
    gte: SemanticVersion, // >=1.2.3
    gt: SemanticVersion, // >1.2.3
    lte: SemanticVersion, // <=1.2.3
    lt: SemanticVersion, // <1.2.3
    range: struct { // 1.2.3 - 2.0.0
        min: SemanticVersion,
        max: SemanticVersion,
    },

    const Self = @This();

    pub const ParseResult = struct {
        constraint: Self,
        raw: ?[]const u8 = null,

        pub fn deinit(self: *ParseResult, allocator: std.mem.Allocator) void {
            self.constraint.deinit(allocator);
            if (self.raw) |raw| allocator.free(raw);
        }
    };

    /// Parse a version constraint string
    pub fn parse(allocator: std.mem.Allocator, constraint_str: []const u8) !Self {
        const parsed = try Self.parseRaw(allocator, constraint_str);
        defer if (parsed.raw) |raw| allocator.free(raw);
        return parsed.constraint;
    }

    pub fn parseRaw(allocator: std.mem.Allocator, constraint_str: []const u8) !ParseResult {
        const trimmed = std.mem.trim(u8, constraint_str, " \t\n\r");
        const constraint = try parseTrimmed(allocator, trimmed);
        const raw_copy = try allocator.dupe(u8, trimmed);
        return ParseResult{ .constraint = constraint, .raw = raw_copy };
    }

    fn parseTrimmed(allocator: std.mem.Allocator, trimmed: []const u8) !Self {
        if (std.mem.startsWith(u8, trimmed, "^")) {
            const version = try SemanticVersion.parse(allocator, trimmed[1..]);
            return Self{ .caret = version };
        } else if (std.mem.startsWith(u8, trimmed, "~")) {
            const version = try SemanticVersion.parse(allocator, trimmed[1..]);
            return Self{ .tilde = version };
        } else if (std.mem.startsWith(u8, trimmed, ">=")) {
            const version = try SemanticVersion.parse(allocator, trimmed[2..]);
            return Self{ .gte = version };
        } else if (std.mem.startsWith(u8, trimmed, ">")) {
            const version = try SemanticVersion.parse(allocator, trimmed[1..]);
            return Self{ .gt = version };
        } else if (std.mem.startsWith(u8, trimmed, "<=")) {
            const version = try SemanticVersion.parse(allocator, trimmed[2..]);
            return Self{ .lte = version };
        } else if (std.mem.startsWith(u8, trimmed, "<")) {
            const version = try SemanticVersion.parse(allocator, trimmed[1..]);
            return Self{ .lt = version };
        } else if (std.mem.indexOf(u8, trimmed, " - ")) |dash_pos| {
            const min_str = std.mem.trim(u8, trimmed[0..dash_pos], " ");
            const max_str = std.mem.trim(u8, trimmed[dash_pos + 3 ..], " ");
            const min = try SemanticVersion.parse(allocator, min_str);
            const max = try SemanticVersion.parse(allocator, max_str);
            return Self{ .range = .{ .min = min, .max = max } };
        } else {
            const version = try SemanticVersion.parse(allocator, trimmed);
            return Self{ .exact = version };
        }
    }

    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        return switch (self) {
            .exact => |version| Self{ .exact = try version.clone(allocator) },
            .caret => |version| Self{ .caret = try version.clone(allocator) },
            .tilde => |version| Self{ .tilde = try version.clone(allocator) },
            .gte => |version| Self{ .gte = try version.clone(allocator) },
            .gt => |version| Self{ .gt = try version.clone(allocator) },
            .lte => |version| Self{ .lte = try version.clone(allocator) },
            .lt => |version| Self{ .lt = try version.clone(allocator) },
            .range => |range| Self{ .range = .{
                .min = try range.min.clone(allocator),
                .max = try range.max.clone(allocator),
            } },
        };
    }

    /// Check if a version satisfies this constraint
    pub fn satisfies(self: Self, version: SemanticVersion) bool {
        return switch (self) {
            .exact => |exact| version.order(exact) == .eq,
            .caret => |base| {
                // ^1.2.3 := >=1.2.3 <2.0.0 (compatible within major version)
                if (base.major == 0) {
                    // ^0.2.3 := >=0.2.3 <0.3.0 (special case for 0.x.y)
                    return version.major == 0 and
                        version.minor == base.minor and
                        version.order(base) != .lt;
                } else {
                    return version.major == base.major and version.order(base) != .lt;
                }
            },
            .tilde => |base| {
                // ~1.2.3 := >=1.2.3 <1.3.0 (compatible within minor version)
                return version.major == base.major and
                    version.minor == base.minor and
                    version.order(base) != .lt;
            },
            .gte => |base| version.order(base) != .lt,
            .gt => |base| version.order(base) == .gt,
            .lte => |base| version.order(base) != .gt,
            .lt => |base| version.order(base) == .lt,
            .range => |range| {
                return version.order(range.min) != .lt and version.order(range.max) != .gt;
            },
        };
    }

    /// Format the constraint back into a string representation
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]const u8 {
        switch (self) {
            .exact => |version| return version.format(allocator),
            .caret => |version| {
                const inner = try version.format(allocator);
                defer allocator.free(inner);
                return std.fmt.allocPrint(allocator, "^{s}", .{inner});
            },
            .tilde => |version| {
                const inner = try version.format(allocator);
                defer allocator.free(inner);
                return std.fmt.allocPrint(allocator, "~{s}", .{inner});
            },
            .gte => |version| {
                const inner = try version.format(allocator);
                defer allocator.free(inner);
                return std.fmt.allocPrint(allocator, ">={s}", .{inner});
            },
            .gt => |version| {
                const inner = try version.format(allocator);
                defer allocator.free(inner);
                return std.fmt.allocPrint(allocator, ">{s}", .{inner});
            },
            .lte => |version| {
                const inner = try version.format(allocator);
                defer allocator.free(inner);
                return std.fmt.allocPrint(allocator, "<={s}", .{inner});
            },
            .lt => |version| {
                const inner = try version.format(allocator);
                defer allocator.free(inner);
                return std.fmt.allocPrint(allocator, "<{s}", .{inner});
            },
            .range => |range| {
                const min = try range.min.format(allocator);
                defer allocator.free(min);
                const max = try range.max.format(allocator);
                defer allocator.free(max);
                return std.fmt.allocPrint(allocator, "{s} - {s}", .{ min, max });
            },
        }
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .exact => |*v| v.deinit(allocator),
            .caret => |*v| v.deinit(allocator),
            .tilde => |*v| v.deinit(allocator),
            .gte => |*v| v.deinit(allocator),
            .gt => |*v| v.deinit(allocator),
            .lte => |*v| v.deinit(allocator),
            .lt => |*v| v.deinit(allocator),
            .range => |*r| {
                r.min.deinit(allocator);
                r.max.deinit(allocator);
            },
        }
    }
};

// Tests
test "parse semantic version" {
    const allocator = std.testing.allocator;

    // Basic version
    var version = try SemanticVersion.parse(allocator, "1.2.3");
    defer version.deinit(allocator);
    try std.testing.expect(version.major == 1);
    try std.testing.expect(version.minor == 2);
    try std.testing.expect(version.patch == 3);
    try std.testing.expect(version.prerelease == null);
    try std.testing.expect(version.build == null);

    // Version with prerelease
    var version_pre = try SemanticVersion.parse(allocator, "1.2.3-alpha.1");
    defer version_pre.deinit(allocator);
    try std.testing.expect(std.mem.eql(u8, version_pre.prerelease.?, "alpha.1"));

    // Version with build metadata
    var version_build = try SemanticVersion.parse(allocator, "1.2.3+build.1");
    defer version_build.deinit(allocator);
    try std.testing.expect(std.mem.eql(u8, version_build.build.?, "build.1"));

    // Version with both
    var version_both = try SemanticVersion.parse(allocator, "1.2.3-alpha.1+build.1");
    defer version_both.deinit(allocator);
    try std.testing.expect(std.mem.eql(u8, version_both.prerelease.?, "alpha.1"));
    try std.testing.expect(std.mem.eql(u8, version_both.build.?, "build.1"));
}

test "version ordering" {
    const allocator = std.testing.allocator;

    var v1 = try SemanticVersion.parse(allocator, "1.0.0");
    defer v1.deinit(allocator);
    var v2 = try SemanticVersion.parse(allocator, "1.0.1");
    defer v2.deinit(allocator);
    var v3 = try SemanticVersion.parse(allocator, "1.1.0");
    defer v3.deinit(allocator);
    var v4 = try SemanticVersion.parse(allocator, "2.0.0");
    defer v4.deinit(allocator);
    var v5 = try SemanticVersion.parse(allocator, "1.0.0-alpha");
    defer v5.deinit(allocator);

    try std.testing.expect(v1.order(v2) == .lt);
    try std.testing.expect(v2.order(v3) == .lt);
    try std.testing.expect(v3.order(v4) == .lt);
    try std.testing.expect(v5.order(v1) == .lt); // prerelease < normal
}

test "version constraints" {
    const allocator = std.testing.allocator;

    // Test caret constraint
    var caret = try VersionConstraint.parse(allocator, "^1.2.3");
    defer caret.deinit(allocator);

    var v1 = try SemanticVersion.parse(allocator, "1.2.3");
    defer v1.deinit(allocator);
    var v2 = try SemanticVersion.parse(allocator, "1.2.4");
    defer v2.deinit(allocator);
    var v3 = try SemanticVersion.parse(allocator, "1.3.0");
    defer v3.deinit(allocator);
    var v4 = try SemanticVersion.parse(allocator, "2.0.0");
    defer v4.deinit(allocator);

    try std.testing.expect(caret.satisfies(v1)); // 1.2.3 satisfies ^1.2.3
    try std.testing.expect(caret.satisfies(v2)); // 1.2.4 satisfies ^1.2.3
    try std.testing.expect(caret.satisfies(v3)); // 1.3.0 satisfies ^1.2.3
    try std.testing.expect(!caret.satisfies(v4)); // 2.0.0 does not satisfy ^1.2.3

    // Test tilde constraint
    var tilde = try VersionConstraint.parse(allocator, "~1.2.3");
    defer tilde.deinit(allocator);

    try std.testing.expect(tilde.satisfies(v1)); // 1.2.3 satisfies ~1.2.3
    try std.testing.expect(tilde.satisfies(v2)); // 1.2.4 satisfies ~1.2.3
    try std.testing.expect(!tilde.satisfies(v3)); // 1.3.0 does not satisfy ~1.2.3
}
