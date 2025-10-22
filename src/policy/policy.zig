const std = @import("std");
const Lockfile = @import("../util/lockfile.zig").Lockfile;

pub const PolicyError = error{
    InvalidPolicyFormat,
};

pub const PolicyEnforceError = error{
    PackageDenied,
    PackageNotAllowed,
    MissingHash,
};

pub const AuditViolation = struct {
    package: []const u8,
    version: []const u8,
    reason: PolicyEnforceError,
};

pub const AuditReport = struct {
    checked: usize = 0,
    violations: std.ArrayListUnmanaged(AuditViolation) = .{},

    pub fn deinit(self: *AuditReport, allocator: std.mem.Allocator) void {
        for (self.violations.items) |violation| {
            allocator.free(violation.package);
            allocator.free(violation.version);
        }
        self.violations.deinit(allocator);
    }
};

pub const Policy = struct {
    allocator: std.mem.Allocator,
    allow: std.ArrayListUnmanaged([]const u8),
    deny: std.ArrayListUnmanaged([]const u8),
    require_hash: bool,

    const Self = @This();
    const default_path = "babylon.policy.json";

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .allow = .{},
            .deny = .{},
            .require_hash = false,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.allow.items) |entry| {
            self.allocator.free(entry);
        }
        for (self.deny.items) |entry| {
            self.allocator.free(entry);
        }
        self.allow.deinit(self.allocator);
        self.deny.deinit(self.allocator);
    }

    pub fn load(allocator: std.mem.Allocator, path: []const u8) !Self {
        var policy = Self.init(allocator);
        errdefer policy.deinit();

        const final_path = if (path.len != 0) path else default_path;

        const contents = std.fs.cwd().readFileAlloc(final_path, allocator, std.Io.Limit.limited(16 * 1024)) catch |err| switch (err) {
            error.FileNotFound => return policy,
            else => return err,
        };
        defer allocator.free(contents);

        const Parsed = struct {
            allow: ?[]const []const u8 = null,
            deny: ?[]const []const u8 = null,
            require_hash: ?bool = null,
        };

        var parsed = std.json.parseFromSlice(Parsed, allocator, contents, .{}) catch |err| switch (err) {
            error.InvalidCharacter, error.UnexpectedToken => return PolicyError.InvalidPolicyFormat,
            else => return err,
        };
        defer parsed.deinit();

        if (parsed.value.require_hash) |value| {
            policy.require_hash = value;
        }

        if (parsed.value.allow) |list| {
            try policy.allow.ensureTotalCapacity(allocator, list.len);
            for (list) |item| {
                const cloned = try allocator.dupe(u8, item);
                policy.allow.appendAssumeCapacity(cloned);
            }
        }

        if (parsed.value.deny) |list| {
            try policy.deny.ensureTotalCapacity(allocator, list.len);
            for (list) |item| {
                const cloned = try allocator.dupe(u8, item);
                policy.deny.appendAssumeCapacity(cloned);
            }
        }

        return policy;
    }

    pub fn checkPackage(self: *const Self, package_name: []const u8, source: Lockfile.Source) PolicyEnforceError!void {
        if (self.matchesAny(self.deny.items, package_name)) {
            return PolicyEnforceError.PackageDenied;
        }

        if (self.allow.items.len != 0 and !self.matchesAny(self.allow.items, package_name)) {
            return PolicyEnforceError.PackageNotAllowed;
        }

        if (self.require_hash) {
            switch (source) {
                .tarball => |tarball| {
                    if (tarball.hash == null) {
                        return PolicyEnforceError.MissingHash;
                    }
                },
                else => {},
            }
        }
    }

    pub fn auditLockfile(self: *const Self, allocator: std.mem.Allocator, lockfile: *const Lockfile) !AuditReport {
        var report = AuditReport{};
        errdefer report.deinit(allocator);

        for (lockfile.packagesSlice()) |pkg| {
            report.checked += 1;
            const result = self.checkPackage(pkg.name, pkg.source) catch |policy_err| {
                const name_copy = try allocator.dupe(u8, pkg.name);
                errdefer allocator.free(name_copy);
                const version_copy = try allocator.dupe(u8, pkg.version);
                errdefer allocator.free(version_copy);

                try report.violations.append(allocator, .{
                    .package = name_copy,
                    .version = version_copy,
                    .reason = policy_err,
                });
                continue;
            };
            _ = result;
        }

        return report;
    }

    fn matchesAny(self: *const Self, patterns: []const []const u8, name: []const u8) bool {
        _ = self;
        for (patterns) |pattern| {
            if (matchPattern(pattern, name)) return true;
        }
        return false;
    }

    fn matchPattern(pattern: []const u8, name: []const u8) bool {
        if (pattern.len == 0) return false;
        if (pattern[pattern.len - 1] == '*') {
            const prefix = pattern[0 .. pattern.len - 1];
            return std.mem.startsWith(u8, name, prefix);
        }
        return std.mem.eql(u8, pattern, name);
    }
};
