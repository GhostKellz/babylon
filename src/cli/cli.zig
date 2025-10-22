const std = @import("std");
const builtin = @import("builtin");
const babylon = @import("babylon");
const Manifest = babylon.manifest.Manifest;
const Lockfile = babylon.lockfile.Lockfile;
const SemverConstraint = babylon.semver.VersionConstraint;
const ResolverDependency = babylon.resolver.Dependency;
const ResolverSource = babylon.resolver.Source;
const ContentAddressedStorage = babylon.cache.ContentAddressedStorage;
const Policy = babylon.policy.Policy;
const PolicyEnforceError = babylon.policy.PolicyEnforceError;
const PolicyError = babylon.policy.PolicyError;

fn ArrayListManaged(comptime T: type) type {
    return std.array_list.AlignedManaged(T, null);
}

const MANIFEST_PATH = Manifest.filename;
const LOCKFILE_PATH = "babylon.lock";
const POLICY_PATH = "babylon.policy.json";

const Command = enum {
    init,
    add,
    update,
    remove,
    fetch,
    graph,
    verify,
    build,
    cache,
    policy,
    help,
    version,
};

const CommandError = error{
    UnknownCommand,
    InvalidArguments,
    MissingArguments,
};

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len < 2) {
        printHelp();
        return 1;
    }

    const command_str = args[1];
    const command = parseCommand(command_str) catch {
        std.debug.print("Error: Unknown command '{s}'\n\n", .{command_str});
        printHelp();
        return 1;
    };

    const command_args = if (args.len > 2) args[2..] else &[_][]const u8{};

    return switch (command) {
        .help => {
            printHelp();
            return 0;
        },
        .version => {
            printVersion();
            return 0;
        },
        .init => runInit(allocator, command_args),
        .add => runAdd(allocator, command_args),
        .update => runUpdate(allocator, command_args),
        .remove => runRemove(allocator, command_args),
        .fetch => runFetch(allocator, command_args),
        .graph => runGraph(allocator, command_args),
        .verify => runVerify(allocator, command_args),
        .build => runBuild(allocator, command_args),
        .cache => runCache(allocator, command_args),
        .policy => runPolicy(allocator, command_args),
    };
}

fn parseCommand(cmd: []const u8) !Command {
    const commands = std.StaticStringMap(Command).initComptime(.{
        .{ "init", .init },
        .{ "add", .add },
        .{ "update", .update },
        .{ "remove", .remove },
        .{ "fetch", .fetch },
        .{ "graph", .graph },
        .{ "verify", .verify },
        .{ "build", .build },
        .{ "help", .help },
        .{ "--help", .help },
        .{ "-h", .help },
        .{ "cache", .cache },
        .{ "policy", .policy },
        .{ "version", .version },
        .{ "--version", .version },
        .{ "-v", .version },
    });

    return commands.get(cmd) orelse CommandError.UnknownCommand;
}

fn printVersion() void {
    std.debug.print("babylon 0.1.0-dev\n", .{});
    std.debug.print("Next-generation Zig package manager\n", .{});
}

fn printHelp() void {
    std.debug.print(
        \\babylon - Next-generation Zig package manager
        \\
        \\USAGE:
        \\    babylon <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    init                     Initialize a new babylon project
        \\    add <pkg>@<constraint>   Add a dependency
        \\    update [pkg]             Update dependencies
        \\    remove <pkg>             Remove a dependency
        \\    fetch [--vendor]         Fetch dependencies to cache
        \\    cache prune [--cache-dir DIR]  Prune unused cached artifacts
        \\    policy audit            Audit lockfile against policy rules
        \\    graph                    Show dependency graph
        \\    verify                   Verify lockfile integrity
        \\    build [-- <zig args...>] Forward arguments to zig build
        \\    help                     Show this help message
        \\    version                  Show version information
        \\
        \\OPTIONS:
        \\    -h, --help               Show help
        \\    -v, --version            Show version
        \\
        \\For more information about a specific command, use:
        \\    babylon <command> --help
        \\
    , .{});
}

// Command implementations (stubs for now)
fn runInit(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    _ = args;

    if (fileExists(MANIFEST_PATH)) {
        std.debug.print("babylon init: manifest already exists at {s}\n", .{MANIFEST_PATH});
        return 0;
    }

    const project_name = try detectProjectName(allocator);
    defer allocator.free(project_name);

    var manifest = try Manifest.init(allocator, project_name, "0.1.0", builtin.zig_version_string);
    defer manifest.deinit();
    try manifest.save(MANIFEST_PATH);

    const target_string = try formatNativeTarget(allocator);
    defer allocator.free(target_string);

    var lockfile = try Lockfile.init(allocator, builtin.zig_version_string, &[_][]const u8{target_string});
    defer lockfile.deinit();
    try lockfile.writeToFile(allocator, LOCKFILE_PATH);

    std.debug.print("Initialized Babylon manifest '{s}' with lockfile {s}.\n", .{ MANIFEST_PATH, LOCKFILE_PATH });
    std.debug.print("Project name: {s}\n", .{project_name});
    return 0;
}

fn runAdd(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Error: Missing package specification\n", .{});
        std.debug.print("Usage: babylon add <pkg>@<constraint>\n", .{});
        return 1;
    }

    if (!fileExists(MANIFEST_PATH)) {
        std.debug.print("Error: {s} not found. Run `babylon init` first.\n", .{MANIFEST_PATH});
        return 1;
    }

    const package_spec = args[0];
    var spec = parsePackageSpec(allocator, package_spec) catch |err| {
        std.debug.print("Error: Invalid package spec '{s}': {}\n", .{ package_spec, err });
        return 1;
    };
    defer spec.deinit(allocator);

    var constraint = SemverConstraint.parse(allocator, spec.constraint) catch |err| {
        std.debug.print("Error: Invalid version constraint '{s}': {}\n", .{ spec.constraint, err });
        return 1;
    };
    defer constraint.deinit(allocator);

    const options = parseAddOptions(args[1..]) catch |err| {
        handleAddOptionError(err);
        return 1;
    };

    const has_git = options.git_url != null;
    const has_tarball = options.tarball_url != null;

    if (!has_git and !has_tarball) {
        std.debug.print("Error: specify either --git <url> or --tarball <url>\n", .{});
        return 1;
    }

    if (has_git and has_tarball) {
        std.debug.print("Error: cannot combine --git and --tarball for the same dependency\n", .{});
        return 1;
    }

    var manifest = try Manifest.load(allocator, MANIFEST_PATH);
    defer manifest.deinit();

    if (has_tarball) {
        try manifest.upsertTarballDependency(allocator, spec.name, spec.constraint, options.tarball_url.?, options.tarball_hash);
    } else {
        try manifest.upsertDependency(allocator, spec.name, spec.constraint, options.git_url.?, options.reference_type, options.reference);
    }
    try manifest.save(MANIFEST_PATH);

    for (manifest.dependencies) |dep| {
        if (dep.constraint == null) {
            std.debug.print("Error: dependency '{s}' is missing a version constraint in the manifest.\n", .{dep.name});
            return 1;
        }
    }

    try resolveAndWriteLockfile(allocator, &manifest);

    if (has_tarball) {
        std.debug.print("Added dependency '{s}' ({s}) from tarball {s}", .{
            spec.name,
            spec.constraint,
            options.tarball_url.?,
        });
        if (options.tarball_hash) |hash| {
            std.debug.print(" (hash {s})", .{hash});
        }
        std.debug.print(".\n", .{});
    } else {
        std.debug.print("Added dependency '{s}' ({s}) from {s} {s}.\n", .{
            spec.name,
            spec.constraint,
            @tagName(options.reference_type),
            options.reference,
        });
    }

    return 0;
}
fn runUpdate(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    _ = allocator;
    if (args.len > 0) {
        std.debug.print("babylon update: Updating package '{s}'...\n", .{args[0]});
    } else {
        std.debug.print("babylon update: Updating all packages...\n", .{});
    }
    std.debug.print("TODO: Re-resolve within constraints, refresh lockfile\n", .{});
    return 0;
}

fn runRemove(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    _ = allocator;
    if (args.len == 0) {
        std.debug.print("Error: Missing package name\n", .{});
        std.debug.print("Usage: babylon remove <pkg>\n", .{});
        return 1;
    }

    std.debug.print("babylon remove: Removing package '{s}'...\n", .{args[0]});
    std.debug.print("TODO: Remove from build.zig.zon, re-resolve, update lock\n", .{});
    return 0;
}

fn runFetch(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var vendor = false;
    var cache_dir_arg: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--vendor")) {
            vendor = true;
        } else if (std.mem.eql(u8, arg, "--cache-dir")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --cache-dir requires a directory path\n", .{});
                return 1;
            }
            cache_dir_arg = args[i];
        } else {
            std.debug.print("Error: Unknown flag '{s}' for fetch command\n", .{arg});
            return 1;
        }
    }

    if (vendor) {
        std.debug.print("babylon fetch: Materializing dependencies to vendor/...\n", .{});
    } else {
        std.debug.print("babylon fetch: Fetching dependencies to cache...\n", .{});
    }

    var vendor_dir: ?std.fs.Dir = null;
    defer if (vendor_dir) |*dir| dir.close();
    if (vendor) {
        vendor_dir = try std.fs.cwd().makeOpenPath("vendor", .{});
    }

    if (!fileExists(LOCKFILE_PATH)) {
        std.debug.print("Warning: Lockfile {s} not found. Run `babylon add` to generate it.\n", .{LOCKFILE_PATH});
        return 0;
    }

    var lockfile = Lockfile.load(allocator, LOCKFILE_PATH) catch |err| {
        std.debug.print("Error: Failed to load lockfile {s}: {s}\n", .{ LOCKFILE_PATH, @errorName(err) });
        return 1;
    };
    defer lockfile.deinit();

    var policy = Policy.load(allocator, POLICY_PATH) catch |err| switch (err) {
        PolicyError.InvalidPolicyFormat => {
            std.debug.print("Error: Policy file {s} is invalid JSON.\n", .{POLICY_PATH});
            return 1;
        },
        else => {
            std.debug.print("Error: Failed to load policy {s}: {s}\n", .{ POLICY_PATH, @errorName(err) });
            return 1;
        },
    };
    defer policy.deinit();

    // Initialize cache
    var cache = babylon.cache.PackageCache.init(allocator, cache_dir_arg) catch |err| {
        std.debug.print("Error: Failed to initialize cache: {}\n", .{err});
        return 1;
    };
    defer cache.deinit();

    // Get cache statistics
    const stats = cache.storage.getStats() catch |err| {
        std.debug.print("Warning: Could not get cache stats: {}\n", .{err});
        return 0;
    };

    const stats_str = stats.format(allocator) catch "unknown";
    defer if (!std.mem.eql(u8, stats_str, "unknown")) allocator.free(stats_str);

    std.debug.print("✓ Cache initialized: {s}\n", .{stats_str});

    const packages = lockfile.packagesSlice();
    if (packages.len == 0) {
        std.debug.print("Lockfile contains no packages. Nothing to fetch.\n", .{});
    } else {
        std.debug.print("Preparing to fetch {d} package(s):\n", .{packages.len});

        var tarball_count: usize = 0;
        for (packages) |pkg| {
            const source_label = switch (pkg.source) {
                .git => "git",
                .path => "path",
                .registry => "registry",
                .tarball => blk: {
                    tarball_count += 1;
                    break :blk "tarball";
                },
            };

            policy.checkPackage(pkg.name, pkg.source) catch |err| {
                reportPolicyViolation(pkg.name, pkg.version, err);
                return 1;
            };
            std.debug.print("  • {s} {s} [{s}]\n", .{ pkg.name, pkg.version, source_label });
        }

        if (tarball_count == 0) {
            std.debug.print("No tarball sources found. Non-tarball fetchers are not implemented yet.\n", .{});
            return 0;
        }

        std.debug.print("Downloading and caching {d} tarball package(s)...\n", .{tarball_count});

        var cached_count: usize = 0;

        for (packages) |pkg| {
            switch (pkg.source) {
                .tarball => |tarball| {
                    const bytes = downloadTarball(allocator, tarball.url) catch |err| switch (err) {
                        error.TarballNotFound => {
                            std.debug.print("Error: tarball not found at {s}\n", .{tarball.url});
                            return 1;
                        },
                        error.TarballTooLarge => {
                            std.debug.print("Error: tarball at {s} exceeds {d} bytes limit\n", .{ tarball.url, max_tarball_bytes });
                            return 1;
                        },
                        error.UnsupportedTarballScheme => {
                            std.debug.print("Error: unsupported tarball URL scheme in {s}\n", .{tarball.url});
                            return 1;
                        },
                        error.HttpDownloadFailed => {
                            std.debug.print("Error: HTTP download failed for {s}\n", .{tarball.url});
                            return 1;
                        },
                        else => {
                            std.debug.print("Error: failed to download tarball {s}: {s}\n", .{ tarball.url, @errorName(err) });
                            return 1;
                        },
                    };
                    defer allocator.free(bytes);

                    const stored_hash = cache.storePackage(pkg.name, pkg.version, bytes, .{ .expected_hash = tarball.hash }) catch |err| switch (err) {
                        error.HashMismatch => {
                            if (tarball.hash) |expected| {
                                std.debug.print("Error: hash mismatch for {s}@{s}. Expected {s}\n", .{ pkg.name, pkg.version, expected });
                            } else {
                                std.debug.print("Error: hash mismatch for {s}@{s}\n", .{ pkg.name, pkg.version });
                            }
                            return 1;
                        },
                        error.InvalidHash => {
                            std.debug.print("Error: invalid expected hash format for {s}@{s}\n", .{ pkg.name, pkg.version });
                            return 1;
                        },
                        else => {
                            std.debug.print("Error: failed to cache tarball for {s}@{s}: {s}\n", .{ pkg.name, pkg.version, @errorName(err) });
                            return 1;
                        },
                    };
                    defer allocator.free(stored_hash);

                    cached_count += 1;

                    if (tarball.hash) |expected| {
                        std.debug.print("  ✓ {s}@{s} cached (expected {s}, actual {s})\n", .{ pkg.name, pkg.version, expected, stored_hash });
                    } else {
                        std.debug.print("  ✓ {s}@{s} cached (hash {s})\n", .{ pkg.name, pkg.version, stored_hash });
                    }

                    if (vendor) {
                        const sanitized_name = try sanitizeFsName(allocator, pkg.name);
                        defer allocator.free(sanitized_name);
                        const sanitized_version = try sanitizeFsName(allocator, pkg.version);
                        defer allocator.free(sanitized_version);

                        var pkg_dir = try vendor_dir.?.makeOpenPath(sanitized_name, .{});
                        defer pkg_dir.close();

                        const file_name = try std.fmt.allocPrint(allocator, "{s}-{s}.tar", .{ sanitized_name, sanitized_version });
                        defer allocator.free(file_name);

                        try pkg_dir.writeFile(.{
                            .sub_path = file_name,
                            .data = bytes,
                            .flags = .{},
                        });

                        std.debug.print("    ↳ vendor/{s}/{s}\n", .{ sanitized_name, file_name });
                    }
                },
                else => {},
            }
        }

        std.debug.print("Fetch complete: cached {d}/{d} tarball package(s).\n", .{ cached_count, tarball_count });
    }
    return 0;
}

fn runCache(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: babylon cache <prune|ls> [options]\n", .{});
        return 1;
    }

    const subcommand = args[0];
    if (std.mem.eql(u8, subcommand, "prune")) {
        return runCachePrune(allocator, args[1..]);
    }

    if (std.mem.eql(u8, subcommand, "ls") or std.mem.eql(u8, subcommand, "list")) {
        return runCacheList(allocator, args[1..]);
    }

    std.debug.print("Error: Unknown cache subcommand '{s}'\n", .{subcommand});
    return 1;
}

fn runCachePrune(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var cache_dir_arg: ?[]const u8 = null;
    var dry_run = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--cache-dir")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --cache-dir requires a directory path\n", .{});
                return 1;
            }
            cache_dir_arg = args[i];
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else {
            std.debug.print("Error: Unknown flag '{s}' for cache prune\n", .{arg});
            return 1;
        }
    }

    if (!fileExists(LOCKFILE_PATH)) {
        std.debug.print("Error: Lockfile {s} not found. Run `babylon fetch` first.\n", .{LOCKFILE_PATH});
        return 1;
    }

    var lockfile = Lockfile.load(allocator, LOCKFILE_PATH) catch |err| {
        std.debug.print("Error: Failed to load lockfile {s}: {s}\n", .{ LOCKFILE_PATH, @errorName(err) });
        return 1;
    };
    defer lockfile.deinit();

    var required_hashes = ArrayListManaged([]const u8).init(allocator);
    defer {
        for (required_hashes.items) |hash| allocator.free(hash);
        required_hashes.deinit();
    }

    try collectRequiredTarballHashes(allocator, &lockfile, &required_hashes);

    if (required_hashes.items.len == 0) {
        std.debug.print("Warning: No tarball hashes found in lockfile; aborting prune.\n", .{});
        return 0;
    }

    var storage = try babylon.cache.ContentAddressedStorage.init(allocator, cache_dir_arg);
    defer storage.deinit();

    const stats = try storage.prune(allocator, required_hashes.items, dry_run);

    std.debug.print("Cache prune summary: kept {d}, removed {d}{s}\n", .{
        stats.kept,
        stats.removed,
        if (dry_run) " (dry-run)" else "",
    });

    return 0;
}

fn runCacheList(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var cache_dir_arg: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--cache-dir")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --cache-dir requires a directory path\n", .{});
                return 1;
            }
            cache_dir_arg = args[i];
        } else {
            std.debug.print("Error: Unknown flag '{s}' for cache ls\n", .{arg});
            return 1;
        }
    }

    var storage = try ContentAddressedStorage.init(allocator, cache_dir_arg);
    defer storage.deinit();

    var objects = try storage.listObjects(allocator);
    defer {
        for (objects.items) |*info| info.deinit(allocator);
        objects.deinit();
    }

    if (objects.items.len == 0) {
        std.debug.print("Cache is empty.\n", .{});
        return 0;
    }

    std.debug.print("Cache contents:\n", .{});
    var total: u64 = 0;
    for (objects.items) |info| {
        total += info.size;
        std.debug.print("  • {s}  {d} bytes\n", .{ info.hash, info.size });
    }
    std.debug.print("Total: {d} object(s), {d} bytes\n", .{ objects.items.len, total });

    return 0;
}

fn collectRequiredTarballHashes(allocator: std.mem.Allocator, lockfile: *const Lockfile, list: *ArrayListManaged([]const u8)) !void {
    for (lockfile.packagesSlice()) |pkg| {
        switch (pkg.source) {
            .tarball => |tarball| {
                if (tarball.hash) |hash_value| {
                    const normalized = ContentAddressedStorage.normalizeHashInput(allocator, hash_value) catch |err| switch (err) {
                        error.InvalidHash => {
                            std.debug.print("Warning: ignoring invalid hash format for {s}@{s}\n", .{ pkg.name, pkg.version });
                            continue;
                        },
                        else => return err,
                    };
                    try list.append(normalized);
                } else {
                    std.debug.print("Warning: {s}@{s} lacks hash; cached artifact cannot be protected by prune.\n", .{ pkg.name, pkg.version });
                }
            },
            else => {},
        }
    }
}

fn runPolicy(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: babylon policy audit\n", .{});
        return 1;
    }

    const subcommand = args[0];
    if (std.mem.eql(u8, subcommand, "audit")) {
        return runPolicyAudit(allocator, args[1..]);
    }

    std.debug.print("Error: Unknown policy subcommand '{s}'\n", .{subcommand});
    return 1;
}

fn runPolicyAudit(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    _ = args;

    var lockfile = Lockfile.load(allocator, LOCKFILE_PATH) catch |err| {
        std.debug.print("Error: Failed to load lockfile {s}: {s}\n", .{ LOCKFILE_PATH, @errorName(err) });
        return 1;
    };
    defer lockfile.deinit();

    var policy = Policy.load(allocator, POLICY_PATH) catch |err| switch (err) {
        PolicyError.InvalidPolicyFormat => {
            std.debug.print("Error: Policy file {s} is invalid JSON.\n", .{POLICY_PATH});
            return 1;
        },
        else => {
            std.debug.print("Error: Failed to load policy {s}: {s}\n", .{ POLICY_PATH, @errorName(err) });
            return 1;
        },
    };
    defer policy.deinit();

    var report = try policy.auditLockfile(allocator, &lockfile);
    defer report.deinit(allocator);

    if (report.violations.items.len == 0) {
        std.debug.print("Policy audit passed: {d} package(s) comply.\n", .{report.checked});
        return 0;
    }

    std.debug.print("Policy audit failed: {d} violation(s) detected out of {d} package(s).\n", .{
        report.violations.items.len,
        report.checked,
    });

    for (report.violations.items) |violation| {
        reportPolicyViolation(violation.package, violation.version, violation.reason);
    }

    return 1;
}

fn runGraph(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    _ = args;

    if (!fileExists(LOCKFILE_PATH)) {
        std.debug.print("babylon graph: Lockfile {s} not found.\n", .{LOCKFILE_PATH});
        return 0;
    }

    var lockfile = Lockfile.load(allocator, LOCKFILE_PATH) catch |err| {
        std.debug.print("Error: Failed to load lockfile {s}: {s}\n", .{ LOCKFILE_PATH, @errorName(err) });
        return 1;
    };
    defer lockfile.deinit();

    std.debug.print("babylon graph: {d} resolved package(s)\n", .{lockfile.packagesSlice().len});
    for (lockfile.packagesSlice()) |pkg| {
        std.debug.print("• {s} {s}\n", .{ pkg.name, pkg.version });
        if (pkg.dependencies.len == 0) {
            std.debug.print("    (no dependencies)\n", .{});
        } else {
            for (pkg.dependencies) |dep| {
                std.debug.print("    └─ {s} {s}\n", .{ dep.name, dep.version });
            }
        }
    }
    return 0;
}

fn runVerify(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    _ = args;
    std.debug.print("babylon verify: Verifying lockfile integrity...\n", .{});

    if (!fileExists(LOCKFILE_PATH)) {
        std.debug.print("Warning: Lockfile {s} not found.\n", .{LOCKFILE_PATH});
        return 1;
    }

    var lockfile = Lockfile.load(allocator, LOCKFILE_PATH) catch |err| {
        std.debug.print("Error: Failed to load lockfile {s}: {s}\n", .{ LOCKFILE_PATH, @errorName(err) });
        return 1;
    };
    defer lockfile.deinit();

    var missing = false;
    for (lockfile.packagesSlice()) |pkg| {
        if (pkg.checksum == null) {
            missing = true;
            std.debug.print("✗ Package {s} {s} missing checksum.\n", .{ pkg.name, pkg.version });
        }
        for (pkg.dependencies) |dep| {
            if (dep.version.len == 0) {
                missing = true;
                std.debug.print("✗ Dependency {s} of {s} missing locked version.\n", .{ dep.name, pkg.name });
            }
        }
    }

    if (!missing) {
        std.debug.print("✓ Lockfile integrity checks passed.\n", .{});
        return 0;
    }

    std.debug.print("Verification completed with warnings.\n", .{});
    return 1;
}

fn runBuild(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    const command_len = 2 + args.len;
    var argv = try allocator.alloc([]const u8, command_len);
    defer allocator.free(argv);

    argv[0] = "zig";
    argv[1] = "build";
    for (args, 0..) |arg, idx| {
        argv[2 + idx] = arg;
    }

    var child = std.process.Child.init(argv, allocator);
    defer child.deinit();
    child.stdin_behavior = .inherit;
    child.stdout_behavior = .inherit;
    child.stderr_behavior = .inherit;

    child.spawn() catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("Error: unable to find `zig` on PATH when running `zig build`\n", .{});
            return 1;
        },
        else => return err,
    };

    const term = try child.wait();
    switch (term) {
        .Exited => |code| return @intCast(code),
        .Signal, .Stopped, .Unknown => {
            std.debug.print("`zig build` terminated abnormally: {any}\n", .{term});
            return 1;
        },
    }
}

const PackageSpec = struct {
    name: []const u8,
    constraint: []const u8,

    pub fn deinit(self: *PackageSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.constraint);
    }
};

const AddOptions = struct {
    git_url: ?[]const u8 = null,
    reference_type: Manifest.GitReferenceType = .branch,
    reference: []const u8 = "main",
    tarball_url: ?[]const u8 = null,
    tarball_hash: ?[]const u8 = null,
};

fn parsePackageSpec(allocator: std.mem.Allocator, input: []const u8) !PackageSpec {
    const at = std.mem.indexOfScalar(u8, input, '@') orelse return error.MissingConstraint;
    const name_part = std.mem.trim(u8, input[0..at], " \t");
    const constraint_part = std.mem.trim(u8, input[at + 1 ..], " \t");
    if (name_part.len == 0 or constraint_part.len == 0) return error.MissingConstraint;

    return .{
        .name = try allocator.dupe(u8, name_part),
        .constraint = try allocator.dupe(u8, constraint_part),
    };
}

fn parseAddOptions(args: []const []const u8) !AddOptions {
    var opts = AddOptions{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--git")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            if (opts.tarball_url != null) return error.ConflictingSource;
            opts.git_url = args[i];
        } else if (std.mem.eql(u8, arg, "--branch")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            if (opts.reference_type != .branch or !std.mem.eql(u8, opts.reference, "main")) return error.ConflictingReference;
            opts.reference_type = .branch;
            opts.reference = args[i];
        } else if (std.mem.eql(u8, arg, "--tag")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            if (opts.reference_type != .branch or !std.mem.eql(u8, opts.reference, "main")) return error.ConflictingReference;
            opts.reference_type = .tag;
            opts.reference = args[i];
        } else if (std.mem.eql(u8, arg, "--commit")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            if (opts.reference_type != .branch or !std.mem.eql(u8, opts.reference, "main")) return error.ConflictingReference;
            opts.reference_type = .commit;
            opts.reference = args[i];
        } else if (std.mem.eql(u8, arg, "--tarball")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            if (opts.git_url != null or opts.tarball_url != null) return error.ConflictingSource;
            opts.tarball_url = args[i];
        } else if (std.mem.eql(u8, arg, "--hash")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            opts.tarball_hash = args[i];
        } else {
            return error.UnknownFlag;
        }
    }

    if (opts.tarball_hash != null and opts.tarball_url == null) return error.HashWithoutTarball;

    return opts;
}

fn handleAddOptionError(err: anyerror) void {
    switch (err) {
        error.MissingValue => std.debug.print("Error: Missing value for flag\n", .{}),
        error.ConflictingReference => std.debug.print("Error: Use only one of --branch, --tag, or --commit\n", .{}),
        error.ConflictingSource => std.debug.print("Error: Choose either --git or --tarball source\n", .{}),
        error.HashWithoutTarball => std.debug.print("Error: --hash requires a preceding --tarball\n", .{}),
        error.UnknownFlag => std.debug.print("Error: Unknown flag for add command\n", .{}),
        else => std.debug.print("Error: {s}\n", .{@errorName(err)}),
    }
}

fn resolveAndWriteLockfile(allocator: std.mem.Allocator, manifest: *Manifest) !void {
    var deps = try allocator.alloc(ResolverDependency, manifest.dependencies.len);

    for (manifest.dependencies, 0..) |manifest_dep, idx| {
        const constraint_text = manifest_dep.constraint orelse return error.ManifestMissingConstraint;
        var parsed_constraint = try SemverConstraint.parseRaw(allocator, constraint_text);
        var parsed_guard = true;
        defer if (parsed_guard) parsed_constraint.deinit(allocator);

        var dep = ResolverDependency{
            .name = try allocator.dupe(u8, manifest_dep.name),
            .constraint = parsed_constraint.constraint,
            .raw_constraint = parsed_constraint.raw,
            .source = null,
        };
        parsed_constraint.raw = null;
        parsed_guard = false;
        var cleanup = true;
        defer if (cleanup) dep.deinit(allocator);

        switch (manifest_dep.source) {
            .git => |git| {
                dep.source = ResolverSource{ .git = .{
                    .url = try allocator.dupe(u8, git.url),
                    .ref = switch (git.reference_type) {
                        .branch => ResolverSource.GitRef{ .branch = try allocator.dupe(u8, git.reference) },
                        .tag => ResolverSource.GitRef{ .tag = try allocator.dupe(u8, git.reference) },
                        .commit => ResolverSource.GitRef{ .commit = try allocator.dupe(u8, git.reference) },
                    },
                } };
            },
            .path => |path| {
                dep.source = ResolverSource{ .path = try allocator.dupe(u8, path.location) };
            },
            .tarball => |tarball| {
                dep.source = ResolverSource{ .tarball = .{
                    .url = try allocator.dupe(u8, tarball.url),
                    .hash = if (tarball.hash) |value| try allocator.dupe(u8, value) else null,
                } };
            },
        }

        deps[idx] = dep;
        cleanup = false;
    }

    defer {
        for (deps) |*dep| dep.deinit(allocator);
        allocator.free(deps);
    }

    var resolver = babylon.resolver.Resolver.init(allocator);
    var resolution = try resolver.resolve(deps);
    defer resolution.deinit();

    const target_string = try formatNativeTarget(allocator);
    defer allocator.free(target_string);

    var lockfile = try Lockfile.fromResolution(allocator, &resolution, builtin.zig_version_string, &[_][]const u8{target_string});
    defer lockfile.deinit();
    try lockfile.writeToFile(allocator, LOCKFILE_PATH);
}

fn fileExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn detectProjectName(allocator: std.mem.Allocator) ![]const u8 {
    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);
    const basename = std.fs.path.basename(cwd_path);
    return allocator.dupe(u8, basename);
}

fn formatNativeTarget(allocator: std.mem.Allocator) ![]const u8 {
    const target = builtin.target;
    const arch = @tagName(target.cpu.arch);
    const os = @tagName(target.os.tag);
    const abi = @tagName(target.abi);
    return std.fmt.allocPrint(allocator, "{s}-{s}-{s}", .{ arch, os, abi });
}

fn reportPolicyViolation(name: []const u8, version: []const u8, err: PolicyEnforceError) void {
    switch (err) {
        PolicyEnforceError.PackageDenied => {
            std.debug.print("Error: {s}@{s} denied by policy deny-list.\n", .{ name, version });
        },
        PolicyEnforceError.PackageNotAllowed => {
            std.debug.print("Error: {s}@{s} not in policy allow-list.\n", .{ name, version });
        },
        PolicyEnforceError.MissingHash => {
            std.debug.print("Error: {s}@{s} missing required hash according to policy.\n", .{ name, version });
        },
    }
}

const max_tarball_bytes: usize = 128 * 1024 * 1024;

var download_tarball_test_ca_bundle_path: ?[]const u8 = null;

pub fn setDownloadTarballTestCABundle(path: ?[]const u8) ?[]const u8 {
    const previous = download_tarball_test_ca_bundle_path;
    download_tarball_test_ca_bundle_path = path;
    return previous;
}

const HttpTestServerContext = struct {
    server: *std.net.Server,
    body: []const u8,
};

fn sanitizeFsName(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const buf = try allocator.dupe(u8, input);
    for (buf) |*ch| {
        switch (ch.*) {
            '/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ' => ch.* = '_',
            else => {},
        }
    }
    return buf;
}

fn httpTestServeOnce(ctx: HttpTestServerContext) void {
    var connection = ctx.server.accept() catch return;
    defer connection.stream.close();

    var drain_buffer: [512]u8 = undefined;
    _ = connection.stream.read(&drain_buffer) catch {};

    var header_buffer: [512]u8 = undefined;
    const header_bytes = std.fmt.bufPrint(
        &header_buffer,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Content-Type: application/octet-stream\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
        .{ctx.body.len},
    ) catch return;

    _ = connection.stream.writeAll(header_bytes) catch return;
    _ = connection.stream.writeAll(ctx.body) catch {};
}

fn downloadTarball(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    if (std.mem.startsWith(u8, url, "file://")) {
        const path = url[7..];
        const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.TarballNotFound,
            else => return err,
        };
        defer file.close();

        var read_buffer: [16 * 1024]u8 = undefined;
        var contents = ArrayListManaged(u8).init(allocator);
        errdefer contents.deinit();

        while (true) {
            const amount = try file.read(read_buffer[0..]);
            if (amount == 0) break;
            if (contents.items.len + amount > max_tarball_bytes) return error.TarballTooLarge;
            try contents.appendSlice(read_buffer[0..amount]);
        }

        return contents.toOwnedSlice();
    }

    if (std.mem.startsWith(u8, url, "http://") or std.mem.startsWith(u8, url, "https://")) {
        const uri = std.Uri.parse(url) catch return error.UnsupportedTarballScheme;

        var client = std.http.Client{
            .allocator = allocator,
        };
        defer client.deinit();
        try client.initDefaultProxies(allocator);

        if (download_tarball_test_ca_bundle_path) |ca_path| {
            client.ca_bundle_mutex.lock();
            defer client.ca_bundle_mutex.unlock();
            try client.ca_bundle.addCertsFromFilePathAbsolute(allocator, ca_path);
        }

        var request = try client.request(.GET, uri, .{});
        defer request.deinit();

        try request.sendBodiless();

        var header_buffer: [16 * 1024]u8 = undefined;
        var response = try request.receiveHead(&header_buffer);

        switch (response.head.status) {
            .ok => {},
            .not_found => return error.TarballNotFound,
            else => return error.HttpDownloadFailed,
        }

        if (response.head.content_length) |len| {
            if (len > max_tarball_bytes) return error.TarballTooLarge;
        }

        var read_buffer: [16 * 1024]u8 = undefined;
        var body = ArrayListManaged(u8).init(allocator);
        errdefer body.deinit();

        const reader = response.reader(&read_buffer);

        while (true) {
            var io_vec = [_][]u8{read_buffer[0..]};
            const amount = reader.*.vtable.readVec(reader, io_vec[0..]) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => return err,
            };
            if (amount == 0) break;
            if (body.items.len + amount > max_tarball_bytes) return error.TarballTooLarge;
            try body.appendSlice(read_buffer[0..amount]);
        }

        if (response.bodyErr()) |body_error| {
            return body_error;
        }

        return body.toOwnedSlice();
    }

    return error.UnsupportedTarballScheme;
}

test "cli add creates lockfile entry for tarball dependency" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var prev_dir = try std.fs.cwd().openDir(".", .{});
    defer prev_dir.close();

    try tmp_dir.dir.setAsCwd();
    defer prev_dir.setAsCwd() catch unreachable;

    var manifest = try Manifest.init(allocator, "example", "0.1.0", builtin.zig_version_string);
    defer manifest.deinit();
    try manifest.save(MANIFEST_PATH);

    const args = [_][]const u8{
        "foo@1.2.3",
        "--tarball",
        "https://example.com/foo.tar.gz",
        "--hash",
        "sha256:deadbeef",
    };

    const exit_code = try runAdd(allocator, &args);
    try std.testing.expectEqual(@as(u8, 0), exit_code);

    var lockfile = try Lockfile.load(allocator, LOCKFILE_PATH);
    defer lockfile.deinit();

    const packages = lockfile.packagesSlice();
    try std.testing.expectEqual(@as(usize, 1), packages.len);

    const pkg = packages[0];
    try std.testing.expect(std.mem.eql(u8, pkg.name, "foo"));
    try std.testing.expect(std.mem.eql(u8, pkg.version, "1.2.3"));
    try std.testing.expect(pkg.source == .tarball);
    const tarball = pkg.source.tarball;
    try std.testing.expect(std.mem.eql(u8, tarball.url, "https://example.com/foo.tar.gz"));
    try std.testing.expect(tarball.hash != null);
    try std.testing.expect(std.mem.eql(u8, tarball.hash.?, "sha256:deadbeef"));
}

test "downloadTarball supports http" {
    const allocator = std.testing.allocator;

    const ResponseBody = "http tarball payload";

    var listen_address = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try listen_address.listen(.{ .reuse_address = true });
    defer server.deinit();

    const port = server.listen_address.getPort();

    var accept_thread = try std.Thread.spawn(.{}, httpTestServeOnce, .{HttpTestServerContext{ .server = &server, .body = ResponseBody }});
    defer accept_thread.join();

    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/artifact.tar", .{port});
    defer allocator.free(url);

    const bytes = try downloadTarball(allocator, url);
    defer allocator.free(bytes);

    try std.testing.expectEqualStrings(ResponseBody, bytes);
}

const OpensslResponderContext = struct {
    stdout_file: *std.fs.File,
    stdin_file: *std.fs.File,
    response: []const u8,
    result: ?anyerror = null,
};

fn runOpensslResponder(ctx: *OpensslResponderContext) void {
    responderImpl(ctx) catch |err| {
        ctx.result = err;
        return;
    };
}

fn responderImpl(ctx: *OpensslResponderContext) !void {
    var buffer: [512]u8 = undefined;
    var state: u32 = 0;

    read_loop: while (true) {
        const count = try ctx.stdout_file.read(&buffer);
        if (count == 0) return error.UnexpectedEof;
        for (buffer[0..count]) |byte| {
            state = ((state << 8) | byte) & 0xffff_ffff;
            if (state == 0x0d0a0d0a) break :read_loop;
        }
    }

    try ctx.stdin_file.writeAll(ctx.response);
    ctx.stdin_file.close();

    while (true) {
        const drained = try ctx.stdout_file.read(&buffer);
        if (drained == 0) break;
    }

    ctx.stdout_file.close();
}

test "downloadTarball supports https" {
    const allocator = std.testing.allocator;
    const ResponseBody = "https tarball payload";

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const cert_path = try std.fs.path.join(allocator, &.{ tmp_path, "server-cert.pem" });
    defer allocator.free(cert_path);
    const key_path = try std.fs.path.join(allocator, &.{ tmp_path, "server-key.pem" });
    defer allocator.free(key_path);
    const ca_cert_path = try std.fs.path.join(allocator, &.{ tmp_path, "ca-cert.pem" });
    defer allocator.free(ca_cert_path);
    const repo_dir = std.fs.cwd();
    try repo_dir.copyFile("tmp/https_test/server-cert.pem", tmp_dir.dir, "server-cert.pem", .{});
    try repo_dir.copyFile("tmp/https_test/server-key.pem", tmp_dir.dir, "server-key.pem", .{});
    try repo_dir.copyFile("tmp/https_test/ca-cert.pem", tmp_dir.dir, "ca-cert.pem", .{});

    const prev_ca = setDownloadTarballTestCABundle(ca_cert_path);
    defer _ = setDownloadTarballTestCABundle(prev_ca);

    var probe_addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var probe_listener = try probe_addr.listen(.{ .reuse_address = true });
    const port = probe_listener.listen_address.getPort();
    probe_listener.deinit();

    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_str);

    const response = try std.fmt.allocPrint(allocator,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Content-Type: application/octet-stream\r\n" ++
            "Connection: close\r\n" ++
            "\r\n{s}",
        .{ ResponseBody.len, ResponseBody },
    );
    defer allocator.free(response);

    var server_cmd = std.process.Child.init(&[_][]const u8{
        "openssl",
        "s_server",
        "-quiet",
        "-no_ticket",
        "-cert", cert_path,
        "-key", key_path,
        "-accept", port_str,
        "-naccept", "1",
    }, allocator);
    server_cmd.stdin_behavior = .Pipe;
    server_cmd.stdout_behavior = .Pipe;
    server_cmd.stderr_behavior = .Inherit;
    server_cmd.spawn() catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };

    var stdout_file = server_cmd.stdout orelse return error.SkipZigTest;
    server_cmd.stdout = null;
    var stdin_file = server_cmd.stdin orelse return error.SkipZigTest;
    server_cmd.stdin = null;

    var responder_ctx = OpensslResponderContext{
        .stdout_file = &stdout_file,
        .stdin_file = &stdin_file,
        .response = response,
    };
    var responder_thread = try std.Thread.spawn(.{}, runOpensslResponder, .{&responder_ctx});

    std.Thread.sleep(20 * std.time.ns_per_ms);

    const url = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/artifact.tar", .{port});
    defer allocator.free(url);

    const download_result = downloadTarball(allocator, url);
    responder_thread.join();

    const bytes = download_result catch |download_err| {
        if (responder_ctx.result) |res_err| return res_err;
        return download_err;
    };
    if (responder_ctx.result) |res_err| return res_err;
    defer allocator.free(bytes);

    try std.testing.expectEqualStrings(ResponseBody, bytes);

    const server_term = server_cmd.wait() catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    switch (server_term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.SkipZigTest,
    }
}

test "runBuild forwards to zig build" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var prev_dir = try std.fs.cwd().openDir(".", .{});
    defer prev_dir.close();

    try tmp_dir.dir.setAsCwd();
    defer prev_dir.setAsCwd() catch unreachable;

    const exit_code = try runBuild(allocator, &[_][]const u8{"--help"});
    try std.testing.expectEqual(@as(u8, 0), exit_code);
}

test "cli fetch caches tarball content" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var prev_dir = try std.fs.cwd().openDir(".", .{});
    defer prev_dir.close();

    try tmp_dir.dir.setAsCwd();
    defer prev_dir.setAsCwd() catch unreachable;

    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);

    const tarball_rel = "artifact.tar";
    const tarball_contents = "tarball payload";
    try tmp_dir.dir.writeFile(.{
        .sub_path = tarball_rel,
        .data = tarball_contents,
        .flags = .{},
    });

    const tarball_abs = try std.fs.path.join(allocator, &.{ cwd_path, tarball_rel });
    defer allocator.free(tarball_abs);

    const tarball_url = try std.fmt.allocPrint(allocator, "file://{s}", .{tarball_abs});
    defer allocator.free(tarball_url);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(tarball_contents, &digest, .{});
    const hex = std.fmt.bytesToHex(&digest, .lower);
    const expected_hash = try std.fmt.allocPrint(allocator, "sha256:{s}", .{hex[0..]});
    defer allocator.free(expected_hash);

    try tmp_dir.dir.writeFile(.{
        .sub_path = "babylon.policy.json",
        .data = "{\"require_hash\":true}",
        .flags = .{},
    });

    var lockfile = try Lockfile.init(allocator, builtin.zig_version_string, &[_][]const u8{});
    defer lockfile.deinit();
    try lockfile.putPackage(.{
        .name = "foo",
        .version = "1.0.0",
        .source = .{ .tarball = .{ .url = tarball_url, .hash = expected_hash } },
    });
    try lockfile.writeToFile(allocator, LOCKFILE_PATH);

    const cache_dir = try std.fmt.allocPrint(allocator, "{s}/cache", .{cwd_path});
    defer allocator.free(cache_dir);

    const args = [_][]const u8{ "--cache-dir", cache_dir };
    const exit_code = try runFetch(allocator, &args);
    try std.testing.expectEqual(@as(u8, 0), exit_code);

    var storage = try babylon.cache.ContentAddressedStorage.init(allocator, cache_dir);
    defer storage.deinit();

    try std.testing.expect(storage.exists(hex[0..]));
    const cached = try storage.retrieve(hex[0..]);
    defer allocator.free(cached);
    try std.testing.expectEqualStrings(tarball_contents, cached);

    const policy_exit = try runPolicy(allocator, &[_][]const u8{"audit"});
    try std.testing.expectEqual(@as(u8, 0), policy_exit);
}

test "cli fetch vendors tarball content" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var prev_dir = try std.fs.cwd().openDir(".", .{});
    defer prev_dir.close();

    try tmp_dir.dir.setAsCwd();
    defer prev_dir.setAsCwd() catch unreachable;

    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);

    const tarball_rel = "artifact.tar";
    const tarball_contents = "tarball payload";
    try tmp_dir.dir.writeFile(.{
        .sub_path = tarball_rel,
        .data = tarball_contents,
        .flags = .{},
    });

    const tarball_abs = try std.fs.path.join(allocator, &.{ cwd_path, tarball_rel });
    defer allocator.free(tarball_abs);

    const tarball_url = try std.fmt.allocPrint(allocator, "file://{s}", .{tarball_abs});
    defer allocator.free(tarball_url);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(tarball_contents, &digest, .{});
    const hex = std.fmt.bytesToHex(&digest, .lower);
    const expected_hash = try std.fmt.allocPrint(allocator, "sha256:{s}", .{hex[0..]});
    defer allocator.free(expected_hash);

    try tmp_dir.dir.writeFile(.{
        .sub_path = "babylon.policy.json",
        .data = "{\"require_hash\":true}",
        .flags = .{},
    });

    var lockfile = try Lockfile.init(allocator, builtin.zig_version_string, &[_][]const u8{});
    defer lockfile.deinit();
    try lockfile.putPackage(.{
        .name = "ghostkellz/flash",
        .version = "1.0.0",
        .source = .{ .tarball = .{ .url = tarball_url, .hash = expected_hash } },
    });
    try lockfile.writeToFile(allocator, LOCKFILE_PATH);

    const cache_dir = try std.fmt.allocPrint(allocator, "{s}/cache", .{cwd_path});
    defer allocator.free(cache_dir);

    const args = [_][]const u8{ "--cache-dir", cache_dir, "--vendor" };
    const exit_code = try runFetch(allocator, &args);
    try std.testing.expectEqual(@as(u8, 0), exit_code);

    const vendor_file_path = try std.fs.path.join(allocator, &.{ cwd_path, "vendor", "ghostkellz_flash", "ghostkellz_flash-1.0.0.tar" });
    defer allocator.free(vendor_file_path);

    const vendor_file = try std.fs.cwd().openFile(vendor_file_path, .{});
    defer vendor_file.close();

    const buffer = try allocator.alloc(u8, tarball_contents.len);
    defer allocator.free(buffer);
    const read_len = try vendor_file.readAll(buffer);
    try std.testing.expectEqual(@as(usize, tarball_contents.len), read_len);
    try std.testing.expectEqualStrings(tarball_contents, buffer);
}

test "cli end-to-end tarball flow" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var prev_dir = try std.fs.cwd().openDir(".", .{});
    defer prev_dir.close();

    try tmp_dir.dir.setAsCwd();
    defer prev_dir.setAsCwd() catch unreachable;

    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);

    try tmp_dir.dir.writeFile(.{
        .sub_path = "babylon.policy.json",
        .data = "{\"require_hash\":true}",
        .flags = .{},
    });

    const tarball_rel = "palette.tar";
    const tarball_contents = "palette payload";
    try tmp_dir.dir.writeFile(.{
        .sub_path = tarball_rel,
        .data = tarball_contents,
        .flags = .{},
    });

    const tarball_abs = try std.fs.path.join(allocator, &.{ cwd_path, tarball_rel });
    defer allocator.free(tarball_abs);
    const tarball_url = try std.fmt.allocPrint(allocator, "file://{s}", .{tarball_abs});
    defer allocator.free(tarball_url);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(tarball_contents, &digest, .{});
    const hex = std.fmt.bytesToHex(&digest, .lower);
    const expected_hash = try std.fmt.allocPrint(allocator, "sha256:{s}", .{hex[0..]});
    defer allocator.free(expected_hash);

    try std.testing.expectEqual(@as(u8, 0), try runInit(allocator, &[_][]const u8{}));

    const add_args = [_][]const u8{
        "palette@1.2.0",
        "--tarball",
        tarball_url,
        "--hash",
        expected_hash,
    };
    try std.testing.expectEqual(@as(u8, 0), try runAdd(allocator, &add_args));

    var lockfile = try Lockfile.load(allocator, LOCKFILE_PATH);
    defer lockfile.deinit();
    const packages = lockfile.packagesSlice();
    try std.testing.expectEqual(@as(usize, 1), packages.len);
    const pkg = packages[0];
    try std.testing.expectEqualStrings("palette", pkg.name);
    try std.testing.expectEqualStrings("1.2.0", pkg.version);
    try std.testing.expect(pkg.source == .tarball);

    const cache_dir = try std.fmt.allocPrint(allocator, "{s}/cache", .{cwd_path});
    defer allocator.free(cache_dir);

    const fetch_args = [_][]const u8{ "--cache-dir", cache_dir };
    try std.testing.expectEqual(@as(u8, 0), try runFetch(allocator, &fetch_args));

    var cache = try babylon.cache.ContentAddressedStorage.init(allocator, cache_dir);
    defer cache.deinit();
    try std.testing.expect(cache.exists(hex[0..]));
    const cached = try cache.retrieve(hex[0..]);
    defer allocator.free(cached);
    try std.testing.expectEqualStrings(tarball_contents, cached);
}

test "policy enforcement rejects tarball without hash" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var prev_dir = try std.fs.cwd().openDir(".", .{});
    defer prev_dir.close();

    try tmp_dir.dir.setAsCwd();
    defer prev_dir.setAsCwd() catch unreachable;

    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);

    try tmp_dir.dir.writeFile(.{
        .sub_path = "babylon.policy.json",
        .data = "{\"require_hash\":true}",
        .flags = .{},
    });

    const tarball_rel = "artifact.tar";
    try tmp_dir.dir.writeFile(.{
        .sub_path = tarball_rel,
        .data = "payload",
        .flags = .{},
    });
    const tarball_abs = try std.fs.path.join(allocator, &.{ cwd_path, tarball_rel });
    defer allocator.free(tarball_abs);

    const tarball_url = try std.fmt.allocPrint(allocator, "file://{s}", .{tarball_abs});
    defer allocator.free(tarball_url);

    var lockfile = try Lockfile.init(allocator, builtin.zig_version_string, &[_][]const u8{});
    defer lockfile.deinit();
    try lockfile.putPackage(.{
        .name = "foo",
        .version = "1.0.0",
        .source = .{ .tarball = .{ .url = tarball_url, .hash = null } },
    });
    try lockfile.writeToFile(allocator, LOCKFILE_PATH);

    const cache_dir = try std.fmt.allocPrint(allocator, "{s}/cache", .{cwd_path});
    defer allocator.free(cache_dir);

    const args = [_][]const u8{ "--cache-dir", cache_dir };
    const exit_code = try runFetch(allocator, &args);
    try std.testing.expectEqual(@as(u8, 1), exit_code);
}
