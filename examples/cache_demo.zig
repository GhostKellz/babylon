const std = @import("std");
const babylon = @import("babylon");

/// Demo program to showcase Babylon's content-addressed cache
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Babylon Content-Addressed Cache Demo ===\n\n", .{});

    // Initialize cache
    var cache = try babylon.cache.PackageCache.init(allocator, "/tmp/babylon_demo");
    defer cache.deinit();

    // Demo content
    const package_content =
        \\# Example Package
        \\This is a demo package for Babylon package manager.
        \\
        \\## Features
        \\- Content-addressed storage
        \\- SHA-256 integrity verification
        \\- Efficient deduplication
        \\- TOML lockfiles
        \\- Semantic versioning
    ;

    std.debug.print("📦 Storing package 'demo-pkg' version '1.0.0'...\n", .{});

    // Store package
    const hash = try cache.storePackage("demo-pkg", "1.0.0", package_content, .{});
    defer allocator.free(hash);

    std.debug.print("✓ Package stored with hash: {s}\n", .{hash});

    // Verify it exists
    if (cache.hasPackage("demo-pkg", "1.0.0")) {
        std.debug.print("✓ Package exists in cache\n", .{});
    }

    // Retrieve and verify
    std.debug.print("📖 Retrieving package...\n", .{});
    const retrieved = try cache.retrievePackage("demo-pkg", "1.0.0");
    defer allocator.free(retrieved);

    if (std.mem.eql(u8, package_content, retrieved)) {
        std.debug.print("✓ Package content verified successfully\n", .{});
    } else {
        std.debug.print("❌ Package content verification failed\n", .{});
        return;
    }

    // Get cache statistics
    const stats = try cache.storage.getStats();
    const stats_str = try stats.format(allocator);
    defer allocator.free(stats_str);

    std.debug.print("📊 Cache stats: {s}\n", .{stats_str});

    // Demo compression (would use zpack in real implementation)
    std.debug.print("\n📦 Storing compressed package 'demo-pkg' version '1.1.0'...\n", .{});
    const compressed_hash = try cache.storePackage("demo-pkg", "1.1.0", package_content, .{ .compressed = true });
    defer allocator.free(compressed_hash);

    std.debug.print("✓ Compressed package stored with hash: {s}\n", .{compressed_hash});

    // Show final stats
    const final_stats = try cache.storage.getStats();
    const final_stats_str = try final_stats.format(allocator);
    defer allocator.free(final_stats_str);

    std.debug.print("📊 Final cache stats: {s}\n", .{final_stats_str});

    std.debug.print("\n🎉 Demo completed successfully!\n", .{});
    std.debug.print("Cache location: /tmp/babylon_demo\n", .{});
}
