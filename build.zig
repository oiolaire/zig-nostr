const std = @import("std");

pub fn build(b: *std.Build) !void {
    // library
    const lib = b.addStaticLibrary(.{
        .name = "zig-nostr",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    });
    lib.linkSystemLibrary("c");
    lib.linkSystemLibrary("secp256k1");
    b.installArtifact(lib);

    // module
    const mod = b.createModule(.{ .source_file = .{ .path = "src/mod.zig" } });
    try b.modules.put(b.dupe("zig-nostr"), mod);

    // tests
    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
    });
    tests.linkSystemLibrary("c");
    tests.linkSystemLibrary("secp256k1");

    const run_unit_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
