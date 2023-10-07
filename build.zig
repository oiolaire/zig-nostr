const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // library
    const lib = b.addStaticLibrary(.{
        .name = "zig-nostr",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    // dependencies
    const ws = b.dependency("ws", .{
        .target = target,
        .optimize = optimize,
    });

    // install
    b.installArtifact(lib);

    // module
    const mod = b.createModule(.{ .source_file = .{ .path = "src/mod.zig" } });
    try b.modules.put(b.dupe("zig-nostr"), mod);

    // tests
    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    // "zig build test" command
    const run_unit_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // add dependencies to everybody
    inline for ([_]*std.build.Step.Compile{ tests, lib }) |pkg| {
        pkg.linkSystemLibrary("c");
        pkg.linkSystemLibrary("secp256k1");
        pkg.addModule("ws", ws.module("ws"));
    }
}
