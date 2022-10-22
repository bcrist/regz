const std = @import("std");
const Pkg = std.build.Pkg;
const FileSource = std.build.FileSource;

pub const build_pkgs = struct {
    pub const libxml2 = @import(".gyro/zig-libxml2-mitchellh-github.com-47fc435b/pkg/libxml2.zig");
};

pub const pkgs = struct {
    pub const clap = Pkg{
        .name = "clap",
        .source = FileSource{
            .path = ".gyro/zig-clap-Hejsil-github.com-4f4196fc/pkg/clap.zig",
        },
    };

    pub const @"Zig-SX" = Pkg{
        .name = "Zig-SX",
        .source = FileSource{
            .path = ".gyro/Zig-SX-bcrist-github.com-b6fecc5d/pkg/sx.zig",
        },
    };

    pub fn addAllTo(artifact: *std.build.LibExeObjStep) void {
        artifact.addPackage(pkgs.clap);
        artifact.addPackage(pkgs.@"Zig-SX");
    }
};
