const std = @import("std");
const clap = @import("clap");
const sx = @import("sx");
const xml = @import("xml.zig");
const svd = @import("svd.zig");
const Database = @import("Database.zig");

const ArenaAllocator = std.heap.ArenaAllocator;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const log_level: std.log.Level = .info;

const svd_schema = @embedFile("cmsis-svd.xsd");

const params = clap.parseParamsComptime(
    \\-h, --help                Display this help and exit
    \\-s, --schema <str>        Explicitly set schema type, one of: svd, atdf, json
    \\-x, --overrides <str>     Specify the path to a file containing register/field type overrides
    \\-o, --output_path <str>   Write to a file
    \\<str>...
    \\
);

pub fn main() !void {
    mainImpl() catch |err| switch (err) {
        error.Explained => std.process.exit(1),
        else => return err,
    };
}

const Schema = enum {
    atdf,
    dslite,
    json,
    svd,
    xml,
};

fn mainImpl() anyerror!void {
    defer xml.cleanupParser();

    var gpa = std.heap.GeneralPurposeAllocator(.{
        .stack_trace_frames = 20,
    }){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var arena = ArenaAllocator.init(allocator);
    defer arena.deinit();

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
    }) catch |err| {
        // Report useful error and exit
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return error.Explained;
    };
    defer res.deinit();

    if (res.args.help)
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});

    var schema: ?Schema = if (res.args.schema) |schema_str|
        if (std.meta.stringToEnum(Schema, schema_str)) |s| s else {
            std.log.err(
                "Unknown schema type: {s}, must be one of: svd, atdf, json",
                .{
                    schema_str,
                },
            );
            return error.Explained;
        }
    else
        null;

    var db = switch (res.positionals.len) {
        0 => blk: {
            if (schema == null) {
                std.log.err("schema must be chosen when reading from stdin", .{});
                return error.Explained;
            }

            if (schema.? == .json) {
                return error.Todo;
            }

            var stdin = std.io.getStdIn().reader();
            const doc: *xml.Doc = xml.readIo(readFn, null, &stdin, null, null, 0) orelse return error.ReadXmlFd;
            defer xml.freeDoc(doc);

            break :blk try parseXmlDatabase(allocator, doc, schema.?);
        },
        1 => blk: {
            // if schema is null, then try to determine using file extension
            if (schema == null) {
                const ext = std.fs.path.extension(res.positionals[0]);
                if (ext.len > 0) {
                    schema = std.meta.stringToEnum(Schema, ext[1..]) orelse {
                        std.log.err("unable to determine schema from file extension of '{s}'", .{res.positionals[0]});
                        return error.Explained;
                    };
                }
            }

            // schema is guaranteed to be non-null from this point on
            if (schema.? == .json) {
                return error.Todo;
            }

            // all other schema types are xml based
            const doc: *xml.Doc = xml.readFile(res.positionals[0].ptr, null, 0) orelse return error.ReadXmlFile;
            defer xml.freeDoc(doc);

            break :blk try parseXmlDatabase(allocator, doc, schema.?);
        },
        else => {
            std.log.err("this program takes max one positional argument for now", .{});
            return error.Explained;
        },
    };
    defer db.deinit();

    if (res.args.overrides) |overrides_path| {
        var temp_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer temp_arena.deinit();

        var f = try std.fs.cwd().openFile(overrides_path, .{});
        defer f.close();

        var reader = sx.reader(temp_arena.allocator(), f.reader());
        defer reader.deinit();

        parseOverrides(temp_arena.allocator(), &reader, &db) catch |e| {
            if (e == error.SExpressionSyntaxError) {
                var stderr = std.io.getStdErr().writer();
                try stderr.writeAll("Syntax error in type overrides file:\n");
                var ctx = try reader.getNextTokenContext();
                try ctx.printForFile(&f, stderr, 80);
            }
            return e;
        };

    }

    const writer = if (res.args.output_path) |output_path|
        if (std.fs.path.isAbsolute(output_path)) writer: {
            if (std.fs.path.dirname(output_path)) |dirname| {
                _ = dirname;
                // TODO: recursively create absolute path if it doesn't exist
            }

            break :writer (try std.fs.createFileAbsolute(output_path, .{})).writer();
        } else writer: {
            if (std.fs.path.dirname(output_path)) |dirname|
                try std.fs.cwd().makePath(dirname);

            break :writer (try std.fs.cwd().createFile(output_path, .{})).writer();
        }
    else
        std.io.getStdOut().writer();

    try db.toZig(writer);
}

fn readFn(ctx: ?*anyopaque, buffer: ?[*]u8, len: c_int) callconv(.C) c_int {
    if (buffer == null)
        return -1;

    return if (ctx) |c| blk: {
        const reader = @ptrCast(*std.fs.File.Reader, @alignCast(@alignOf(*std.fs.File.Reader), c));
        const n = reader.read(buffer.?[0..@intCast(usize, len)]) catch return -1;
        break :blk @intCast(c_int, n);
    } else -1;
}

fn parseXmlDatabase(allocator: Allocator, doc: *xml.Doc, schema: Schema) !Database {
    return switch (schema) {
        .json => unreachable,
        .atdf => try Database.initFromAtdf(allocator, doc),
        .svd => try Database.initFromSvd(allocator, doc),
        .dslite => return error.Todo,
        .xml => determine_type: {
            const root_element: *xml.Node = xml.docGetRootElement(doc) orelse return error.NoRoot;
            if (xml.findValueForKey(root_element, "device") != null)
                break :determine_type try Database.initFromSvd(allocator, doc)
            else if (xml.findValueForKey(root_element, "avr-tools-device-file") != null)
                break :determine_type try Database.initFromAtdf(allocator, doc)
            else {
                std.log.err("unable do detect register schema type", .{});
                return error.Explained;
            }
        },
    };
}

fn parseOverrides(alloc: std.mem.Allocator, reader: *sx.Reader(std.fs.File.Reader), db: *Database) !void {
    db.device.?.rt_import = try db.arena.allocator().dupe(u8, try reader.requireAnyExpression());

    var peripheral_name = std.ArrayList(u8).init(alloc);
    var register_name = std.ArrayList(u8).init(alloc);
    var field_name = std.ArrayList(u8).init(alloc);

    while (try reader.anyExpression()) |temp_peripheral_name| {
        peripheral_name.clearRetainingCapacity();
        try peripheral_name.appendSlice(temp_peripheral_name);
        while (try reader.anyExpression()) |temp_register_name| {
            register_name.clearRetainingCapacity();
            try register_name.appendSlice(temp_register_name);
            if (try reader.anyString()) |register_type_override| {
                try addRegisterTypeOverride(db,
                    peripheral_name.items,
                    register_name.items,
                    register_type_override
                );
            } else while (try reader.anyExpression()) |temp_field_name| {
                field_name.clearRetainingCapacity();
                try field_name.appendSlice(temp_field_name);
                const field_type_override = try reader.requireAnyString();
                try addFieldTypeOverride(db,
                    peripheral_name.items,
                    register_name.items,
                    field_name.items,
                    field_type_override
                );
                try reader.requireClose();
            }
            try reader.requireClose();
        }
        try reader.requireClose();
    }

    try reader.requireClose();
    try reader.requireDone();
}

fn addRegisterTypeOverride(db: *Database, peripheral_spec: []const u8, register_spec: []const u8, type_spec: []const u8) !void {
    var simple_type_name = std.mem.indexOfAny(u8, type_spec, "/%@") == null;
    const final_type_spec = if (simple_type_name) try db.arena.allocator().dupe(u8, type_spec) else type_spec;

    for (db.peripherals.items) |peripheral, i| {
        const peripheral_matches = if (std.mem.endsWith(u8, peripheral_spec, "*"))
            std.mem.startsWith(u8, peripheral.name, peripheral_spec[0..peripheral_spec.len-1])
        else
            std.mem.eql(u8, peripheral.name, peripheral_spec)
        ;
        if (!peripheral_matches) continue;

        const peripheral_idx = @intCast(Database.PeripheralIndex, i);

        if (db.registers_in_peripherals.get(peripheral_idx)) |reg_range| {
            const registers = db.registers.items[reg_range.begin..reg_range.end];
            for (registers) |_, range_offset| {
                const reg_idx = @intCast(Database.RegisterIndex, reg_range.begin + range_offset);
                try addRegisterTypeOverrideForRegister(db, peripheral.name, reg_idx, register_spec, final_type_spec, simple_type_name);
            }
        }

        for (db.clusters_in_peripherals.items) |cip| {
            if (cip.peripheral_idx == peripheral_idx) {
                if (db.registers_in_clusters.get(cip.cluster_idx)) |range| {
                    const registers = db.registers.items[range.begin..range.end];
                    for (registers) |_, offset| {
                        const reg_idx = @intCast(Database.RegisterIndex, range.begin + offset);
                        try addRegisterTypeOverrideForRegister(db, peripheral.name, reg_idx, register_spec, final_type_spec, simple_type_name);
                    }
                }
            }
        }
    }
}

fn addRegisterTypeOverrideForRegister(db: *Database, peripheral: []const u8, reg_idx: Database.RegisterIndex, register_spec: []const u8, type_spec: []const u8, simple_type_name: bool) !void {
    const register = &db.registers.items[reg_idx];
    const register_matches = if (std.mem.endsWith(u8, register_spec, "*"))
        std.mem.startsWith(u8, register.name, register_spec[0..register_spec.len-1])
    else
        std.mem.eql(u8, register.name, register_spec)
    ;
    if (!register_matches) return;

    if (simple_type_name) {
        register.type_override = type_spec;
    } else {
        var type_len = type_spec.len;
        for (type_spec) |c| {
            switch (c) {
                '%' => type_len += register.name.len - 1,
                '@' => type_len += peripheral.len - 1,
                else => {},
            }
        }
        var type_name = try std.ArrayList(u8).initCapacity(db.arena.allocator(), type_len);
        var lowercase = false;
        for (type_spec) |c| {
            const text = switch (c) {
                '%' => register.name,
                '@' => peripheral,
                '/' => {
                    lowercase = !lowercase;
                    continue;
                },
                else => {
                    try type_name.append(c);
                    continue;
                },
            };
            if (lowercase) {
                for (text) |tc| {
                    try type_name.append(std.ascii.toLower(tc));
                }
            } else {
                try type_name.appendSlice(text);
            }
        }
        register.type_override = type_name.items;
    }
}

fn addFieldTypeOverride(db: *Database, peripheral_spec: []const u8, register_spec: []const u8, field_spec: []const u8, type_spec: []const u8) !void {
    var simple_type_name = std.mem.indexOfAny(u8, type_spec, "/$%@") == null;
    const final_type_spec = if (simple_type_name) try db.arena.allocator().dupe(u8, type_spec) else type_spec;

    for (db.peripherals.items) |peripheral, i| {
        const peripheral_matches = if (std.mem.endsWith(u8, peripheral_spec, "*"))
            std.mem.startsWith(u8, peripheral.name, peripheral_spec[0..peripheral_spec.len-1])
        else
            std.mem.eql(u8, peripheral.name, peripheral_spec)
        ;
        if (!peripheral_matches) continue;

        const peripheral_idx = @intCast(Database.PeripheralIndex, i);

        if (db.registers_in_peripherals.get(peripheral_idx)) |reg_range| {
            const registers = db.registers.items[reg_range.begin..reg_range.end];
            for (registers) |_, range_offset| {
                const reg_idx = @intCast(Database.RegisterIndex, reg_range.begin + range_offset);
                try addFieldTypeOverrideForRegister(db, peripheral.name, reg_idx, register_spec, field_spec, final_type_spec, simple_type_name);
            }
        }

        for (db.clusters_in_peripherals.items) |cip| {
            if (cip.peripheral_idx == peripheral_idx) {
                if (db.registers_in_clusters.get(cip.cluster_idx)) |range| {
                    const registers = db.registers.items[range.begin..range.end];
                    for (registers) |_, offset| {
                        const reg_idx = @intCast(Database.RegisterIndex, range.begin + offset);
                        try addFieldTypeOverrideForRegister(db, peripheral.name, reg_idx, register_spec, field_spec, final_type_spec, simple_type_name);
                    }
                }
            }
        }
    }
}

fn addFieldTypeOverrideForRegister(db: *Database, peripheral: []const u8, reg_idx: Database.RegisterIndex, register_spec: []const u8, field_spec: []const u8, type_spec: []const u8, simple_type_name: bool) !void {
    const register = &db.registers.items[reg_idx];
    const register_matches = if (std.mem.endsWith(u8, register_spec, "*"))
        std.mem.startsWith(u8, register.name, register_spec[0..register_spec.len-1])
    else
        std.mem.eql(u8, register.name, register_spec)
    ;
    if (!register_matches) return;

    if (db.fields_in_registers.get(reg_idx)) |range| {
        const fields = db.fields.items[range.begin..range.end];
        for (fields) |*field| {
            const field_matches = if (std.mem.endsWith(u8, field_spec, "*"))
                std.mem.startsWith(u8, field.name, field_spec[0..field_spec.len-1])
            else
                std.mem.eql(u8, field.name, field_spec)
            ;
            if (!field_matches) continue;

            if (simple_type_name) {
                field.type_override = type_spec;
            } else {
                var type_len = type_spec.len;
                for (type_spec) |c| {
                    switch (c) {
                        '$' => type_len += field.name.len - 1,
                        '%' => type_len += register.name.len - 1,
                        '@' => type_len += peripheral.len - 1,
                        else => {},
                    }
                }
                var type_name = try std.ArrayList(u8).initCapacity(db.arena.allocator(), type_len);
                var lowercase = false;
                for (type_spec) |c| {
                    const text = switch (c) {
                        '$' => field.name,
                        '%' => register.name,
                        '@' => peripheral,
                        '/' => {
                            lowercase = !lowercase;
                            continue;
                        },
                        else => {
                            try type_name.append(c);
                            continue;
                        },
                    };
                    if (lowercase) {
                        for (text) |tc| {
                            try type_name.append(std.ascii.toLower(tc));
                        }
                    } else {
                        try type_name.appendSlice(text);
                    }
                }
                field.type_override = type_name.items;
            }
        }
    }
}
