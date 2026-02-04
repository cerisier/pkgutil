const std = @import("std");

pub fn main() !void {
	var gpa = std.heap.GeneralPurposeAllocator(.{}){};
	defer _ = gpa.deinit();

	const allocator = gpa.allocator();
	const args = try std.process.argsAlloc(allocator);
	defer std.process.argsFree(allocator, args);

	if (args.len < 3) {
		return usage();
	}

	const mode = args[1];
	const expect_exists = if (std.mem.eql(u8, mode, "-e"))
		true
	else if (std.mem.eql(u8, mode, "-ne"))
		false
	else {
		return usage();
	};

	var ok = true;

	var i: usize = 2;
	while (i < args.len) : (i += 1) {
		const path = args[i];
		const exists = pathExists(path);

		if (expect_exists and !exists) {
			ok = false;
			eprint("missing: {s}\n", .{path});
		} else if (!expect_exists and exists) {
			ok = false;
			eprint("unexpected: {s}\n", .{path});
		}
	}

	if (!ok) {
		std.process.exit(1);
	}
}

fn pathExists(path: []const u8) bool {
	if (std.fs.cwd().access(path, .{})) |_| {
		return true;
	} else |err| {
		if (err == error.FileNotFound) {
			return false;
		}

		eprint("error accessing {s}: {s}\n", .{ path, @errorName(err) });
		return false;
	}
}

fn usage() void {
	eprint("usage: test.zig (-e|-ne) <path> [path...]\n", .{});
	std.process.exit(2);
}

fn eprint(comptime fmt: []const u8, args: anytype) void {
	std.debug.print(fmt, args);
}
