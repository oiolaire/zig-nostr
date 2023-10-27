const std = @import("std");
const filter = @import("filter.zig");

pub fn formatReq(flt: filter.Filter, w: std.io.Writer) !void {
    w.writeAll("[\"REQ\",\"_\",");
    flt.serializeToWriter(w);
    w.writeByte(']');
}
