//! Lightweight marker types for the small subset of the D-Bus type system
//! we use to talk to the Secret Service. Slices borrow from the caller's
//! buffer; nothing owns memory here.

/// D-Bus type code `o`. A bus-validated object path (e.g. `/org/freedesktop/secrets`).
pub const ObjectPath = struct {
    value: []const u8,
};

/// D-Bus type code `g`. A signature string (e.g. `a{sv}`).
pub const Signature = struct {
    value: []const u8,
};

/// D-Bus type code `v`. The wire format is a signature byte+bytes
/// followed by a value whose type is described by that signature.
/// `body` is the raw, already-marshalled bytes of the inner value,
/// at the correct alignment for the start of the variant in the
/// enclosing message.
pub const Variant = struct {
    signature: []const u8,
    body: []const u8,
};

/// A Secret Service secret: `(oayays)` — (session path, params, value, content type).
pub const Secret = struct {
    session: []const u8,
    parameters: []const u8,
    value: []const u8,
    content_type: []const u8,
};
