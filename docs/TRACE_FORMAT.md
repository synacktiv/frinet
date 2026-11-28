# Trace format

A trace file (`.trace`) starts with a text header (UTF-8), followed by a binary stream of events.

## Header

One item per line (the binary stream starts right after `end\n`):

```
FRINET-TRACE 1\n
reg rip 8\n
reg rax 8\n
...
module ls 0x5555555a0000 0x5555555c4000\n
module libc.so.6 0x7ffff7c00000 0x7ffff7e05000\n
...
end\n
<binary stream>
```

| Line                                | Description                                                                                                           |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `FRINET-TRACE 1\n`                  | Magic and format version, must be the first line                                                                      |
| `reg <name> <byte_size>\n`          | A register and its size in bytes (`byte_size` power of two, at most 64), up to 240 registers. The first one is the PC |
| `module <name> 0x<start> 0x<end>\n` | A module loaded in the process at `start..end` (`end` excluded), the name has no space                                |
| `end\n`                             | End of the header                                                                                                     |

## Events

Each event is a 1 byte tag followed by its payload. Integers are little-endian and unaligned.
The time starts at 0 and is incremented by each `step` event.

| Tag           | Event                               | Payload                                                          |
| ------------- | ----------------------------------- | ---------------------------------------------------------------- |
| `0x00`        | Step (end of the instruction)       | none                                                             |
| `0x01`        | Memory read                         | address (`u64`), length (`u16`, non zero), data (`length` bytes) |
| `0x02`        | Memory write                        | same as memory read                                              |
| `0x03`        | Memory read-write                   | same as memory read                                              |
| `0x04`-`0x0F` | Reserved                            |                                                                  |
| `0x10 + i`    | Write of the `i`-th header register | value (`byte_size` bytes)                                        |
