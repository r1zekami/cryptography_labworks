
a = 0xfbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1

hex_str = hex(a)[2:]

byte_data = bytes.fromhex(hex_str)
formatted_string = "" + "".join(f"0x{byte:02x}, " for byte in byte_data)

print(formatted_string)


