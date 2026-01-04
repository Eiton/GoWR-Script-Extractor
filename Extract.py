import lz4.frame
import io
import os

def decompress_to_memory(input_file):
    with open(input_file, 'rb') as f_in:
        compressed_data = f_in.read()
        decompressed_data = lz4.frame.decompress(compressed_data)

    # Wrap in BytesIO for file-like access in memory
    return io.BytesIO(decompressed_data)
    
def read_null_terminated_string(binary_stream, encoding="ascii"):
    byte_array = bytearray()
    while True:
        byte = binary_stream.read(1)  # Read one byte at a time
        if not byte:
            # End of file reached before null terminator
            break
        # Replace strange things with space
        if byte > b'\x7E':
            byte = b'\x20'
        if byte == b'\x00':
            # Null terminator found
            break
        byte_array.extend(byte)
    
    try:
        return byte_array.decode(encoding)
    except UnicodeDecodeError:
        print(byte_array)
        raise ValueError("Invalid byte sequence for encoding: " + encoding)
        
def extract_lua_from_wad(input_path):
    output_path = "./extract/"
    data = decompress_to_memory(input_path)
    data.seek(0x8)
    numFiles = int.from_bytes(data.read(4), byteorder='little')
    base = 0x40+0x90*numFiles
    data.seek(base)
    files = data.read()
    padding = 0
    for i in range(numFiles):
        data.seek(0x40+0x90*i)
        fType = int.from_bytes(data.read(1), byteorder='little')
        data.seek(3,1)
        size = int.from_bytes(data.read(4), byteorder='little')
        tmp = data.tell()
        data.seek(16,1)
        name = read_null_terminated_string(data)
        data.seek(tmp+112)
        offset = int.from_bytes(data.read(4), byteorder='little')
        if fType == 0x24:
            data.seek(base+offset+padding+0x204)
            signature = data.read(5)
            if signature != b'\x1bLuaR':
                offset1 = files.find(name.encode('ascii'))
                data.seek(base+offset1+files[offset1:].find(b'\x1bLuaR')-0x204)
                padding = data.tell() - base - offset
            else:
                data.seek(base+offset+padding)
            outFilePath = output_path+read_null_terminated_string(data)[3:]
            data.seek(base+offset+padding+0x204)
            luaBinary = data.read(size-0x204)
            os.makedirs(os.path.dirname(outFilePath), exist_ok=True)
            with open(outFilePath, "wb") as file:
                file.write(luaBinary)
            print("Extract lua file "+outFilePath)
        elif fType == 0x19:
            padding += size
            
directory_path = './exec/wad/pc_le'

for root, dirs, files in os.walk(directory_path):
    for filename in files:
        if filename[-3:] == "wad":
            file_path = os.path.join(root, filename)
            print("Searching "+file_path)
            extract_lua_from_wad(file_path)
