NAME_OF_FILE = "test.bin"

def wr_to_bin(binary_content):
    wr_file = open(binary_content, "wb")
    try:
        wr_file.write(binary_content)
    finally: 
        wr_file.close()
    print(wr_file)

def read_from_bin(filename):
    file = open(filename, "rb")
    file_contents = file.read()
    return file_contents


if __name__ == "__main__":
    binary_content = read_from_bin(NAME_OF_FILE)
    # fix
    wr_to_bin(binary_content)
