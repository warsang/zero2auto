import zlib
import csv


filepath = 'bruteforce_dict.txt'
my_hash_dict = dict()
with open(filepath) as fp:
    for line in fp:
        my_escaped_line = line.replace('\n','')
        my_hash_dict[my_escaped_line] = hex(zlib.crc32(my_escaped_line.encode('utf-8')))
        ## I'm doing this as I was missing the A and W versions of some API calls. ex: CreateProcessA etc.
        my_escaped_line_w = f"{my_escaped_line}W"
        my_escaped_line_a = f"{my_escaped_line}A"
        my_hash_dict[my_escaped_line_a] = hex(zlib.crc32(my_escaped_line_a.encode('utf-8')))
        my_hash_dict[my_escaped_line_w] = hex(zlib.crc32(my_escaped_line_w.encode('utf-8')))
csv_file = "Hash_list.csv"
try:
    with open(csv_file, 'w') as csv_file:
        for key, value in my_hash_dict.items():
            csv_file.write(f"{key},{value}\n")
except IOError:
    print("I/O error")
