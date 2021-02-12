#Small script to decrypt and comment our rot13 strings used in LoadLibA+GetProcA
#@warsang
#@category Z2A
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.address import Address
import ghidra.program.model.data.StringDataType as StringDataType

my_string_table = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./="
address_list = [0x00414894,0x004148a4,0x004148b4,0x004148c4,0x004148d4,0x004148f8,0x0041490c]

# helper function to get a Ghidra Address type from https://github.com/HackOvert/GhidraSnippets
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def getStringAtAddr(addr):
    """Get string at an address, if present"""
    data = getDataAt(addr)
    if data is not None:
        dt = data.getDataType()
        if isinstance(dt, StringDataType):
            return str(data)
    return None

def rot13_string(encrypted):
	for pos,char in enumerate(encrypted):
		position = my_string_table.find(char)
		new_char=my_string_table[position+13]
		new_string = encrypted[:pos] + new_char + encrypted[pos+1:]
		encrypted = new_string
	return encrypted

listing = currentProgram.getListing()

for addr in address_list:
	addr1 = getAddress(addr)
	decrypted_string = rot13_string(getStringAtAddr(addr1)[4:-1])
	# Get xrefs we want to comment
	references = getReferencesTo(addr1)
	for ref in references:
		my_ref_addr = ref.getFromAddress()
		codeUnit = listing.getCodeUnitAt(my_ref_addr)
		codeUnit.setComment(codeUnit.PLATE_COMMENT, decrypted_string)
	

