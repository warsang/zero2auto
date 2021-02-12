#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

import csv
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit



symbolTable = currentProgram.getSymbolTable()
string_hash = dict()
with open('C:\Users\Administrator\Desktop\Malware\custom_sample1\Hash_list.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    for row in csv_reader:
        string_hash[row[1]] = row[0]

for symbol in symbolTable.getAllSymbols(False):
	func = getFunctionAt(symbol.getAddress())
	if func == None or func.getProgram() == None:
		continue
	iter = func.getProgram().getListing().getCodeUnits(func.getBody(), True)
	skip = 0
	for i in iter:
		if skip<=0 and (i.getScalar(1) or i.getScalar(0)):
			if 'MOV E' in i.toString():
				#print(i.toString().split(',')[1])
				my_hash = i.toString().split(',')[1]
				if my_hash in string_hash:
					print(string_hash[my_hash])
					i.setComment(i.REPEATABLE_COMMENT, string_hash[my_hash])
		skip -= 1

