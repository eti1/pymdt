# pymdt
Manipulation of mdt firmware images

# Examples

## Build an elf from a splitted mdt image: 

\#unsplit.py:
	from pymdt import *

	# unsplit the dump into an elf
	ELFFile.from_mdt('dump/modem','build/modem.elf')

$ ls dump/
modem.mdt modem.b01 modem.b02 [etc...]
$ mkdir build
$ ./unsplit.py
$ ls build
modem.elf


## Patch an elf, then split it

\#patch.py
	from pymdt import *

	# load an elf
	elf = ModemFirmware('build/modem.elf')

	# Patch something
	elf.put_data(0x89000000, "BREAKTHEBOOT")

	# Fix the hash segment
	elf.regen()

	# Save the patched elf
	elf.write("build/modem_patched.elf")

	# Save the splitted image
	elf.write_mdt("build/modem")

$ ls build/
modem.elf
$ ./patch.py
$ ls build/
modem.elf modem\_patched.elf modem.mdt modem.b01 modem.b02 [etc...]

