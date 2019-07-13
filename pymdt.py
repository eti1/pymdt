#!/usr/bin/python3
import sys
from struct import unpack, pack
from binascii import hexlify
from hashlib import sha1
from os.path import basename
import os

class PHDR:
	def __init__(self, p_type, p_offset, p_vaddr, p_paddr,
			p_filesz, p_memsz, p_flags, p_align):
		( 	self.p_type,self.p_offset,self.p_vaddr,self.p_paddr,
			self.p_filesz,self.p_memsz,self.p_flags,self.p_align
		) = ( p_type, p_offset, p_vaddr, p_paddr,
			p_filesz, p_memsz, p_flags, p_align )

	@staticmethod
	def unpack(f):
		return PHDR(*unpack("<IIIIIIII", f))

	def pack(self):
		return pack("<IIIIIIII",
			self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
			self.p_filesz, self.p_memsz, self.p_flags, self.p_align
		)

	def __str__(self):
		return ("phdr:type %8x offset %8x vaddr %8x paddr %8x\n"
				+ "     size %8x p_memsz %8x flags %8x align %8x")%(
			self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
			self.p_filesz, self.p_memsz, self.p_flags, self.p_align)

class MIBI:
	def __init__(self, image_id, vsn_num, image_src, image_dst, 
			image_size, code_size, signature_ptr, signature_size,
			cert_chain_ptr, cert_chain_size):
		(self.image_id,self.vsn_num, self.image_src, self.image_dst, 
			self.image_size, self.code_size, self.signature_ptr, 
			self.signature_size, self.cert_chain_ptr, self.cert_chain_size
		) = (image_id, vsn_num, image_src, image_dst, 
			image_size, code_size, signature_ptr, signature_size,
			cert_chain_ptr, cert_chain_size)

	@staticmethod
	def unpack(f):
		return MIBI(*unpack("<IIIIIIIIII", f[:40]))

	def pack(self):
		return pack("<IIIIIIIIII",
			self.image_id,self.vsn_num, self.image_src, self.image_dst, 
			self.image_size, self.code_size, self.signature_ptr, 
			self.signature_size, self.cert_chain_ptr, self.cert_chain_size
		)

	def __str__(self):
		return ("MIBI(img_id %8x vsn_num %8x image_src %8x image_dst %8x\n"
			+ "img_sz %8x code_sz %8x sig_ptr %8x sig_sz %8x cert_ptr %8x cert_sz %8x")%(
				self.image_id,self.vsn_num, self.image_src, self.image_dst, 
				self.image_size, self.code_size, self.signature_ptr, 
				self.signature_size, self.cert_chain_ptr, self.cert_chain_size)
				
		
class ELFHDR:
	def __init__(self, e_ident, e_type, e_machine, e_version,
					e_entry, e_phoff, e_shoff, e_flags,
					e_ehsize, e_phentsize, e_phnum, e_shentsize,
					e_shnum, e_shstrndx ):
		(self.e_ident,self.e_type,self.e_machine,self.e_version,
			self.e_entry,self.e_phoff,self.e_shoff,self.e_flags,
			self.e_ehsize,self.e_phentsize,self.e_phnum,self.e_shentsize,
			self.e_shnum,self.e_shstrndx
		) = (e_ident, e_type, e_machine, e_version,
			e_entry, e_phoff, e_shoff, e_flags,
			e_ehsize, e_phentsize, e_phnum, e_shentsize,
			e_shnum, e_shstrndx )

	@staticmethod
	def unpack(f):
		return ELFHDR(*unpack("<16sHHIIIIIHHHHHH",f[:52]))

	def pack(self):
		return pack("<16sHHIIIIIHHHHHH",
			self.e_ident,self.e_type,self.e_machine,self.e_version,
			self.e_entry,self.e_phoff,self.e_shoff,self.e_flags,
			self.e_ehsize,self.e_phentsize,self.e_phnum,self.e_shentsize,
			self.e_shnum,self.e_shstrndx )

	def __str__(self):
		return (("ident %s type %d machine %d version %d entry %x phoff %x shoff %x\n"
			+ "flags %d ehsize %d phentsize %d phnum %d shentsize %d shnum %d shstrndx %d")%(
			self.e_ident.decode()[1:4], self.e_type, self.e_machine, self.e_version,
			self.e_entry, self.e_phoff, self.e_shoff, self.e_flags,
			self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize,
			self.e_shnum, self.e_shstrndx ))

class Segment:
	def __init__(self, h, data):
		self.h = h
		self.data = data

class ELFFile:
	def __init__(self, fn):
		self.contents = open(fn,'rb').read()
		self.h = ELFHDR.unpack(self.contents[:52])
		# support check
		assert(self.h.e_ehsize == 52)
		assert(self.h.e_phentsize == 32)
		assert(self.h.e_shnum == 0)

		prog_hdr = self.h.e_ehsize
		self.seg = []
		for i in range (self.h.e_phnum):
			pidx = prog_hdr + self.h.e_phentsize*i
			phdr = PHDR.unpack(self.contents[pidx:pidx+self.h.e_phentsize])
			pdata = self.load_seg(phdr)
			if phdr.p_filesz:
				assert(phdr.p_filesz == len(pdata))
			self.seg.append(Segment(phdr, pdata))
			#print (phdr)
		assert (not self.check_ssd())


	def check_ssd(self):
		hseg = self.hash_seg()
		mibi = MIBI.unpack(hseg.data[:40])
		hash_seg_sz = self.h.e_phnum * 20 + 40
		exp_h_sz = hash_seg_sz + mibi.signature_size + mibi.cert_chain_size
		if hseg.h.p_filesz > exp_h_sz:
			print ("has ssd (%d > %d)"%(hseg.h.p_filesz, exp_h_sz))
		elif hseg.h.p_filesz == exp_h_sz:
			return False
		else:
			print ("dafuq ssd (%d > %d)"%(hseg.h.p_filesz, exp_h_sz))
			return True

	@staticmethod
	def from_mdt(inf, outf):
		mdt = open('%s.mdt'%inf,'rb').read()
		h = ELFHDR.unpack(mdt[:52])
		of = open(outf,'wb')
		for i in range (h.e_phnum):
			pidx = 52 + 32*i
			phdr = PHDR.unpack(mdt[pidx:pidx+32])
			if (phdr.p_filesz != 0):
				pdata = open('%s.b%02d'%(inf,i),'rb').read()
				of.write(b'\0'*(phdr.p_offset - of.tell()))
				of.write(pdata)
		of.close()

	def load_seg(self, p):
		if p.p_filesz > 0:
			return self.contents[p.p_offset:p.p_offset+p.p_filesz]

	def find_seg(self, addr):
		for i in range(len(self.seg)):
			p = self.seg[i].h
			if p.p_vaddr <= addr <= p.p_vaddr + p.p_filesz:
				return i, addr - p.p_vaddr
				

	def get_data(self, addr, size):
		n, of = self.find_seg(addr)
		return self.seg[n].data[of:of+size]

	def put_data(self, addr, data, force=False):
		n, of = self.find_seg(addr)
		# print ("put data (0x%x) in section %d"%(len(data),n))
		d = self.seg[n].data
		end = len(data) + of
		if force:
			if end > len(d):
				self.append_seg_data(n,b'\x00'*(end-len(d)))
		assert(end <= len(d))
		self.seg[n].data = d[:of] + data + d[of+len(data):]

	def get_dw(self, addr):
		return unpack("<I", self.get_data(addr, 4))[0]

	def put_dw(self, addr, val):
		self.put_data(addr, pack("<I",val))

	def get_string(self, addr):
		n, of = self.find_seg(addr)
		f = self.seg[n].data
		ofe = f.find(0, of)
		return f[of:ofe].decode()

	def hash_seg(self):
		hseg, = (s for s in self.seg if s.h.p_flags == 0x2200000)
		return hseg

	def gen_hdr(self):
		return self.h.pack()+b''.join(s.h.pack() for s in self.seg)
		
	def gen_hashes(self):
		hdr = self.gen_hdr()
		hb = sha1(hdr).digest()
		for s in self.seg:
			if s.h.p_offset == 0:
				# skip elf segment
				assert(s.data[:52+32*len(self.seg)] == hdr)
				continue
			if s.h.p_flags == 0x2200000 or s.data is None:
				h = b'\0'*20
				# skip hashes
			else:
				h = sha1(s.data).digest()
			hb += h
		return hb

	def dump_h(self, data, n=20):
		for i in range(0, len(data), n):
			print (hexlify(data[i:i+n]).decode())

	def check_hashes(self):
		# find hash seg
		hseg = self.hash_seg()
		hdata = hseg.data[40:40+20*len(self.seg)]
		htest = self.gen_hashes()
		if hdata != htest:
			self.dump_h(hdata)
			print ("--")
			self.dump_h(htest)
		return hdata == htest

	def append_seg_data(self, n, data):
		data = self.seg[n].data + data
		self.seg[n].data = data
		self.seg[n].h.p_filesz = len(data)
		ms = self.seg[n].h.p_memsz
		if (ms != 0 and ms < self.seg[n].h.p_filesz):
			raise ValueError( "append_seg_data: ms=0x%x, fs=0x%x"%(
				ms, self.seg[n].h.p_filesz))
		# assert(ms == 0 or ms >= self.seg[n].h.p_filesz)

	def set_seg_data(self, n, data):
		self.seg[n].data = data
		self.seg[n].h.p_filesz = len(data)
		ms = self.seg[n].h.p_memsz
		assert(ms == 0 or ms >= self.seg[n].h.p_filesz)

	def add_seg(self, type_, data, memsz, vaddr, paddr, flags, align=0x1000):
		oe = 0
		# find next offset in file
		for s in self.seg:
			ot = s.h.p_offset + s.h.p_filesz
			if ot > oe:
				oe = ot
		oe = (oe + 0xfff) & 0xfffff000
		print ("add seg at %x"%oe)
		hdr = PHDR(type_, oe, vaddr, paddr, len(data), memsz, flags, align)
		self.seg.append(Segment(hdr, data))

	def regen(self):
		#fix offsets
		of = 0
		for s in self.seg:
			s.h.p_offset = of
			sz = (s.h.p_filesz+0xfff)&0xfffff000
			of += sz
		# fix generated segments size 
		self.seg[0].h.p_filesz = 52 + 32 * len(self.seg)
		self.seg[1].h.p_filesz = 40 + 20*len(self.seg)
		# regen elf
		self.h.e_phnum = len(self.seg)
		self.set_seg_data(0, self.gen_hdr())
		# regen hash segment
		self.set_seg_data(1, (b'\0'*40) + self.gen_hashes())
		# check all fine
		assert(self.check_hashes())

	def __str__(self):
		s = str(self.h)
		s += '\n' + '\n'.join(str(s.h) for s in self.seg)
		return s

	def write_mdt(self, path):
		for i,s in enumerate(self.seg):
			if s.data is not None:
				open("%s.b%02d"%(path,i),"wb").write(s.data)
		open("%s.mdt"%path,"wb").write(self.seg[0].data+self.seg[1].data)

	def write(self, path):
		of = open(path, 'wb')
		for s in self.seg:
			of.write(b'\0'*(s.h.p_offset - of.tell()))
			if s.data is not None:
				of.write(s.data)
		of.close()
        

class ModemFirmware(ELFFile):
	class ModemTask:	
		def __init__(self, modem, addr):
			self.modem = modem
			self.addr = addr
			(self.name, self.entry, self.pri, self.obj,
			self.stack_size, self.stack_ptr, self.cpu
			) = unpack("<IIIIIII", modem.get_data(addr, 28))
			self.typ, self.rex = unpack("<II", modem.get_data(self.obj,8))

		def __str__(self):
			def pad (s,n):
				d = n-len(s)
				if d > 0: s += d*" "
				return s
			return ("@%08x |%2d | %s | entry %8x pri %4x stack_sz %5d cpu %x"%(
				self.addr, self.typ, pad(self.modem.get_string(self.name),20),
				self.entry, self.pri, self.stack_size, self.cpu ))

