# WDOSX Executable File unpacker
#
# Author: Daniel Burian
#
# Description:
# This module can unpack files packed with WDOSX.
#
# example usage:
# python WDOSXUnpacker.py TARGET.EXE OUTFOLDER
#
# License: unlicense (see unlicense.org)
#
# Known possible bug:
# It seems that sometimes invalid virtual filesizes are used.
# For example in one analyzed exe file, pmirq.wdl has
# virtual size 0xc400, but the unpacking algorithm isn't
# finished when reaching this point, resulting in an
# index out of bounds exception. Since I don't know the real
# filesize and it might be correct behavior, for now unpacking
# just stops at 0xc400, the file is written to disk and
# a warning message is printed.

import sys
import json
from array import array
import math

DEBUG = False

def log(txt):
	if (DEBUG):
		print txt

def parseArgs():
	# check args
	if (len(sys.argv) != 3):
		print "usage: python %s exe unpack_destination_folder" % (sys.argv[0])
		sys.exit(0)
	
	# read exe file
	exeFilePath = sys.argv[1]
	with open(exeFilePath,"r") as f:
		exeFile = f.read()

	outPath = sys.argv[2]

	return exeFile, outPath

def validateExeFile(exeFile):
	# check executable header
	if (exeFile[:2] != "MZ"):
		print("Error: not an executable file")
		sys.exit(1)

	# check TIPPACH signature
	if (exeFile[0x19:0x20] != "TIPPACH"):
		print("Error: TIPPACH signature not found!")
		sys.exit(1)

def strToInt(string):
	string = string + "\x00"*(4-len(string))
	return (ord(string[3])<<24) + (ord(string[2])<<16) + (ord(string[1])<<8) + ord(string[0])

# parse zero delimited string
def parseString(src, offset):
	if ("\x00" in src[offset:]):
		return src[offset:src.index("\x00",offset)]
	return src[offset:]

def strToHex(s):
	return ":".join("{:02x}".format(ord(c)) for c in s)

# this algorithm looks ugly because it was reversed from assembly
class WfseUnpacker():
	srcBuf = None
	srcIndex = 0
	dstBuf = None
	dstIndex = 0
	tagBits = 0x80
	dh = 0x80
	wbp = 0

	def __init__(self, wfseInfo):
		self.wfseInfo = wfseInfo
		self.srcBuf = array('B', wfseInfo["packedContent"])
		self.dstBuf = array('B', "\x00"*wfseInfo["VirtualSize"])

	# left shift one byte
	def shiftLeft(self, byte, shiftInBit=0):
		byte = (byte<<1) + shiftInBit
		carry = byte>>8
		byte = byte&0xFF
		return byte, carry

	# left shift two bytes
	def shiftLeftDW(self, dw, shiftInBit=0):
		lower = dw & 0xFF
		upper = dw>>8
		lower, carry = self.shiftLeft(lower, shiftInBit)
		upper, carry = self.shiftLeft(upper, carry)
		dw = (upper<<8) + lower
		return dw, carry

	# read tagbits
	def getBit(self):
		# get msb
		self.tagBits, nextBit = self.shiftLeft(self.tagBits)

		if (self.tagBits == 0):
			# get next byte
			self.tagBits = self.srcBuf[self.srcIndex]
			self.srcIndex += 1

			# previous msb becomes new lsb, shift out loaded msb
			self.tagBits, nextBit = self.shiftLeft(self.tagBits, nextBit)

		return nextBit

	# main unpack function.
	def unpack(self):
		try:
			# algo always unpacks 0x1000 Bytes at a time (one page)
			numPages = int(math.ceil(float(len(self.dstBuf)) / 0x1000))

			for i in range(numPages):
				self.tagBits = 0x80
				self.mainLoop()

		except Exception as e:
			print \
			"""
			\rdecompression error, file was extracted but might be damaged.
			\rdebug information:
			\r	file: %s
			\r	dstIndex: 0x%x
			\r	fileSize: 0x%x
			\r	srcIndex: 0x%x
			\r	srcSize: 0x%x
			""" % (self.wfseInfo["FileName"], self.dstIndex, len(self.dstBuf), self.srcIndex, len(self.srcBuf))

		self.wfseInfo["unpackedContent"] = bytearray(self.dstBuf)

	# copies one byte from input buffer to output buffer
	def copyLiteral(self):
		self.dstBuf[self.dstIndex] = self.srcBuf[self.srcIndex]
		log("copied literal %02x" % self.dstBuf[self.dstIndex])
		self.dstIndex += 1
		self.srcIndex += 1
		self.dh = 0x80

	# copies a given range from dstBuf to dstBuf at current offset
	def inflate(self):
		# dstIndexOffset:
		# 	holds the offset into dstBuf where
		# 	bytes will be copied from.
		#
		# numBytesToCopy:
		#	number of bytes to copy to current position in dstBuf


		self.numBytesToCopy = self.readNumber(1)
		self.dstIndexOffset = self.readNumber(1)

		log("numBytesToCopy: %x" % self.numBytesToCopy)
		log("dstIndexOffset: %x" % self.dstIndexOffset)
		
		# shift out msb from dh
		self.dh, cf = self.shiftLeft(self.dh)

		# compute dstIndexOffset
		# don't ask, I just translated asm magic
		self.dstIndexOffset = self.dstIndexOffset - 2 - cf
		log("dstIndexOffset after sbb: %d" % self.dstIndexOffset)
		if (self.dstIndexOffset>=0):
			self.dstIndexOffset = self.dstIndexOffset | 0x400
			log("dstIndexOffset after or: %d" % self.dstIndexOffset)
			while(True):
				# shift in tagBits until a 1 is shifted out
				self.dstIndexOffset, cf = self.shiftLeftDW(self.dstIndexOffset, self.getBit())
				log("in loop: 0x%x" % self.dstIndexOffset)
				if (cf == 1):
					break
			log("exited while loop, dstIndexOffset: %d" % self.dstIndexOffset)
			self.dstIndexOffset += 1
			if (self.dstIndexOffset >= 0x781):
				self.numBytesToCopy += 1
			log("set numBytesToCopy to %d" % self.numBytesToCopy)

			self.wbp = self.dstIndexOffset
			log("set wbp to %d" % self.dstIndexOffset)

		# copy bytes
		self.dstIndexOffset = self.wbp
		copyFromIndex = self.dstIndex-self.dstIndexOffset
		for i in range(self.numBytesToCopy):
			self.dstBuf[self.dstIndex] = self.dstBuf[copyFromIndex]
			log("copied %02x" % self.dstBuf[self.dstIndex])
			self.dstIndex += 1
			copyFromIndex += 1

		log("inflation done.")

	# main algorithm loop for 0x1000 byte blocks
	def mainLoop(self):
		startAtDstIndex = self.dstIndex
		doCopyLiteral = True
		while(True):
			if (doCopyLiteral):
				self.copyLiteral()

			# end reached (asm decompDone)
			positionInPage = (self.dstIndex - startAtDstIndex)
			endOfPageReached = positionInPage >= 0x1000
			endOfFileReached = self.srcIndex >= len(self.srcBuf)
			if (endOfPageReached or endOfFileReached):
				return self.dstBuf

			# tag bit chooses whether to loop to copy literal or inflate dstBuf
			doCopyLiteral = self.getBit() == 0
			if (not doCopyLiteral):
				self.inflate()
	
	# read number parameter from tagbits		
	def readNumber(self, startValue):
		startValue = startValue*2 + self.getBit()
		if (self.getBit() == 1):
			return self.readNumber(startValue)
		else:
			return startValue

def parseWdxInfo(exeFile, offset=0x20):
	# Format:
	# 4B Signature
	# 2B Revision
	# 1B Flags
	# 1B StubClass
	# 4B XMemReserve
	# 4B XMemAlloc
	# 4B Wfse Start

	# check length
	if (len(exeFile) - offset < 20):
		raise Exception("invalid wdxInfo: too short!")

	wdxInfo = {
		"Signature": exeFile[offset:offset+4],
		"Revision": strToInt(exeFile[offset+4:offset+6]),
		"Flags": strToHex(exeFile[offset+6:offset+7]),
		"StubClass": strToHex(exeFile[offset+7:offset+8]),
		"XMemReserve": strToHex(exeFile[offset+8:offset+12]),
		"XMemAlloc": strToHex(exeFile[offset+12:offset+16]),
		"WfseStart": strToInt(exeFile[offset+16:offset+20])
	}

	# check signature
	if (wdxInfo["Signature"] != "$WdX"):
		raise Exception("Error parsing WdxInfo: invalid signature!")

	return wdxInfo

def parseWfseInfo(src, offset):
	# Format:
	# 4B Signature "WFSE"
	# 4B Size
	# 4B VirtualSize
	# 4B Flags
	# 1-255B FileName
	# ?B uiHeader
	# ?B packedContent

	# check length
	if (len(src) < 17):
		raise Exception("Error parsing wfseInfo: too short!")

	wfseInfo = {
		"offsetInFile": offset,
		"Signature": src[offset:offset+4],
		"Size": strToInt(src[offset+4:offset+8]),
		"VirtualSize": strToInt(src[offset+8:offset+12]),
		"Flags": strToHex(src[offset+12:offset+16]),
		"FileName": parseString(src,offset+16)
	}

	if (wfseInfo["Signature"] != "WFSE"):
		raise Exception("Error parsing wfseInfo: invalid signature")

	# handle wfse content
	wfseInfo["uiHeaderSize"] = ((wfseInfo["VirtualSize"] + 0xFFF) / 0x1000 * 4) + 6;

	startOfPackedContent = wfseInfo["offsetInFile"] + 16 + len(wfseInfo["FileName"]) + 1 + wfseInfo["uiHeaderSize"]
	endOfPackedContent = wfseInfo["offsetInFile"] + wfseInfo["Size"]
	wfseInfo["packedContent"] = src[startOfPackedContent:endOfPackedContent]

	return wfseInfo

def getAllWfseInfo(exeFile, wdxInfo):
	wfseInfoList = []

	offset = wdxInfo["WfseStart"]
	while(offset < len(exeFile)):

		wfseInfo = parseWfseInfo(exeFile, offset)

		wfseInfoList += [wfseInfo]

		offset += wfseInfo["Size"]

	return wfseInfoList

if __name__ == '__main__':
	
	exeFile, outPath = parseArgs()

	validateExeFile(exeFile)

	wdxInfo = parseWdxInfo(exeFile)

	wfseInfoList = getAllWfseInfo(exeFile, wdxInfo)

	for wfseInfo in wfseInfoList:
		d = WfseUnpacker(wfseInfo)
		d.unpack()
		
		# write to file in output folder
		filePath = outPath + "/" + wfseInfo["FileName"]
		with open(filePath,"w") as f:
			f.write(wfseInfo["unpackedContent"])

		print "extracted %s (%dB)." % (filePath, wfseInfo["VirtualSize"])
