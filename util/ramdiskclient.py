import plistlib
import struct
import socket
from datetime import datetime
from progressbar import ProgressBar, Percentage, Bar, SimpleProgress, ETA
from usbmux import usbmux
from util import sizeof_fmt

kIOAESAcceleratorEncrypt = 0
kIOAESAcceleratorDecrypt = 1
	
kIOAESAcceleratorGIDMask = 0x3E8
kIOAESAcceleratorUIDMask = 0x7D0

	
class DeviceInfo(dict):
	@staticmethod
	def create(dict):
		try:
			assert dict.has_key("dataVolumeUUID")
			filename = "%s.plist" % dict.get("dataVolumeUUID")
			return DeviceInfo(plistlib.readPlist(filename))
		except:
			return DeviceInfo(dict)

	def save(self):
		filename = "%s.plist" % self.get("dataVolumeUUID", "unk")
		plistlib.writePlist(self, filename)

	#stop doing magic stuff
	#def __del__(self):
	#	self.save()

class RamdiskToolClient(object):
	instance = None
	@staticmethod
	def get():
		if not RamdiskToolClient.instance:
			RamdiskToolClient.instance = RamdiskToolClient()
		return RamdiskToolClient.instance
	
	def __init__(self, udid=None, host="localhost", port=1999):
		self.host = host
		self.port = port
		self.device_infos = {}
		self.s = None
		self.connect(udid)
		self.getDeviceInfos()
	
	def close(self):
		if self.s:
			self.s.close()
			self.s = None

	def connect(self, udid=None):
		mux = usbmux.USBMux()
		mux.process(1.0)
		if not mux.devices:
			print "Waiting for iOS device"
			while not mux.devices:
				mux.process(1.0)
		if not mux.devices:
			print "No device found"
			return
		dev = mux.devices[0]
		print "Connecting to device : " + dev.serial
		try:
			self.s = mux.connect(dev, self.port)
		except:
			raise Exception("Connexion to device port %d failed" % self.port)

	def getDeviceInfos(self):
		self.device_infos = self.send_req({"Request":"DeviceInfo"})
		keys = self.grabDeviceKeys()
		if keys:
			self.device_infos.update(keys)
		return DeviceInfo.create(self.device_infos)
	
	def downloadFile(self, path):
		res = self.send_req({"Request": "DownloadFile",
							  "Path": path})
		if type(res) == plistlib._InternalDict and res.has_key("Data"):
			return res["Data"].data

	def getSystemKeyBag(self):
		return self.send_req({"Request":"GetSystemKeyBag"})

	def bruteforceKeyBag(self, KeyBagKeys):
		return self.send_req({"Request":"BruteforceSystemKeyBag",
							"KeyBagKeys": plistlib.Data(KeyBagKeys)})
	
	def getEscrowRecord(self, hostID):
		return self.send_req({"Request":"GetEscrowRecord",
					  "HostID": hostID})
	
	def getPasscodeKey(self, keybagkeys, passcode):
		return self.send_req({"Request":"KeyBagGetPasscodeKey",
					  "KeyBagKeys": plistlib.Data(keybagkeys),
					  "passcode": passcode})
	
	def send_msg(self, dict):
		plist = plistlib.writePlistToString(dict)
		data = struct.pack("<L",len(plist)) + plist
		return self.s.send(data)
	
	def recv_msg(self):
		try:
			l = self.s.recv(4)
			if len(l) != 4:
				return None
			ll = struct.unpack("<L",l)[0]
			data = ""
			l = 0
			while l < ll:
				x = self.s.recv(ll-l)
				if not x:
					return None
				data += x
				l += len(x)
			return plistlib.readPlistFromString(data)
		except:
			raise
			return None

	def send_req(self, dict):
		start = None
		self.send_msg(dict)
		while True:
			r = self.recv_msg()
			if type(r) == plistlib._InternalDict and r.get("MessageType") == "Progress":
				if not start:
					pbar = ProgressBar(r.get("Total",100),[SimpleProgress(), " ", ETA(), "\n", Percentage(), " ", Bar()])
					pbar.start()
					start = datetime.utcnow()
				pbar.update( r.get("Progress", 0))
			else:
				if start:
					pbar.finish()
					print dict.get("Request"), ":", datetime.utcnow() - start
				return r

	def aesUID(self, data):
		return self.aes(data, kIOAESAcceleratorUIDMask, kIOAESAcceleratorEncrypt)
	
	def aesGID(self, data):
		return self.aes(data, kIOAESAcceleratorGIDMask, kIOAESAcceleratorDecrypt)
	
	def aes(self, data, keyMask, mode):
		return self.send_req({"Request":"AES",
							"input": plistlib.Data(data),
							"keyMask": keyMask,
							"mode": mode,
							"bits": 128
							})

	def grabDeviceKeys(self):
		blobs = {"key835": "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
				"key899": "\xD1\xE8\xFC\xB5\x39\x37\xBF\x8D\xEF\xC7\x4C\xD1\xD0\xF1\xD4\xB0",
				"key89A": "\xDB\x1F\x5B\x33\x60\x6C\x5F\x1C\x19\x34\xAA\x66\x58\x9C\x06\x61",
				"key89B": "\x18\x3E\x99\x67\x6B\xB0\x3C\x54\x6F\xA4\x68\xF5\x1C\x0C\xBD\x49"
		}
		for k,b in blobs.items():
			r = self.aesUID(b)
			if not r or r.returnCode != 0 or not r.has_key("data"):
				print "AES UID error"
				return
			blobs[k] = r.data.data.encode("hex")
		return blobs

	def reboot(self):
		print "Rebooting device"
		return self.send_req({"Request":"Reboot"})