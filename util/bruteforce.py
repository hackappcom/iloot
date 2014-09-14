from keystore.keybag import Keybag
from keystore.effaceable import EffaceableLockers
from util.ramdiskclient import RamdiskToolClient
import plistlib

COMPLEXITY={
            0: "4 digits",
            1: "n digits",
            2: "n alphanum"
            }

def checkPasscodeComplexity(data_volume):
    pl = data_volume.readFile("/mobile/Library/ConfigurationProfiles/UserSettings.plist", returnString=True)
    if not pl:
        print "Failed to read UserSettings.plist, assuming simple passcode"
        return 0
    pl = plistlib.readPlistFromString(pl)
    #print "passcodeKeyboardComplexity :", pl["restrictedValue"]["passcodeKeyboardComplexity"]
    value =  pl["restrictedValue"]["passcodeKeyboardComplexity"]["value"]
    print "passcodeKeyboardComplexity %d => %s" % (value, COMPLEXITY.get(value)) 
    return pl["restrictedValue"]["passcodeKeyboardComplexity"]["value"]

def loadKeybagFromVolume(volume, device_infos):
    systembag = volume.readFile("/keybags/systembag.kb", returnString=True)
    if not systembag or not systembag.startswith("bplist"):
        print "FAIL: could not read /keybags/systembag.kb from data partition"
        return False
    lockers = EffaceableLockers(device_infos["lockers"].data)
    bag1key = lockers.get("BAG1")[-32:]
    keybag = Keybag.createWithSystemkbfile(systembag, bag1key, device_infos.get("key835", "").decode("hex"))
    keybag.setDKey(device_infos)
    if device_infos.has_key("passcodeKey"):
        keybag.unlockWithPasscodeKey(device_infos.get("passcodeKey").decode("hex"))
    return keybag

def bruteforcePasscode(device_infos, data_volume):
    if device_infos.has_key("passcode"):
        print "Passcode already found, no bruteforce required"
        return False
    kb = data_volume.keybag
    if not kb:
        return False
    
    rd = RamdiskToolClient.get()
    if rd.device_infos.udid != device_infos.udid:
        print "Wrong device connected"
        return
    
    print "Passcode comlexity (from OpaqueStuff) : %s" % COMPLEXITY.get(kb.passcodeComplexity)
    print "Enter passcode or leave blank for bruteforce:"
    z = raw_input()
    bf = rd.getPasscodeKey(kb.KeyBagKeys, z)
    if kb.unlockWithPasscodeKey(bf.get("passcodeKey").decode("hex")):
        print "Passcode \"%s\" OK" % z
    else:
        if z != "":
            print "Wrong passcode, trying to bruteforce !"
        if kb.passcodeComplexity != 0:
            print "Complex passcode used, not bruteforcing"
            return False

        bf = rd.bruteforceKeyBag(kb.KeyBagKeys)
        if bf and kb.unlockWithPasscodeKey(bf.get("passcodeKey").decode("hex")):
            print "Bruteforce successful, passcode : %s" % bf["passcode"]
            print "Passcode key : %s" % bf.get("passcodeKey")
    if kb.unlocked:
        device_infos.update(bf)
        device_infos["classKeys"] = kb.getClearClassKeysDict()
        device_infos["KeyBagKeys"] = plistlib.Data(kb.KeyBagKeys)
        return True
    return False
