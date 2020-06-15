new Packages.org.eclipse.ease.modules.EnvironmentModule().loadModule("/System/Environment", false);

loadModule("Communicator");
var sd = getCommandSetByName("Open FIPS 201");
sd.connect()
sd.selectByAID("a000000308000010000100", false)
sd.openSC();
var secStatus = sd.send("00 48 00 00")
print("SecurityLevel = " + secStatus)

print(" ADD DATA OBJECT - 5FC107 - Card Capability Container")
var res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 07 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC102 - Cardholder Unique Identifier")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 02 8C 01 7F 8D 01 7F")
res.checkOK()

print(" ADD DATA OBJECT - 5FC105 - X509 Certificate for PIV Authentication")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 05 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC103 - Cardholder Fingerprints")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 03 8C 01 01 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC106 - Security Object")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 06 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC108 - Cardholder Facial Image")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 08 8C 01 01 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC101 - X509 Certificate for Card Authentication")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 01 8C 01 7F 8D 01 7F")
res.checkOK()

print(" ADD DATA OBJECT - 5FC10A - X509 Certificate for Digital Signature")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 0A 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC10B - X509 Certificate for Key Management")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 0B 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC109 - Printed Information")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 09 8C 01 01 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 7E - Discovery Object")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 7E 8C 01 7F 8D 01 7F")
res.checkOK()

print(" ADD DATA OBJECT - 5FC10C - Key History Object")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 0C 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC10D - Retired X509 Certificate for Key Management 1")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 0D 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC10E - Retired X509 Certificate for Key Management 2")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 0E 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC10F - Retired X509 Certificate for Key Management 3")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 0F 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC110 - Retired X509 Certificate for Key Management 4")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 10 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC111 - Retired X509 Certificate for Key Management 5")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 11 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC112 - Retired X509 Certificate for Key Management 6")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 12 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC113 - Retired X509 Certificate for Key Management 7")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 13 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC114 - Retired X509 Certificate for Key Management 8")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 14 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC115 - Retired X509 Certificate for Key Management 9")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 15 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC116 - Retired X509 Certificate for Key Management 10")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 16 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC117 - Retired X509 Certificate for Key Management 11")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 17 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC118 - Retired X509 Certificate for Key Management 12")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 18 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC119 - Retired X509 Certificate for Key Management 13")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 19 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC11A - Retired X509 Certificate for Key Management 14")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 1A 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC11B - Retired X509 Certificate for Key Management 15")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 1B 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC11C - Retired X509 Certificate for Key Management 16")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 1C 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC11D - Retired X509 Certificate for Key Management 17")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 1D 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC11E - Retired X509 Certificate for Key Management 18")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 1E 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC11F - Retired X509 Certificate for Key Management 19")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 1F 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC120 - Retired X509 Certificate for Key Management 20")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 20 8C 01 7F 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 5FC121 - Cardholder Iris Images")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 21 8C 01 01 8D 01 00")
res.checkOK()

print(" ADD DATA OBJECT - 7F61 - Biometric Information Templates Group Template")
res = sd.send("00 DB 3F 00 0E 30 0C 8A 01 01 8B 01 61 8C 01 7F 8D 01 7F")
res.checkOK()

print(" ADD KEY - 9A - PIV Authentication Key (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9A 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 9B - Application Administration Key (TDEA3KEY)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9B 8C 01 7F 8D 01 00 8E 01 03 8F 01 03")
res.checkOK()

print(" ADD KEY - 9B - Application Administration Key (AES128)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9B 8C 01 7F 8D 01 00 8E 01 08 8F 01 03")
res.checkOK()

print(" ADD KEY - 9B - Application Administration Key (AES192)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9B 8C 01 7F 8D 01 00 8E 01 0A 8F 01 03")
res.checkOK()

print(" ADD KEY - 9B - Application Administration Key (AES256)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9B 8C 01 7F 8D 01 00 8E 01 0C 8F 01 03")
res.checkOK()

print(" ADD KEY - 9C - Digital Signature Key (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9C 8C 01 02 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 9D - Key Management Key (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9D 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 9E - Card Authentication Key (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9E 8C 01 7F 8D 01 7F 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 9E - Card Authentication Key (TDEA3KEY)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9E 8C 01 7F 8D 01 7F 8E 01 03 8F 01 04")
res.checkOK()

print(" ADD KEY - 9E - Card Authentication Key (AES128)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9E 8C 01 7F 8D 01 7F 8E 01 08 8F 01 04")
res.checkOK()

print(" ADD KEY - 9E - Card Authentication Key (AES192)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9E 8C 01 7F 8D 01 7F 8E 01 0A 8F 01 04")
res.checkOK()

print(" ADD KEY - 9E - Card Authentication Key (AES256)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 9E 8C 01 7F 8D 01 7F 8E 01 0C 8F 01 04")
res.checkOK()

print(" ADD KEY - 82 - Retired Key Management Key 01 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 82 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 83 - Retired Key Management Key 02 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 83 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 84 - Retired Key Management Key 03 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 84 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 85 - Retired Key Management Key 04 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 85 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 86 - Retired Key Management Key 05 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 86 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 87 - Retired Key Management Key 06 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 87 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 88 - Retired Key Management Key 07 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 88 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 89 - Retired Key Management Key 08 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 89 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 8A - Retired Key Management Key 09 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 8A 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 8B - Retired Key Management Key 10 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 8B 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 8C - Retired Key Management Key 11 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 8C 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 8D - Retired Key Management Key 12 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 8D 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 8E - Retired Key Management Key 13 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 8E 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 8F - Retired Key Management Key 14 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 8F 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 90 - Retired Key Management Key 15 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 90 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 91 - Retired Key Management Key 16 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 91 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 92 - Retired Key Management Key 17 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 92 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 93 - Retired Key Management Key 18 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 93 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 94 - Retired Key Management Key 19 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 94 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()

print(" ADD KEY - 95 - Retired Key Management Key 20 (RSA2048)")
res = sd.send("00 DB 3F 00 14 30 12 8A 01 02 8B 01 95 8C 01 01 8D 01 00 8E 01 07 8F 01 04")
res.checkOK()