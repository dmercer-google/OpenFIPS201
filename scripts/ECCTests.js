new Packages.org.eclipse.ease.modules.EnvironmentModule().loadModule("/System/Environment", false);

loadModule("Communicator");
importPackage(com.infineon.tools.apdu)
var sd = getCommandSetByName("Open FIPS 201");
sd.connect()
sd.selectByAID("a000000308000010000100", false)
sd.openSC();
var secStatus = sd.send("00 48 00 00")
print("SecurityLevel = " + secStatus)

try {
print("ADD KEY - 9A - PIV Authentication Key (ECP256)")
res = sd.send("00 DB 3F 00 14 " +
		"30 12 " +
		"8A 01 02 " +  // Key
		"8B 01 9A " +  // ID 9A
		"8C 01 01 " +  // Contact = PIN
		"8D 01 00 " +  // Contactless = Never
		"8E 01 11 " +  // P256
		"8F 01 04"     // Role Auth Internal
		)
res.checkOK()

print("ADD KEY - 9A - PIV Authentication Key (ECP384)")
res = sd.send("00 DB 3F 00 14 " +
		"30 12 " +
		"8A 01 02 " +  // Key
		"8B 01 9A " +  // ID 9A
		"8C 01 01 " +  // Contact = PIN
		"8D 01 00 " +  // Contactless = Never
		"8E 01 14 " +  // P384
		"8F 01 04"     // Role Auth Internal
		)
res.checkOK()

print("ADD KEY - 9E - Card Authentication Key (P256)")
res = sd.send("00 DB " +
		"3F 00 " +  // Admin
		"14 " +  //14 bytes
		"30 12 " +  // Sequence 12 bytes
		"8A 01 02 " +  // Key
		"8B 01 9E " +  // ID = 9E
		"8C 01 7F " +  // Contact always
		"8D 01 7F " +  // Contactless always
		"8E 01 11 " +  // P256
		"8F 01 04"     // Role Auth Internal
		)
res.checkOK()

print("ADD KEY - 9E - Card Authentication Key (P384)")
res = sd.send("00 DB " +
		"3F 00 " +  // Admin
		"14 " +  //14 bytes
		"30 12 " +  // Sequence 12 bytes
		"8A 01 02 " +  // Key
		"8B 01 9E " +  // ID = 9E
		"8C 01 7F " +  // Contact always
		"8D 01 7F " +  // Contactless always
		"8E 01 14 " +  // P384
		"8F 01 04"     // Role Auth Internal
		)
res.checkOK()

print("ADD KEY - 9F - RSA 1024")
res = sd.send("00 DB " +
		"3F 00 " +  // Admin
		"14 " +  //14 bytes
		"30 12 " +  // Sequence 12 bytes
		"8A 01 02 " +  // Key
		"8B 01 9F " +  // ID = 9E
		"8C 01 7F " +  // Contact always
		"8D 01 7F " +  // Contactless always
		"8E 01 06 " +  // RSA 1024
		"8F 01 04"     // Role Auth Internal
		)
res.checkOK()

print("ADD KEY - 9F - RSA 2048)")
res = sd.send("00 DB " +
		"3F 00 " +  // Admin
		"14 " +  //14 bytes
		"30 12 " +  // Sequence 12 bytes
		"8A 01 02 " +  // Key
		"8B 01 9F " +  // ID = 9F
		"8C 01 7F " +  // Contact always
		"8D 01 7F " +  // Contactless always
		"8E 01 07 " +  // RSA 2048
		"8F 01 04"     // Role Auth Internal
		)


print("SUCCESS: Key containers created")
} catch (err) {
	if (res.getSW() == 0x6A84) {
		print("\tKey containers already created")
	} else {
		print("ERROR: creating key containers: 0x" + res.getSW().toString(16))
		throw err;
	}
} finally {
	print()
 }


/**

P-256 Keys
Public Key (W)
  04 01 F4 8C 5F ED 23 C7 5D FF F4 3A F8 49 2B F6 6A 18 37 8B FB 06 E9 2D 3E 9A AE 96 0C B0 AE 40 87 BC 3B 38 D2 82 EF 06 32 EB B9 9C 7A 65 94 26 5E E1 93 CF 96 4F 5B CE ED A0 EB AD E8 36 D1 F5 14     
Private Key (S)
  AF C6 76 48 A4 15 84 F4 4D F5 90 AB 82 6B F9 DE 6F 49 9C 85 4A F9 66 DF BE 7B 7F 2B 2C C2 29 0F 

Public Key (W)
  04 E2 DC 5D 77 4F 86 DB 42 04 36 1D 78 E6 E8 36 1C 3B BE 6E 1A 6E 8F 34 6C 3F 98 6B C1 5E 73 CE 9E 86 D4 C6 B9 81 6C BC B0 C6 A9 D7 6D C3 FF 33 C5 03 C5 0A 67 A4 E3 76 27 73 07 E0 67 D9 D0 21 23 
Private Key (S)
  E3 59 58 DD 0C A2 11 24 4D 10 9C 89 7A 53 C6 73 FE 6F 4D 7E 4E F1 2A D1 4D 2F EE 6B 16 E1 2B 10
  
P-384 Keys
Public key (W) 
  04 FB CB B8 61 D1 2E 0D CA 17 D0 B5 98 59 6F 2E 5F B9 56 03 D8 80 79 1D B5 D6 3E 38 25 68 BA DB 23 0C 5B 56 A4 68 19 61 C5 28 BA 9C 66 36 9C EB A8 65 37 5E FD 2B 49 6C B7 91 99 A5 B2 CB FA FE 13 F2 C7 EC 36 8A 16 42 9C A4 25 4E E7 7E 90 3A E3 BC 4F 64 35 6C 74 A5 29 92 32 1A 24 F9 A9 A4 BF
Private Key (S)
  51 74 AC 94 11 DE F1 3D D0 E0 6E 97 EB 71 F0 BB 05 50 FA BF 9D C1 F5 10 03 4E BA A1 2B 81 74 5E 4A 4E B4 54 C4 85 32 19 2E 49 D5 DC 75 93 9D 2F
  
Public Key (W)
  04 FB 7B 8E 37 57 66 CE F8 A1 7E EB F1 C5 EB 01 84 73 DE 8E 41 B3 09 93 48 67 51 58 EE BC A6 74 4A C2 FF 6D 5B 40 7D 47 BA 0D 1E 1C FB D9 D4 33 85 8D 04 65 14 5C F3 19 F0 2E 1D 57 07 25 40 2B 3D 8D EB 0C 99 75 E4 CE F3 96 AA 06 F0 D1 EF EB A9 BF C5 09 C2 C4 76 80 3A 97 A2 90 27 46 41 7B E9
Private Key (S)
  57 A6 E5 55 72 97 10 AB CB F6 F1 7C 7B 49 04 9D D9 5D AB D9 E6 15 91 A6 1A 79 68 31 61 44 22 DF EA 11 D9 46 21 A2 D6 37 BC E4 3B 45 10 C2 14 E1 00 00


*/

print("Pre Personalization complete")

const ITERATIONS = 1
var i = 0

print("ECC tests.  Iterations: " + ITERATIONS)
i = 0
while (i++ < ITERATIONS) {
	if(ITERATIONS > 1){
		print("Iteration:" + i)
	}
	print("---")
	
	print("Generating ECC P256 9E Key")
	res = sd.send("00 47 00 9E 05 AC 03 80 01 11")
	res.checkOK()
	print(res)
	// P256
	print("\tSigning with key 9E - SHA1")
	res = sd.send("00 87 11 9E 1A 7C 18 81 14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 82 00")
	res.checkOK()
	print("Signature: " + res)
	print("\tExecution time: " + res.getExecutionTime())

	print("\tSigning with key 9E - SHA256")
	res = sd.send("00 87 11 9E 26 7C 24 81 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 82 00")
	res.checkOK()
	print("\tExecution time: " + res.getExecutionTime())
	
	print("\tSigning with key 9E - SHA384")
	res = sd.send("00 87 11 9E 36 7C 34 81 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 82 00")
	res.checkOK()
	print("\tExecution time: " + res.getExecutionTime())
	
	print("\tSigning with key 9E - SHA512")
	res = sd.send("00 87 11 9E 46 7C 44 81 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 82 00")
	res.checkOK()
	print("\tExecution time: " + res.getExecutionTime())
	
	// P384
	print()
	print("Generating ECC P384 9E Key")
	res = sd.send("00 47 00 9E 05 AC 03 80 01 14")
	res.checkOK()
	
	print("\tSigning with key 9E - SHA1")
	res = sd.send("00 87 11 9E 1A 7C 16 81 14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 82 00")
	res.checkOK()
	print("\tExecution time: " + res.getExecutionTime())
	
	print("\tSigning with key 9E - SHA256")
	res = sd.send("00 87 11 9E 26 7C 24 81 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 82 00")
	res.checkOK()
	print("\tExecution time: " + res.getExecutionTime())
	
	print("\tSigning with key 9E - SHA384")
	res = sd.send("00 87 11 9E 36 7C 34 81 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 82 00")
	res.checkOK()
	print("\tExecution time: " + res.getExecutionTime())
	
	print("\tSigning with key 9E - SHA512")
	res = sd.send("00 87 11 9E 46 7C 44 81 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 82 00")
	res.checkOK()
	print("\tExecution time: " + res.getExecutionTime())
	
	print("---")
}

print("RSA tests.  Iterations: " + ITERATIONS)
i = 0
while (i++ < ITERATIONS) {
	if(ITERATIONS > 1){
		print("Iteration:" + i)
	}
	print("---")
	print("Generating RSA 1024 9F Key")
	res = sd.send("00 47 00 9F 05 AC 03 80 01 06")
	res.checkOK()

	print("Generating RSA 2048 Key 9F")
	res = sd.send("00 47 00 9F 05 AC 03 80 01 07")
	res.checkOK()
	print("\tPublic Key: " + res)
	
	sd.selectByAID("a000000308000010000100", false)

	print("Signing with key 9F - 128 bytes - 1/2")
	res = sd.send("10 87 07 9F EF 7C 82 01 06 81 82 01 00 4D 86 09 82 76 1E 42 F6 D0 73 30 CD 96 F0 14 0A 25 C2 67 78 1D DD 35 B5 EA 2C D0 0F 57 B4 90 D7 1A 25 CC 9D 49 6A AD 40 A0 0F 0F F3 90 1F 0A A7 66 FA EB E4 E8 A9 07 C4 24 87 1F A0 F4 82 4B 64 B4 13 86 50 25 D1 13 4A 85 B2 F9 7C FF 2F 40 C4 4C F5 EA 71 51 30 C6 33 87 59 E0 88 23 36 35 39 F1 5B DA 83 A6 F6 76 76 3A 7A 8C B4 FF E0 E3 60 C1 06 C8 4E FC 68 95 74 40 84 EB 4F 7B 24 FE E2 C8 A5 56 8D 92 CA 67 8F 30 98 85 D8 00 00 D0 16 54 66 38 72 1D 71 68 02 A2 E9 BA 52 60 15 29 02 38 8F 39 FD BD 75 E0 AE C5 F7 E7 50 95 3A 78 01 6F 30 36 59 18 A4 23 F0 91 D0 3D 3C 0F 85 14 E7 0D 4F 7E 3D 82 2A 8C 11 11 04 38 E8 19 52 88 AA 2E B7 C8 ED 00 DC FD CF 1C F8 96 38 09 19 DF 16 6E 79 37 6C 78 3F 52")
	res.checkOK()

	print("Signing with key 9F - 128 bytes - 2/2")
	res = sd.send("00 87 07 9F 1B 02 54 2F 07 34 BB A3 BB FE 62 16 C8 8D 63 90 34 30 84 B8 6A E5 3E 56 03 42 82 00")
	res.checkOK()
	print("\tSignature: " + res)
	print("\tExecution time: " + res.getExecutionTime())
		
	print("---")
}
print("ECC Key Generation done.")


