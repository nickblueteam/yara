rule RAT_toxiceye {

	 meta:

		 description = "Detect ToxicEye using the .pdb file as reference."
		 author = "SushiGhosts"
		 date = "05-11-2021"
		 rule_version = "1.0"
     malware_type = "RAT"
     malware_family = "Rat:W64/ToxicEye"
     actor_type = "Not Enough Data"
     actor_group = "Unknown"
		 reference = "https://github.com/LimerBoy/ToxicEye"
		 hash = "1a4a5123d7b2c534cb3e3168f7032cf9ebf38b9a2a97226d0fdb7933cf6030ff"
     hash = "6f7840c77f99049d788155c1351e1560b62b8ad18ad0e9adda8218b9f432f0a9"
     hash = "36b36ee9515e0a60629d2c722b006b33e543dce1c8c2611053e0651a0bfdb2e9"

	 strings:

	 	$pdb = "-------------.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 1440KB and
	 	any of them
}
