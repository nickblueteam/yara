rule RAT_toxiceye
{
	meta:

		description = "ToxicEye Rat"
		date = "05/12/2021"
        rule_version = "v1"
        malware_type = "rat"
        malware_family = "Rat:W32/ToxicEye"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://github.com/LimerBoy/ToxicEye"


	strings:

		$1 = "taskmgr"
		$2 = "netstat"
		$3 = "netmon"
		$4 = "ProcessHacker"
		$5 = "FileManagerSplit" wide
    $6 = "tcpview"
    $7 = "wireshark"
    $8 = "filemon"
    $9 = "regmon"
    $10 = "cain"

	condition:

		all of them
}
