rule office_magic_bytes
{
	strings:
		$magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
	condition:
		$magic
}

rule chm_file
{
	strings:
		$magic = { 49 54 53 46 03 00 00 00  60 00 00 00 01 00 00 00 }
	condition:
		$magic
}


rule excel_document
{
	strings:
		$rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$workbook = "Workbook" wide nocase
		$msexcel = "Microsoft Excel" nocase

	condition:
		all of them
}

rule word_document 
{
	strings:
		$rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$worddoc = "WordDocument" wide
		$msworddoc = "MSWordDoc" nocase

	condition:
		$rootentry and ($worddoc or $msworddoc)
}


rule powerpoint_document
{
	strings:
		$pptdoc = "PowerPoint Document" wide nocase
		$rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

		condition:
			all of them
}

rule pdf_document
{
	strings:
		$a = "%PDF-"
	condition:
		$a at 0
}

rule mz_executable // from YARA user's manual
{ 
    condition:
    // MZ signature at offset 0 and ... 
    uint16(0) == 0x5A4D and 
    // ... PE signature at offset stored in MZ header at 0x3C 
    uint32(uint32(0x3C)) == 0x00004550 
} 

rule zip_file
{
	strings:
		$magic = { 50 4b 03 04 }
		$magic2 = { 50 4b 05 06 }
		$magic3 = { 50 4b 07 08 }
	condition:
		($magic at 0) or ($magic2 at 0) or ($magic3 at 0)
}
