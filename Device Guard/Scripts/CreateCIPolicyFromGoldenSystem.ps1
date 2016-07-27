Import-Module -force CreateCIPolicy

function Main (){
	$outPathRoot = (Join-Path $env:USERPROFILE "desktop")
	New-CIPolicyFromGoldenSystem -OutputFileRootDir $outPathRoot


	
}


Main

