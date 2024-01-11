Param
(
    [parameter(Mandatory=$true)][string]$exeFile,
    [switch][bool]$replace=$false
)




$exeFileBasename=split-path  -leaf $exeFile 
$exePath=split-path  -resolve $exeFile 
$exeNonExt=[System.IO.Path]::GetFileNameWithoutExtension($exeFile)


write-host $exeFile
write-host $exePath
write-host $exeNonExt


if (-not ( Test-Path -Path $exeFile)) {

   write-host "Path doesn't exist."
   exit
}

if ((Test-Path -Path $exeFile"NimByteArray.txt") -and (!$replace)) {
   write-host $exeFile" is already converted"

} else {

   . .\CsharpToNimByteArray.ps1

   write-host "Converting to Nim Byte array"

   CsharpToNimByteArray $exeFile
}




if (-not (Test-Path -Path $exeFile"NimByteArray.txt")) {
   write-host $exeFile+"NimByteArray.txt file not found"
   exit
}

write-host "Encrypting with default key"

.\nimCrypter.exe -e  $exeFile"NimByteArray.txt"

if (-not (Test-Path -Path $exeFile"NimByteArray.txt_enc.txt")) {
   write-host $exeFile"NimByteArray.txt_enc.txt file not found"
   exit
}

write-host "Done. Example runs:"

write-host ".\NimLoader.exe -d "$exeFileBasename"NimByteArray.txt_enc.txt"
write-host ".\NimLoader.exe -d -p "params" "$exeFileBasename"NimByteArray.txt_enc.txt"
write-host ".\NimLoader.exe -d "$exeFile"NimByteArray.txt_enc.txt"
write-host ".\NimLoader.exe -d -p "params" "$exeFile"NimByteArray.txt_enc.txt"
write-host "copy "$exeFile"NimByteArray.txt_enc.txt ."
