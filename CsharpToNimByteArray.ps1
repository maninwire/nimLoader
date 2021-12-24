function CSharpToNimByteArray
# Code below is adapted from @s3cur3th1ssh1t' blog. Read linked article for more details.
# https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/

{

Param
    (
        [string]
        $inputfile,
	    [switch]
        $folder
)

    if ($folder)
    {
        $Files = Get-Childitem -Path $inputfile -File
        $fullname = $Files.FullName
        foreach($file in $fullname)
        {
            Write-Host "Converting $file"
            $outfile = $File + "NimByteArray.txt"
    
            [byte[]] $hex = get-content -encoding byte -path $File
            $hexString = ($hex|ForEach-Object ToString X2) -join ',0x'
            #$Results = $hexString.Insert(0,"var buf: array[" + $hex.Length + ", byte] = [byte 0x")
            #$Results = $Results + "]"         
            #$Results | out-file $outfile
            $hexString="0x"+$hexString
            $hexString| out-file $outfile -encoding utf8
         
        }
        Write-Host -ForegroundColor yellow "Results Written to the same folder"
    }
    else
    {
        Write-Host "Converting $inputfile"
        $outfile = $inputfile + "NimByteArray.txt"
        
        [byte[]] $hex = get-content -encoding byte -path $inputfile
        $hexString = ($hex|ForEach-Object ToString X2) -join ',0x'
        #$Results = $hexString.Insert(0,"var buf: array[" + $hex.Length + ", byte] = [byte 0x")
        #$Results = $Results + "]" 

        #write-output $Results | out-file $outfile
        $hexString="0x"+$hexString
        $hexString| out-file $outfile -encoding utf8        
        Write-Host "Result Written to $outfile"

    }


        # dos2unix conversion

        [string]::Join("`n",(gc $outfile)) | sc $outfile

}
        Write-Host "Done"
