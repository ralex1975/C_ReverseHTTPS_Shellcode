Param (
    [Parameter(Position = 0, Mandatory = $True)]
    [String]
    $InputExe,

    [Parameter(Position = 1, Mandatory = $True)]
    [ValidateScript({ Test-Path $_ })]
    [String]
    $ProjectDir,

    [Parameter(Position = 2, Mandatory = $True)]
    [ValidateScript({ Test-Path $_ })]
    [String]
    $InputMapFile,

    [Parameter(Position = 3, Mandatory = $True)]
    [String]
    $OutputFile
)

$GetPEHeader = Join-Path $ProjectDir Get-PEHeader.ps1

. $GetPEHeader

$PE = Get-PEHeader $InputExe -GetSectionData
$TextSection = $PE.SectionHeaders | Where-Object { $_.Name -eq '.text' }

$MapContents = Get-Content $InputMapFile
$TextSectionInfo = @($MapContents | Where-Object { $_ -match '\.text\W+CODE' })[0]

$ShellcodeLength = [Int] "0x$(( $TextSectionInfo -split ' ' | Where-Object { $_ } )[1].TrimEnd('H'))" - 1

Write-Host "Shellcode length: 0x$(($ShellcodeLength + 1).ToString('X4'))"

$tmpShellcode = $TextSection.RawData[0..$ShellcodeLength]


$j = 0
$retIndex = 0

#Busqueda de la instruccion ret, que es donde termina el main de la aplicacion
for($i=0 
    $i -le $ShellcodeLength 
    $i++)
{
    if ($tmpShellcode[$i]  -eq 195) #First ret C3, aca termina el main
    {
        $j = $i
        $j--
        if ($tmpShellcode[$j]  -eq 95) #5F
        {
            $j--
            if ($tmpShellcode[$j]  -eq 48) #48
            {
                $retIndex = $i
                [int] $retOffset = $ShellcodeLength - $i
                $offsetBytes = [bitconverter]::GetBytes($retOffset)
				#Se agrega patch, con un jmp al final del exe, 
				#donde se redirecciona el flujo al entry point original
                $tmpShellcode[$i--] = $offsetBytes[3]
                $tmpShellcode[$i--] = $offsetBytes[2]
                $tmpShellcode[$i--] = $offsetBytes[1]
                $tmpShellcode[$i--] = $offsetBytes[0]
                $tmpShellcode[$i] = 0xE9 

                break
            }
        }
    }
}

[IO.File]::WriteAllBytes($OutputFile, $tmpShellcode)

#C:\Users\Alpiste\Desktop\PIC_Bindshell-master\PIC_Bindshell\Out-Shellcode.ps1 C:\Users\Alpiste\Desktop\PIC_Bindshell-master\Release\PIC_Bindshell.exe C:\Users\Alpiste\Desktop\PIC_Bindshell-master\PIC_Bindshell C:\Users\Alpiste\Desktop\PIC_Bindshell-master\Release\PIC_Bindshell.map C:\Users\Alpiste\Desktop\PIC_Bindshell-master\Release\test.bin