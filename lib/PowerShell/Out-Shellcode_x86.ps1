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
        if ($tmpShellcode[$j]  -eq 201) #C9 Veerifico que la instruccion anterior sea un leave
        {
            $j--
            if ($tmpShellcode[$j]  -eq 144) #90 Veerifico que la instruccion anterior sea un nop
            {
                $retIndex = $i
                [int] $retOffset = $ShellcodeLength - $i
                $offsetBytes = [bitconverter]::GetBytes($retOffset)
                #Se agrega un jmp a la instruccion siguiente de donde termina la shellcode,
                #ahi comienza la redireccion al end point original(parche que agrega el injector justo despues del shellcode)
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

$j =0

#Se buscan las instrucciones push(parametros) de la api CreateThread, 
#y se reemplaza la direccion de memoria con la direccion donde se 
#encuantra la funcion del thread
for($i=0 
    $i -le $ShellcodeLength 
    $i++)
{
    if ($tmpShellcode[$i]  -eq 106) #push 0
    {
        $i = $i + 2
        if ($tmpShellcode[$i]  -eq 106) #push 0
        {
            $i = $i + 2
            if ($tmpShellcode[$i]  -eq 106) #push 0
            {
                $i = $i + 2
                $offsetThreadBytes = [bitconverter]::GetBytes($retIndex + 1) #rva del thread
				Se agrega la direccion de memoria de la funcion del thread
                $tmpShellcode[$i++] = 0x83
                $tmpShellcode[$i++] = 0xC6
                $tmpShellcode[$i++] = $offsetThreadBytes[0]
                $tmpShellcode[$i++] = 0x56
                $tmpShellcode[$i++] = 0x90

                #$tmpShellcode[$i--] = $offsetThreadBytes[3]
                #$tmpShellcode[$i--] = $offsetThreadBytes[2]
                #$tmpShellcode[$i--] = $offsetThreadBytes[1]
                #$tmpShellcode[$i--] = $offsetThreadBytes[0]
                #$tmpShellcode[$i] = 0x68

                break
            }
        }
    }
}

[IO.File]::WriteAllBytes($OutputFile, $tmpShellcode)

#[IO.File]::WriteAllBytes($OutputFile, $TextSection.RawData[0..$ShellcodeLength])

#./Out-Shellcode_x86.ps1 C:\Users\alpiste\Downloads\Shellcode\Release\Shellcode.exe C:\Users\alpiste\Downloads\Shellcode\Shellcode C:\Users\alpiste\Downloads\Shellcode\Release\Shellcode.map C:\Users\alpiste\Desktop\Dropper\test.bin