# Various path
$testCasesBasePath = "..\res"
$cliExePath = "..\bin\cliaes\cliaes.exe"

$modes = "ctr", "ecb", "cbc"
$keySizes = "128", "192", "256"

$defaultKeys = @{
    "128" = "000102030405060708090a0b0c0d0e0f"
    "192" = "000102030405060708090a0b0c0d0e0f08090a0b0c0d0e0f"
    "256" = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
}
$defaultIv = "000102030405060708090a0b0c0d0e0f"
$defaultFiles = "lt1block", "eq1block", "gt1block", "3block"

# Call the cliaes
function Invoke-Cliaes {
    param (
        [string]$KeySize,
        [string]$Mode,
        [string]$FileIn,
        [string]$FileOut,
        [string]$Iv,
        [string]$Key,
        [string]$Aad = "",
        [string]$Tag = "",
        [boolean]$Decrypt,
        [boolean]$NoPadding
    )

    $params = "-m $Mode", "-s $KeySize", "-n $Iv", "-k $Key", "-i $FileIn", "-o $FileOut"
    if ($Decrypt) {
        $params += "-d"
    }
    if ($NoPadding) {
        $params += "--nopad"
    }
    if ($Aad) {
        $params += "-a $Aad"
    }
    if ($Tag) {
        $params += "-t $Tag"
    }

    $process = Start-Process -PassThru -FilePath $cliExePath -ArgumentList $params
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        Write-Host " - Error in command : $cliExePath $params"
        return $false
    }
    return $true
}
