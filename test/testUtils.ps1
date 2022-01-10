
# Various path
$testCasesPath = "..\res\testCases"
$cliExePath = "..\bin\cliaes\cliaes.exe"

# Various data
$keys = @{
    "128" = "000102030405060708090a0b0c0d0e0f"
    "192" = "000102030405060708090a0b0c0d0e0f08090a0b0c0d0e0f"
    "256" = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
}
$ivs = @{
    "128" = "000102030405060708090a0b0c0d0e0f"
    "192" = "000102030405060708090a0b0c0d0e0f"
    "256" = "000102030405060708090a0b0c0d0e0f"
}

$modes = "ctr", "ecb", "cbc"
$keySizes = "128", "192", "256"

$files = "lt1block", "eq1block", "gt1block", "3block"

# Call the cliaes
function Invoke-Cliaes {
    param (
        [string]$KeySize,
        [string]$Mode,
        [string]$FileIn,
        [string]$FileOut,
        [string]$Iv,
        [string]$Key,
        [boolean]$Decrypt
    )

    $params = "-m $Mode", "-s $KeySize", "-n $Iv", "-k $Key", "-i $FileIn", "-o $FileOut"
    if ($Decrypt) {
        $params += "-d"
    }
    $process = Start-Process -PassThru -FilePath $cliExePath -ArgumentList $params
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        Write-Host "Error in command : $cliExePath $params"
        return $false
    }
    return $true
}
