# Execute test suite

. .\testUtils.ps1

$testCasesPath = "$testCasesBasePath\nistTestCases"
$testPath = ".\dummyTestNist"

$plainPath = "$testCasePath\msg"

$keys = @{
    "128" = "2b7e151628aed2a6abf7158809cf4f3c"
    "192" = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    "256" = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
}
$iv = "000102030405060708090a0b0c0d0e0f"
$counter = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

function Invoke-Test {
    param (
        [string]$FileIn,
        [string]$KeySize,
        [string]$Mode
    )

    $key = $keys[$KeySize]
    $nonce = $iv
    if ($Mode -eq "ctr") {
        $nonce = $counter
    }
    $basePlain = "$testCasesPath\$FileIn"
    $baseEncrypted = "$testCasesPath\$FileIn.$KeySize.$Mode"
    $fileEncrypted = "$testPath\$FileIn.$KeySize.$Mode"
    $fileDecrypted = "$testPath\$FileIn"

    Invoke-Cliaes -KeySize $KeySize -Mode $Mode -Key $key -Iv $nonce -FileIn $basePlain -FileOut $fileEncrypted -Decrypt $false -NoPadding $true | Out-Null
    Invoke-Cliaes -KeySize $KeySize -Mode $Mode -Key $key -Iv $nonce -FileIn $fileEncrypted -FileOut $fileDecrypted -Decrypt $true -NoPadding $true | Out-Null

    # Test decrypted file
    $diffPlain = Compare-Object (Get-Content $basePlain) (Get-Content $fileDecrypted)
    $diffEncrypted = Compare-Object (Get-Content $baseEncrypted) (Get-Content $fileEncrypted)

    if ($diffPlain) {
        Write-Host "Diff in plain/decrypted file"
        return $false
    }
    elseif ($diffEncrypted) {
        Write-Host "Diff in encrypted file"
        return $false
    }

    return $true
}

Write-Host "Running nist tests suite..."

# Create temporary dir to store generated files
New-Item -Force -ItemType "directory" -Path $testPath | Out-Null

# Execute all test combination
foreach ($keySize in $keySizes) {
    foreach ($mode in $modes) {
        $ret = Invoke-Test -FileIn $plainPath -KeySize $keySize -Mode $mode
        if (!$ret) {
            Write-Host "Error : $file / $keySize-$mode"
        }
    }
}

Write-Host "Tests suite done!"
