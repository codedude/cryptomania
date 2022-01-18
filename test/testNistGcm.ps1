# Execute test suite

. .\testUtils.ps1

$testCasesPath = "$testCasesBasePath\nistGcmTestCases"
$testPath = ".\dummyTestNistGcm"

function Invoke-Test {
    param (
        [string]$FileIn,
        [string]$KeySize,
        [string]$Key,
        [string]$Iv,
        [string]$Aad,
        [string]$Tag
    )

    $basePlain = "$testCasesPath\$FileIn"
    $basePlainSave = $basePlain
    $baseEncrypted = "$testCasesPath\$FileIn.$KeySize"
    $fileEncrypted = "$testPath\$FileIn.$KeySize"
    $fileDecrypted = "$testPath\$FileIn"

    Invoke-Cliaes -KeySize $KeySize -Mode "gcm" -Key $Key -Iv $Iv -Aad $Aad -Tag $Tag -FileIn $basePlain -FileOut $fileEncrypted -Decrypt $false -NoPadding $true | Out-Null
    Invoke-Cliaes -KeySize $KeySize -Mode "gcm" -Key $Key -Iv $Iv -Aad $Aad -Tag $Tag -FileIn $fileEncrypted -FileOut $fileDecrypted -Decrypt $true -NoPadding $true | Out-Null

    # Test decrypted file
    $basePlain = Get-Content -Raw $basePlain;
    $baseEncrypted = Get-Content -Raw $baseEncrypted;
    $fileDecrypted = Get-Content -Raw $fileDecrypted;
    $fileEncrypted = Get-Content -Raw $fileEncrypted;
    if ($Null -eq $basePlain) {
        $basePlain = ""
    }
    if ($Null -eq $baseEncrypted) {
        $baseEncrypted = ""
    }
    if ($Null -eq $fileDecrypted) {
        $fileDecrypted = ""
    }
    if ($Null -eq $fileEncrypted) {
        $fileEncrypted = ""
    }
    $diffPlain = Compare-Object $basePlain $fileDecrypted
    $diffEncrypted = Compare-Object $baseEncrypted $fileEncrypted

    $ret = $true;
    if ($diffPlain) {
        Write-Host "Diff in plain/decrypted file"
        $ret = $false
    }
    elseif ($diffEncrypted) {
        Write-Host "Diff in encrypted file"
        $ret = $false
    }

    if (!$ret) {
        Write-Host "Error : $FileIn / KeySize = $KeySize"
    }
}

Write-Host "Running nist gcm tests suite..."

# Create temporary dir to store generated files
New-Item -Force -ItemType "directory" -Path $testPath | Out-Null

# Execute all test combination
Invoke-Test -FileIn "msgEmpty" -KeySize "128" -Key "00000000000000000000000000000000" -Iv "000000000000000000000000" -Aad "" -Tag "58e2fccefa7e3061367f1d57a4e7455a"
Invoke-Test -FileIn "msgZeros" -KeySize "128" -Key "00000000000000000000000000000000" -Iv "000000000000000000000000" -Aad "" -Tag "ab6e47d42cec13bdf53a67b21257bddf"
Invoke-Test -FileIn "msg64" -KeySize "128" -Key "feffe9928665731c6d6a8f9467308308" -Iv "cafebabefacedbaddecaf888" -Aad "" -Tag "4d5c2af327cd64a62cf35abd2ba6fab4"
Invoke-Test -FileIn "msg60" -KeySize "128" -Key "feffe9928665731c6d6a8f9467308308" -Iv "cafebabefacedbaddecaf888" -Aad "feedfacedeadbeeffeedfacedeadbeefabaddad2" -Tag "5bc94fbc3221a5db94fae95ae7121a47"
Invoke-Test -FileIn "msg60iv12" -KeySize "128" -Key "feffe9928665731c6d6a8f9467308308" -Iv "cafebabefacedbad" -Aad "feedfacedeadbeeffeedfacedeadbeefabaddad2" -Tag "3612d2e79e3b0785561be14aaca2fccb"
Invoke-Test -FileIn "msg60iv120" -KeySize "128" -Key "feffe9928665731c6d6a8f9467308308" -Iv "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b" -Aad "feedfacedeadbeeffeedfacedeadbeefabaddad2" -Tag "619cc5aefffe0bfa462af43c1699d050"


Write-Host "Tests suite done!"
