Set-Variable tempfile -option Constant -value "tempfile"

function hash($path) {
    $fullPath = Resolve-Path $path
    $hash = new-object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider

    $contents = [IO.File]::ReadAllText($fullPath) -replace "`r`n?", "`n"
    # create UTF-8 encoding without signature
    $utf8 = New-Object System.Text.UTF8Encoding $false
    # write the text back
    [IO.File]::WriteAllText($tempfile, $contents, $utf8)

    $file = [System.IO.File]::Open($tempfile,[System.IO.Filemode]::Open, [System.IO.FileAccess]::Read)
    $result = [System.BitConverter]::ToString($hash.ComputeHash($file))
    $file.Dispose()

    if (Test-Path $tempfile) {
        Remove-Item $tempfile
    }

    return $result
}

function main() {
    $files = $(Get-ChildItem * | Where-Object { $_.Name -match '^[a-z2]*(_v)?[0-9]*$' } | select -ExpandProperty name)

    foreach ($file in $files) {
        $new = $(hash $file).replace("-","")
        $new = $new.ToLower()

        $old=$(Get-Content $file".shasum")
        $old = $old.Substring(0, $old.IndexOf(" "))

        if ($new -eq $old) {
            Write-Host $file "`tOK"
        } else {
            Write-Host $file "`tERROR"
        }
    }
}

main
