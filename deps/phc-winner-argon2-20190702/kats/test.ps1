$ErrorActionPreference = "Stop"

Set-Variable tempfile -option Constant -value "tempfile"

function CompareFiles($f1, $f2, $i) {
    $f1_content = $(Get-Content $f1)
    $f2_content = $(Get-Content $f2)

    if (Compare-Object $f1_content $f2_content) {
        Write-Host -NoNewline "ERROR"
        exit $i
    } else {
        Write-Host -NoNewline "OK"
    }
}

function main() {
    $i = 0
    foreach ($opt in @("Ref", "Opt")) {
        Write-Output "$opt"

        foreach ($version in @(16, 19)) {
            foreach ($type in @("i", "d", "id")) {
                $i++

                if ("Ref" -eq $opt) {
                    vs2015\build\Argon2RefGenKAT.exe $type $version > $tempfile
                } else {
                    vs2015\build\Argon2OptGenKAT.exe $type $version > $tempfile
                }

                if (19 -eq $version) {
                    $kats = "kats\argon2" + $type
                } else {
                    $kats = "kats\argon2" + $type + "_v" + $version
                }

                Write-Host -NoNewline "Argon2$type v=$version : "
                CompareFiles $tempfile $kats $i
                Write-Output ""
            }
        }
    }

    if (Test-Path $tempfile) {
        Remove-Item $tempfile
    }
}

main
