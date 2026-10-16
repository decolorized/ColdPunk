# Used by secure-first-flash.bat: reads the JSON eFuse summary written by
#   espefuse --chip esp32s3 summary --format json --file state.json
# and prints NAME=VALUE lines for the batch file:
#   SB_EN=true|false   CRYPT=<SPI_BOOT_CRYPT_CNT>   HMAC=<blocks with HMAC_UP>
#   XTS=<blocks with XTS_AES_128_KEY>   FREE=<empty key blocks, lowest first>
param([string]$File)
$s = Get-Content -Raw -LiteralPath $File | ConvertFrom-Json
$hmac = @(); $xts = @(); $free = @()
foreach ($i in 0..5) {
    $p = $s."KEY_PURPOSE_$i".value
    $b = $s."BLOCK_KEY$i"
    if ($p -eq 'HMAC_UP') { $hmac += $i }
    elseif ($p -eq 'XTS_AES_128_KEY') { $xts += $i }
    elseif ($p -eq 'USER' -and $b.readable -and ($b.raw_value -replace '^0x', '') -match '^0*$') { $free += $i }
}
"SB_EN=" + ([string]$s.SECURE_BOOT_EN.value).ToLower()
"CRYPT=" + $s.SPI_BOOT_CRYPT_CNT.value
"HMAC=" + ($hmac -join ' ')
"XTS=" + ($xts -join ' ')
"FREE=" + ($free -join ' ')
