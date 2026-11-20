# Recomputes the sha256 hashes of the inline <script> blocks in index.html
# and writes them into the Content-Security-Policy script-src list.
# Run after editing any inline script:  powershell -File tools/update-csp.ps1
param([string]$Path = (Join-Path $PSScriptRoot '..\index.html'))
$Path = (Resolve-Path $Path).Path
$html = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
$text = $html -replace "`r`n", "`n"            # browsers hash the LF-normalised text
$sha = [Security.Cryptography.SHA256]::Create()
$hashes = foreach($m in [regex]::Matches($text, '<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>')){
  "'sha256-" + [Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($m.Groups[1].Value))) + "'"
}
$list = ($hashes -join ' ')
$new = [regex]::Replace($html, "script-src 'self' [^;]*? https://cdn\.jsdelivr\.net", "script-src 'self' $list https://cdn.jsdelivr.net")
[IO.File]::WriteAllText($Path, $new, (New-Object Text.UTF8Encoding($false)))
"Updated script-src with $($hashes.Count) hashes"
