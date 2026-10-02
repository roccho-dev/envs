#requires -Version 5.1
# envs placement entrance (windows #14). The target's operator runs it from the verified envs-placement-<sha>
# artifact (its identity is checked against GitHub's artifact record, outside this file). It decrypts one envelope
# with the pinned sops.exe beside it and the target's own age identity, then hands the value to the target's writer
# through a private stdin pipe only:
#   -Target client  windows' win.ps1 -Mode RentAccess from the verified windows-dist (G6I3 owner-only slot)
#   -Target rent    rent-receive.sh in a one-shot WSLC container of the exact rent image on the state volume
# The plaintext exists only in this process's memory and the child pipes: never printed, logged, put in argv,
# environment or a file. The result is the writer's exit code; a refusal is one fixed stderr line.
param(
    [Parameter(Mandatory)][ValidateSet('client', 'rent')][string]$Target,
    [Parameter(Mandatory)][string]$Identity,
    [string]$Ciphertext,
    [string]$WindowsDist,
    [string]$RentImage
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Refuse([string]$Reason) {
    [Console]::Error.WriteLine("place: $Reason; nothing placed.")
    exit 2
}
function PlainFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return $item -and -not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}
# Every child: no shell, no window, all three standard streams redirected to this process. Output is drained and
# never shown; only the exit code counts.
function Start-Child([string]$Exe, [string]$Arguments, [hashtable]$Environment) {
    $info = [Diagnostics.ProcessStartInfo]::new($Exe, $Arguments)
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    foreach ($name in $Environment.Keys) { $info.EnvironmentVariables[$name] = $Environment[$name] }
    return [Diagnostics.Process]::Start($info)
}
function Finish($Child, [int]$Seconds) {
    if (-not $Child.WaitForExit($Seconds * 1000)) { $Child.Kill(); $Child.WaitForExit(); return -1 }
    $Child.WaitForExit()
    return $Child.ExitCode
}
# One value from the envelope, read from the child's stdout into one fixed buffer of the value's bound plus a line
# break: more bytes stop the child and refuse before anything is kept. One trailing LF or CRLF is dropped.
function Decrypt([string]$Key, [int]$Limit) {
    $child = Start-Child $sops ('--decrypt --input-type yaml --extract "[\"' + $Key + '\"]" "' + $Ciphertext + '"') @{ SOPS_AGE_KEY_FILE = $Identity }
    $buffer, $count = [byte[]]::new($Limit + 3), 0
    try {
        try { $child.StandardInput.BaseStream.Close() } catch { }
        try { $child.StandardInput.Close() } catch { }
        $null = $child.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        $stream = $child.StandardOutput.BaseStream
        while ($true) {
            $read = $stream.ReadAsync($buffer, $count, $buffer.Length - $count)
            if (-not $read.Wait(60000)) { try { $child.Kill() } catch { }; Refuse 'decryption did not finish' }
            if ($read.Result -le 0) { break }
            $count += $read.Result
            if ($count -gt $Limit + 2) { try { $child.Kill() } catch { }; Refuse 'the decrypted value exceeds its bound' }
        }
        if ((Finish $child 60) -ne 0) { Refuse 'decryption failed' }
        if ($count -gt 0 -and $buffer[$count - 1] -eq 10) { $count--; if ($count -gt 0 -and $buffer[$count - 1] -eq 13) { $count-- } }
        if ($count -gt $Limit) { Refuse 'the decrypted value exceeds its bound' }
        $value = [byte[]]::new($count)
        [Array]::Copy($buffer, $value, $count)
        return ,$value
    } finally {
        [Array]::Clear($buffer, 0, $buffer.Length)
        $child.Dispose()
    }
}
function Matches([byte[]]$Bytes, [string]$Pattern) {
    return [Text.Encoding]::GetEncoding(28591).GetString($Bytes) -cmatch $Pattern
}

$sops = Join-Path $PSScriptRoot 'sops.exe'
if (-not (PlainFile $sops)) { Refuse 'the pinned sops.exe is absent' }
if (-not (PlainFile $Identity)) { Refuse 'the target age identity is absent' }
if (-not $Ciphertext) { $Ciphertext = Join-Path $PSScriptRoot $(if ($Target -ceq 'client') { 'ciphertexts\dev-rent-client.sops.yaml' } else { 'ciphertexts\dev-rent-tunnel.sops.yaml' }) }
if (-not (PlainFile $Ciphertext)) { Refuse 'the envelope is absent' }
if ($Target -ceq 'client') {
    $win = if ($WindowsDist) { Join-Path $WindowsDist 'win.ps1' } else { '' }
    if (-not $win -or -not (PlainFile $win)) { Refuse 'the verified windows-dist win.ps1 is absent' }
    $exe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -NonInteractive -File "' + $win + '" -Mode RentAccess'
} else {
    if ($RentImage -cnotmatch '^ghcr\.io/roccho-dev/windows-rent@sha256:[0-9a-f]{64}\z') { Refuse 'the rent image is not one exact digest' }
    $script = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'rent-receive.sh'))
    # The receiver travels as one bash -c argument; it holds no quote or backslash to re-escape.
    if ($script.Contains('"') -or $script.Contains('\')) { Refuse 'the rent receiver is not argv-safe' }
    $exe = 'C:\Program Files\WSL\wslc.exe'
    $arguments = 'run --rm -i --volume windows-rent-state:/var/lib/rent ' + $RentImage + ' /bin/bash -c "' + $script + '"'
}

$payload = $null
try {
    if ($Target -ceq 'client') {
        $id = Decrypt 'RENT_ACCESS_CLIENT_ID' 1024
        $secret = Decrypt 'RENT_ACCESS_CLIENT_SECRET' 1024
        try {
            if (-not (Matches $id '^[!-~]{1,1024}\z') -or -not (Matches $secret '^[!-~]{1,1024}\z')) { Refuse 'the envelope is not one Access client credential' }
            $payload = [byte[]]::new($id.Length + $secret.Length + 2)
            [Array]::Copy($id, 0, $payload, 0, $id.Length)
            $payload[$id.Length] = 10
            [Array]::Copy($secret, 0, $payload, $id.Length + 1, $secret.Length)
            $payload[$payload.Length - 1] = 10
        } finally { [Array]::Clear($id, 0, $id.Length); [Array]::Clear($secret, 0, $secret.Length) }
    } else {
        $payload = Decrypt 'RENT_TUNNEL_TOKEN' 4096
        if (-not (Matches $payload '^[A-Za-z0-9+/=_-]{1,4096}\z')) { Refuse 'the envelope is not one tunnel token' }
    }
    # Windows PowerShell (.NET Framework) opens a child's redirected stdin with Console.InputEncoding and writes that
    # encoding's preamble at once: on a UTF-8 console a BOM would precede the value. Start the writer under a
    # preamble-free encoding, or refuse before anything is sent.
    $saved = [Console]::InputEncoding
    try { [Console]::InputEncoding = [Text.UTF8Encoding]::new($false) } catch { }
    try {
        if ([Console]::InputEncoding.GetPreamble().Length) { Refuse 'the console input encoding would prefix the value' }
        $writer = Start-Child $exe $arguments @{}
    } finally { try { [Console]::InputEncoding = $saved } catch { } }
    try {
        $null = $writer.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
        $null = $writer.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        try { $writer.StandardInput.BaseStream.Write($payload, 0, $payload.Length); $writer.StandardInput.BaseStream.Flush() } catch { }
        # End of input at the raw pipe; the unused StreamWriter is disposed after it.
        try { $writer.StandardInput.BaseStream.Close() } catch { }
        try { $writer.StandardInput.Close() } catch { }
        $code = Finish $writer 300
    } finally { $writer.Dispose() }
} finally {
    if ($null -ne $payload) { [Array]::Clear($payload, 0, $payload.Length) }
}
if ($code -ne 0) { [Console]::Error.WriteLine("place: the $Target writer exited $code; see the target's own state.") }
exit $code
