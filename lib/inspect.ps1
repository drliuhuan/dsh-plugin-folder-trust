param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Sid,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'

$GRANT_MASK = [int]1114454
$DENY_MASK = [int]64
$report = [ordered]@{
    path = $Path
    sid = $Sid
    exists = $false
    ok = $false
    writeDac = $false
    writeOwner = $false
    rootGrant = $false
    rootDeny = $false
    childDirs = 0
    childDirsWithGrant = 0
    childFiles = 0
    error = $null
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DshTrustProbe2 {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    public static int Open(string path, uint access) {
        IntPtr handle = CreateFileW(path, access, 7u, IntPtr.Zero, 3u, 0x02000000u, IntPtr.Zero);
        if (handle == new IntPtr(-1)) return Marshal.GetLastWin32Error();
        CloseHandle(handle);
        return 0;
    }
}
'@

function Get-AceSid($ace) {
    try { return $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $ace.IdentityReference.Value }
}

try {
    $info = New-Object System.IO.DirectoryInfo($Path)
    if (-not $info.Exists) { throw "not a directory: $Path" }
    $report.exists = $true

    $report.writeDac = ([DshTrustProbe2]::Open($Path, [uint32]0x00040000) -eq 0)
    $report.writeOwner = ([DshTrustProbe2]::Open($Path, [uint32]0x00080000) -eq 0)

    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $world = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $acl = $info.GetAccessControl()
    $report.rootGrant = @($acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        (Get-AceSid $_) -eq $sidObj.Value -and
        ([int]$_.FileSystemRights -band $GRANT_MASK) -eq $GRANT_MASK
    }).Count -gt 0
    $report.rootDeny = @($acl.Access | Where-Object {
        $_.AccessControlType -eq 'Deny' -and
        (Get-AceSid $_) -eq $world.Value -and
        ([int]$_.FileSystemRights -band $DENY_MASK) -eq $DENY_MASK
    }).Count -gt 0

    $dirs = @($info.GetDirectories())
    $report.childDirs = $dirs.Count
    $inherited = 0
    foreach ($child in $dirs) {
        try {
            $childAcl = $child.GetAccessControl()
            $has = @($childAcl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                (Get-AceSid $_) -eq $sidObj.Value -and
                ([int]$_.FileSystemRights -band $GRANT_MASK) -eq $GRANT_MASK
            }).Count -gt 0
            if ($has) { $inherited++ }
        } catch { }
    }
    $report.childDirsWithGrant = $inherited
    try { $report.childFiles = @($info.GetFiles()).Count } catch { }
    $report.ok = $true
} catch {
    $report.error = $_.Exception.Message
}

[System.IO.File]::WriteAllText($Out, ($report | ConvertTo-Json -Compress -Depth 4))

