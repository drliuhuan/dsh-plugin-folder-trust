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
    protected = $false
    owner = $null
    ownerName = $null
    ownerKind = 'unknown'
    rootGrant = $false
    rootDeny = $false
    lowLabel = 'unknown'
    labelError = $null
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

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DshTrustLabelRead {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetNamedSecurityInfoW(string name, int objectType, uint info,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetSecurityDescriptorSacl(IntPtr descriptor, out bool present, out IntPtr sacl, out bool defaultValue);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetAclInformation(IntPtr acl, IntPtr info, uint size, uint infoClass);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetAce(IntPtr acl, uint index, out IntPtr ace);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr handle);
}
'@

# The Low integrity label is HALF of a usable grant, and the half this plugin used
# to assume: `@deepseek-ai/dsh-sandbox-windows-acl` calls a folder provisioned only
# when the capability grant, the Everyone deny AND the Low no-write-up label are all
# present. Reading a label does NOT need SeSecurityPrivilege (only writing one does),
# so the state can be diagnosed without it.
$LABEL_INFO = [uint32]0x00000010
$LOW_SID = 'S-1-16-4096'
$NO_WRITE_UP = 0x1

function Get-IntegrityState([string]$target) {
    $descriptor = [IntPtr]::Zero
    $rc = [DshTrustLabelRead]::GetNamedSecurityInfoW($target, 1, $LABEL_INFO, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$descriptor)
    if ($rc -ne 0) { throw "GetNamedSecurityInfoW failed with $rc" }
    try {
        $present = $false; $sacl = [IntPtr]::Zero; $defaulted = $false
        if (-not [DshTrustLabelRead]::GetSecurityDescriptorSacl($descriptor, [ref]$present, [ref]$sacl, [ref]$defaulted)) { throw 'GetSecurityDescriptorSacl failed' }
        if (-not $present -or $sacl -eq [IntPtr]::Zero) { return 'none' }
        $sizeInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)
        try {
            if (-not [DshTrustLabelRead]::GetAclInformation($sacl, $sizeInfo, 12, 2)) { throw 'GetAclInformation failed' }
            $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($sizeInfo, 4)
            for ($i = 0; $i -lt $count; $i++) {
                $ace = [IntPtr]::Zero
                if (-not [DshTrustLabelRead]::GetAce($sacl, [uint32]$i, [ref]$ace)) { continue }
                if ([System.Runtime.InteropServices.Marshal]::ReadByte($ace) -ne 0x11) { continue }
                $policy = [System.Runtime.InteropServices.Marshal]::ReadInt32($ace, 4)
                $sid = (New-Object System.Security.Principal.SecurityIdentifier([IntPtr]::Add($ace, 8))).Value
                if ($sid -eq $LOW_SID -and (($policy -band $NO_WRITE_UP) -eq $NO_WRITE_UP)) { return 'low' }
                return 'other'
            }
            return 'other'
        } finally { [void][System.Runtime.InteropServices.Marshal]::FreeHGlobal($sizeInfo) }
    } finally { [void][DshTrustLabelRead]::LocalFree($descriptor) }
}

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

    # Who owns the folder decides HOW the missing right can be repaired. Windows
    # always grants the owner implicit READ_CONTROL and WRITE_DAC, so a folder
    # whose owner is the signed-in account never needs help — but an account SID
    # that no longer resolves on this machine (a folder copied from another PC)
    # is an owner nobody can inherit rights from, and only an approved elevation
    # can rewrite that DACL. Classifying the owner here lets the browser say why
    # instead of repeating "permission denied".
    $acl = Get-Acl -LiteralPath $Path
    $report.protected = [bool]$acl.AreAccessRulesProtected
    $meSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # Get-Acl is inconsistent by design: it returns a *display name*
    # ("NT AUTHORITY\SYSTEM", "PC\User") when the SID resolves on this machine, and
    # the SDDL form ("O:S-1-5-21-...") only when it does not. Both must classify.
    $ownerValue = ([string]$acl.Owner) -replace '^O:', ''
    $report.owner = $ownerValue
    $report.ownerName = $ownerValue
    if ($ownerValue.Length -gt 0) {
        try {
            if ($ownerValue -match '^S-1-') {
                $ownerIdentity = New-Object System.Security.Principal.SecurityIdentifier($ownerValue)
            } else {
                $ownerIdentity = (New-Object System.Security.Principal.NTAccount($ownerValue)).Translate([System.Security.Principal.SecurityIdentifier])
            }
            $report.owner = $ownerIdentity.Value
            try { $report.ownerName = $ownerIdentity.Translate([System.Security.Principal.NTAccount]).Value }
            catch { $report.ownerName = $ownerIdentity.Value }
            if ($ownerIdentity.Value -eq $meSid) { $report.ownerKind = 'current' }
            elseif ($ownerIdentity.Value -eq 'S-1-5-18' -or $ownerIdentity.Value.StartsWith('S-1-5-32-')) { $report.ownerKind = 'system' }
            elseif ($report.ownerName -eq $ownerIdentity.Value) { $report.ownerKind = 'foreign' }
            else { $report.ownerKind = 'local-other' }
        } catch {
            $report.ownerKind = 'unknown'
        }
    }

    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $world = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
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
            $childAcl = Get-Acl -LiteralPath $child.FullName
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
    try { $report.lowLabel = Get-IntegrityState($Path) }
    catch {
        $report.lowLabel = 'unknown'
        $report.labelError = $_.Exception.Message
    }
    $report.ok = $true
} catch {
    $report.error = $_.Exception.Message
}

[System.IO.File]::WriteAllText($Out, ($report | ConvertTo-Json -Compress -Depth 4))

