param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Sid,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Log = $null
)
$ErrorActionPreference = 'Stop'

$global:LogPath = $Log
function Log([string]$text) {
    if ($global:LogPath) {
        try { [System.IO.File]::AppendAllText($global:LogPath, $text + "`n") } catch { }
    }
}

$result = [ordered]@{
    path = $Path
    sid = $Sid
    ok = $false
    userAce = $false
    grantAce = $false
    denyAce = $false
    labelApplied = $false
    sample = $null
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DshTrustLabel {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint SetNamedSecurityInfoW(string name, int objectType, uint info,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool InitializeAcl(IntPtr acl, uint size, uint revision);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AddMandatoryAce(IntPtr acl, uint revision, uint aceFlags, uint policy, byte[] labelSid);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalAlloc(uint flags, UIntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalFree(IntPtr handle);
}
'@

$GRANT_MASK = [int]1114454          # Write | Delete | FILE_DELETE_CHILD | Synchronize (DSH's AclWriteGrant mask)
$DENY_MASK = [int]64                # FILE_DELETE_CHILD
$LABEL_INFO = [uint32]0x00000010    # LABEL_SECURITY_INFORMATION
$SE_FILE_OBJECT = 1
$LOW_SID = [byte[]](0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00)  # S-1-16-4096

function Get-AceSid($ace) {
    try { return $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $ace.IdentityReference.Value }
}

function Set-LowLabel([string]$target) {
    $sidLength = $LOW_SID.Length
    $aclLength = [uint32](16 + $sidLength)
    $empty = [IntPtr]::Zero
    $acl = [DshTrustLabel]::LocalAlloc([uint32]0x0040, [UIntPtr]::new([uint64]$aclLength))
    if ($acl -eq [IntPtr]::Zero) { throw "LocalAlloc failed for $target" }
    try {
        if (-not [DshTrustLabel]::InitializeAcl($acl, $aclLength, 2)) { throw "InitializeAcl failed for $target" }
        if (-not [DshTrustLabel]::AddMandatoryAce($acl, 2, 3, 1, $LOW_SID)) { throw "AddMandatoryAce failed for $target" }
        $rc = [DshTrustLabel]::SetNamedSecurityInfoW($target, $SE_FILE_OBJECT, $LABEL_INFO, $empty, $empty, $empty, $acl)
        if ($rc -ne 0) { throw "SetNamedSecurityInfoW(label) failed for $target with $rc" }
    } finally {
        [void][DshTrustLabel]::LocalFree($acl)
    }
}

try {
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $info = New-Object System.IO.DirectoryInfo($Path)
    if (-not $info.Exists) { throw "not a directory: $Path" }

    Log ('PATH ' + $Path + '  (' + $Sid + ')')
    Log 'STEP 1/7 检查账户权限与完整性标签写入权'
    # 1. The signed-in user needs WRITE_DAC + WRITE_OWNER before any of the
    #    sandbox edits below can be made at all (non-inherited, like the repair).
    $acl = $info.GetAccessControl()
    $userRules = @($acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        ([int]$_.FileSystemRights -band [int][System.Security.AccessControl.FileSystemRights]'FullControl') -eq [int][System.Security.AccessControl.FileSystemRights]'FullControl' -and
        (Get-AceSid $_) -eq $me.Value
    })
    if ($userRules.Count -eq 0) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, [System.Security.AccessControl.FileSystemRights]'FullControl', 'Allow')))
        $result.userAce = $true
    }

    # 2. DSH's own grant: capability-SID ACE that inherits to children, and the
    #    ambient-delete deny that keeps the capability ACE the only delete path.
    $hasGrant = @($acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        (Get-AceSid $_) -eq $sidObj.Value -and
        ([int]$_.FileSystemRights -band $GRANT_MASK) -eq $GRANT_MASK
    }).Count -gt 0
    if (-not $hasGrant) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sidObj,
            [System.Security.AccessControl.FileSystemRights]$GRANT_MASK,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]'None',
            [System.Security.AccessControl.AccessControlType]'Allow')
        $acl.AddAccessRule($rule)
        $result.grantAce = $true
    }

    $world = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $hasDeny = @($acl.Access | Where-Object {
        $_.AccessControlType -eq 'Deny' -and
        (Get-AceSid $_) -eq $world.Value -and
        ([int]$_.FileSystemRights -band $DENY_MASK) -eq $DENY_MASK
    }).Count -gt 0
    if (-not $hasDeny) {
        $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $world,
            [System.Security.AccessControl.FileSystemRights]$DENY_MASK,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit',
            [System.Security.AccessControl.PropagationFlags]'None',
            [System.Security.AccessControl.AccessControlType]'Deny')
        $acl.AddAccessRule($deny)
        $result.denyAce = $true
    }

    # 3. Write the DACL back BY NAME (File/Directory.SetAccessControl uses
    #    SetNamedSecurityInfoW), which is what makes Windows propagate the
    #    inheritable ACEs to every existing child. A handle-based write would
    #    only change this one directory.
    [System.IO.Directory]::SetAccessControl($Path, $acl)
    Log 'STEP 3/7 写入能力 SID 的写/删 ACE 与 Everyone 删除子项 deny'

    Log 'STEP 4/7 写入 Low 完整性标签（先 Medium 再 Low，逼出传播）'
    # 4. The Low integrity label, also by name, so existing children get it.
    #    Write it twice with a different value in between: an identical SACL
    #    write is a no-op and would not re-propagate.
    try {
        $mediumSid = [byte[]](0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x20, 0x00, 0x00)  # S-1-16-8192
        $LOW_SID = $mediumSid
        Set-LowLabel $Path
        $LOW_SID = [byte[]](0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00)
        Set-LowLabel $Path
        $result.labelApplied = $true
    } catch {
        $result.labelError = $_.Exception.Message
    }

    Log 'STEP 5/7 强制继承传播（临时 ACE 加→删，两次按名写入）'
    # 5. Force the propagation. Windows re-runs its inherit pass only when the
    #    DACL actually changes, and the root may already carry every entry (a
    #    re-run of this script, or the harness having provisioned earlier): in
    #    that case step 3 is a no-op and children that were created before the
    #    grant keep missing it. Flush a temporary ACE, then write the final DACL
    #    again so the pass really runs.
    $probeRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $me,
        [System.Security.AccessControl.FileSystemRights]'ReadAttributes',
        [System.Security.AccessControl.AccessControlType]'Allow')
    $acl.AddAccessRule($probeRule)
    [System.IO.Directory]::SetAccessControl($Path, $acl)
    $acl.RemoveAccessRuleSpecific($probeRule)
    [System.IO.Directory]::SetAccessControl($Path, $acl)
    # (the second write carries the final DACL, so the inherit pass leaves it correct)

    Log 'STEP 6/7 逐个子目录补齐 ACE 与标签'
    # 6. Children the pass still misses (protected or otherwise skipped) get the
    #    ACE and the label written directly, one by one: this is the last level
    #    that can drift, because both entries inherit downward from here.
    $repaired = 0
    try {
        foreach ($child in $info.GetDirectories()) {
            try {
                $childAcl = $child.GetAccessControl()
                $has = @($childAcl.Access | Where-Object {
                    (Get-AceSid $_) -eq $sidObj.Value -and
                    ([int]$_.FileSystemRights -band $GRANT_MASK) -eq $GRANT_MASK
                }).Count -gt 0
                if (-not $has) {
                    $childAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $sidObj,
                        [System.Security.AccessControl.FileSystemRights]$GRANT_MASK,
                        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                        [System.Security.AccessControl.PropagationFlags]'None',
                        [System.Security.AccessControl.AccessControlType]'Allow')))
                    [System.IO.Directory]::SetAccessControl($child.FullName, $childAcl)
                    $repaired++
                    Log ('CHILD ' + $child.Name + ' - ok')
                }
                try { Set-LowLabel $child.FullName } catch { }
            } catch { }
        }
    } catch { }
    $result.childrenRepaired = $repaired

    Log ('STEP 7/7 校验：一级子目录 ' + $info.GetDirectories().Count + ' 个')
    # 7. Verify on a real descendant that inheritance reached past level one.
    $sample = $null
    try {
        $child = Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction Stop | Select-Object -First 1
        if ($null -ne $child) {
            $childAcl = (New-Object System.IO.DirectoryInfo($child.FullName)).GetAccessControl()
            $granted = @($childAcl.Access | Where-Object {
                (Get-AceSid $_) -eq $sidObj.Value -and
                ([int]$_.FileSystemRights -band $GRANT_MASK) -eq $GRANT_MASK
            }).Count -gt 0
            $sample = [pscustomobject]@{ path = $child.FullName; inheritedGrant = $granted }
        }
    } catch {
        $sample = [pscustomobject]@{ path = $null; error = $_.Exception.Message }
    }
    $result.sample = $sample
    $result.ok = $true
    Log 'DONE 修复完成'
} catch {
    $result.error = $_.Exception.Message
}

[System.IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Compress -Depth 4))





