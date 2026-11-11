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
    childrenRepaired = 0
    childrenFailed = 0
    childErrors = @()
    partial = $false
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
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetNamedSecurityInfoW(string name, int objectType, uint info,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetSecurityDescriptorSacl(IntPtr sd, out bool present, out IntPtr sacl, out bool defaulted);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetAclInformation(IntPtr acl, IntPtr info, uint size, uint infoClass);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetAce(IntPtr acl, uint index, out IntPtr ace);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalAlloc(uint flags, UIntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalFree(IntPtr handle);
}
'@

$GRANT_MASK = [int]1114454          # Write | Delete | FILE_DELETE_CHILD | Synchronize (DSH's AclWriteGrant mask)
$DENY_MASK = [int]64                # FILE_DELETE_CHILD
$LABEL_INFO = [uint32]0x00000010    # LABEL_SECURITY_INFORMATION
$DACL_INFO = [uint32]0x00000004     # DACL_SECURITY_INFORMATION
# 0x80000004 = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
# Decimal because PowerShell parses 0x80000004 as a negative Int32.
$DACL_INFO_PROTECTED = [uint32]2147483652
$SE_FILE_OBJECT = 1
$LOW_SID = [byte[]](0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00)  # S-1-16-4096

function Get-AceSid($ace) {
    try { return $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $ace.IdentityReference.Value }
}

function Set-Dacl([string]$target, $acl) {
    # Write ONLY this folder's DACL, by name, through SetNamedSecurityInfoW. The
    # Set-Acl cmdlet cannot be used here: on a folder whose DACL already carries the
    # protected ("inheritance disabled") flag it also writes the SACL and fails with
    # PrivilegeNotHeldException / SeSecurityPrivilege, even for the folder's owner.
    # Preserve the flag explicitly, or the write would silently re-enable inheritance.
    $bytes = $acl.GetSecurityDescriptorBinaryForm()
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
    try {
        [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)
        $present = $false
        $dacl = [IntPtr]::Zero
        $defaulted = $false
        if (-not [DshTrustLabel]::GetSecurityDescriptorDacl($ptr, [ref]$present, [ref]$dacl, [ref]$defaulted)) {
            throw "GetSecurityDescriptorDacl failed for $target"
        }
        if (-not $present -or $dacl -eq [IntPtr]::Zero) { throw "no DACL in the security descriptor for $target" }
        $info = if ($acl.AreAccessRulesProtected) { $DACL_INFO_PROTECTED } else { $DACL_INFO }
        $rc = [DshTrustLabel]::SetNamedSecurityInfoW($target, $SE_FILE_OBJECT, $info, [IntPtr]::Zero, [IntPtr]::Zero, $dacl, [IntPtr]::Zero)
        if ($rc -ne 0) { throw "SetNamedSecurityInfoW(dacl) failed for $target with $rc" }
    } finally {
        [void][System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    }
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

function Get-IntegrityState([string]$target) {
    # Reading the label does NOT need SeSecurityPrivilege; writing it does need
    # WRITE_OWNER. The check is here so a child that already inherited the label is
    # not rewritten (which would need WRITE_OWNER it may not have).
    $descriptor = [IntPtr]::Zero
    $rc = [DshTrustLabel]::GetNamedSecurityInfoW($target, $SE_FILE_OBJECT, $LABEL_INFO, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$descriptor)
    if ($rc -ne 0) { throw "GetNamedSecurityInfoW(label) failed for $target with $rc" }
    try {
        $present = $false
        $sacl = [IntPtr]::Zero
        $defaulted = $false
        if (-not [DshTrustLabel]::GetSecurityDescriptorSacl($descriptor, [ref]$present, [ref]$sacl, [ref]$defaulted)) { throw "GetSecurityDescriptorSacl failed for $target" }
        if (-not $present -or $sacl -eq [IntPtr]::Zero) { return 'none' }
        $sizeInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)
        try {
            if (-not [DshTrustLabel]::GetAclInformation($sacl, $sizeInfo, 12, 2)) { throw "GetAclInformation failed for $target" }
            $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($sizeInfo, 4)
            for ($i = 0; $i -lt $count; $i++) {
                $ace = [IntPtr]::Zero
                if (-not [DshTrustLabel]::GetAce($sacl, [uint32]$i, [ref]$ace)) { continue }
                if ([System.Runtime.InteropServices.Marshal]::ReadByte($ace) -ne 0x11) { continue }
                $policy = [System.Runtime.InteropServices.Marshal]::ReadInt32($ace, 4)
                $sid = (New-Object System.Security.Principal.SecurityIdentifier([IntPtr]::Add($ace, 8))).Value
                if ($sid -eq 'S-1-16-4096' -and (($policy -band 1) -eq 1)) { return 'low' }
                return 'other'
            }
            return 'other'
        } finally {
            [void][System.Runtime.InteropServices.Marshal]::FreeHGlobal($sizeInfo)
        }
    } finally {
        [void][DshTrustLabel]::LocalFree($descriptor)
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
    $acl = Get-Acl -LiteralPath $Path
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

    # 3. Write the DACL back BY NAME through SetNamedSecurityInfoW, which is what
    #    makes Windows propagate the inheritable ACEs to every existing child. A
    #    handle-based write would only change this one directory. The write uses the
    #    DACL-only helper because Set-Acl also writes the SACL and fails with
    #    SeSecurityPrivilege on a folder whose DACL is already protected.
    Set-Dacl $Path $acl
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
    Set-Dacl $Path $acl
    $acl.RemoveAccessRuleSpecific($probeRule)
    Set-Dacl $Path $acl
    # (the second write carries the final DACL, so the inherit pass leaves it correct)

    Log 'STEP 6/7 逐个子目录补齐 ACE 与标签'
    # 6. Children the pass still misses (protected or otherwise skipped) get the
    #    ACE and the label written directly, one by one: this is the last level
    #    that can drift, because both entries inherit downward from here.
    $repaired = 0
    $childFailures = @()
    try {
        foreach ($child in $info.GetDirectories()) {
            $failure = $null
            try {
                $childAcl = Get-Acl -LiteralPath $child.FullName
                $hasGrant = @($childAcl.Access | Where-Object {
                    (Get-AceSid $_) -eq $sidObj.Value -and
                    ([int]$_.FileSystemRights -band $GRANT_MASK) -eq $GRANT_MASK
                }).Count -gt 0
                $labelState = 'unknown'
                try { $labelState = Get-IntegrityState $child.FullName } catch { }
                $needsLabel = ($labelState -ne 'low')
                if (-not $hasGrant -or $needsLabel) {
                    if (-not $hasGrant) {
                        $childAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $sidObj,
                            [System.Security.AccessControl.FileSystemRights]$GRANT_MASK,
                            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                            [System.Security.AccessControl.PropagationFlags]'None',
                            [System.Security.AccessControl.AccessControlType]'Allow')))
                    }
                    $woRule = $null
                    if ($needsLabel) {
                        # Writing the Low label needs WRITE_OWNER, which an owner that
                        # only holds Modify does not have. Add TakeOwnership for the
                        # length of the write, then take it back out: the child keeps
                        # only the capability ACE.
                        $woRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $me,
                            [System.Security.AccessControl.FileSystemRights]'TakeOwnership',
                            [System.Security.AccessControl.AccessControlType]'Allow')
                        $childAcl.AddAccessRule($woRule)
                    }
                    Set-Dacl $child.FullName $childAcl
                    if (-not $hasGrant) {
                        $repaired++
                        Log ('CHILD ' + $child.Name + ' - ok')
                    }
                    if ($null -ne $woRule) {
                        try {
                            Set-LowLabel $child.FullName
                            Log ('CHILD ' + $child.Name + ' - label')
                        } finally {
                            # RemoveAccessRule (not ...Specific): AddAccessRule merged
                            # TakeOwnership into the existing Modify ACE, and only the
                            # right-level removal takes it back out.
                            $childAcl.RemoveAccessRule($woRule)
                            Set-Dacl $child.FullName $childAcl
                        }
                    }
                }
            } catch {
                $failure = $_.Exception.Message
            }
            if ($null -ne $failure) {
                $childFailures += [pscustomobject]@{ name = $child.Name; error = $failure }
                Log ('CHILD ' + $child.Name + ' - FAILED ' + $failure)
            }
        }
    } catch {
        $childFailures += [pscustomobject]@{ name = '<enumerate>'; error = $_.Exception.Message }
        Log ('CHILD enumeration failed: ' + $_.Exception.Message)
    }
    $result.childrenRepaired = $repaired
    $result.childrenFailed = @($childFailures).Count
    $result.childErrors = @($childFailures)
    $result.partial = (@($childFailures).Count -gt 0)

    Log ('STEP 7/7 校验：一级子目录 ' + $info.GetDirectories().Count + ' 个')
    # 7. Verify on a real descendant that inheritance reached past level one.
    $sample = $null
    try {
        $child = Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction Stop | Select-Object -First 1
        if ($null -ne $child) {
            $childAcl = Get-Acl -LiteralPath $child.FullName
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
    # A folder is only usable once the Low label is ON it: the sandbox's write token is a
    # Low-integrity, write-restricted one, so the capability grant alone is inert.
    # Writing the label needs WRITE_OWNER on the object, which this script has already
    # established by the time it gets here: the FullControl ACE added in step 1 includes
    # it, and the owner holds WRITE_DAC implicitly. SeSecurityPrivilege is NOT required
    # (measured: a folder owned by the signed-in account takes the label without any
    # elevation), so a failure here means the account really is missing the right —
    # a deny entry, or an owner that is somebody else — and only an elevation can help.
    if ($result.labelApplied -ne $true) {
        $detail = if ($result.labelError) { $result.labelError } else { 'unknown error' }
        $result.ok = $false
        $result.error = 'the Low integrity label could not be written: ' + $detail + ' — this account lacks change-owner rights on the folder, so an administrator has to repair it once, or the session has to switch to full access'
    } elseif ($result.childrenFailed -gt 0) {
        # The root is provisioned, but at least one immediate child is not. Say so
        # instead of leaving a folder the confined shell still refuses to write in.
        $first = @($result.childErrors)[0]
        $result.ok = $false
        $result.error = 'the workspace root is provisioned, but ' + $result.childrenFailed + ' immediate subfolder(s) could not be: ' + $first.name + ': ' + $first.error + ' — repair them as administrator, or move them out of the workspace'
    } else {
        $result.ok = $true
    }
    Log ('DONE 修复完成 ok=' + $result.ok)
} catch {
    $result.error = $_.Exception.Message
}

[System.IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Compress -Depth 4))





