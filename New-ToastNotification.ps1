<#
.SYNOPSIS
    Displays customizable toast notifications on Windows 10/11 systems, supporting a wide range of configuration options.

.DESCRIPTION
    The Toast Notification Script is a comprehensive PowerShell solution for displaying rich toast notifications to end users on Windows 10/11.
    It is highly configurable via an XML configuration file, allowing organizations to tailor notifications for various scenarios such as OS upgrades, pending reboots, password expirations, and more.

    The script supports:
      - Multiple action buttons (up to three), each with custom actions (protocols, scripts, etc.).
      - Dismiss and snooze buttons, with logic to prevent conflicting or excessive button combinations.
      - Dynamic content, including deadlines, device uptime, and AD password expiration, all localized via multi-language support.
      - Custom branding with hero and logo images, including support for downloading images from URLs.
      - Integration with ConfigMgr (Software Center), PowerShell, or a custom notification app for notification delivery.
      - Registry and file system checks to ensure prerequisites are met and to prevent excessive notification frequency.
      - Logging of all actions and errors for troubleshooting and auditing.
      - **Automatic conversion of PowerShell script paths to base64** for use with ToastRunPSScript actions, ensuring secure and correct execution of custom scripts from the notification.

    **Process Overview:**
    1. **Initialization:**
       The script sets up global variables, checks for required folders and registry paths, and loads the XML configuration file (local or remote).
    2. **Configuration Parsing:**
       It parses the XML to extract feature toggles, button states, text content, image paths, and other options. Multi-language support is handled here.
    3. **Validation:**
       The script performs extensive validation to prevent conflicting options (e.g., multiple mutually exclusive features enabled), and ensures required files and registry keys exist.
    4. **Dynamic Content Preparation:**
       Depending on enabled features, it gathers dynamic data such as device uptime, AD password expiration, or deadline information from WMI/ConfigMgr.
    5. **Button Logic:**
       The script dynamically constructs the set of action and dismiss buttons based on the configuration, ensuring only valid combinations are presented. If no buttons are enabled, it defaults to enabling ActionButton1.
    6. **Toast XML Construction:**
       It builds the toast notification XML, inserting images, text, and the correct set of buttons. Special cases (like snooze or deadline) are handled with additional XML sections.
    7. **Display:**
       The notification is displayed using the appropriate app context (ConfigMgr, PowerShell, or custom app). If running as SYSTEM, it uses a helper script to display as the user.
    8. **Post-Display Actions:**
       Optionally, custom audio can be played, and the last run time is saved to the registry to enforce notification frequency limits.

    **Note:**
    - The script now automatically converts the PowerShell script path specified for ToastRunPSScript actions into a base64-encoded command, ensuring secure and reliable execution.

.PARAMETER Config
    Path to the XML configuration file. Can be a local path or a URL. If not specified, defaults to 'config-toast.xml' in the script directory.

.EXAMPLE
    .\New-ToastNotification.ps1 -Config 'C:\Scripts\config-toast.xml'

    Runs the script using the specified local configuration file.

.NOTES
    - Requires Windows 10/11.
    - Extensive logging is written to $env:AppData\ToastNotification\log\ToastNotification.log.

.LINK
   - https://github.com/imabdk/Toast-Notification-Script
   - https://www.imab.dk/windows-10-toast-notification-script/
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Path to XML Configuration File')]
    [string]$Config
)

#region Logging
# This region contains functions related to logging script activities.

<#
.SYNOPSIS
    Writes a message to a log file with a specified level.

.DESCRIPTION
    Logs messages to a file, supporting Info, Warn, and Error levels. If the log file exceeds 5MB, it is deleted and recreated. Creates the log file if it doesn't exist.

.PARAMETER Message
    The message to be logged.

.PARAMETER Path
    The path to the log file. Defaults to "$env:AppData\ToastNotification\log\ToastNotification.log".

.PARAMETER Level
    The log level: 'Info', 'Warn', or 'Error'. Defaults to 'Info'.

.EXAMPLE
    Write-ToastLog -Message 'Script started' -Level 'Info'
#>
function Write-ToastLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('LogContent')]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [Alias('LogPath')]
        [string]$Path = "$env:AppData\ToastNotification\log\ToastNotification.log",
        [Parameter(Mandatory = $false)]
        [ValidateSet('Error', 'Warn', 'Info')]
        [string]$Level = 'Info'
    )
    Begin {
        $VerbosePreference = 'Continue'
    }
    Process {
        if (Test-Path $Path) {
            $LogSize = (Get-Item -Path $Path).Length / 1MB
            $MaxLogSize = 5
        }
        if ((Test-Path $Path) -and $LogSize -gt $MaxLogSize) {
            Write-Error "Log file $Path already exists and file exceeds maximum file size. Deleting the log and starting fresh."
            Remove-Item $Path -Force
            New-Item $Path -Force -ItemType File | Out-Null
        } elseif (-not (Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            New-Item $Path -Force -ItemType File | Out-Null
        }
        $FormattedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
            }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
            }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
            }
        }
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End {
    }
}
#endregion

#region System and Environment Checks
# This region contains functions that perform various system state and environment checks.

<#
.SYNOPSIS
    Checks for pending reboots in the registry.

.DESCRIPTION
    Examines specific registry keys to determine if a reboot is pending due to component-based servicing, Windows Update, or file rename operations.

.EXAMPLE
    Test-PendingRebootRegistry
#>
function Test-PendingRebootRegistry {
    Write-ToastLog -Message 'Running Test-PendingRebootRegistry function'
    $CBSRebootKey = Get-ChildItem 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Ignore
    $WURebootKey = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Ignore
    if (($CBSRebootKey) -or ($WURebootKey)) {
        Write-ToastLog -Message 'Check returned TRUE on ANY of the registry checks: Reboot is pending!'
        $true
    } else {
        Write-ToastLog -Message 'Check returned FALSE on ANY of the registry checks: Reboot is NOT pending!'
        $false
    }
}

<#
.SYNOPSIS
    Checks for pending reboots using WMI.

.DESCRIPTION
    Uses the ConfigMgr client SDK via WMI to determine if a reboot is pending. Requires the ConfigMgr client to be installed.

.EXAMPLE
    Test-PendingRebootWMI
#>
function Test-PendingRebootWMI {
    Write-ToastLog -Message 'Running Test-PendingRebootWMI function'
    if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
        Write-ToastLog -Message 'Computer has ConfigMgr client installed - checking for pending reboots in WMI'
        $Util = [wmiclass]'\\.\root\ccm\clientsdk:CCM_ClientUtilities'
        $Status = $Util.DetermineIfRebootPending()
        if (($Status) -and ($Status.RebootPending -eq $True)) {
            Write-ToastLog -Message 'Check returned TRUE on checking WMI for pending reboot: Reboot is pending!'
            $true
        } else {
            Write-ToastLog -Message 'Check returned FALSE on checking WMI for pending reboot: Reboot is NOT pending!'
            $false
        }
    } else {
        Write-ToastLog -Level Error -Message 'Computer has no ConfigMgr client installed - skipping checking WMI for pending reboots'
        $false
    }
}

<#
.SYNOPSIS
    Retrieves the device's uptime in days.

.DESCRIPTION
    Calculates the number of days since the last system boot using CIM.

.EXAMPLE
    Get-DeviceUptime
#>
function Get-DeviceUptime() {
    Write-ToastLog -Message 'Running Get-DeviceUptime function'
    $OS = Get-CimInstance Win32_OperatingSystem
    $Uptime = (Get-Date) - ($OS.LastBootUpTime)
    $Uptime.Days
}

<#
.SYNOPSIS
    Verifies if the system is running a supported Windows version.

.DESCRIPTION
    Checks if the OS is Windows 10 or 11 and a workstation type. Returns $true if supported, $false otherwise.

.EXAMPLE
    Get-WindowsVersion
#>
function Get-WindowsVersion {
    $OS = Get-CimInstance Win32_OperatingSystem
    if (($OS.Version -like '10.0.*') -and ($OS.ProductType -eq 1)) {
        Write-ToastLog -Message 'Running supported version of Windows. Windows 10 and workstation OS detected'
        $true
    } elseif ($OS.Version -notlike '10.0.*') {
        Write-ToastLog -Level Error -Message 'Not running supported version of Windows'
        $false
    } else {
        Write-ToastLog -Level Error -Message 'Not running supported version of Windows'
        $false
    }
}

<#
.SYNOPSIS
    Tests if Windows push notifications are enabled for the user.

.DESCRIPTION
    Checks the registry to see if toast notifications are enabled for the current user.

.EXAMPLE
    Test-WindowsPushNotificationsEnabled
#>
function Test-WindowsPushNotificationsEnabled {
    $ToastEnabledKey = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name ToastEnabled -ErrorAction Ignore).ToastEnabled
    if ($ToastEnabledKey -eq '1') {
        Write-ToastLog -Message 'Toast notifications for the logged on user are enabled in Windows'
        $true
    } elseif ($ToastEnabledKey -eq '0') {
        Write-ToastLog -Level Error -Message 'Toast notifications for the logged on user are not enabled in Windows. The script will try to enable toast notifications for the logged on user'
        $false
    }
}

<#
.SYNOPSIS
    Enables Windows push notifications for the user.

.DESCRIPTION
    Modifies the registry and restarts the Windows Push Notification service to enable toast notifications.

.EXAMPLE
    Enable-WindowsPushNotification
#>
function Enable-WindowsPushNotification {
    $ToastEnabledKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications'
    Write-ToastLog -Message 'Trying to enable toast notifications for the logged on user'
    try {
        Set-ItemProperty -Path $ToastEnabledKeyPath -Name ToastEnabled -Value 1 -Force
        Get-Service -Name WpnUserService** | Restart-Service -Force
        Write-ToastLog -Message 'Successfully enabled toast notifications for the logged on user'
    } catch {
        Write-ToastLog -Level Error -Message 'Failed to enable toast notifications for the logged on user. Toast notifications will probably not be displayed'
    }
}

<#
.SYNOPSIS
    Determines if the script is running under the SYSTEM account.

.DESCRIPTION
    Checks the current security principal to identify if the script is running as SYSTEM or a user.

.EXAMPLE
    Test-NTSystem
#>
function Test-NTSystem {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentUser.IsSystem -eq $true) {
        Write-ToastLog -Message 'Script is initially running in SYSTEM context. Please be vary, that this has limitations and may not work!'
        $true
    } elseif ($currentUser.IsSystem -eq $false) {
        Write-ToastLog -Message 'Script is initially running in USER context'
        $false
    }
}
#endregion

#region User and AD Information
# This region contains functions that retrieve user-specific information from Active Directory or the system.

<#
.SYNOPSIS
    Retrieves the user's given name.

.DESCRIPTION
    Attempts to get the user's given name from Active Directory, falling back to registry data if AD is unavailable.

.EXAMPLE
    Get-GivenName
#>
function Get-GivenName {
    Write-ToastLog -Message 'Running Get-GivenName function'
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $PrincipalContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain, [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())
        $GivenName = ([System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($PrincipalContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, [Environment]::UserName)).GivenName
        $PrincipalContext.Dispose()
    } catch [System.Exception] {
        Write-ToastLog -Level Warn -Message "$_"
    }
    if (-not [string]::IsNullOrEmpty($GivenName)) {
        Write-ToastLog -Message "Given name retrieved from Active Directory: $GivenName"
        $GivenName
    } elseif ([string]::IsNullOrEmpty($GivenName)) {
        Write-ToastLog -Message 'Given name not found in AD or no local AD is available. Continuing looking for given name elsewhere'
        $RegKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
        if ((Get-ItemProperty $RegKey).LastLoggedOnDisplayName) {
            $LoggedOnUserDisplayName = Get-ItemProperty -Path $RegKey -Name 'LastLoggedOnDisplayName' | Select-Object -ExpandProperty LastLoggedOnDisplayName
            if (-not [string]::IsNullOrEmpty($LoggedOnUserDisplayName)) {
                $DisplayName = $LoggedOnUserDisplayName.Split(' ')
                $GivenName = $DisplayName[0]
                Write-ToastLog -Message "Given name found directly in registry: $GivenName"
                $GivenName
            } else {
                Write-ToastLog -Message 'Given name not found in registry. Using nothing as placeholder'
                $GivenName = $null
            }
        } else {
            Write-ToastLog -Message 'Given name not found in registry. Using nothing as placeholder'
            $GivenName = $null
        }
    }
}

<#
.SYNOPSIS
    Checks if the user's AD password is nearing expiration.

.DESCRIPTION
    Queries AD to determine the password expiration date and compares it against a specified threshold in days.

.PARAMETER fADPasswordExpirationDays
    The number of days within which to check for password expiration.

.EXAMPLE
    Get-ADPasswordExpiration -fADPasswordExpirationDays "14"
#>
function Get-ADPasswordExpiration {
    Param (
        [Parameter(Mandatory)]
        [string]$fADPasswordExpirationDays
    )
    Write-ToastLog -Message 'Running Get-ADPasswordExpiration function'
    try {
        Write-ToastLog -Message 'Looking up SamAccountName and DomainName in local Active Directory'
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $PrincipalContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain, [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())
        $SamAccountName = ([System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($PrincipalContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, [Environment]::UserName)).SamAccountName
        $DomainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
        $PrincipalContext.Dispose()
    } catch [System.Exception] {
        Write-ToastLog -Level Error -Message "$_"
    }
    if (($SamAccountName) -and ($DomainName)) {
        Write-ToastLog -Message "SamAccountName found: $SamAccountName and DomainName found: $DomainName. Continuing looking for AD password expiration date"
        try {
            $Root = [ADSI] "LDAP://$($DomainName)"
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($Root, "(SamAccountName = $($SamAccountName))")
            $Searcher.PropertiesToLoad.Add('msDS-UserPasswordExpiryTimeComputed') | Out-Null
            $Result = $Searcher.FindOne();
            $ExpiryDate = [DateTime]::FromFileTime([Int64]::Parse((($Result.Properties['msDS-UserPasswordExpiryTimeComputed'])[0]).ToString()))
        } catch {
            Write-ToastLog -Level Error -Message 'Failed to retrieve password expiration date from Active Directory. Script is continuing, but without password expiration date'
        }
        if ($ExpiryDate) {
            Write-ToastLog -Message "Password expiration date found. Password is expiring on $ExpiryDate. Calculating time to expiration"
            $LocalCulture = Get-Culture
            $RegionDateFormat = [System.Globalization.CultureInfo]::GetCultureInfo($LocalCulture.LCID).DateTimeFormat.LongDatePattern
            $ExpiryDate = Get-Date $ExpiryDate -f "$RegionDateFormat"
            $Today = Get-Date -f "$RegionDateFormat"
            $DateDiff = New-TimeSpan -Start $Today -End $ExpiryDate
            if ($DateDiff.Days -le $fADPasswordExpirationDays -and $DateDiff.Days -ge 0) {
                Write-ToastLog -Message 'Password is expiring within the set period. Returning True'
                Write-ToastLog -Message "ADPasswordExpirationDays is set to: $fADPasswordExpirationDays"
                $true
                $ExpiryDate
                $DateDiff
            } else {
                Write-ToastLog -Message 'Password is not expiring anytime soon. Returning False'
                Write-ToastLog -Message "ADPasswordExpirationDays is set to: $fADPasswordExpirationDays"
                $false
            }
        } elseif (-not ($ExpiryDate)) {
            Write-ToastLog -Level Error -Message 'No password expiration date found. Returning False'
            $false
        }
    } elseif (-not ($SamAccountName) -or ($DomainName)) {
        Write-ToastLog -Level Error -Message 'Failed to retrieve SamAccountName or DomainName from local Active Directory. Script is continuing, but password expiration date cannot be retrieved'
        $false
    }
}
#endregion

#region ConfigMgr Integration
# This region contains functions that integrate with Configuration Manager (ConfigMgr) for tasks like deadlines and software deployment.

<#
.SYNOPSIS
    Retrieves a dynamic deadline from ConfigMgr.

.DESCRIPTION
    Fetches deadline information from WMI based on PackageID, UpdateID, or ApplicationID, if the ConfigMgr client is present.

.EXAMPLE
    Get-DynamicDeadline
#>
function Get-DynamicDeadline {
    Write-ToastLog -Message 'Running Get-DynamicDeadline function. Trying to get deadline details from WMI and ConfigMgr'
    if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
        if ($RunPackageIDEnabled -eq 'True') {
            Write-ToastLog -Message 'RunPackageIDEnabled is True. Trying to get deadline information based on package id'
            try {
                $PackageID = Get-CimInstance -Namespace root\ccm\clientsdk -Query "SELECT * FROM CCM_Program where PackageID = '$DynDeadlineValue'"
            } catch {
                Write-ToastLog -Level Error -Message 'Failed to get Package ID from WMI'
            }
        } elseif ($RunUpdateIDEnabled -eq 'True') {
            Write-ToastLog -Message 'RunUpdateIDEnabled is True. Trying to get deadline information based on update id'
            $UpdateID = Get-CMUpdate
        } elseif ($RunApplicationIDEnabled -eq 'True') {
            Write-ToastLog -Message 'RunApplicationIDEnabled is True. Trying to get deadline information based on application id'
            try {
                $ApplicationID = Get-CimInstance -Namespace root\ccm\clientsdk -Query "SELECT * FROM CCM_Application where ID = '$DynDeadlineValue'"
            } catch {
                Write-ToastLog -Level Error -Message 'Failed to get Application ID from WMI'
            }
        } else {
            Write-ToastLog -Level Error -Message 'Currently no option enabled within the toast configuration which supports getting the deadline retrieved dynamically'
            Write-ToastLog -Level Error -Message 'This currently only works for packages/task sequences and software updates'
        }

        if (-not [string]::IsNullOrEmpty($PackageID)) {
            Write-ToastLog -Message "PackageID retrieved. PackageID is: $DynDeadlineValue. Now getting deadline date and time"
            $Deadline = ($PackageID | Where-Object {$_.Deadline -gt (Get-Date).AddDays(-1)} | Measure-Object -Property Deadline -Minimum).Minimum
            if ($Deadline) {
                Write-ToastLog -Message "Deadline date and time successfully retrieved from WMI. Deadline is: $Deadline"
                $Deadline.ToUniversalTime()
            } else {
                Write-ToastLog -Level Error -Message 'Failed to get deadline date and time from WMI'
                Write-ToastLog -Level Error -Message 'Please check if there really is a deadline configured'
                Write-ToastLog -Level Error -Message 'The script is continuing, but the toast is displayed without deadline date and time'
            }
        } elseif (-not [string]::IsNullOrEmpty($UpdateID)) {
            Write-ToastLog -Message "Update ID retrieved. Update ID is: $DynDeadlineValue. Now getting deadline date and time"
            if (-not [string]::IsNullOrEmpty($UpdateID.Deadline)) {
                Write-ToastLog -Message "Deadline date and time successfully retrieved from WMI. Deadline is: $($UpdateID.Deadline)"
                $UpdateID.Deadline.ToUniversalTime()
            } else {
                Write-ToastLog -Level Error -Message 'Failed to get deadline date and time from WMI'
                Write-ToastLog -Level Error -Message 'Please check if there really is a deadline configured'
                Write-ToastLog -Level Error -Message 'The script is continuing, but the toast is displayed without deadline date and time'
            }
        } elseif (-not [string]::IsNullOrEmpty($ApplicationID)) {
            Write-ToastLog -Message "Application ID retrieved. Application ID is: $DynDeadlineValue. Now getting deadline date and time"
            if (-not [string]::IsNullOrEmpty($ApplicationID.Deadline)) {
                Write-ToastLog -Message "Deadline date and time successfully retrieved from WMI. Deadline is: $($ApplicationID.Deadline)"
                $ApplicationID.Deadline.ToUniversalTime()
            } else {
                Write-ToastLog -Level Error -Message 'Failed to get deadline date and time from WMI'
                Write-ToastLog -Level Error -Message 'Please check if there really is a deadline configured'
                Write-ToastLog -Level Error -Message 'The script is continuing, but the toast is displayed without deadline date and time'
            }
        } else {
            Write-ToastLog -Level Warn -Message "Appears that the specified Package ID or Update ID or Application ID: $DynDeadlineValue is not deployed to the device"
        }
    } else {
        Write-ToastLog -Level Error -Message 'ConfigMgr service not found. This function requires the ConfigMgr client to be installed'
    }
}

<#
.SYNOPSIS
    Retrieves software update information from ConfigMgr.

.DESCRIPTION
    Queries WMI for a specific software update based on ArticleID and title, returning the update object if available.

.EXAMPLE
    Get-CMUpdate
#>
function Get-CMUpdate {
    Write-ToastLog -Message 'Running Get-CMUpdate function'
    if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
        try {
            $GetCMUpdate = Get-CimInstance -Namespace root\ccm\clientSDK -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ArticleID = '$RunUpdateIDValue' AND Name LIKE '%$RunUpdateTitleValue%'"
        } catch {
            Write-ToastLog -Level Error -Message 'Failed to retrieve UpdateID from WMI with the CM client'
        }
        if (-not [string]::IsNullOrEmpty($GetCMUpdate)) {
            switch ($GetCMUpdate.EvaluationState) {
                0 { $EvaluationState = 'None' }
                1 { $EvaluationState = 'Available' }
                2 { $EvaluationState = 'Submitted' }
                7 { $EvaluationState = 'Installing' }
                8 { $EvaluationState = 'Reboot' }
                9 { $EvaluationState = 'Reboot' }
                13 { $EvaluationState = 'Error' }
            }
            if ($EvaluationState -eq 'None' -or $EvaluationState -eq 'Available' -or $EvaluationState -eq 'Submitted') {
                Write-ToastLog -Level Info -Message "Found update that matches UpdateID: $($GetCMUpdate.ArticleID) and name: $($GetCMUpdate.Name)"
                $GetCMUpdate
            } elseif ($EvaluationState -eq 'Error') {
                Write-ToastLog -Message "UpdateID: $($GetCMUpdate.ArticleID) is in evaluation state: $EvaluationState. Retrying installation"
                $GetCMUpdate
            } else {
                Write-ToastLog -Level Error -Message "EvalutationState of UpdateID: $($GetCMUpdate.ArticleID) is not set to available. EvaluationState is: $EvaluationState"
                Write-ToastLog -Level Error -Message "Script will exit here. Not displaying toast notification when when EvaluationState is: $EvaluationState"
                Exit 1
            }
        } else {
            Write-ToastLog -Level Error -Message "Specified update was not found on system. UpdateID: $RunUpdateIDValue and name: $RunUpdateTitleValue. Please check deployment in ConfigMgr"
            Write-ToastLog -Level Error -Message 'Script will exit here. Not displaying toast notification when specified update is not deployed'
            Exit 1
        }
    } else {
        Write-ToastLog -Level Error -Message 'ConfigMgr service not found. This function requires the ConfigMgr client to be installed'
    }
}

#region Custom Action Setup
# This region contains functions that set up custom actions for toast notification buttons.

<#
.SYNOPSIS
    Registers custom action protocols in the registry.

.DESCRIPTION
    Creates registry entries for custom protocols (e.g., ToastReboot, ToastRunPackageID) used by toast action buttons.

.PARAMETER ActionType
    The type of action to register (e.g., 'ToastReboot, 'ToastRunPackageID').

.PARAMETER RegCommandPath
    The path where the command script is located. Defaults to $global:CustomScriptsPath.

.EXAMPLE
    Write-CustomActionRegistry -ActionType 'ToastReboot'
#>
function Write-CustomActionRegistry {
    [CmdletBinding()]
    param (
        [Parameter(Position = '0')]
        [ValidateSet('ToastRunApplicationID', 'ToastRunPackageID', 'ToastRunUpdateID', 'ToastReboot', 'ToastRunPSScript')]
        [string]$ActionType, 
        [Parameter(Position = '1')]
        [string]$RegCommandPath = $global:CustomScriptsPath
    )
    Write-ToastLog -Message "Running Write-CustomActionRegistry function: $ActionType"
    switch ($ActionType) {
        ToastReboot {
            try {
                New-Item "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name 'URL Protocol' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name '(default)' -Value "URL:$($ActionType) Protocol" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                $RegCommandValue = $RegCommandPath  + '\' + "$($ActionType).cmd"
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Name '(default)' -Value $RegCommandValue -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the $ActionType custom protocol in HKCU\Software\Classes. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
        }
        ToastRunUpdateID {
            try {
                New-Item "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name 'URL Protocol' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name '(default)' -Value "URL:$($ActionType) Protocol" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                $RegCommandValue = $RegCommandPath  + '\' + "$($ActionType).cmd"
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Name '(default)' -Value $RegCommandValue -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the $ActionType custom protocol in HKCU\Software\Classes. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
        }
        ToastRunPackageID {
            try {
                New-Item "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name 'URL Protocol' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name '(default)' -Value "URL:$($ActionType) Protocol" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                $RegCommandValue = $RegCommandPath  + '\' + "$($ActionType).cmd"
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Name '(default)' -Value $RegCommandValue -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the $ActionType custom protocol in HKCU\Software\Classes. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
        }
        ToastRunApplicationID {
            try {
                New-Item "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name 'URL Protocol' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name '(default)' -Value "URL:$($ActionType) Protocol" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                $RegCommandValue = $RegCommandPath  + '\' + "$($ActionType).cmd"
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Name '(default)' -Value $RegCommandValue -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the $ActionType custom protocol in HKCU\Software\Classes. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
        }
        ToastRunPSScript {
            try {
                New-Item "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name 'URL Protocol' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)" -Name '(default)' -Value "URL:$($ActionType) Protocol" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
                $RegCommandValue = $RegCommandPath + '\' + "$($ActionType).cmd `"%1`""
                New-ItemProperty -LiteralPath "HKCU:\Software\Classes\$($ActionType)\shell\open\command" -Name '(default)' -Value $RegCommandValue -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the $ActionType custom protocol in HKCU\Software\Classes. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
        }
    }
}

<#
.SYNOPSIS
    Creates scripts for custom actions triggered by toast buttons.

.DESCRIPTION
    Generates .cmd and .ps1 scripts for actions like rebooting or running ConfigMgr deployments, storing them in the specified path.

.PARAMETER Type
    The type of action script to create (e.g., 'ToastReboot', 'ToastRunPackageID').

.PARAMETER Path
    The directory where scripts are saved. Defaults to $global:CustomScriptsPath.

.EXAMPLE
    Write-CustomActionScript -Type 'ToastReboot'
#>
function Write-CustomActionScript {
    [CmdletBinding()]
    param (
        [Parameter(Position = '0')]
        [ValidateSet('ToastRunApplicationID', 'ToastRunPackageID', 'ToastRunUpdateID', 'ToastReboot', 'InvokePSScriptAsUser', 'ToastRunPSScript')]
        [string]$Type, 
        [Parameter(Position = '1')]
        [String]$Path = $global:CustomScriptsPath
    )
    Write-ToastLog -Message "Running Write-CustomActionScript function: $Type"
    switch ($Type) {
        ToastRunUpdateID {
            try {
                $CMDFileName = $Type + '.cmd'
                try {
                    New-Item -Path $Path -Name $CMDFileName -Force -OutVariable PathInfo | Out-Null
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
                try {
                    $GetCustomScriptPath = $PathInfo.FullName
                    [String]$Script = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File `"$global:CustomScriptsPath\ToastRunUpdateID.ps1`""
                    if (-not [string]::IsNullOrEmpty($Script)) {
                        Out-File -FilePath $GetCustomScriptPath -InputObject $Script -Encoding ASCII -Force
                    }
                } catch {
                    Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
            try {
                $PS1FileName = $Type + '.ps1'
                try {
                    New-Item -Path $Path -Name $PS1FileName -Force -OutVariable PathInfo | Out-Null
                } catch { 
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
                try {
                    $GetCustomScriptPath = $PathInfo.FullName
                    [String]$Script = @'
$RegistryPath = "HKCU:\SOFTWARE\ToastNotificationScript"
$UpdateID = (Get-ItemProperty -Path $RegistryPath -Name "RunUpdateID").RunUpdateID
$TestUpdateID = Get-WmiObject -Namespace ROOT\ccm\ClientSDK -Query "SELECT * FROM CCM_SoftwareUpdate WHERE UpdateID = '$UpdateID'"
if (-not [string]::IsNullOrEmpty($TestUpdateID)) {
    Invoke-WmiMethod -Namespace ROOT\ccm\ClientSDK -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (, $TestUpdateID)
    if (Test-Path -Path "$env:windir\CCM\ClientUX\SCClient.exe") { Start-Process -FilePath "$env:windir\CCM\ClientUX\SCClient.exe" -ArgumentList "SoftwareCenter:Page = Updates" -WindowStyle Maximized }
}
exit 0
'@
                    if (-not [string]::IsNullOrEmpty($Script)) {
                        Out-File -FilePath $GetCustomScriptPath -InputObject $Script -Encoding ASCII -Force
                    }
                } catch {
                    Write-ToastLog -Level Error -Message "Failed to create the custom .ps1 script for $Type. Action button might not work"
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the custom .ps1 script for $Type. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
            break
        }
        ToastReboot {
            try {
                $CMDFileName = $Type + '.cmd'
                try {
                    New-Item -Path $Path -Name $CMDFileName -Force -OutVariable PathInfo | Out-Null
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
                try {
                    $GetCustomScriptPath = $PathInfo.FullName
                    [String]$Script = 'shutdown /r /t 0 /d p:0:0 /c "Toast Notification Reboot"'
                    if (-not [string]::IsNullOrEmpty($Script)) {
                        Out-File -FilePath $GetCustomScriptPath -InputObject $Script -Encoding ASCII -Force
                    }
                } catch {
                    Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
            break
        }
        ToastRunPackageID {
            try {
                $CMDFileName = $Type + '.cmd'
                try {
                    New-Item -Path $Path -Name $CMDFileName -Force -OutVariable PathInfo | Out-Null
                } catch { 
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
                try {
                    $GetCustomScriptPath = $PathInfo.FullName
                    [String]$Script = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File `"$global:CustomScriptsPath\ToastRunPackageID.ps1`""
                    if (-not [string]::IsNullOrEmpty($Script)) {
                        Out-File -FilePath $GetCustomScriptPath -InputObject $Script -Encoding ASCII -Force
                    }
                } catch {
                    Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
            try {
                $PS1FileName = $Type + '.ps1'
                try {
                    New-Item -Path $Path -Name $PS1FileName -Force -OutVariable PathInfo | Out-Null
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
                try {
                    $GetCustomScriptPath = $PathInfo.FullName
                    [String]$Script = @'
$RegistryPath = "HKCU:\SOFTWARE\ToastNotificationScript"
$PackageID = (Get-ItemProperty -Path $RegistryPath -Name "RunPackageID").RunPackageID
$TestPackageID = Get-WmiObject -Namespace ROOT\ccm\ClientSDK -Query "SELECT * FROM CCM_Program where PackageID = '$PackageID'"
if (-not [string]::IsNullOrEmpty($TestPackageID)) {
    $ProgramID = $TestPackageID.ProgramID
    ([wmiclass]'ROOT\ccm\ClientSDK:CCM_ProgramsManager').ExecuteProgram($ProgramID, $PackageID)
    if (Test-Path -Path "$env:windir\CCM\ClientUX\SCClient.exe") { Start-Process -FilePath "$env:windir\CCM\ClientUX\SCClient.exe" -ArgumentList "SoftwareCenter:Page = OSD" -WindowStyle Maximized }
}
exit 0
'@
                    if (-not [string]::IsNullOrEmpty($Script)) {
                        Out-File -FilePath $GetCustomScriptPath -InputObject $Script -Encoding ASCII -Force
                    }
                } catch {
                    Write-ToastLog -Level Error -Message "Failed to create the custom .ps1 script for $Type. Action button might not work"
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the custom .ps1 script for $Type. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
            break
        }
        ToastRunApplicationID {
            try {
                $CMDFileName = $Type + '.cmd'
                try {
                    New-Item -Path $Path -Name $CMDFileName -Force -OutVariable PathInfo | Out-Null
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
                try {
                    $GetCustomScriptPath = $PathInfo.FullName
                    [String]$Script = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File `"$global:CustomScriptsPath\ToastRunApplicationID.ps1`""
                    if (-not [string]::IsNullOrEmpty($Script)) {
                        Out-File -FilePath $GetCustomScriptPath -InputObject $Script -Encoding ASCII -Force
                    }
                } catch {
                    Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
            try {
                $PS1FileName = $Type + '.ps1'
                try {
                    New-Item -Path $Path -Name $PS1FileName -Force -OutVariable PathInfo | Out-Null
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
                try {
                    $GetCustomScriptPath = $PathInfo.FullName
                    [String]$Script = @'
$RegistryPath = "HKCU:\SOFTWARE\ToastNotificationScript"
$ApplicationID = (Get-ItemProperty -Path $RegistryPath -Name "RunApplicationID").RunApplicationID
$TestApplicationID = Get-CimInstance -ClassName CCM_Application -Namespace ROOT\ccm\ClientSDK | Where-Object {$_.Id -eq $ApplicationID}
$AppArguments = @{
    Id = $TestApplicationID.Id
    IsMachineTarget = $TestApplicationID.IsMachineTarget
    Revision = $TestApplicationID.Revision
}
if (-not [string]::IsNullOrEmpty($TestApplicationID)) {
    if ($TestApplicationID.InstallState -eq "NotInstalled") { Invoke-CimMethod -Namespace "ROOT\ccm\clientSDK" -ClassName CCM_Application -MethodName Install -Arguments $AppArguments }
    elseif ($TestApplicationID.InstallState -eq "Installed") { Invoke-CimMethod -Namespace "ROOT\ccm\clientSDK" -ClassName CCM_Application -MethodName Repair -Arguments $AppArguments }
    elseif ($TestApplicationID.InstallState -eq "NotUpdated") { Invoke-CimMethod -Namespace "ROOT\ccm\clientSDK" -ClassName CCM_Application -MethodName Install -Arguments $AppArguments }
    if (Test-Path -Path "$env:windir\CCM\ClientUX\SCClient.exe") { Start-Process -FilePath "$env:windir\CCM\ClientUX\SCClient.exe" -ArgumentList "SoftwareCenter:Page = InstallationStatus" -WindowStyle Maximized }
}
exit 0
'@
                    if (-not [string]::IsNullOrEmpty($Script)) {
                        Out-File -FilePath $GetCustomScriptPath -InputObject $Script -Encoding ASCII -Force
                    }
                } catch {
                    Write-ToastLog -Level Error -Message "Failed to create the custom .ps1 script for $Type. Action button might not work"
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the custom .ps1 script for $Type. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
            break
        }
        InvokePSScriptAsUser {
            try {
                $PS1FileName = 'InvokePSScriptAsUser.ps1'
                try {
                    New-Item -Path $Path -Name $PS1FileName -Force -OutVariable PathInfo | Out-Null
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
                try {
                    $GetCustomScriptPath = $PathInfo.FullName
                    [String]$Script = @'
param($File, $argument)

$Source = @"
using System;
using System.Runtime.InteropServices;

namespace Runasuser
{
    public static class ProcessExtensions
    {

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken, 
            String lpApplicationName, 
            String lpCommandLine, 
            IntPtr lpProcessAttributes, 
            IntPtr lpThreadAttributes, 
            bool bInheritHandle, 
            uint dwCreationFlags, 
            IntPtr lpEnvironment, 
            String lpCurrentDirectory, 
            ref STARTUPINFO lpStartupInfo, 
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle, 
            uint dwDesiredAccess, 
            IntPtr lpThreadAttributes, 
            int TokenType, 
            int ImpersonationLevel, 
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer, 
            int Reserved, 
            int Version, 
            ref IntPtr ppSessionInfo, 
            ref int pCount);

        private enum SW
        {
            SW_HIDE = 0, 
            SW_SHOWNORMAL = 1, 
            SW_NORMAL = 1, 
            SW_SHOWMINIMIZED = 2, 
            SW_SHOWMAXIMIZED = 3, 
            SW_MAXIMIZE = 3, 
            SW_SHOWNOACTIVATE = 4, 
            SW_SHOW = 5, 
            SW_MINIMIZE = 6, 
            SW_SHOWMINNOACTIVE = 7, 
            SW_SHOWNA = 8, 
            SW_RESTORE = 9, 
            SW_SHOWDEFAULT = 10, 
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive, 
            WTSConnected, 
            WTSConnectQuery, 
            WTSShadow, 
            WTSDisconnected, 
            WTSIdle, 
            WTSListen, 
            WTSReset, 
            WTSDown, 
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0, 
            SecurityIdentification = 1, 
            SecurityImpersonation = 2, 
            SecurityDelegation = 3, 
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1, 
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        // Gets the user token from the currently active session
        private static bool GetSessionUserToken(ref IntPtr phUserToken)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;

                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero, 
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary, 
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                if (!GetSessionUserToken(ref hUserToken))
                {
                    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken, 
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero, 
                    IntPtr.Zero, 
                    false, 
                    dwCreationFlags, 
                    pEnv, 
                    workDir, // Working directory
                    ref startInfo, 
                    out procInfo))
                {
                    iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
                    throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.  Error Code -" + iResultOfCreateProcessAsUser);
                }

                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }

            return true;
        }

    }
}
"@
Add-Type -ReferencedAssemblies ''System'', ''System.Runtime.InteropServices'' -TypeDefinition $Source -Language CSharp -ErrorAction Stop
[Runasuser.ProcessExtensions]::StartProcessAsCurrentUser("$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe", " -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$File`" $argument") | Out-Null
'@
                    if (-not [string]::IsNullOrEmpty($Script)) {
                        Out-File -FilePath $GetCustomScriptPath -InputObject $Script -Encoding ASCII -Force
                    }
                } catch {
                    Write-ToastLog -Level Error -Message "Failed to create the .ps1 script for $Type. Show notification if run under SYSTEM might not work"
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the .ps1 script for $Type. Show notification if run under SYSTEM might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
            break
        }
        ToastRunPSScript {
            try {
                $CMDFileName = $Type + '.cmd'
                try {
                    New-Item -Path $Path -Name $CMDFileName -Force -OutVariable PathInfo | Out-Null
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
                try {
                    $GetCustomScriptPath = $PathInfo.FullName
                    [String]$Script = "
set passedArg=%1
:: remove part before : from passed string
set base64=%passedArg:*:=%
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand %base64%"
                    if (-not [string]::IsNullOrEmpty($Script)) {
                        Out-File -FilePath $GetCustomScriptPath -InputObject $Script -Encoding ASCII -Force
                    }
                } catch {
                    Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                    $ErrorMessage = $_.Exception.Message
                    Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
                }
            } catch {
                Write-ToastLog -Level Error -Message "Failed to create the custom .cmd script for $Type. Action button might not work"
                $ErrorMessage = $_.Exception.Message
                Write-ToastLog -Level Error -Message "Error message: $ErrorMessage"
            }
            break
        }
    }
}
#endregion

#region Toast Notification Management
# This region contains functions that manage the display and tracking of toast notifications.

<#
.SYNOPSIS
    Displays the toast notification to the user.

.DESCRIPTION
    Shows the constructed toast notification, handling SYSTEM context by invoking a user-context script, and optionally plays custom audio.

.EXAMPLE
    Show-ToastNotification
#>
function Show-ToastNotification {
    try {
        if ($isSystem -eq $true) {
            Write-ToastLog -Message 'Confirmed SYSTEM context before displaying toast'
            & (Join-Path -Path $global:CustomScriptsPath -ChildPath 'InvokePSScriptAsUser.ps1') "$PSCommandPath" "$Config"
        } else {
            Write-ToastLog -Message 'Confirmed USER context before displaying toast'
            $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
            $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
            $ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
            $ToastXml.LoadXml($Toast.OuterXml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($App).Show($ToastXml)
        }
        Write-ToastLog -Message 'All good. Toast notification was displayed'
        Write-Output 'All good. Toast notification was displayed'
        if ($CustomAudio -eq 'True') {
            Invoke-Command -ScriptBlock {
                Add-Type -AssemblyName System.Speech
                $speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
                Start-Sleep -Seconds 1.25
                $speak.SelectVoiceByHints('female', 65)
                $speak.Speak($using:CustomAudioTextToSpeech)
                $speak.Dispose()
            }
        }
        Save-NotificationLastRunTime
        Exit 0
    } catch {
        Write-ToastLog -Message 'Something went wrong when displaying the toast notification' -Level Error
        Write-ToastLog -Message 'Make sure the script is running as the logged on user' -Level Error
        Write-Output 'Something went wrong when displaying the toast notification. Make sure the script is running as the logged on user'
        Exit 1
    }
}

<#
.SYNOPSIS
    Retrieves the time since the last toast notification was displayed.

.DESCRIPTION
    Reads the last run time from the registry and calculates the minutes elapsed since then.

.EXAMPLE
    Get-NotificationLastRunTime
#>
function Get-NotificationLastRunTime {
    $LastRunTime = (Get-ItemProperty $global:RegistryPath -Name LastRunTime -ErrorAction Ignore).LastRunTime
    $CurrentTime = Get-Date -Format s
    if (-not [string]::IsNullOrEmpty($LastRunTime)) {
        $Difference = ([datetime]$CurrentTime - [datetime]$LastRunTime)
        $MinutesSinceLastRunTime = [math]::Round($Difference.TotalMinutes)
        Write-ToastLog -Message "Toast notification was previously displayed $MinutesSinceLastRunTime minutes ago"
        $MinutesSinceLastRunTime
    }
}

<#
.SYNOPSIS
    Saves the current time as the last run time of the toast notification.

.DESCRIPTION
    Stores the current timestamp in the registry to track when the toast was last shown.

.EXAMPLE
    Save-NotificationLastRunTime
#>
function Save-NotificationLastRunTime {
    $RunTime = Get-Date -Format s
    if (-not (Get-ItemProperty -Path $global:RegistryPath -Name LastRunTime -ErrorAction Ignore)) {
        New-ItemProperty -Path $global:RegistryPath -Name LastRunTime -Value $RunTime -Force | Out-Null
    } else {
        Set-ItemProperty -Path $global:RegistryPath -Name LastRunTime -Value $RunTime -Force | Out-Null
    }
}

<#
.SYNOPSIS
    Registers a custom notification app in the registry.

.DESCRIPTION
    Creates registry entries to define a custom app for displaying toast notifications.

.PARAMETER fAppID
    The ID of the custom app.

.PARAMETER fAppDisplayName
    The display name of the custom app.

.EXAMPLE
    Register-CustomNotificationApp -fAppID "Toast.Custom.App" -fAppDisplayName "Custom Toast App"
#>
function Register-CustomNotificationApp {
    param (
        [Parameter(Mandatory)]
        [String]$fAppID, 
        [Parameter(Mandatory)]
        [String]$fAppDisplayName
    )
    Write-ToastLog -Message 'Running Register-NotificationApp function'
    $AppID = $fAppID
    $AppDisplayName = $fAppDisplayName
    [int]$ShowInSettings = 0
    [int]$IconBackgroundColor = 0
    $IconUri = '%SystemRoot%\ImmersiveControlPanel\images\logo.png'
    $AppRegPath = 'HKCU:\Software\Classes\AppUserModelId'
    $RegPath = "$AppRegPath\$AppID"
    try {
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $AppRegPath -Name $AppID -Force | Out-Null
        }
        $DisplayName = Get-ItemProperty -Path $RegPath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        if ($DisplayName -ne $AppDisplayName) {
            New-ItemProperty -Path $RegPath -Name DisplayName -Value $AppDisplayName -PropertyType String -Force | Out-Null
        }
        $ShowInSettingsValue = Get-ItemProperty -Path $RegPath -Name ShowInSettings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ShowInSettings -ErrorAction SilentlyContinue
        if ($ShowInSettingsValue -ne $ShowInSettings) {
            New-ItemProperty -Path $RegPath -Name ShowInSettings -Value $ShowInSettings -PropertyType DWORD -Force | Out-Null
        }
        $IconUriValue = Get-ItemProperty -Path $RegPath -Name IconUri -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IconUri -ErrorAction SilentlyContinue
        if ($IconUriValue -ne $IconUri) {
            New-ItemProperty -Path $RegPath -Name IconUri -Value $IconUri -PropertyType ExpandString -Force | Out-Null
        }
        $IconBackgroundColorValue = Get-ItemProperty -Path $RegPath -Name IconBackgroundColor -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IconBackgroundColor -ErrorAction SilentlyContinue
        if ($IconBackgroundColorValue -ne $IconBackgroundColor) {
            New-ItemProperty -Path $RegPath -Name IconBackgroundColor -Value $IconBackgroundColor -PropertyType ExpandString -Force | Out-Null
        }
        Write-ToastLog -Message "Created registry entries for custom notification app: $fAppDisplayName"
    }
    catch {
        Write-ToastLog -Message 'Failed to create one or more registry entries for the custom notification app' -Level Error
        Write-ToastLog -Message 'Toast Notifications are usually not displayed if the notification app does not exist' -Level Error
    }
}
#endregion

#region Initialization
# This region initializes global variables and ensures required paths exist.

# Define global variables used throughout the script
$global:ScriptVersion = '3.0'  # Version of the script
$global:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition  # Path where the script is located
$global:CustomScriptsPath = "$env:AppData\ToastNotification\Scripts"  # Path for custom action scripts
$global:RegistryPath = 'HKCU:\SOFTWARE\ToastNotificationScript'  # Registry path for script settings

$RunningOS = try {
    Get-CimInstance -Class Win32_OperatingSystem | Select-Object BuildNumber
} catch {
    Write-ToastLog -Level Error -Message 'Failed to get running OS build. This is used with the OSUpgrade option, which now might not work properly'
}  # OS build number

$userCulture = try {
    (Get-Culture).Name
} catch {
    Write-ToastLog -Level Error -Message 'Failed to get users local culture. This is used with the multi-language option, which now might not work properly'
}  # User's culture for localization

$defaultUserCulture = 'en-US'  # Default culture if user's culture fails
$LogoImageTemp = "$env:TEMP\ToastLogoImage.jpg"  # Temporary file for logo image
$HeroImageTemp = "$env:TEMP\ToastHeroImage.jpg"  # Temporary file for hero image
$ImagesPath = "file:///$global:ScriptPath/Images"  # Path for local images

# Ensure the registry path exists
if (-not (Test-Path -Path $global:RegistryPath)) {
    Write-ToastLog -Message ('ToastNotificationScript registry path not found. Creating it: {0}' -f $global:RegistryPath)
    try {
        New-Item -Path $global:RegistryPath -Force | Out-Null
    } catch {
        Write-ToastLog -Message ('Failed to create the ToastNotificationScript registry path: {0}' -f $global:RegistryPath) -Level Error
        Write-ToastLog -Message 'This is required. Script will now exit' -Level Error
        Exit 1
    }
}

# Ensure the custom scripts directory exists
if (-not (Test-Path -Path $global:CustomScriptsPath)) {
    Write-ToastLog -Message ('CustomScriptPath not found. Creating it: {0}' -f $global:CustomScriptsPath)
    try {
        New-Item -Path $global:CustomScriptsPath -ItemType Directory -Force | Out-Null
    } catch {
        Write-ToastLog -Level Error -Message ('Failed to create the CustomScriptPath folder: {0}' -f $global:CustomScriptsPath)
        Write-ToastLog -Message 'This is required. Script will now exit' -Level Error
        Exit 1
    }
}

# Verify the OS version is supported
$SupportedWindowsVersion = Get-WindowsVersion
if ($SupportedWindowsVersion -eq $false) {
    Write-ToastLog -Message 'Aborting script' -Level Error
    Exit 1
}

# Check if running as SYSTEM and enable push notifications if needed
$isSystem = Test-NTSystem
if ($isSystem -eq $true) {
    Write-ToastLog -Message 'The toast notification script is being run as SYSTEM. This is not recommended, but can be required in certain situations'
    Write-ToastLog -Message 'Scripts and log file are now located in: C:\Windows\System32\config\systemprofile\AppData\Roaming\ToastNotificationScript'
}
$WindowsPushNotificationsEnabled = Test-WindowsPushNotificationsEnabled
if ($WindowsPushNotificationsEnabled -eq $false) {
    Enable-WindowsPushNotification
}
#endregion

#region Configuration Loading
# This region handles loading and parsing the XML configuration file.

# Set default config file if not provided
if (-not $Config) {
    Write-ToastLog -Message 'No config file set as parameter. Using local config file'
    $Config = Join-Path $global:ScriptPath 'config-toast.xml'
}

# Load the config file based on whether it's a URL or local path
if ($Config.StartsWith('https://') -or $Config.StartsWith('http://')) {
    Write-ToastLog -Message 'Specified config file seems hosted [online]. Treating it accordingly'
    try { $testOnlineConfig = Invoke-WebRequest -Uri $Config -UseBasicParsing } catch { $null }
    if ($testOnlineConfig.StatusDescription -eq 'OK') {
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.Encoding = [System.Text.Encoding]::UTF8
            $Xml = [xml]$webClient.DownloadString($Config)
            Write-ToastLog -Message "Successfully loaded $Config"
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-ToastLog -Message "Error, could not read $Config" -Level Error
            Write-ToastLog -Message "Error message: $ErrorMessage" -Level Error
            Write-Output "Error, could not read $Config. Error message: $ErrorMessage"
            Exit 1
        }
    } else {
        Write-ToastLog -Level Error -Message 'The provided URL to the config does not reply or does not come back OK'
        Write-Output 'The provided URL to the config does not reply or does not come back OK'
        Exit 1
    }
} elseif (-not ($Config.StartsWith('https://')) -or (-not ($Config.StartsWith('http://')))) {
    Write-ToastLog -Message 'Specified config file seems hosted [locally or fileshare]. Treating it accordingly'
    if (Test-Path -Path $Config) {
        try {
            $Xml = [xml](Get-Content -Path $Config -Encoding UTF8)
            Write-ToastLog -Message "Successfully loaded $Config"
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-ToastLog -Message "Error, could not read $Config" -Level Error
            Write-ToastLog -Message "Error message: $ErrorMessage" -Level Error
            Exit 1
        }
    } else {
        Write-ToastLog -Level Error -Message 'No config file found on the specified location [locally or fileshare]'
        Exit 1
    }
} else {
    Write-ToastLog -Level Error -Message 'Something about the config file is completely off'
    Write-Output 'Something about the config file is completely off'
    Exit 1
}

# Parse the XML configuration into variables
if (-not [string]::IsNullOrEmpty($Xml)) {
    try {
        Write-ToastLog -Message "Loading xml content from $Config into variables"
        $ToastEnabled = $Xml.Configuration.Feature | Where-Object { $_.Name -like 'Toast' } | Select-Object -ExpandProperty 'Enabled'
        $UpgradeOS = $Xml.Configuration.Feature | Where-Object { $_.Name -like 'UpgradeOS' } | Select-Object -ExpandProperty 'Enabled'
        $PendingRebootUptime = $Xml.Configuration.Feature | Where-Object { $_.Name -like 'PendingRebootUptime' } | Select-Object -ExpandProperty 'Enabled'
        $PendingRebootCheck = $Xml.Configuration.Feature | Where-Object { $_.Name -like 'PendingRebootCheck' } | Select-Object -ExpandProperty 'Enabled'
        $ADPasswordExpiration = $Xml.Configuration.Feature | Where-Object { $_.Name -like 'ADPasswordExpiration' } | Select-Object -ExpandProperty 'Enabled'
        $PendingRebootUptimeTextEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'PendingRebootUptimeText' } | Select-Object -ExpandProperty 'Enabled'
        $MaxUptimeDays = $Xml.Configuration.Option | Where-Object { $_.Name -like 'MaxUptimeDays' } | Select-Object -ExpandProperty 'Value'
        $PendingRebootCheckTextEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'PendingRebootCheckText' } | Select-Object -ExpandProperty 'Enabled'
        $ADPasswordExpirationTextEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'ADPasswordExpirationText' } | Select-Object -ExpandProperty 'Enabled'
        $ADPasswordExpirationDays = $Xml.Configuration.Option | Where-Object { $_.Name -like 'ADPasswordExpirationDays' } | Select-Object -ExpandProperty 'Value'
        $TargetOS = $Xml.Configuration.Option | Where-Object { $_.Name -like 'TargetOS' } | Select-Object -ExpandProperty 'Build'
        $DeadlineEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Deadline' } | Select-Object -ExpandProperty 'Enabled'
        $DeadlineContent = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Deadline' } | Select-Object -ExpandProperty 'Value'
        $DynDeadlineEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'DynamicDeadline' } | Select-Object -ExpandProperty 'Enabled'
        $DynDeadlineValue = $Xml.Configuration.Option | Where-Object { $_.Name -like 'DynamicDeadline' } | Select-Object -ExpandProperty 'Value'
        $CreateScriptsProtocolsEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'CreateScriptsAndProtocols' } | Select-Object -ExpandProperty 'Enabled'
        $LimitToastToRunEveryMinutesEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'LimitToastToRunEveryMinutes' } | Select-Object -ExpandProperty 'Enabled'
        $LimitToastToRunEveryMinutesValue = $Xml.Configuration.Option | Where-Object { $_.Name -like 'LimitToastToRunEveryMinutes' } | Select-Object -ExpandProperty 'Value'
        $RunPackageIDEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RunPackageID' } | Select-Object -ExpandProperty 'Enabled'
        $RunPackageIDValue = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RunPackageID' } | Select-Object -ExpandProperty 'Value'
        $RunApplicationIDEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RunApplicationID' } | Select-Object -ExpandProperty 'Enabled'
        $RunApplicationIDValue = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RunApplicationID' } | Select-Object -ExpandProperty 'Value'
        $RunUpdateIDEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RunUpdateID' } | Select-Object -ExpandProperty 'Enabled'
        $RunUpdateIDValue = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RunUpdateID' } | Select-Object -ExpandProperty 'Value'
        $RunUpdateTitleEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RunUpdateTitle' } | Select-Object -ExpandProperty 'Enabled'
        $RunUpdateTitleValue = $Xml.Configuration.Option | Where-Object { $_.Name -like 'RunUpdateTitle' } | Select-Object -ExpandProperty 'Value'
        $CustomAppEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'CustomNotificationApp' } | Select-Object -ExpandProperty 'Enabled'
        $CustomAppValue = $Xml.Configuration.Option | Where-Object { $_.Name -like 'CustomNotificationApp' } | Select-Object -ExpandProperty 'Value'
        $SCAppName = $Xml.Configuration.Option | Where-Object { $_.Name -like 'UseSoftwareCenterApp' } | Select-Object -ExpandProperty 'Name'
        $SCAppStatus = $Xml.Configuration.Option | Where-Object { $_.Name -like 'UseSoftwareCenterApp' } | Select-Object -ExpandProperty 'Enabled'
        $PSAppName = $Xml.Configuration.Option | Where-Object { $_.Name -like 'UsePowershellApp' } | Select-Object -ExpandProperty 'Name'
        $PSAppStatus = $Xml.Configuration.Option | Where-Object { $_.Name -like 'UsePowershellApp' } | Select-Object -ExpandProperty 'Enabled'
        $CustomAudio = $Xml.Configuration.Option | Where-Object { $_.Name -like 'CustomAudio' } | Select-Object -ExpandProperty 'Enabled'
        $LogoImageFileName = $Xml.Configuration.Option | Where-Object { $_.Name -like 'LogoImageName' } | Select-Object -ExpandProperty 'Value'
        $HeroImageFileName = $Xml.Configuration.Option | Where-Object { $_.Name -like 'HeroImageName' } | Select-Object -ExpandProperty 'Value'
        if (($LogoImageFileName -match [Regex]::Escape(':\'))) {
            $LogoImage = $LogoImageFileName
        }
        if (($HeroImageFileName -match [Regex]::Escape(':\'))) {
            $HeroImage = $HeroImageFileName
        }
        if ((-not [string]::IsNullOrEmpty($LogoImageFileName)) -and ([string]::IsNullOrEmpty($LogoImage))) {
            $LogoImage = $ImagesPath + '/' + $LogoImageFileName
        }
        if ((-not [string]::IsNullOrEmpty($LogoImageFileName)) -and ([string]::IsNullOrEmpty($HeroImage))) {
            $HeroImage = $ImagesPath + '/' + $HeroImageFileName
        }
        $Scenario = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Scenario' } | Select-Object -ExpandProperty 'Type'
        $Action1 = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Action1' } | Select-Object -ExpandProperty 'Value'
        $Action2 = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Action2' } | Select-Object -ExpandProperty 'Value'
        $Action3 = $Xml.Configuration.Option | Where-Object { $_.Name -like 'Action3' } | Select-Object -ExpandProperty 'Value'
        $GreetGivenName = $Xml.Configuration.Text | Where-Object { $_.Option -like 'GreetGivenName' } | Select-Object -ExpandProperty 'Enabled'
        $MultiLanguageSupport = $Xml.Configuration.Text | Where-Object { $_.Option -like 'MultiLanguageSupport' } | Select-Object -ExpandProperty 'Enabled'
        $ActionButton1Enabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'ActionButton1' } | Select-Object -ExpandProperty 'Enabled'
        $ActionButton2Enabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'ActionButton2' } | Select-Object -ExpandProperty 'Enabled'
        $ActionButton3Enabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'ActionButton3' } | Select-Object -ExpandProperty 'Enabled'
        $DismissButtonEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'DismissButton' } | Select-Object -ExpandProperty 'Enabled'
        $SnoozeButtonEnabled = $Xml.Configuration.Option | Where-Object { $_.Name -like 'SnoozeButton' } | Select-Object -ExpandProperty 'Enabled'
        if ($MultiLanguageSupport -eq 'True') {
            Write-ToastLog -Message "MultiLanguageSupport set to True. Current language culture is $userCulture. Checking for language support"
            if (-not [string]::IsNullOrEmpty($xml.Configuration.$userCulture)) {
                Write-ToastLog -Message "Support for the users language culture found, localizing text using $userCulture"
                $XmlLang = $xml.Configuration.$userCulture
            }
            elseif (-not [string]::IsNullOrEmpty($xml.Configuration.$defaultUserCulture)) {
                Write-ToastLog -Message "No support for the users language culture found, using $defaultUserCulture as default fallback language"
                $XmlLang = $xml.Configuration.$defaultUserCulture
            }
        }
        elseif ($MultiLanguageSupport -eq 'False') {
            $XmlLang = $xml.Configuration.$defaultUserCulture
        }
        else {
            $XmlLang = $xml.Configuration.$defaultUserCulture
        }
        $PendingRebootUptimeTextValue = $XmlLang.Text | Where-Object { $_.Name -like 'PendingRebootUptimeText' } | Select-Object -ExpandProperty '#text'
        $PendingRebootCheckTextValue = $XmlLang.Text | Where-Object { $_.Name -like 'PendingRebootCheckText' } | Select-Object -ExpandProperty '#text'
        $ADPasswordExpirationTextValue = $XmlLang.Text | Where-Object { $_.Name -like 'ADPasswordExpirationText' } | Select-Object -ExpandProperty '#text'
        $CustomAudioTextToSpeech = $XmlLang.Text | Where-Object { $_.Name -like 'CustomAudioTextToSpeech' } | Select-Object -ExpandProperty '#text'
        $ActionButton1Content = $XmlLang.Text | Where-Object { $_.Name -like 'ActionButton1' } | Select-Object -ExpandProperty '#text'
        $ActionButton2Content = $XmlLang.Text | Where-Object { $_.Name -like 'ActionButton2' } | Select-Object -ExpandProperty '#text'
        $ActionButton3Content = $XmlLang.Text | Where-Object { $_.Name -like 'ActionButton3' } | Select-Object -ExpandProperty '#text'
        $DismissButtonContent = $XmlLang.Text | Where-Object { $_.Name -like 'DismissButton' } | Select-Object -ExpandProperty '#text'
        $SnoozeButtonContent = $XmlLang.Text | Where-Object { $_.Name -like 'SnoozeButton' } | Select-Object -ExpandProperty '#text'
        $AttributionText = $XmlLang.Text | Where-Object { $_.Name -like 'AttributionText' } | Select-Object -ExpandProperty '#text'
        $HeaderText = $XmlLang.Text | Where-Object { $_.Name -like 'HeaderText' } | Select-Object -ExpandProperty '#text'
        $TitleText = $XmlLang.Text | Where-Object { $_.Name -like 'TitleText' } | Select-Object -ExpandProperty '#text'
        $BodyText1 = $XmlLang.Text | Where-Object { $_.Name -like 'BodyText1' } | Select-Object -ExpandProperty '#text'
        $BodyText2 = $XmlLang.Text | Where-Object { $_.Name -like 'BodyText2' } | Select-Object -ExpandProperty '#text'
        $SnoozeText = $XmlLang.Text | Where-Object { $_.Name -like 'SnoozeText' } | Select-Object -ExpandProperty '#text'
        $DeadlineText = $XmlLang.Text | Where-Object { $_.Name -like 'DeadlineText' } | Select-Object -ExpandProperty '#text'
        $GreetMorningText = $XmlLang.Text | Where-Object { $_.Name -like 'GreetMorningText' } | Select-Object -ExpandProperty '#text'
        $GreetAfternoonText = $XmlLang.Text | Where-Object { $_.Name -like 'GreetAfternoonText' } | Select-Object -ExpandProperty '#text'
        $GreetEveningText = $XmlLang.Text | Where-Object { $_.Name -like 'GreetEveningText' } | Select-Object -ExpandProperty '#text'
        $MinutesText = $XmlLang.Text | Where-Object { $_.Name -like 'MinutesText' } | Select-Object -ExpandProperty '#text'
        $HourText = $XmlLang.Text | Where-Object { $_.Name -like 'HourText' } | Select-Object -ExpandProperty '#text'
        $HoursText = $XmlLang.Text | Where-Object { $_.Name -like 'HoursText' } | Select-Object -ExpandProperty '#text'
        $ComputerUptimeText = $XmlLang.Text | Where-Object { $_.Name -like 'ComputerUptimeText' } | Select-Object -ExpandProperty '#text'
        $ComputerUptimeDaysText = $XmlLang.Text | Where-Object { $_.Name -like 'ComputerUptimeDaysText' } | Select-Object -ExpandProperty '#text'
        Write-ToastLog -Message "Successfully loaded xml content from $Config"
    } catch {
        Write-ToastLog -Message "Xml content from $Config was not loaded properly"
        Exit 1
    }
}
#endregion

#region Validation
# This region validates the configuration to prevent conflicts and ensure requirements are met.

# Check if toast notifications are enabled
if ($ToastEnabled -ne 'True') {
    Write-ToastLog -Message "Toast notification is not enabled. Please check $Config file"
    Exit 1
}

# Validate feature conflicts
if (($UpgradeOS -eq 'True') -and ($PendingRebootCheck -eq 'True')) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have both UpgradeOS feature set to True AND PendingRebootCheck feature set to True at the same time. Check your config"
    Exit 1
}
if (($UpgradeOS -eq 'True') -and ($PendingRebootUptime -eq 'True')) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have both UpgradeOS feature set to True AND PendingRebootUptime feature set to True at the same time. Check your config"
    Exit 1
}
if (($PendingRebootCheck -eq 'True') -and ($PendingRebootUptime -eq 'True')) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You currently can't have both PendingReboot features set to True. Please use them separately"
    Exit 1
}
if (($ADPasswordExpiration -eq 'True') -and ($UpgradeOS -eq 'True')) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have both ADPasswordExpiration AND UpgradeOS set to True at the same time. Check your config"
    Exit 1
}
if (($ADPasswordExpiration -eq 'True') -and ($PendingRebootCheck -eq 'True')) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have both ADPasswordExpiration AND PendingRebootCheck set to True at the same time. Check your config"
    Exit 1
}
if (($ADPasswordExpiration -eq 'True') -and ($PendingRebootUptime -eq 'True')) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have both ADPasswordExpiration AND PendingRebootUptime set to True at the same time. Check your config"
    Exit 1
}

# Validate app selection
if ( ( $SCAppStatus -eq 'True' ) -and ( -not ( Get-Service -Name ccmexec ) ) ) {
    Write-ToastLog -Level Error -Message 'Error. Using Software Center app for the notification requires the ConfigMgr client installed'
    Write-ToastLog -Level Error -Message 'Error. Please install the ConfigMgr client or use Powershell as app doing the notification'
    Exit 1
}
if ( ( $SCAppStatus -eq 'True' ) -and ( $PSAppStatus -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have both SoftwareCenter app set to True AND PowershellApp set to True at the same time. Check your config"
    Exit 1
}
if ( ( $SCAppStatus -ne 'True' ) -and ( $PSAppStatus -ne 'True' ) -and ( $CustomAppEnabled -ne 'True' ) ) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You need to enable at least 1 app in the config doing the notification. ie. Software Center or Powershell. Check your config"
    Exit 1
}
if ( ( $SCAppStatus -eq 'True' ) -and ( $CustomAppEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have both SoftwareCenter app set to True AND CustomNotificationApp set to True at the same time. Check your config"
    Exit 1
}
if ( ( $CustomAppEnabled -eq 'True' ) -and ( $PSAppStatus -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have both PowerShell app set to True AND CustomNotificationApp set to True at the same time. Check your config"
    Exit 1
}

# Validate text option conflicts
if ( ( $UpgradeOS -eq 'True' ) -and ( $PendingRebootUptimeTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have UpgradeOS set to True and PendingRebootUptimeText set to True at the same time. Check your config"
    Exit 1
}
if ( ( $UpgradeOS -eq 'True' ) -and ( $PendingRebootCheckTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message "Error. Conflicting selection in the $Config file"
    Write-ToastLog -Level Error -Message "Error. You can't have UpgradeOS set to True and PendingRebootCheckText set to True at the same time. Check your config"
    Exit 1
}
if ( ( $PendingRebootUptimeTextEnabled -eq 'True' ) -and ( $PendingRebootCheckTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'Error. You can''t have PendingRebootUptimeText set to True and PendingRebootCheckText set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the text options. Check your config'
    Exit 1
}
if ( ( $PendingRebootCheck -eq 'True' ) -and ( $PendingRebootUptimeTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'Error. You can''t have PendingRebootCheck set to True and PendingRebootUptimeText set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should use PendingRebootCheck with the PendingRebootCheckText option instead'
    Exit 1
}
if ( ( $PendingRebootUptime -eq 'True' ) -and ( $PendingRebootCheckTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'Error. You can''t have PendingRebootUptime set to True and PendingRebootCheckText set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should use PendingRebootUptime with the PendingRebootUptimeText option instead. Check your config'
    Exit 1
}
if ( ( $ADPasswordExpirationTextEnabled -eq 'True' ) -and ( $PendingRebootCheckTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'Error. You can''t have ADPasswordExpirationTextEnabled set to True and PendingRebootCheckText set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the text options. Check your config'
    Exit 1
}
if ( ( $ADPasswordExpirationTextEnabled -eq 'True' ) -and ( $PendingRebootUptimeTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'Error. You can''t have ADPasswordExpirationTextEnabled set to True and PendingRebootUptimeTextEnabled set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the text options. Check your config'
    Exit 1
}

# Validate deadline options
if ( ( $DeadlineEnabled -eq 'True' ) -and ( $DynDeadlineEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'Error. You can''t have DeadlineEnabled set to True and DynamicDeadlineEnabled set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the deadline options. Check your config'
    Exit 1
}

# Validate ConfigMgr action options
if ( ( $RunApplicationIDEnabled -eq 'True' ) -and ( $RunPackageIDEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'Error. You can''t have RunApplicationIDEnabled set to True and RunPackageIDEnabled set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the options. Check your config'
    Exit 1
}
if ( ( $RunApplicationIDEnabled -eq 'True' ) -and ( $RunUpdateIDEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'Error. You can''t have RunApplicationIDEnabled set to True and RunUpdateIDEnabled set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the options. Check your config'
    Exit 1
}
if ( ( $RunUpdateIDEnabled -eq 'True' ) -and ( $RunPackageIDEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'Error. You can''t have RunUpdateIDEnabled set to True and RunPackageIDEnabled set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the options. Check your config'
    Exit 1
}

# Validate button combinations
if ( ( $ActionButton2Enabled -eq 'True' ) -and ( $SnoozeButtonEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'You can''t have ActionButton2 enabled and SnoozeButton enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too many buttons. Check your config'
    Exit 1
}
if ( ( $ActionButton3Enabled -eq 'True' ) -and ( $SnoozeButtonEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'You can''t have ActionButton3 enabled and SnoozeButton enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too many buttons. Check your config'
    Exit 1
}
if ( ( $ActionButton3Enabled -eq 'True' ) -and ( $DeadlineEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'You can''t have ActionButton3 enabled and Deadline enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too many buttons. Check your config'
    Exit 1
}
if ( ( $SnoozeButtonEnabled -eq 'True' ) -and ( $PendingRebootUptimeTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'You can''t have SnoozeButton enabled and have PendingRebootUptimeText enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too much text and the toast notification will render without buttons. Check your config'
    Exit 1
}
if ( ( $SnoozeButtonEnabled -eq 'True' ) -and ( $PendingRebootCheckTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'You can''t have SnoozeButton enabled and have PendingRebootCheckText enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too much text and the toast notification will render without buttons. Check your config'
    Exit 1
}
if ( ( $SnoozeButtonEnabled -eq 'True' ) -and ( $ADPasswordExpirationTextEnabled -eq 'True' ) ) {
    Write-ToastLog -Level Error -Message 'Error. Conflicting selection in the $Config file'
    Write-ToastLog -Level Error -Message 'You can''t have SnoozeButton enabled and have ADPasswordExpirationText enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too much text and the toast notification will render without buttons. Check your config'
    Exit 1
}

# Validate custom PowerShell script actions
if ( $ActionButton1Content -match '^ToastRunPSScript:' -and $ActionButton1Content -notmatch '\.ps1' ) {
    Write-ToastLog -Level Error -Message 'Error. Incomplete Value in the $Config file Action1 tag'
    Write-ToastLog -Level Error -Message 'Error. You have to specify also the ps1 path: like ToastRunPSScript:C:\ProgramData\_Automation\Script\ScriptName.PS1'
    Exit 1
}
if ( $ActionButton2Content -match '^ToastRunPSScript:$' -and $ActionButton2Content -notmatch '\.ps1' ) {
    Write-ToastLog -Level Error -Message 'Error. Incomplete Value in the $Config file Action2 tag'
    Write-ToastLog -Level Error -Message 'Error. You have to specify also the ps1 path: like ToastRunPSScript:C:\ProgramData\_Automation\Script\ScriptName.PS1'
    Exit 1
}
if ( $ActionButton3Content -match '^ToastRunPSScript:$' -and $ActionButton2Content -notmatch '\.ps1' ) {
    Write-ToastLog -Level Error -Message 'Error. Incomplete Value in the $Config file Action3 tag'
    Write-ToastLog -Level Error -Message 'Error. You have to specify also the ps1 path: like ToastRunPSScript:C:\ProgramData\_Automation\Script\ScriptName.PS1'
    Exit 1
}

# Extract and validate PowerShell script path if used
$psScriptPath = if ($Action1 -match '^ToastRunPSScript:') {
    (($Action1 -split ':')[1..$($Action1.Length)]) -join ':'
} elseif ($Action2 -match '^ToastRunPSScript:') {
    (($Action2 -split ':')[1..$($Action2.Length)]) -join ':'
} else {
    (($Action3 -split ':')[1..$($Action3.Length)]) -join ':'
}
if (-not (Test-Path -Path $psScriptPath)) {
    Write-ToastLog -Level Error -Message "Provided path of the script to run '$psScriptPath' not found."
    Exit 1
}

# Set Base64 Code in ToastRunPSScript action
$psCommandToExecute = '& "{0}"' -f $psScriptPath
# encode to base64
$bytes = [System.Text.Encoding]::Unicode.GetBytes($psCommandToExecute)
$encodedString = [Convert]::ToBase64String($bytes)

if ($Action1 -match '^ToastRunPSScript:') {
    $Action1 = 'ToastRunPSScript:{0}' -f $encodedString
} elseif ($Action2 -match '^ToastRunPSScript:') {
    $Action2 = 'ToastRunPSScript:{0}' -f $encodedString
} else {
    $Action3 = 'ToastRunPSScript:{0}' -f $encodedString
}
#endregion

#region Toast Notification Preparation
# This region prepares dynamic content and constructs the toast notification XML.

# Register custom app if enabled
if ($CustomAppEnabled -eq 'True') {
    $App = 'Toast.Custom.App'
    Register-CustomNotificationApp -fAppID $App -fAppDisplayName $CustomAppValue
}

# Check notification frequency limit
if ( $LimitToastToRunEveryMinutesEnabled -eq 'True' ) {
    $LastRunTimeOutput = Get-NotificationLastRunTime
    if ( -not [string]::IsNullOrEmpty( $LastRunTimeOutput ) ) {
        if ( $LastRunTimeOutput -lt $LimitToastToRunEveryMinutesValue ) {
            Write-ToastLog -Level Error -Message 'Toast notification was displayed too recently'
            Write-ToastLog -Level Error -Message "Toast notification was displayed $LastRunTimeOutput minutes ago and the config.xml is configured to allow $LimitToastToRunEveryMinutesValue minutes intervals"
            Write-ToastLog -Level Error -Message 'This is done to prevent ConfigMgr catching up on missed schedules, and thus display multiple toasts of the same appearance in a row'
            break
        }
    }
}

# Download hero image if hosted online
if ( ( $HeroImageFileName.StartsWith( 'https://' ) ) -or ( $HeroImageFileName.StartsWith( 'http://' ) ) ) {
    Write-ToastLog -Message 'ToastHeroImage appears to be hosted online. Will need to download the file'
    try {
        $testOnlineHeroImage = Invoke-WebRequest -Uri $HeroImageFileName -UseBasicParsing 
    } catch {
        $null
    }
    if ( $testOnlineHeroImage.StatusDescription -eq 'OK' ) {
        try {
            Invoke-WebRequest -Uri $HeroImageFileName -OutFile $HeroImageTemp
            $HeroImage = $HeroImageTemp
            Write-ToastLog -Message "Successfully downloaded $HeroImageTemp from $HeroImageFileName"
        } catch {
            Write-ToastLog -Level Error -Message "Failed to download the $HeroImageTemp from $HeroImageFileName"
        }
    } else {
        Write-ToastLog -Level Error -Message "The image supposedly located on $HeroImageFileName is not available"
    }
}

# Create custom scripts and protocols if enabled
if ( $CreateScriptsProtocolsEnabled -eq 'True' ) {
    $RegistryName = 'ScriptsAndProtocolsVersion'
    Write-ToastLog -Message 'CreateScriptsAndProtocols set to True. Will allow creation of scripts and protocols'
    if ( Test-Path -Path $global:RegistryPath ) {
        if ( ( ( Get-Item -Path $global:RegistryPath -ErrorAction SilentlyContinue ).Property -contains $RegistryName ) -ne $true ) {
            New-ItemProperty -Path $global:RegistryPath -Name $RegistryName -Value '0' -PropertyType 'String' -Force | Out-Null
        }
        if ( ( ( Get-Item -Path $global:RegistryPath -ErrorAction SilentlyContinue ).Property -contains $RegistryName ) -eq $true ) {
            try {
                Write-ToastLog -Message 'Creating scripts and protocols for the logged on user'
                Write-CustomActionRegistry -ActionType ToastReboot
                Write-CustomActionRegistry -ActionType ToastRunApplicationID
                Write-CustomActionRegistry -ActionType ToastRunPackageID
                Write-CustomActionRegistry -ActionType ToastRunUpdateID
                Write-CustomActionRegistry -ActionType ToastRunPSScript
                Write-CustomActionScript -Type ToastReboot
                Write-CustomActionScript -Type ToastRunApplicationID
                Write-CustomActionScript -Type ToastRunPackageID
                Write-CustomActionScript -Type ToastRunUpdateID
                Write-CustomActionScript -Type InvokePSScriptAsUser
                Write-CustomActionScript -Type ToastRunPSScript
                New-ItemProperty -Path $global:RegistryPath -Name $RegistryName -Value $global:ScriptVersion -PropertyType 'String' -Force | Out-Null
            }
            catch { 
                Write-ToastLog -Level Error -Message 'Something failed during creation of custom scripts and protocols'
            }
        }
    }
}

# Prepare dynamic content based on configuration
if ( $DynDeadlineEnabled -eq 'True' ) {
    Write-ToastLog -Message 'DynDeadlineEnabled set to True. Overriding deadline details using date and time from WMI'
    $DeadlineContent = Get-DynamicDeadline
}

if ( $ADPasswordExpiration -eq 'True' ) {
    Write-ToastLog -Message 'ADPasswordExpiration set to True. Checking for expiring AD password'
    $TestADPasswordExpiration = Get-ADPasswordExpiration -fADPasswordExpirationDays $ADPasswordExpirationDays
    $ADPasswordExpirationResult = $TestADPasswordExpiration[0]
    $ADPasswordExpirationDate = $TestADPasswordExpiration[1]
    $ADPasswordExpirationDiff = $TestADPasswordExpiration[2]
}

if ( $PendingRebootCheck -eq 'True' ) {
    Write-ToastLog -Message 'PendingRebootCheck set to True. Checking for pending reboots'
    $TestPendingRebootRegistry = Test-PendingRebootRegistry
    $TestPendingRebootWMI = Test-PendingRebootWMI
}

if ( $PendingRebootUptime -eq 'True' ) {
    $Uptime = Get-DeviceUptime
    Write-ToastLog -Message "PendingRebootUptime set to True. Checking for device uptime. Current uptime is: $Uptime days"
}

# Setup notification app in registry
if ( $CustomAppEnabled -eq 'True' ) {
    $RegPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'
    $App = 'Toast.Custom.App'
    if ( -not ( Test-Path -Path "$RegPath\$App" ) ) {
        New-Item -Path $RegPath -Name $App -Force
        New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 0 -PropertyType 'DWORD'
        New-ItemProperty -Path "$RegPath\$App" -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
        New-ItemProperty -Path "$RegPath\$App" -Name 'SoundFile' -PropertyType 'STRING' -Force
    }
    if ( ( Get-ItemProperty -Path "$RegPath\$App" -Name 'Enabled' -ErrorAction SilentlyContinue ).Enabled -ne '1' ) {
        New-ItemProperty -Path "$RegPath\$App" -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
    }
    if ( ( Get-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -ErrorAction SilentlyContinue ).ShowInActionCenter -ne '0' ) {
        New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 0 -PropertyType 'DWORD' -Force
    }
    if ( -not ( Get-ItemProperty -Path "$RegPath\$App" -Name 'SoundFile' -ErrorAction SilentlyContinue ) ) {
        New-ItemProperty -Path "$RegPath\$App" -Name 'SoundFile' -PropertyType 'STRING' -Force
    }
}

if ( $SCAppStatus -eq 'True' ) {
    if ( Get-Service -Name ccmexec -ErrorAction SilentlyContinue ) {
        $RegPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'
        $App = 'Microsoft.SoftwareCenter.DesktopToasts'
        if ( -not ( Test-Path -Path "$RegPath\$App" ) ) {
            New-Item -Path $RegPath -Name $App -Force
            New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD' -Force
            New-ItemProperty -Path "$RegPath\$App" -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
            New-ItemProperty -Path "$RegPath\$App" -Name 'SoundFile' -PropertyType 'STRING' -Force
        }
        if ( ( Get-ItemProperty -Path "$RegPath\$App" -Name 'Enabled' -ErrorAction SilentlyContinue ).Enabled -ne '1' ) {
            New-ItemProperty -Path "$RegPath\$App" -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
        }
        if ( ( Get-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -ErrorAction SilentlyContinue ).ShowInActionCenter -ne '1' ) {
            New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD' -Force
        }
        if ( -not ( Get-ItemProperty -Path "$RegPath\$App" -Name 'SoundFile' -ErrorAction SilentlyContinue ) ) {
            New-ItemProperty -Path "$RegPath\$App" -Name 'SoundFile' -PropertyType 'STRING' -Force
        }
    } else {
        Write-ToastLog -Message 'No ConfigMgr client installed. Cannot use Software Center as notifying app' -Level Error
    }
}

if ( $PSAppStatus -eq 'True' ) {
    $RegPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'
    $App = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    if ( -not ( Test-Path -Path "$RegPath\$App" ) ) {
        New-Item -Path $RegPath -Name $App -Force
        New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD'
        New-ItemProperty -Path "$RegPath\$App" -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
        New-ItemProperty -Path "$RegPath\$App" -Name 'SoundFile' -PropertyType 'STRING' -Force
    }
    if ( ( Get-ItemProperty -Path "$RegPath\$App" -Name 'Enabled' -ErrorAction SilentlyContinue ).Enabled -ne '1' ) {
        New-ItemProperty -Path "$RegPath\$App" -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
    }
    if ( ( Get-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -ErrorAction SilentlyContinue ).ShowInActionCenter -ne '1' ) {
        New-ItemProperty -Path "$RegPath\$App" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD' -Force
    }
    if ( -not ( Get-ItemProperty -Path "$RegPath\$App" -Name 'SoundFile' -ErrorAction SilentlyContinue ) ) {
        New-ItemProperty -Path "$RegPath\$App" -Name 'SoundFile' -PropertyType 'STRING' -Force
    }
}

# Personalize greeting if enabled
if ( $GreetGivenName -eq 'True' ) {
    Write-ToastLog -Message 'Greeting with given name selected. Replacing HeaderText'
    $Hour = ( Get-Date ).TimeOfDay.Hours
    if ( ( $Hour -ge 0 ) -and ( $Hour -lt 12 ) ) {
        Write-ToastLog -Message "Greeting with $GreetMorningText"
        $Greeting = $GreetMorningText
    } elseif ( ( $Hour -ge 12 ) -and ( $Hour -lt 16 ) ) {
        Write-ToastLog -Message "Greeting with $GreetAfternoonText"
        $Greeting = $GreetAfternoonText
    } else {
        Write-ToastLog -Message "Greeting with personal greeting: $GreetEveningText"
        $Greeting = $GreetEveningText
    }
    $GivenName = Get-GivenName
    $HeaderText = "$Greeting $GivenName"
}

# Determine which action buttons are enabled
$action1Enabled = $ActionButton1Enabled -eq 'True'
$action2Enabled = $ActionButton2Enabled -eq 'True'
$action3Enabled = $ActionButton3Enabled -eq 'True'
$dismissButtonEnabled = $DismissButtonEnabled -eq 'True'

# Ensure at least one action button or dismiss is enabled
$enabledActions = @($action1, $action2, $action3) -eq $true
$actionCount = $enabledActions.Count

if ($actionCount -le 1 -and !$dismiss) {
    $dismiss = $true
}

# Build actions XML
$actionsXml = [System.Collections.Generic.List[string]]::new()

if ($action1Enabled) {
    $actionsXml.Add("<action activationType = `"protocol`" arguments = `"$Action1`" content = `"$ActionButton1Content`" />")
}
if ($action2Enabled) {
    $actionsXml.Add("<action activationType = `"protocol`" arguments = `"$Action2`" content = `"$ActionButton2Content`" />")
}
if ($action3Enabled) {
    $actionsXml.Add("<action activationType = `"protocol`" arguments = `"$Action3`" content = `"$ActionButton3Content`" />")
}
if ($dismissButtonEnabled) {
    $actionsXml.Add("<action activationType = `"system`" arguments = `"dismiss`" content = `"$DismissButtonContent`" />")
}

$actionsSection = $actionsXml -join "`n"

# Base toast XML
Write-ToastLog -Message 'Creating the xml for enabled action buttons'
[xml]$Toast = @"
<toast scenario = "$Scenario">
    <visual>
    <binding template = "ToastGeneric">
        <image placement = "hero" src = "$HeroImage"/>
        <image id = "1" placement = "appLogoOverride" hint-crop = "circle" src = "$LogoImage"/>
        <text placement = "attribution">$AttributionText</text>
        <text>$HeaderText</text>
        <group>
            <subgroup>
                <text hint-style = "title" hint-wrap = "true">$TitleText</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style = "body" hint-wrap = "true">$BodyText1</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style = "body" hint-wrap = "true">$BodyText2</text>
            </subgroup>
        </group>
    </binding>
    </visual>
    <actions>
        $actionsSection
    </actions>
</toast>
"@

# Add snooze button if enabled
if ($SnoozeButtonEnabled -eq 'True') {
    Write-ToastLog -Message 'Creating the xml for displaying the snooze button'
    Write-ToastLog -Message 'This will always enable the action button as well as the dismiss button' -Level Warn
    Write-ToastLog -Message 'Replacing any previous formatting of the toast xml' -Level Warn
    [xml]$Toast = @"
<toast scenario = "$Scenario">
    <visual>
    <binding template = "ToastGeneric">
        <image placement = "hero" src = "$HeroImage"/>
        <image id = "1" placement = "appLogoOverride" hint-crop = "circle" src = "$LogoImage"/>
        <text placement = "attribution">$AttributionText</text>
        <text>$HeaderText</text>
        <group>
            <subgroup>
                <text hint-style = "title" hint-wrap = "true">$TitleText</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style = "body" hint-wrap = "true">$BodyText1</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style = "body" hint-wrap = "true">$BodyText2</text>
            </subgroup>
        </group>
    </binding>
    </visual>
    <actions>
        <input id = "snoozeTime" type = "selection" title = "$SnoozeText" defaultInput = "15">
            <selection id = "15" content = "15 $MinutesText"/>
            <selection id = "30" content = "30 $MinutesText"/>
            <selection id = "60" content = "1 $HourText"/>
            <selection id = "240" content = "4 $HoursText"/>
            <selection id = "480" content = "8 $HoursText"/>
        </input>
        <action activationType = "protocol" arguments = "$Action1" content = "$ActionButton1Content" />
        <action activationType = "system" arguments = "snooze" hint-inputId = "snoozeTime" content = "$SnoozeButtonContent"/>
        <action activationType = "system" arguments = "dismiss" content = "$DismissButtonContent"/>
    </actions>
</toast>
"@
}

# Add deadline information if enabled
if (($DeadlineEnabled -eq 'True') -or ($DynDeadlineEnabled -eq 'True')) {
    if ($DeadlineContent) {
        $LocalCulture = Get-Culture
        $RegionDateFormat = [System.Globalization.CultureInfo]::GetCultureInfo($LocalCulture.LCID).DateTimeFormat.LongDatePattern
        $RegionTimeFormat = [System.Globalization.CultureInfo]::GetCultureInfo($LocalCulture.LCID).DateTimeFormat.ShortTimePattern
        $LocalDateFormat = $DeadlineContent
        $LocalDateFormat = Get-Date $LocalDateFormat -f "$RegionDateFormat $RegionTimeFormat"

        $DeadlineGroup = @"
        <group>
            <subgroup>
                <text hint-style = "base" hint-align = "left">$DeadlineText</text>
                 <text hint-style = "caption" hint-align = "left">$LocalDateFormat</text>
            </subgroup>
        </group>
"@
        $Toast.toast.visual.binding.InnerXml += $DeadlineGroup
    }
}

# Add pending reboot text if enabled
if ($PendingRebootCheckTextEnabled -eq 'True') {
    $PendingRebootGroup = @"
        <group>
            <subgroup> 
                <text hint-style = "body" hint-wrap = "true" >$PendingRebootCheckTextValue</text>
            </subgroup>
        </group>
"@
    $Toast.toast.visual.binding.InnerXml += $PendingRebootGroup
}

# Add AD password expiration text if enabled
if ($ADPasswordExpirationTextEnabled -eq 'True') {
    $ADPasswordExpirationGroup = @"
        <group>
            <subgroup>
                <text hint-style = "body" hint-wrap = "true" >$ADPasswordExpirationTextValue $ADPasswordExpirationDate</text>
            </subgroup>
        </group>
"@
    $Toast.toast.visual.binding.InnerXml += $ADPasswordExpirationGroup
}

# Add uptime text if conditions are met
if (($PendingRebootUptimeTextEnabled -eq 'True') -and ($Uptime -gt $MaxUptimeDays)) {
    $UptimeGroup = @"
        <group>
            <subgroup>
                <text hint-style = "body" hint-wrap = "true" >$PendingRebootUptimeTextValue</text>
            </subgroup>
        </group>
        <group>
            <subgroup>
                <text hint-style = "base" hint-align = "left">$ComputerUptimeText $Uptime $ComputerUptimeDaysText</text>
            </subgroup>
        </group>
"@
    $Toast.toast.visual.binding.InnerXml += $UptimeGroup
}

# Determine when to display the toast based on conditions
if (($UpgradeOS -eq 'True') -and ($RunningOS.BuildNumber -lt $TargetOS)) {
    Write-ToastLog -Message 'Toast notification is used in regards to OS upgrade. Taking running OS build into account'
    Show-ToastNotification
} elseif (($PendingRebootUptime -eq 'True') -and ($Uptime -gt $MaxUptimeDays)) {
    Write-ToastLog -Message "Toast notification is used in regards to pending reboot. Uptime count is greater than $MaxUptimeDays"
    Show-ToastNotification
} elseif (($PendingRebootCheck -eq 'True') -and ($TestPendingRebootRegistry -eq $True)) {
    Write-ToastLog -Message "Toast notification is used in regards to pending reboot registry. TestPendingRebootRegistry returned $TestPendingRebootRegistry"
    Show-ToastNotification
} elseif (($PendingRebootCheck -eq 'True') -and ($TestPendingRebootWMI -eq $True)) {
    Write-ToastLog -Message "Toast notification is used in regards to pending reboot WMI. TestPendingRebootWMI returned $TestPendingRebootWMI"
    Show-ToastNotification
} elseif (($ADPasswordExpiration -eq 'True') -and ($ADPasswordExpirationResult -eq $True)) {
    Write-ToastLog -Message "Toast notification is used in regards to ADPasswordExpiration. ADPasswordExpirationResult returned $ADPasswordExpirationResult"
    Show-ToastNotification
} elseif (($UpgradeOS -ne 'True') -and ($PendingRebootCheck -ne 'True') -and ($PendingRebootUptime -ne 'True') -and ($ADPasswordExpiration -ne 'True')) {
    Write-ToastLog -Message 'Toast notification is not used in regards to OS upgrade OR Pending Reboots OR ADPasswordExpiration. Displaying default toast'
    Show-ToastNotification
} else {
    Write-ToastLog -Level Warn -Message 'Conditions for displaying toast notification are not fulfilled'
}