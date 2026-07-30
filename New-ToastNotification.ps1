[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
<#
.SYNOPSIS
    Displays customizable toast notifications on Windows 10/11 systems.

.DESCRIPTION
    The Toast Notification Script is a streamlined PowerShell solution for displaying rich toast
    notifications to end users on Windows 10/11. It is configurable through an XML configuration file,
    allowing organizations to tailor notifications for scenarios such as pending reboots, password
    expirations and general information delivery.

    The script supports:
        - Up to three action buttons with custom actions (reboot, PowerShell scripts, Learn More URLs).
        - Dismiss and snooze buttons, with logic to prevent conflicting or excessive button combinations.
        - Dynamic content including device uptime and AD password expiration.
        - Custom branding with hero and logo images, including downloading images from URLs.
        - Integration with PowerShell or a custom notification app for notification delivery.
        - Registry and file system checks to ensure prerequisites are met and to prevent excessive frequency.
        - Logging of all actions and errors for troubleshooting and auditing.
        - Learn More button functionality that opens a URL and re-displays the notification if clicked.
        - PowerShell script execution via ToastRunPSScript actions for custom automation tasks.
        - Silent execution of custom PowerShell scripts via SilentLauncher.exe to prevent window flashing.

    This version focuses on core notification scenarios and removes legacy ConfigMgr integration and OS
    upgrade features. The script makes changes to the local machine (registry entries, custom action
    scripts and protocols). It must run in the logged on user context (it is designed to be launched by
    the scheduled task that Invoke-ToastNotification.ps1 creates); if it detects the SYSTEM or any
    non-user context it logs the reason and throws, because toast notifications can only be shown in the
    user session.

    If a custom PowerShell script (Action3) is configured, the script will automatically download
    SilentLauncher.exe to the working directory. The ToastRunPSScript protocol handler is then configured
    to use SilentLauncher.exe to execute the target script, ensuring it runs completely silently without
    flashing a PowerShell window when the user clicks the action button.

.PARAMETER Config
    Path to the XML configuration file. Can be a local path or a URL. If not specified, defaults to
    'config-toast.xml' in the script directory.

.EXAMPLE
    .\New-ToastNotification.ps1 -Config 'C:\Scripts\config-toast.xml'

    Runs the script using the specified local configuration file.

.NOTES
    - Requires Windows 10/11.
    - Must run as the logged on user, not SYSTEM. The script throws if launched in a non-user context.
    - Extensive logging is written to $env:ProgramData\_Automation\Script\New-ToastNotification\ToastNotification.log.
    - Learn More button functionality creates temporary files and registry entries for protocol handling.
    - If Action3 (Run Script) is used, SilentLauncher.exe is downloaded to execute the script silently.

.LINK
    https://github.com/imabdk/Toast-Notification-Script
#>

[CmdletBinding()]
param (
    [Parameter(HelpMessage = 'Path to XML Configuration File')]
    [String]$Config
)

#region globals
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'
#endregion

#region variables
$scriptVersion = '4.0'
$scriptRootPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$customScriptsPath = '{0}\_Automation\Script\New-ToastNotification' -f $env:ProgramData
$silentLauncherName = 'SilentLauncher'
$silentLauncherPath = '{0}\{1}.exe' -f $customScriptsPath, $silentLauncherName
$baseUrl = 'https://contentrepo.net/repo'
$silentLauncherUrl = '{0}/app/{1}.exe' -f $baseUrl, $silentLauncherName
$registryPath = 'HKCU:\SOFTWARE\ToastNotificationScript'
$defaultUserCulture = 'en-US'
$logoImageTemp = '{0}\ToastLogoImage.jpg' -f $customScriptsPath
$heroImageTemp = '{0}\ToastHeroImage.jpg' -f $customScriptsPath
$imagesPath = 'file:///{0}/New-ToastNotification/Images' -f $customScriptsPath
$learnMoreLogPath = '{0}\learn-more.txt' -f $customScriptsPath
#endregion

#region functions
function Write-ToastLog {
    <#
    .SYNOPSIS
        Writes a message to a log file with a specified level.
    .DESCRIPTION
        Logs messages to a file, supporting Info, Warn and Error levels. If the log file exceeds 5MB it
        is deleted and recreated. Creates the log file if it does not exist.
    .PARAMETER Message
        The message to be logged.
    .PARAMETER Path
        The path to the log file. Defaults to the ToastNotification.log in the custom scripts path.
    .PARAMETER Level
        The log level: Info, Warn or Error. Defaults to Info.
    .EXAMPLE
        Write-ToastLog -Message 'Script started' -Level 'Info'
        Writes an informational log entry.
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('LogContent')]
        [String]$Message,
        [Parameter(Mandatory = $false)]
        [Alias('LogPath')]
        [String]$Path = ('{0}\ToastNotification.log' -f $customScriptsPath),
        [Parameter(Mandatory = $false)]
        [ValidateSet('Error', 'Warn', 'Info')]
        [String]$Level = 'Info'
    )
    begin {  }
    process {
        $maxLogSize = 5
        if (Test-Path -Path $Path) {
            $logSize = (Get-Item -Path $Path).Length / 1MB
        }
        if ((Test-Path -Path $Path) -and $logSize -gt $maxLogSize) {
            Write-Error -Message ('Log file {0} already exists and file exceeds maximum file size. Deleting the log and starting fresh.' -f $Path)
            Remove-Item -Path $Path -Force
            New-Item -Path $Path -Force -ItemType File | Out-Null
        } elseif (-not (Test-Path -Path $Path)) {
            Write-Verbose -Message ('Creating {0}.' -f $Path)
            New-Item -Path $Path -Force -ItemType File | Out-Null
        }
        $formattedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        switch ($Level) {
            'Error' {
                Write-Error -Message $Message
                $levelText = 'ERROR:'
            }
            'Warn' {
                Write-Warning -Message $Message
                $levelText = 'WARNING:'
            }
            'Info' {
                Write-Verbose -Message $Message
                $levelText = 'INFO:'
            }
        }
        ('{0} {1} {2}' -f $formattedDate, $levelText, $Message) | Out-File -FilePath $Path -Append
    }
    end { }
}

function Test-PendingRebootRegistry {
    <#
    .SYNOPSIS
        Checks for pending reboots in the registry.
    .DESCRIPTION
        Examines specific registry keys to determine if a reboot is pending due to component-based
        servicing or Windows Update operations.
    .EXAMPLE
        Test-PendingRebootRegistry
        Returns True when a reboot is pending.
    #>
    [CmdletBinding()]
    [OutputType([Bool])]
    param ()

    Write-ToastLog -Message 'Running Test-PendingRebootRegistry function'
    $cbsRebootKey = Test-Path -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $wuRebootKey = Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    if (($cbsRebootKey) -or ($wuRebootKey)) {
        Write-ToastLog -Message 'Check returned TRUE on ANY of the registry checks: Reboot is pending!'
        return $true
    } else {
        Write-ToastLog -Message 'Check returned FALSE on ANY of the registry checks: Reboot is NOT pending!'
        return $false
    }
}

function Get-DeviceUptime {
    <#
    .SYNOPSIS
        Retrieves the device uptime in days.
    .DESCRIPTION
        Calculates the number of days since the last system boot using CIM.
    .EXAMPLE
        Get-DeviceUptime
        Returns the number of days since the last boot.
    #>
    [CmdletBinding()]
    [OutputType([Int])]
    param ()

    Write-ToastLog -Message 'Running Get-DeviceUptime function'
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $uptime = (Get-Date) - ($operatingSystem.LastBootUpTime)
    return $uptime.Days
}

function Get-WindowsVersion {
    <#
    .SYNOPSIS
        Verifies if the system is running a supported Windows version.
    .DESCRIPTION
        Checks if the OS is Windows 10 or 11 and a workstation type. Returns True if supported.
    .EXAMPLE
        Get-WindowsVersion
        Returns True on a supported workstation OS.
    #>
    [CmdletBinding()]
    [OutputType([Bool])]
    param ()

    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    if (($operatingSystem.Version -like '10.0.*') -and ($operatingSystem.ProductType -eq 1)) {
        Write-ToastLog -Message 'Running supported version of Windows. Windows 10 and workstation OS detected'
        return $true
    } else {
        Write-ToastLog -Level Error -Message 'Not running supported version of Windows'
        return $false
    }
}

function Test-WindowsPushNotificationsEnabled {
    <#
    .SYNOPSIS
        Tests if Windows push notifications are enabled for the user.
    .DESCRIPTION
        Checks the registry to see if toast notifications are enabled for the current user. Returns True
        when enabled and False when disabled or when the value is missing.
    .EXAMPLE
        Test-WindowsPushNotificationsEnabled
        Returns True when toast notifications are enabled.
    #>
    [CmdletBinding()]
    [OutputType([Bool])]
    param ()

    $toastEnabledKey = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name ToastEnabled -ErrorAction Ignore).ToastEnabled
    if ($toastEnabledKey -eq '1') {
        Write-ToastLog -Message 'Toast notifications for the logged on user are enabled in Windows'
        return $true
    } else {
        Write-ToastLog -Level Error -Message 'Toast notifications for the logged on user are not enabled in Windows. The script will try to enable toast notifications for the logged on user'
        return $false
    }
}

function Enable-WindowsPushNotification {
    <#
    .SYNOPSIS
        Enables Windows push notifications for the user.
    .DESCRIPTION
        Modifies the registry and restarts the Windows Push Notification service to enable toast notifications.
    .EXAMPLE
        Enable-WindowsPushNotification
        Enables toast notifications for the logged on user.
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param ()

    $toastEnabledKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications'
    Write-ToastLog -Message 'Trying to enable toast notifications for the logged on user'
    try {
        Set-ItemProperty -Path $toastEnabledKeyPath -Name ToastEnabled -Value 1 -Force
        Get-Service -Name 'WpnUserService*' | Restart-Service -Force
        Write-ToastLog -Message 'Successfully enabled toast notifications for the logged on user'
    } catch {
        Write-ToastLog -Level Error -Message 'Failed to enable toast notifications for the logged on user. Toast notifications will probably not be displayed'
    }
}

function Test-NTSystem {
    <#
    .SYNOPSIS
        Determines if the script is running under the SYSTEM account.
    .DESCRIPTION
        Checks the current security principal to identify if the script is running as SYSTEM or a user.
    .EXAMPLE
        Test-NTSystem
        Returns True when running as SYSTEM.
    #>
    [CmdletBinding()]
    [OutputType([Bool])]
    param ()

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentUser.IsSystem -eq $true) {
        Write-ToastLog -Message 'Script is initially running in SYSTEM context. Please be vary, that this has limitations and may not work!'
        return $true
    } else {
        Write-ToastLog -Message 'Script is initially running in USER context'
        return $false
    }
}

function Get-GivenName {
    <#
    .SYNOPSIS
        Retrieves the user given name.
    .DESCRIPTION
        Attempts to get the user given name from Active Directory using a native ADSI/LDAP query,
        falling back to registry data if AD is unavailable.
    .EXAMPLE
        Get-GivenName
        Returns the given name of the logged on user.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param ()

    Write-ToastLog -Message 'Running Get-GivenName function'
    try {
        $searcher = [ADSISearcher]('(&(objectCategory=person)(objectClass=user)(sAMAccountName={0}))' -f [Environment]::UserName)
        $null = $searcher.PropertiesToLoad.Add('givenName')
        $result = $searcher.FindOne()
        if ($null -ne $result) {
            $givenNameProperty = $result.Properties['givenname']
            if ($givenNameProperty.Count -gt 0) {
                $givenName = [string]$givenNameProperty[0]
            }
        }
    } catch [System.Exception] {
        Write-ToastLog -Level Warn -Message ('{0}' -f $_)
    } finally {
        if ($null -ne $searcher) { $searcher.Dispose() }
    }
    if (-not [string]::IsNullOrEmpty($givenName)) {
        Write-ToastLog -Message ('Given name retrieved from Active Directory: {0}' -f $givenName)
        return $givenName
    } else {
        Write-ToastLog -Message 'Given name not found in AD or no local AD is available. Continuing looking for given name elsewhere'
        $regKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
        if ((Get-ItemProperty -Path $regKey).LastLoggedOnDisplayName) {
            $loggedOnUserDisplayName = Get-ItemProperty -Path $regKey -Name 'LastLoggedOnDisplayName' | Select-Object -ExpandProperty LastLoggedOnDisplayName
            if (-not [string]::IsNullOrEmpty($loggedOnUserDisplayName)) {
                $displayName = $loggedOnUserDisplayName.Split(' ')
                $givenName = $displayName[0]
                Write-ToastLog -Message ('Given name found directly in registry: {0}' -f $givenName)
                return $givenName
            } else {
                Write-ToastLog -Message 'Given name not found in registry. Using nothing as placeholder'
                return $null
            }
        } else {
            Write-ToastLog -Message 'Given name not found in registry. Using nothing as placeholder'
            return $null
        }
    }
}

function Get-ADPasswordExpiration {
    <#
    .SYNOPSIS
        Checks if the user AD password is nearing expiration.
    .DESCRIPTION
        Queries AD to determine the password expiration date and compares it against a threshold in days.
    .PARAMETER FADPasswordExpirationDays
        The number of days within which to check for password expiration.
    .EXAMPLE
        Get-ADPasswordExpiration -FADPasswordExpirationDays '14'
        Returns True with the expiry date and time span when the password expires within 14 days.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true)]
        [String]$FADPasswordExpirationDays
    )

    Write-ToastLog -Message 'Running Get-ADPasswordExpiration function'
    Write-ToastLog -Message 'Getting SamAccountName and DomainName for the current user session'
    $samAccountName = [Environment]::UserName
    $domainName = $env:USERDNSDOMAIN
    if (($samAccountName) -and ($domainName)) {
        Write-ToastLog -Message ('SamAccountName found: {0} and DomainName found: {1}. Continuing looking for AD password expiration date' -f $samAccountName, $domainName)
        try {
            $root = [ADSI] ('LDAP://{0}' -f $domainName)
            $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $root, ('(SamAccountName = {0})' -f $samAccountName)
            $searcher.PropertiesToLoad.Add('msDS-UserPasswordExpiryTimeComputed') | Out-Null
            $result = $searcher.FindOne()
            $expiryDate = [DateTime]::FromFileTime([Int64]::Parse((($result.Properties['msDS-UserPasswordExpiryTimeComputed'])[0]).ToString()))
        } catch {
            Write-ToastLog -Level Error -Message 'Failed to retrieve password expiration date from Active Directory. Script is continuing, but without password expiration date'
        }
        if ($expiryDate) {
            Write-ToastLog -Message ('Password expiration date found. Password is expiring on {0}. Calculating time to expiration' -f $expiryDate)
            $localCulture = Get-Culture
            $regionDateFormat = [System.Globalization.CultureInfo]::GetCultureInfo($localCulture.LCID).DateTimeFormat.LongDatePattern
            $expiryDate = Get-Date -Date $expiryDate -Format $regionDateFormat
            $today = Get-Date -Format $regionDateFormat
            $dateDiff = New-TimeSpan -Start $today -End $expiryDate
            if ($dateDiff.Days -le $FADPasswordExpirationDays -and $dateDiff.Days -ge 0) {
                Write-ToastLog -Message 'Password is expiring within the set period. Returning True'
                Write-ToastLog -Message ('ADPasswordExpirationDays is set to: {0}' -f $FADPasswordExpirationDays)
                return @($true, $expiryDate, $dateDiff)
            } else {
                Write-ToastLog -Message 'Password is not expiring anytime soon. Returning False'
                Write-ToastLog -Message ('ADPasswordExpirationDays is set to: {0}' -f $FADPasswordExpirationDays)
                return @($false)
            }
        } else {
            Write-ToastLog -Level Error -Message 'No password expiration date found. Returning False'
            return @($false)
        }
    } else {
        Write-ToastLog -Level Error -Message 'Failed to retrieve SamAccountName or DomainName from the current user session. Script is continuing, but password expiration date cannot be retrieved'
        return @($false)
    }
}

function Write-CustomActionRegistry {
    <#
    .SYNOPSIS
        Registers custom action protocols in the registry.
    .DESCRIPTION
        Creates registry entries for custom protocols (for example ToastReboot) used by toast action buttons.
        Points the protocol handler to SilentLauncher.exe to execute the .cmd files silently and guarantee 
        zero window flashing at the OS level.
    .PARAMETER ActionType
        The type of action to register (for example ToastReboot).
    .PARAMETER RegCommandPath
        The path where the command script is located. Defaults to the custom scripts path.
    .EXAMPLE
        Write-CustomActionRegistry -ActionType 'ToastReboot'
        Registers the ToastReboot protocol.
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [Parameter(Position = 0)]
        [ValidateSet('ToastReboot', 'ToastRunPSScript', 'ToastLearnMore')]
        [String]$ActionType,
        [Parameter(Position = 1)]
        [String]$RegCommandPath = $customScriptsPath
    )

    Write-ToastLog -Message ('Running Write-CustomActionRegistry function: {0}' -f $ActionType)
    try {
        New-Item -Path ('HKCU:\Software\Classes\{0}\shell\open\command' -f $ActionType) -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath ('HKCU:\Software\Classes\{0}' -f $ActionType) -Name 'URL Protocol' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath ('HKCU:\Software\Classes\{0}' -f $ActionType) -Name '(default)' -Value ('URL:{0} Protocol' -f $ActionType) -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

        $silentLauncherPath = '{0}\SilentLauncher.exe' -f $RegCommandPath
        $cmdFilePath = '{0}\{1}.cmd' -f $RegCommandPath, $ActionType

        if ($ActionType -eq 'ToastRunPSScript') {
            $regCommandValue = '{0}{1}{0} -script {0}{2}{0} %1' -f [char]34, $silentLauncherPath, $cmdFilePath
        } else {
            $regCommandValue = '{0}{1}{0} -script {0}{2}{0}' -f [char]34, $silentLauncherPath, $cmdFilePath
        }

        New-ItemProperty -LiteralPath ('HKCU:\Software\Classes\{0}\shell\open\command' -f $ActionType) -Name '(default)' -Value $regCommandValue -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-ToastLog -Level Error -Message ('Failed to create the {0} custom protocol in HKCU\Software\Classes. Action button might not work. Reason: {1}' -f $ActionType, $_.Exception.Message)
    }
}

function Write-CustomActionScript {
    <#
    .SYNOPSIS
        Creates scripts for custom actions triggered by toast buttons.
    .DESCRIPTION
        Generates the .cmd and .ps1 scripts for actions like rebooting, running the toast as the user,
        running a PowerShell script or opening a Learn More URL, storing them in the specified path.
    .PARAMETER Type
        The type of action script to create (for example ToastReboot).
    .PARAMETER Path
        The directory where scripts are saved. Defaults to the custom scripts path.
    .EXAMPLE
        Write-CustomActionScript -Type 'ToastReboot'
        Creates the ToastReboot command script.
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [Parameter(Position = 0)]
        [ValidateSet('ToastReboot', 'ToastRunPSScript', 'ToastLearnMore')]
        [String]$Type,
        [Parameter(Position = 1)]
        [String]$Path = $customScriptsPath
    )

    Write-ToastLog -Message ('Running Write-CustomActionScript function: {0}' -f $Type)
    switch ($Type) {
        'ToastReboot' {
            try {
                $cmdFileName = '{0}.cmd' -f $Type
                New-Item -Path $Path -Name $cmdFileName -Force -OutVariable pathInfo | Out-Null
                $getCustomScriptPath = $pathInfo.FullName
                $scriptContent = 'shutdown /r /t 0 /d p:0:0 /c {0}Toast Notification Reboot{0}' -f [char]34
                if (-not [string]::IsNullOrEmpty($scriptContent)) {
                    Out-File -FilePath $getCustomScriptPath -InputObject $scriptContent -Encoding ASCII -Force
                }
            } catch {
                Write-ToastLog -Level Error -Message ('Failed to create the custom .cmd script for {0}. Action button might not work' -f $Type)
                Write-ToastLog -Level Error -Message ('Error message: {0}' -f $_.Exception.Message)
            }
            break
        }
        'ToastRunPSScript' {
            try {
                $cmdFileName = '{0}.cmd' -f $Type
                New-Item -Path $Path -Name $cmdFileName -Force -OutVariable pathInfo | Out-Null
                $getCustomScriptPath = $pathInfo.FullName

                $scriptContent = '{0} -script {1}{2}{1}' -f $silentLauncherPath, [char]34, $psScriptPath

                if (-not [string]::IsNullOrEmpty($scriptContent)) {
                    Out-File -FilePath $getCustomScriptPath -InputObject $scriptContent -Encoding ASCII -Force
                }
            } catch {
                Write-ToastLog -Level Error -Message ('Failed to create the custom .cmd script for {0}. Action button might not work' -f $Type)
                Write-ToastLog -Level Error -Message ('Error message: {0}' -f $_.Exception.Message)
            }
            break
        }
        'ToastLearnMore' {
            try {
                $cmdFileName = '{0}.cmd' -f $Type
                New-Item -Path $Path -Name $cmdFileName -Force -OutVariable pathInfo | Out-Null
                $getCustomScriptPath = $pathInfo.FullName
                $learnMoreTemplate = @'
@echo off
start {1}
set {0}learnMoreUrl={1}{0}
set {0}logFile={2}{0}
echo [%date% %time%] URL [%learnMoreUrl%] launched >> {0}%logFile%{0}
'@
                $scriptContent = $learnMoreTemplate -f [char]34, [String]$learnMoreUrl, [String]$learnMoreLogPath
                if (-not [string]::IsNullOrEmpty($scriptContent)) {
                    Out-File -FilePath $getCustomScriptPath -InputObject $scriptContent -Encoding ASCII -Force
                }
            } catch {
                Write-ToastLog -Level Error -Message ('Failed to create the custom .cmd script for {0}. Action button might not work' -f $Type)
                Write-ToastLog -Level Error -Message ('Error message: {0}' -f $_.Exception.Message)
            }
            break
        }
    }
}

function Show-ToastNotification {
    <#
    .SYNOPSIS
        Displays the toast notification to the user.
    .DESCRIPTION
        Shows the constructed toast notification in the logged on user context and optionally plays
        custom audio.
    .EXAMPLE
        Show-ToastNotification
        Displays the toast notification.
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param ()

    try {
        Write-ToastLog -Message 'Confirmed USER context before displaying toast'
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $toastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
        $toastXml.LoadXml($Toast.OuterXml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($App).Show($toastXml)
        Write-ToastLog -Message 'All good. Toast notification was displayed'
        Write-Information -MessageData 'All good. Toast notification was displayed' -InformationAction Continue
        if ($CustomAudio -eq 'True') {
            Add-Type -AssemblyName System.Speech
            $speak = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
            Start-Sleep -Seconds 1.25
            $speak.SelectVoiceByHints('Female', 65)
            $speak.Speak($CustomAudioTextToSpeech)
            $speak.Dispose()
        }
        Save-NotificationLastRunTime
    } catch {
        Write-ToastLog -Message 'Something went wrong when displaying the toast notification' -Level Error
        Write-ToastLog -Message 'Make sure the script is running as the logged on user' -Level Error
        Write-Information -MessageData 'Something went wrong when displaying the toast notification. Make sure the script is running as the logged on user' -InformationAction Continue
    }
}

function Get-NotificationLastRunTime {
    <#
    .SYNOPSIS
        Retrieves the time since the last toast notification was displayed.
    .DESCRIPTION
        Reads the last run time from the registry and calculates the minutes elapsed since then.
    .EXAMPLE
        Get-NotificationLastRunTime
        Returns the number of minutes since the toast was last displayed.
    #>
    [CmdletBinding()]
    [OutputType([Int])]
    param ()

    $lastRunTime = (Get-ItemProperty -Path $registryPath -Name LastRunTime -ErrorAction Ignore).LastRunTime
    $currentTime = Get-Date -Format s
    if (-not [string]::IsNullOrEmpty($lastRunTime)) {
        $difference = ([datetime]$currentTime - [datetime]$lastRunTime)
        $minutesSinceLastRunTime = [math]::Round($difference.TotalMinutes)
        Write-ToastLog -Message ('Toast notification was previously displayed {0} minutes ago' -f $minutesSinceLastRunTime)
        return $minutesSinceLastRunTime
    }
}

function Save-NotificationLastRunTime {
    <#
    .SYNOPSIS
        Saves the current time as the last run time of the toast notification.
    .DESCRIPTION
        Stores the current timestamp in the registry to track when the toast was last shown.
    .EXAMPLE
        Save-NotificationLastRunTime
        Saves the current time to the registry.
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param ()

    $runTime = Get-Date -Format s
    if (-not (Get-ItemProperty -Path $registryPath -Name LastRunTime -ErrorAction Ignore)) {
        New-ItemProperty -Path $registryPath -Name LastRunTime -Value $runTime -Force | Out-Null
    } else {
        Set-ItemProperty -Path $registryPath -Name LastRunTime -Value $runTime -Force | Out-Null
    }
}

function Register-CustomNotificationApp {
    <#
    .SYNOPSIS
        Registers a custom notification app in the registry.
    .DESCRIPTION
        Creates registry entries to define a custom app for displaying toast notifications.
    .PARAMETER FAppID
        The ID of the custom app.
    .PARAMETER FAppDisplayName
        The display name of the custom app.
    .EXAMPLE
        Register-CustomNotificationApp -FAppID 'Toast.Custom.App' -FAppDisplayName 'Custom Toast App'
        Registers a custom notification app.
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true)]
        [String]$FAppID,
        [Parameter(Mandatory = $true)]
        [String]$FAppDisplayName
    )

    Write-ToastLog -Message 'Running Register-NotificationApp function'
    $appID = $FAppID
    $appDisplayName = $FAppDisplayName
    [int]$showInSettings = 0
    [int]$iconBackgroundColor = 0
    $iconUri = '%SystemRoot%\ImmersiveControlPanel\images\logo.png'
    $appRegPath = 'HKCU:\Software\Classes\AppUserModelId'
    $regPath = '{0}\{1}' -f $appRegPath, $appID
    try {
        if (-not (Test-Path -Path $regPath)) {
            New-Item -Path $appRegPath -Name $appID -Force | Out-Null
        }
        $displayName = Get-ItemProperty -Path $regPath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        if ($displayName -ne $appDisplayName) {
            New-ItemProperty -Path $regPath -Name DisplayName -Value $appDisplayName -PropertyType String -Force | Out-Null
        }
        $showInSettingsValue = Get-ItemProperty -Path $regPath -Name ShowInSettings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ShowInSettings -ErrorAction SilentlyContinue
        if ($showInSettingsValue -ne $showInSettings) {
            New-ItemProperty -Path $regPath -Name ShowInSettings -Value $showInSettings -PropertyType DWORD -Force | Out-Null
        }
        $iconUriValue = Get-ItemProperty -Path $regPath -Name IconUri -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IconUri -ErrorAction SilentlyContinue
        if ($iconUriValue -ne $iconUri) {
            New-ItemProperty -Path $regPath -Name IconUri -Value $iconUri -PropertyType ExpandString -Force | Out-Null
        }
        $iconBackgroundColorValue = Get-ItemProperty -Path $regPath -Name IconBackgroundColor -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IconBackgroundColor -ErrorAction SilentlyContinue
        if ($iconBackgroundColorValue -ne $iconBackgroundColor) {
            New-ItemProperty -Path $regPath -Name IconBackgroundColor -Value $iconBackgroundColor -PropertyType ExpandString -Force | Out-Null
        }
        Write-ToastLog -Message ('Created registry entries for custom notification app: {0}' -f $FAppDisplayName)
    } catch {
        Write-ToastLog -Message 'Failed to create one or more registry entries for the custom notification app' -Level Error
        Write-ToastLog -Message 'Toast Notifications are usually not displayed if the notification app does not exist' -Level Error
    }
}

function ConvertTo-ToastImageUri {
    <#
    .SYNOPSIS
        Converts a raw image reference into a URI usable by toast notifications.
    .DESCRIPTION
        Normalizes an image reference into a URI. If the value is already an http, https, or file URL
        it is returned unchanged. If it resolves to an existing local file it is converted to a file URI.
        Otherwise the value is treated as a file name and appended to a default folder URI. Empty or
        whitespace input returns nothing.
    .PARAMETER Raw
        The image reference to convert. Accepts an http/https/file URL, a local file path, or a bare
        file name. Empty or whitespace input returns $null.
    .PARAMETER DefaultFolderUri
        The base folder URI used as a prefix when Raw is a bare file name that is neither a URL nor an
        existing local path.
    .EXAMPLE
        ConvertTo-ToastImageUri -Raw 'C:\ProgramData\ToastNotification\logo.png'
        Returns a file:/// URI pointing to the resolved local image path.
    .EXAMPLE
        ConvertTo-ToastImageUri -Raw 'logo.png' -DefaultFolderUri 'https://cdn.example.com/toast'
        Returns 'https://cdn.example.com/toast/logo.png' when logo.png is not a URL or an existing local file.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter()]
        [String]$Raw,

        [Parameter()]
        [String]$DefaultFolderUri
    )
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    if ($Raw -match '^(https?|file)://') { return $Raw }
    if ($Raw -match '^([A-Za-z]:[\\/]|\\\\)') {
        if (Test-Path -LiteralPath $Raw) {
            $p = (Resolve-Path -LiteralPath $Raw).Path -replace '\\', '/'
            return $(if ($p -match '^//') { 'file:{0}' -f $p } else { 'file:///{0}' -f $p.TrimStart('/') })
        }
        Write-ToastLog -Level Warn -Message ('Image path not found on this machine; no image will be set: {0}' -f $Raw)
        return $null
    }
    if (Test-Path -LiteralPath $Raw) {
        $p = (Resolve-Path -LiteralPath $Raw).Path -replace '\\', '/'
        return $(if ($p -match '^//') { 'file:{0}' -f $p } else { 'file:///{0}' -f $p.TrimStart('/') })
    }
    return ('{0}/{1}' -f $DefaultFolderUri, $Raw)
}
#endregion

#region set tls policy
$supportedTlsVersions = [enum]::GetValues('Net.SecurityProtocolType')
if (($supportedTlsVersions -contains 'Tls13') -and ($supportedTlsVersions -contains 'Tls12')) {
    [System.Net.ServicePointManager]::SecurityProtocol =
    [Enum]::ToObject([Net.SecurityProtocolType], 12288) -bor
    [Enum]::ToObject([Net.SecurityProtocolType], 3072)
} else {
    [Net.ServicePointManager]::SecurityProtocol =
    [Enum]::ToObject([Net.SecurityProtocolType], 3072)
}
#endregion

#region initialization
$userCulture = try {
    (Get-Culture).Name
} catch {
    Write-ToastLog -Level Error -Message 'Failed to get users local culture. This is used with the multi-language option, which now might not work properly'
}

if (-not (Test-Path -Path $registryPath)) {
    Write-ToastLog -Message ('ToastNotificationScript registry path not found. Creating it: {0}' -f $registryPath)
    try {
        New-Item -Path $registryPath -Force | Out-Null
    } catch {
        Write-ToastLog -Message ('Failed to create the ToastNotificationScript registry path: {0}' -f $registryPath) -Level Error
        Write-ToastLog -Message 'This is required. Script will now exit' -Level Error
        exit 1
    }
}

if (-not (Test-Path -Path $customScriptsPath)) {
    Write-ToastLog -Message ('CustomScriptPath not found. Creating it: {0}' -f $customScriptsPath)
    try {
        New-Item -Path $customScriptsPath -ItemType Directory -Force | Out-Null
    } catch {
        Write-ToastLog -Level Error -Message ('Failed to create the CustomScriptPath folder: {0}' -f $customScriptsPath)
        Write-ToastLog -Message 'This is required. Script will now exit' -Level Error
        exit 1
    }
}

$supportedWindowsVersion = Get-WindowsVersion
if ($supportedWindowsVersion -eq $false) {
    Write-ToastLog -Message 'Aborting script' -Level Error
    exit 1
}

$isSystem = Test-NTSystem
if ($isSystem -eq $true) {
    Write-ToastLog -Level Error -Message 'This script is running in the SYSTEM (non-user) context. Toast notifications can only be displayed in the logged on user session'
    Write-ToastLog -Level Error -Message 'This script must be launched as the logged on user (for example through the scheduled task created by Invoke-ToastNotification.ps1). Aborting'
    throw 'New-ToastNotification.ps1 must run in the logged on user context, not as SYSTEM.'
}
$windowsPushNotificationsEnabled = Test-WindowsPushNotificationsEnabled
if ($windowsPushNotificationsEnabled -eq $false) {
    Enable-WindowsPushNotification
}
#endregion

#region configuration loading
if (-not $Config) {
    Write-ToastLog -Message 'No config file set as parameter. Using local config file'
    $Config = Join-Path -Path $scriptRootPath -ChildPath 'config-toast.xml'
}

if ($Config.StartsWith('https://') -or $Config.StartsWith('http://')) {
    Write-ToastLog -Message 'Specified config file seems hosted [online]. Treating it accordingly'
    try { $testOnlineConfig = Invoke-WebRequest -Uri $Config -UseBasicParsing } catch { $null }
    if ($testOnlineConfig.StatusDescription -eq 'OK') {
        try {
            $webClient = New-Object -TypeName System.Net.WebClient
            $webClient.Encoding = [System.Text.Encoding]::UTF8
            $xml = [xml]$webClient.DownloadString($Config)
            Write-ToastLog -Message ('Successfully loaded {0}' -f $Config)
        } catch {
            Write-ToastLog -Message ('Error, could not read {0}' -f $Config) -Level Error
            Write-ToastLog -Message ('Error message: {0}' -f $_.Exception.Message) -Level Error
            Write-Information -MessageData ('Error, could not read {0}. Error message: {1}' -f $Config, $_.Exception.Message) -InformationAction Continue
            exit 1
        }
    } else {
        Write-ToastLog -Level Error -Message 'The provided URL to the config does not reply or does not come back OK'
        Write-Information -MessageData 'The provided URL to the config does not reply or does not come back OK' -InformationAction Continue
        exit 1
    }
} else {
    Write-ToastLog -Message 'Specified config file seems hosted [locally or fileshare]. Treating it accordingly'
    if (Test-Path -Path $Config) {
        try {
            $xml = [xml](Get-Content -Path $Config -Encoding UTF8)
            Write-ToastLog -Message ('Successfully loaded {0}' -f $Config)
        } catch {
            Write-ToastLog -Message ('Error, could not read {0}' -f $Config) -Level Error
            Write-ToastLog -Message ('Error message: {0}' -f $_.Exception.Message) -Level Error
            exit 1
        }
    } else {
        Write-ToastLog -Level Error -Message 'No config file found on the specified location [locally or fileshare]'
        exit 1
    }
}

if (-not [string]::IsNullOrEmpty($xml)) {
    try {
        Write-ToastLog -Message ('Loading xml content from {0} into variables' -f $Config)
        $toastEnabled = $xml.Configuration.Feature | Where-Object -FilterScript { $_.Name -like 'Toast' } | Select-Object -ExpandProperty 'Enabled'
        $pendingRebootUptime = $xml.Configuration.Feature | Where-Object -FilterScript { $_.Name -like 'PendingRebootUptime' } | Select-Object -ExpandProperty 'Enabled'
        $pendingRebootCheck = $xml.Configuration.Feature | Where-Object -FilterScript { $_.Name -like 'PendingRebootCheck' } | Select-Object -ExpandProperty 'Enabled'
        $aDPasswordExpiration = $xml.Configuration.Feature | Where-Object -FilterScript { $_.Name -like 'ADPasswordExpiration' } | Select-Object -ExpandProperty 'Enabled'
        $pendingRebootUptimeTextEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'PendingRebootUptimeText' } | Select-Object -ExpandProperty 'Enabled'
        $maxUptimeDays = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'MaxUptimeDays' } | Select-Object -ExpandProperty 'Value'
        $pendingRebootCheckTextEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'PendingRebootCheckText' } | Select-Object -ExpandProperty 'Enabled'
        $aDPasswordExpirationTextEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'ADPasswordExpirationText' } | Select-Object -ExpandProperty 'Enabled'
        $aDPasswordExpirationDays = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'ADPasswordExpirationDays' } | Select-Object -ExpandProperty 'Value'
        $deadlineEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'Deadline' } | Select-Object -ExpandProperty 'Enabled'
        $deadlineContent = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'Deadline' } | Select-Object -ExpandProperty 'Value'
        $dynDeadlineEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'DynamicDeadline' } | Select-Object -ExpandProperty 'Enabled'
        $createScriptsProtocolsEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'CreateScriptsAndProtocols' } | Select-Object -ExpandProperty 'Enabled'
        $limitToastToRunEveryMinutesEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'LimitToastToRunEveryMinutes' } | Select-Object -ExpandProperty 'Enabled'
        $limitToastToRunEveryMinutesValue = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'LimitToastToRunEveryMinutes' } | Select-Object -ExpandProperty 'Value'
        $customAppEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'CustomNotificationApp' } | Select-Object -ExpandProperty 'Enabled'
        $customAppValue = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'CustomNotificationApp' } | Select-Object -ExpandProperty 'Value'
        $psAppStatus = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'UsePowershellApp' } | Select-Object -ExpandProperty 'Enabled'
        $customAudio = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'CustomAudio' } | Select-Object -ExpandProperty 'Enabled'
        $logoImageFileName = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'LogoImageName' } | Select-Object -ExpandProperty 'Value'
        $heroImageFileName = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'HeroImageName' } | Select-Object -ExpandProperty 'Value'
        $logoImage = ConvertTo-ToastImageUri -Raw $logoImageFileName -DefaultFolderUri $imagesPath
        $heroImage = ConvertTo-ToastImageUri -Raw $heroImageFileName -DefaultFolderUri $imagesPath
        $scenario = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'Scenario' } | Select-Object -ExpandProperty 'Type'
        $action1 = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'Action1' } | Select-Object -ExpandProperty 'Value'
        $action2 = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'Action2' } | Select-Object -ExpandProperty 'Value'
        $action3 = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'Action3' } | Select-Object -ExpandProperty 'Value'
        $greetGivenName = $xml.Configuration.Text | Where-Object -FilterScript { $_.Option -like 'GreetGivenName' } | Select-Object -ExpandProperty 'Enabled'
        $multiLanguageSupport = $xml.Configuration.Text | Where-Object -FilterScript { $_.Option -like 'MultiLanguageSupport' } | Select-Object -ExpandProperty 'Enabled'
        $actionButton1Enabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'ActionButton1' } | Select-Object -ExpandProperty 'Enabled'
        $actionButton2Enabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'ActionButton2' } | Select-Object -ExpandProperty 'Enabled'
        $actionButton3Enabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'ActionButton3' } | Select-Object -ExpandProperty 'Enabled'
        $dismissButtonEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'DismissButton' } | Select-Object -ExpandProperty 'Enabled'
        $snoozeButtonEnabled = $xml.Configuration.Option | Where-Object -FilterScript { $_.Name -like 'SnoozeButton' } | Select-Object -ExpandProperty 'Enabled'
        if ($multiLanguageSupport -eq 'True') {
            Write-ToastLog -Message ('MultiLanguageSupport set to True. Current language culture is {0}. Checking for language support' -f $userCulture)
            if (-not [string]::IsNullOrEmpty($xml.Configuration.$userCulture)) {
                Write-ToastLog -Message ('Support for the users language culture found, localizing text using {0}' -f $userCulture)
                $xmlLang = $xml.Configuration.$userCulture
            } elseif (-not [string]::IsNullOrEmpty($xml.Configuration.$defaultUserCulture)) {
                Write-ToastLog -Message ('No support for the users language culture found, using {0} as default fallback language' -f $defaultUserCulture)
                $xmlLang = $xml.Configuration.$defaultUserCulture
            }
        } else {
            $xmlLang = $xml.Configuration.$defaultUserCulture
        }
        $pendingRebootUptimeTextValue = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'PendingRebootUptimeText' } | Select-Object -ExpandProperty '#text'
        $pendingRebootCheckTextValue = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'PendingRebootCheckText' } | Select-Object -ExpandProperty '#text'
        $aDPasswordExpirationTextValue = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'ADPasswordExpirationText' } | Select-Object -ExpandProperty '#text'
        $customAudioTextToSpeech = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'CustomAudioTextToSpeech' } | Select-Object -ExpandProperty '#text'
        $actionButton1Content = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'ActionButton1' } | Select-Object -ExpandProperty '#text'
        $actionButton2Content = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'ActionButton2' } | Select-Object -ExpandProperty '#text'
        $actionButton3Content = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'ActionButton3' } | Select-Object -ExpandProperty '#text'
        $dismissButtonContent = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'DismissButton' } | Select-Object -ExpandProperty '#text'
        $snoozeButtonContent = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'SnoozeButton' } | Select-Object -ExpandProperty '#text'
        $attributionText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'AttributionText' } | Select-Object -ExpandProperty '#text'
        $headerText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'HeaderText' } | Select-Object -ExpandProperty '#text'
        $titleText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'TitleText' } | Select-Object -ExpandProperty '#text'
        $bodyText1 = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'BodyText1' } | Select-Object -ExpandProperty '#text'
        $bodyText2 = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'BodyText2' } | Select-Object -ExpandProperty '#text'
        $snoozeText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'SnoozeText' } | Select-Object -ExpandProperty '#text'
        $deadlineText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'DeadlineText' } | Select-Object -ExpandProperty '#text'
        $greetMorningText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'GreetMorningText' } | Select-Object -ExpandProperty '#text'
        $greetAfternoonText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'GreetAfternoonText' } | Select-Object -ExpandProperty '#text'
        $greetEveningText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'GreetEveningText' } | Select-Object -ExpandProperty '#text'
        $minutesText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'MinutesText' } | Select-Object -ExpandProperty '#text'
        $hourText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'HourText' } | Select-Object -ExpandProperty '#text'
        $hoursText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'HoursText' } | Select-Object -ExpandProperty '#text'
        $computerUptimeText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'ComputerUptimeText' } | Select-Object -ExpandProperty '#text'
        $computerUptimeDaysText = $xmlLang.Text | Where-Object -FilterScript { $_.Name -like 'ComputerUptimeDaysText' } | Select-Object -ExpandProperty '#text'
        Write-ToastLog -Message ('Successfully loaded xml content from {0}' -f $Config)
    } catch {
        Write-ToastLog -Message ('Xml content from {0} was not loaded properly. Reason: {1}' -f $Config, $_.Exception.Message)
        exit 1
    }
}
#endregion

#region validation
if ($toastEnabled -ne 'True') {
    Write-ToastLog -Message ('Toast notification is not enabled. Please check {0} file' -f $Config)
    exit 1
}

if (($pendingRebootCheck -eq 'True') -and ($pendingRebootUptime -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You currently cannot have both PendingReboot features set to True. Please use them separately'
    exit 1
}
if (($aDPasswordExpiration -eq 'True') -and ($pendingRebootCheck -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You cannot have both ADPasswordExpiration AND PendingRebootCheck set to True at the same time. Check your config'
    exit 1
}
if (($aDPasswordExpiration -eq 'True') -and ($pendingRebootUptime -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You cannot have both ADPasswordExpiration AND PendingRebootUptime set to True at the same time. Check your config'
    exit 1
}

if (($customAppEnabled -eq 'True') -and ($psAppStatus -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You cannot have both PowerShell app set to True AND CustomNotificationApp set to True at the same time. Check your config'
    exit 1
}

if (($pendingRebootUptimeTextEnabled -eq 'True') -and ($pendingRebootCheckTextEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You cannot have PendingRebootUptimeText set to True and PendingRebootCheckText set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the text options. Check your config'
    exit 1
}
if (($pendingRebootCheck -eq 'True') -and ($pendingRebootUptimeTextEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You cannot have PendingRebootCheck set to True and PendingRebootUptimeText set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should use PendingRebootCheck with the PendingRebootCheckText option instead'
    exit 1
}
if (($pendingRebootUptime -eq 'True') -and ($pendingRebootCheckTextEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You cannot have PendingRebootUptime set to True and PendingRebootCheckText set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should use PendingRebootUptime with the PendingRebootUptimeText option instead. Check your config'
    exit 1
}
if (($aDPasswordExpirationTextEnabled -eq 'True') -and ($pendingRebootCheckTextEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You cannot have ADPasswordExpirationTextEnabled set to True and PendingRebootCheckText set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the text options. Check your config'
    exit 1
}
if (($aDPasswordExpirationTextEnabled -eq 'True') -and ($pendingRebootUptimeTextEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You cannot have ADPasswordExpirationTextEnabled set to True and PendingRebootUptimeTextEnabled set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the text options. Check your config'
    exit 1
}

if (($deadlineEnabled -eq 'True') -and ($dynDeadlineEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You cannot have DeadlineEnabled set to True and DynamicDeadlineEnabled set to True at the same time'
    Write-ToastLog -Level Error -Message 'You should only enable one of the deadline options. Check your config'
    exit 1
}

if (($actionButton2Enabled -eq 'True') -and ($snoozeButtonEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'You cannot have ActionButton2 enabled and SnoozeButton enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too many buttons. Check your config'
    exit 1
}
if (($actionButton3Enabled -eq 'True') -and ($snoozeButtonEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'You cannot have ActionButton3 enabled and SnoozeButton enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too many buttons. Check your config'
    exit 1
}
if (($actionButton3Enabled -eq 'True') -and ($deadlineEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'You cannot have ActionButton3 enabled and Deadline enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too many buttons. Check your config'
    exit 1
}
if (($snoozeButtonEnabled -eq 'True') -and ($pendingRebootUptimeTextEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'You cannot have SnoozeButton enabled and have PendingRebootUptimeText enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too much text and the toast notification will render without buttons. Check your config'
    exit 1
}
if (($snoozeButtonEnabled -eq 'True') -and ($pendingRebootCheckTextEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'You cannot have SnoozeButton enabled and have PendingRebootCheckText enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too much text and the toast notification will render without buttons. Check your config'
    exit 1
}
if (($snoozeButtonEnabled -eq 'True') -and ($aDPasswordExpirationTextEnabled -eq 'True')) {
    Write-ToastLog -Level Error -Message ('Error. Conflicting selection in the {0} file' -f $Config)
    Write-ToastLog -Level Error -Message 'You cannot have SnoozeButton enabled and have ADPasswordExpirationText enabled at the same time'
    Write-ToastLog -Level Error -Message 'That will result in too much text and the toast notification will render without buttons. Check your config'
    exit 1
}

if ($action3 -match '^ToastRunPSScript:$' -and $action3 -notmatch '\.ps1') {
    Write-ToastLog -Level Error -Message ('Error. Incomplete Value in the {0} file Action3 tag' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You have to specify also the ps1 path: like ToastRunPSScript:C:\ProgramData\_Automation\Script\ScriptName.ps1'
    exit 1
}

$psScriptPath = if ($action3 -match '^ToastRunPSScript:') {
    (($action3 -split ':')[1..$($action3.Length)]) -join ':'
}
if ($action3 -match '^ToastRunPSScript:') {
    if ([string]::IsNullOrEmpty($psScriptPath)) {
        Write-ToastLog -Level Error -Message ('Error. Incomplete Value in the {0} file Action3 tag' -f $Config)
        Write-ToastLog -Level Error -Message 'Error. You have to specify also the ps1 path: like ToastRunPSScript:C:\ProgramData\_Automation\Script\ScriptName.ps1'
        exit 1
    }
}
if ($psScriptPath) {
    if (-not (Test-Path -Path $psScriptPath)) {
        Write-ToastLog -Level Error -Message ('Provided path of the script to run ''{0}'' not found.' -f $psScriptPath)
        exit 1
    }
}

if ($action2 -match '^ToastLearnMore:$') {
    Write-ToastLog -Level Error -Message ('Error. Incomplete Value in the {0} file Action2 tag' -f $Config)
    Write-ToastLog -Level Error -Message 'Error. You have to specify also the learn more url: like ToastLearnMore:https:\\www.xyz.com'
    exit 1
}

$learnMoreUrl = if ($action2 -match '^ToastLearnMore:') {
    (($action2 -split ':')[1..$($action2.Length)]) -join ':'
}
#endregion

#region download silent launcher
if ($psScriptPath) {
    if (-not (Test-Path -Path $silentLauncherPath)) {
        Write-ToastLog -Level Error -Message ('Downloading {0}.exe from {1}' -f $silentLauncherName, $silentLauncherUrl)
        try {
            Invoke-WebRequest -Uri $silentLauncherUrl -OutFile $silentLauncherPath -UseBasicParsing -ErrorAction Stop
        } catch {
            if (-not (Test-Path -Path $silentLauncherPath)) {
                Write-ToastLog -Level Error -Message ('Failed to download ''SilentLauncher.exe'' file. Reason: {0}' -f $Error[0].Exception.Message)
            }
        }
        Unblock-File -Path $silentLauncherPath -ErrorAction SilentlyContinue -Confirm:$false
    }
}
#endregion

#region toast preparation
if ($customAppEnabled -eq 'True') {
    $app = 'Toast.Custom.App'
    Register-CustomNotificationApp -FAppID $app -FAppDisplayName $customAppValue
}

if ($limitToastToRunEveryMinutesEnabled -eq 'True') {
    $lastRunTimeOutput = Get-NotificationLastRunTime
    if (-not [string]::IsNullOrEmpty($lastRunTimeOutput)) {
        if ($lastRunTimeOutput -lt $limitToastToRunEveryMinutesValue) {
            Write-ToastLog -Level Error -Message 'Toast notification was displayed too recently'
            Write-ToastLog -Level Error -Message ('Toast notification was displayed {0} minutes ago and the config.xml is configured to allow {1} minutes intervals' -f $lastRunTimeOutput, $limitToastToRunEveryMinutesValue)
            Write-ToastLog -Level Error -Message 'This is done to prevent ConfigMgr catching up on missed schedules, and thus display multiple toasts of the same appearance in a row'
            break
        }
    }
}

if (($heroImageFileName.StartsWith('https://')) -or ($heroImageFileName.StartsWith('http://'))) {
    Write-ToastLog -Message 'ToastHeroImage appears to be hosted online. Will need to download the file'
    $ok = $false
    try { if ((Invoke-WebRequest -Uri $heroImageFileName -UseBasicParsing).StatusDescription -eq 'OK') { $ok = $true } } catch { $null }
    if ($ok) {
        try {
            Invoke-WebRequest -Uri $heroImageFileName -OutFile $heroImageTemp -UseBasicParsing
            $heroImage = ConvertTo-ToastImageUri -Raw $heroImageTemp -DefaultFolderUri $imagesPath
            Write-ToastLog -Message ('Successfully downloaded {0} from {1}' -f $heroImageTemp, $heroImageFileName)
        } catch {
            Write-ToastLog -Level Error -Message ('Failed to download the {0} from {1}' -f $heroImageTemp, $heroImageFileName)
            $heroImage = ConvertTo-ToastImageUri -Raw 'ToastHeroImageDefault.jpg' -DefaultFolderUri $imagesPath
        }
    } else {
        Write-ToastLog -Level Error -Message ('The image supposedly located on {0} is not available' -f $heroImageFileName)
        $heroImage = ConvertTo-ToastImageUri -Raw 'ToastHeroImageDefault.jpg' -DefaultFolderUri $imagesPath
    }
}

if (($logoImageFileName.StartsWith('https://')) -or ($logoImageFileName.StartsWith('http://'))) {
    Write-ToastLog -Message 'ToastLogoImage appears to be hosted online. Will need to download the file'
    $ok = $false
    try { if ((Invoke-WebRequest -Uri $logoImageFileName -UseBasicParsing).StatusDescription -eq 'OK') { $ok = $true } } catch { $null }
    if ($ok) {
        try {
            Invoke-WebRequest -Uri $logoImageFileName -OutFile $logoImageTemp -UseBasicParsing
            $logoImage = ConvertTo-ToastImageUri -Raw $logoImageTemp -DefaultFolderUri $imagesPath
            Write-ToastLog -Message ('Successfully downloaded {0} from {1}' -f $logoImageTemp, $logoImageFileName)
        } catch {
            Write-ToastLog -Level Error -Message ('Failed to download the {0} from {1}' -f $logoImageTemp, $logoImageFileName)
            $logoImage = ConvertTo-ToastImageUri -Raw 'ToastLogoImageDefault.jpg' -DefaultFolderUri $imagesPath
        }
    } else {
        Write-ToastLog -Level Error -Message ('The image supposedly located on {0} is not available' -f $logoImageFileName)
        $logoImage = ConvertTo-ToastImageUri -Raw 'ToastLogoImageDefault.jpg' -DefaultFolderUri $imagesPath
    }
}

if ($createScriptsProtocolsEnabled -eq 'True') {
    $registryName = 'ScriptsAndProtocolsVersion'
    Write-ToastLog -Message 'CreateScriptsAndProtocols set to True. Will allow creation of scripts and protocols'
    if (Test-Path -Path $registryPath) {
        if (((Get-Item -Path $registryPath -ErrorAction SilentlyContinue).Property -contains $registryName) -ne $true) {
            New-ItemProperty -Path $registryPath -Name $registryName -Value '0' -PropertyType 'String' -Force | Out-Null
        }
        if (((Get-Item -Path $registryPath -ErrorAction SilentlyContinue).Property -contains $registryName) -eq $true) {
            try {
                Write-ToastLog -Message 'Creating scripts and protocols for the logged on user'
                Write-CustomActionRegistry -ActionType 'ToastReboot'
                Write-CustomActionRegistry -ActionType 'ToastRunPSScript'
                Write-CustomActionRegistry -ActionType 'ToastLearnMore'
                Write-CustomActionScript -Type 'ToastReboot'
                Write-CustomActionScript -Type 'ToastRunPSScript'
                Write-CustomActionScript -Type 'ToastLearnMore'
                New-ItemProperty -Path $registryPath -Name $registryName -Value $scriptVersion -PropertyType 'String' -Force | Out-Null
            } catch {
                Write-ToastLog -Level Error -Message 'Something failed during creation of custom scripts and protocols'
            }
        }
    }
}

if ($aDPasswordExpiration -eq 'True') {
    Write-ToastLog -Message 'ADPasswordExpiration set to True. Checking for expiring AD password'
    $testADPasswordExpiration = Get-ADPasswordExpiration -FADPasswordExpirationDays $aDPasswordExpirationDays
    $aDPasswordExpirationResult = $testADPasswordExpiration[0]
    $aDPasswordExpirationDate = $testADPasswordExpiration[1]
}

if ($pendingRebootCheck -eq 'True') {
    Write-ToastLog -Message 'PendingRebootCheck set to True. Checking for pending reboots'
    $testPendingRebootRegistry = Test-PendingRebootRegistry
}

if ($pendingRebootUptime -eq 'True') {
    $uptime = Get-DeviceUptime
    Write-ToastLog -Message ('PendingRebootUptime set to True. Checking for device uptime. Current uptime is: {0} days' -f $uptime)
}

if ($customAppEnabled -eq 'True') {
    $regPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'
    $app = 'Toast.Custom.App'
    if (-not (Test-Path -Path ('{0}\{1}' -f $regPath, $app))) {
        New-Item -Path $regPath -Name $app -Force
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'ShowInActionCenter' -Value 0 -PropertyType 'DWORD'
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'SoundFile' -PropertyType 'STRING' -Force
    }
    if ((Get-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled -ne '1') {
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
    }
    if ((Get-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'ShowInActionCenter' -ErrorAction SilentlyContinue).ShowInActionCenter -ne '0') {
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'ShowInActionCenter' -Value 0 -PropertyType 'DWORD' -Force
    }
    if (-not (Get-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'SoundFile' -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'SoundFile' -PropertyType 'STRING' -Force
    }
}

if ($psAppStatus -eq 'True') {
    $regPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'
    $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -Path ('{0}\{1}' -f $regPath, $app))) {
        New-Item -Path $regPath -Name $app -Force
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD'
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'SoundFile' -PropertyType 'STRING' -Force
    }
    if ((Get-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled -ne '1') {
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
    }
    if ((Get-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'ShowInActionCenter' -ErrorAction SilentlyContinue).ShowInActionCenter -ne '1') {
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD' -Force
    }
    if (-not (Get-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'SoundFile' -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path ('{0}\{1}' -f $regPath, $app) -Name 'SoundFile' -PropertyType 'STRING' -Force
    }
}

if ($greetGivenName -eq 'True') {
    Write-ToastLog -Message 'Greeting with given name selected. Replacing HeaderText'
    $hour = (Get-Date).TimeOfDay.Hours
    if (($hour -ge 0) -and ($hour -lt 12)) {
        Write-ToastLog -Message ('Greeting with {0}' -f $greetMorningText)
        $greeting = $greetMorningText
    } elseif (($hour -ge 12) -and ($hour -lt 16)) {
        Write-ToastLog -Message ('Greeting with {0}' -f $greetAfternoonText)
        $greeting = $greetAfternoonText
    } else {
        Write-ToastLog -Message ('Greeting with personal greeting: {0}' -f $greetEveningText)
        $greeting = $greetEveningText
    }
    $givenName = Get-GivenName
    $headerText = '{0} {1}' -f $greeting, $givenName
}

$action1Enabled = $actionButton1Enabled -eq 'True'
$action2Enabled = $actionButton2Enabled -eq 'True'
$action3Enabled = $actionButton3Enabled -eq 'True'
$dismissEnabled = $dismissButtonEnabled -eq 'True'

$actionsXml = [System.Collections.Generic.List[string]]::new()
$actionTemplate = '<action activationType={0}{1}{0} arguments={0}{2}{0} content={0}{3}{0} />'

if ($action1Enabled) {
    $actionsXml.Add(($actionTemplate -f [char]34, 'protocol', $action1, $actionButton1Content))
}
if ($action2Enabled) {
    $actionsXml.Add(($actionTemplate -f [char]34, 'protocol', $action2, $actionButton2Content))
}
if ($action3Enabled) {
    $actionsXml.Add(($actionTemplate -f [char]34, 'protocol', $action3, $actionButton3Content))
}
if ($dismissEnabled) {
    $actionsXml.Add(($actionTemplate -f [char]34, 'system', 'dismiss', $dismissButtonContent))
}

$actionsSection = $actionsXml -join [Environment]::NewLine

Write-ToastLog -Message 'Creating the xml for enabled action buttons'
[xml]$Toast = @'
<toast scenario={0}{1}{0}>
    <visual>
    <binding template={0}ToastGeneric{0}>
        <image placement={0}hero{0} src={0}{2}{0}/>
        <image id={0}1{0} placement={0}appLogoOverride{0} hint-crop={0}circle{0} src={0}{3}{0}/>
        <text placement={0}attribution{0}>{4}</text>
        <text>{5}</text>
        <group>
            <subgroup>
                <text hint-style={0}Subtitle{0} hint-wrap={0}true{0}>{6}</text>
            </subgroup>
        </group>
        <group>
            <subgroup>
                <text hint-style={0}body{0} hint-wrap={0}true{0}>{7}</text>
            </subgroup>
        </group>
        <group>
            <subgroup>
                <text hint-style={0}body{0} hint-wrap={0}true{0}>{8}</text>
            </subgroup>
        </group>
    </binding>
    </visual>
    <actions>
        {9}
    </actions>
</toast>
'@ -f [char]34, $scenario, $heroImage, $logoImage, $attributionText, $headerText, $titleText, $bodyText1, $bodyText2, $actionsSection

if ($snoozeButtonEnabled -eq 'True') {
    Write-ToastLog -Message 'Creating the xml for displaying the snooze button'
    Write-ToastLog -Message 'This will always enable the action button as well as the dismiss button' -Level Warn
    Write-ToastLog -Message 'Replacing any previous formatting of the toast xml' -Level Warn
    [xml]$Toast = @'
<toast scenario={0}{1}{0}>
    <visual>
    <binding template={0}ToastGeneric{0}>
        <image placement={0}hero{0} src={0}{2}{0}/>
        <image id={0}1{0} placement={0}appLogoOverride{0} hint-crop={0}circle{0} src={0}{3}{0}/>
        <text placement={0}attribution{0}>{4}</text>
        <text>{5}</text>
        <group>
            <subgroup>
                <text hint-style={0}Subtitle{0} hint-wrap={0}true{0}>{6}</text>
            </subgroup>
        </group>
        <group>
            <subgroup>
                <text hint-style={0}body{0} hint-wrap={0}true{0}>{7}</text>
            </subgroup>
        </group>
        <group>
            <subgroup>
                <text hint-style={0}body{0} hint-wrap={0}true{0}>{8}</text>
            </subgroup>
        </group>
    </binding>
    </visual>
    <actions>
        <input id={0}snoozeTime{0} type={0}selection{0} title={0}{9}{0} defaultInput={0}15{0}>
            <selection id={0}15{0} content={0}15 {10}{0}/>
            <selection id={0}30{0} content={0}30 {10}{0}/>
            <selection id={0}60{0} content={0}1 {11}{0}/>
            <selection id={0}240{0} content={0}4 {12}{0}/>
            <selection id={0}480{0} content={0}8 {12}{0}/>
        </input>
        <action activationType={0}protocol{0} arguments={0}{13}{0} content={0}{14}{0} />
        <action activationType={0}system{0} arguments={0}snooze{0} hint-inputId={0}snoozeTime{0} content={0}{15}{0}/>
        <action activationType={0}system{0} arguments={0}dismiss{0} content={0}{16}{0}/>
    </actions>
</toast>
'@ -f [char]34, $scenario, $heroImage, $logoImage, $attributionText, $headerText, $titleText, $bodyText1, $bodyText2, $snoozeText, $minutesText, $hourText, $hoursText, $action1, $actionButton1Content, $snoozeButtonContent, $dismissButtonContent
}

if ($deadlineEnabled -eq 'True') {
    if ($deadlineContent) {
        $localCulture = Get-Culture
        $regionDateFormat = [System.Globalization.CultureInfo]::GetCultureInfo($localCulture.LCID).DateTimeFormat.LongDatePattern
        $regionTimeFormat = [System.Globalization.CultureInfo]::GetCultureInfo($localCulture.LCID).DateTimeFormat.ShortTimePattern
        $localDateFormat = Get-Date -Date $deadlineContent -Format ('{0} {1}' -f $regionDateFormat, $regionTimeFormat)
        $deadlineGroup = @'
        <group>
            <subgroup>
                <text hint-style={0}base{0} hint-align={0}left{0}>{1}</text>
                 <text hint-style={0}caption{0} hint-align={0}left{0}>{2}</text>
            </subgroup>
        </group>
'@ -f [char]34, $deadlineText, $localDateFormat
        $Toast.toast.visual.binding.InnerXml += $deadlineGroup
    }
}

if ($pendingRebootCheckTextEnabled -eq 'True') {
    $pendingRebootGroup = @'
        <group>
            <subgroup>
                <text hint-style={0}body{0} hint-wrap={0}true{0} >{1}</text>
            </subgroup>
        </group>
'@ -f [char]34, $pendingRebootCheckTextValue
    $Toast.toast.visual.binding.InnerXml += $pendingRebootGroup
}

if ($aDPasswordExpirationTextEnabled -eq 'True') {
    $aDPasswordExpirationGroup = @'
        <group>
            <subgroup>
                <text hint-style={0}body{0} hint-wrap={0}true{0} >{1} {2}</text>
            </subgroup>
        </group>
'@ -f [char]34, $aDPasswordExpirationTextValue, $aDPasswordExpirationDate
    $Toast.toast.visual.binding.InnerXml += $aDPasswordExpirationGroup
}

if (($pendingRebootUptimeTextEnabled -eq 'True') -and ($uptime -gt $maxUptimeDays)) {
    $uptimeGroup = @'
        <group>
            <subgroup>
                <text hint-style={0}body{0} hint-wrap={0}true{0} >{1}</text>
            </subgroup>
        </group>
        <group>
            <subgroup>
                <text hint-style={0}base{0} hint-align={0}left{0}>{2} {3} {4}</text>
            </subgroup>
        </group>
'@ -f [char]34, $pendingRebootUptimeTextValue, $computerUptimeText, $uptime, $computerUptimeDaysText
    $Toast.toast.visual.binding.InnerXml += $uptimeGroup
}
#endregion

#region display
Remove-Item -Path $learnMoreLogPath -Force -ErrorAction SilentlyContinue
if (($pendingRebootUptime -eq 'True') -and ($uptime -gt $maxUptimeDays)) {
    Write-ToastLog -Message ('Toast notification is used in regards to pending reboot. Uptime count is greater than {0}' -f $maxUptimeDays)
    Show-ToastNotification
} elseif (($pendingRebootCheck -eq 'True') -and ($testPendingRebootRegistry -eq $true)) {
    Write-ToastLog -Message ('Toast notification is used in regards to pending reboot registry. TestPendingRebootRegistry returned {0}' -f $testPendingRebootRegistry)
    Show-ToastNotification
} elseif (($aDPasswordExpiration -eq 'True') -and ($aDPasswordExpirationResult -eq $true)) {
    Write-ToastLog -Message ('Toast notification is used in regards to ADPasswordExpiration. ADPasswordExpirationResult returned {0}' -f $aDPasswordExpirationResult)
    Show-ToastNotification
} elseif (($pendingRebootCheck -ne 'True') -and ($pendingRebootUptime -ne 'True') -and ($aDPasswordExpiration -ne 'True')) {
    Write-ToastLog -Message 'Toast notification is not used in regards to OS upgrade OR Pending Reboots OR ADPasswordExpiration. Displaying default toast'
    Show-ToastNotification
} else {
    Write-ToastLog -Level Warn -Message 'Conditions for displaying toast notification are not fulfilled'
    exit 0
}

if ($action2Enabled) {
    $timeOut = 600
    $timeSpent = 0
    $fileWritten = $false
    do {
        $lastWriteTime = (Get-Item -Path $learnMoreLogPath -ErrorAction SilentlyContinue).LastWriteTime
        if ($lastWriteTime) {
            if ($lastWriteTime -ge (Get-Date).AddSeconds(-600)) {
                $fileWritten = $true
            }
        }
        $timeSpent += 5
        Start-Sleep -Seconds 5
    } until ($fileWritten -or ($timeSpent -gt $timeOut))

    if ($fileWritten) {
        Write-ToastLog -Message 'Learn More button was clicked. Resending the notification.'
        Show-ToastNotification
    } else {
        Write-ToastLog -Message 'Learn More button was not clicked within 600 seconds.'
    }
}
#endregion