function New-SymbolicLink {
	Param($Target,$Link, [switch]$s)

	If (Test-Path -Path $Link) {
		Write-Information "File/Link already exists"
	} else {
		If ($PSVersionTable.Platform -eq 'Unix') {
			ln -s $Target $Link
		} else {
			If ((Get-Item $Target).PSIsContainer) {
				cmd.exe /c mklink /D $Link $Target
			} else {
				cmd.exe /c mklink $Link $Target
			}
		}
	}
}

function od {
    Param([switch]$Show)
    $OD = Get-ChildItem $HOME\OneDrive* | Select-Object -Last 1
    If ($Show) {$OD} else { Set-Location $OD }
}

function Find-Dev {
    $Locations = 'C:\Jesse\dev','D:\dev','C:\Scratch\drees\git', "$(od -show)\Jesse\dev"
    $Locations | %{
        If (Test-Path -Path $_) { cd $_; break }
    }
}

Function Reset-Module {
    [CmdLetBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({
            Get-Module -Name $_
        })]$Name
    )

    $Module = Get-Module -Name $Name
    Remove-Module -Name $Name
    Import-Module $Module.Path
}

Set-Alias rsm -Value Reset-Module

function ConvertTo-ShortPath {
    Param(
        [string]$Path
    )
    # Replace Home with ~ symbol
    $Location = $Path.Replace($HOME, '~')
    # Remove prefix for UNC paths
    $Location = $Location -replace '^[^:]+::', ''
    # Handle paths starting with \\ and . correctly
    # For paths not the current directory, display only a single
    #   character for each directory in the tree
    If ($IsMacOS -or $IsLinux) {
        # Systems with / paths 
        $Location = $Location -replace '(.?)([^/])[^/]*(?=/)','$1$2'
    } else {
        # Systems with \ paths
        $Location = $Location -replace '\\(\.?)([^\\])[^\\]*(?=\\)','\$1$2'
    }
    return $Location
}

If ($PSVersionTable.PSEdition -eq 'Desktop') {
    $IsWindows = $True
}

function Test-CurrentAdminRights {
    $Admin = $False
    If ($PSVersionTable.PSEdition -eq 'Desktop') {
        #$IsWindows = $True
    }
    If ($IsWindows) {

    } elseif ($IsMacOS -or $IsLinux) {
        if ((whoami) -eq 'root') {
           $Admin = $True
        }
    }
    return $Admin
}

function Test-VTSupport {

}

function prompt {
    If ($PSEdition -eq "Core") {
        $BC = "`e[96m" #Bright Cyan
        $C = "`e[36m" #Cyan
        $G = "`e[32m" #Green
        $N = "`e[0m" #No Color
    } else {
        $C = [ConsoleColor]::DarkCyan
        $G = [ConsoleColor]::Green
        $BC = [ConsoleColor]::Cyan
    }

    $root = [char]0x0E3
    $nonroot = [char]0x0A7
    $H = $([net.dns]::GetHostName()) -replace '\..*',''
    if (Test-CurrentAdminRights) {
        $priv = $root
    } else {
        $priv = $nonroot
    }

    if ($PSEdition -eq "Core"){
        # PSCore doesn't like a prompt using Write-Host
        #   thankfully, using VT100 signals works fine
        "${BC}${priv} $G$H $C{ $BC$(ConvertTo-ShortPath ((pwd).Path)) $C}$N "
    } else {
        Write-Host "$priv " -NoNewline -ForegroundColor $BC
        Write-Host $H -NoNewline -ForegroundColor $G
        Write-Host ' { ' -NoNewline -ForegroundColor $C
        Write-Host (ConvertTo-ShortPath (pwd).Path) -NoNewline -ForegroundColor $BC
        Write-Host ' }' -NoNewline -ForegroundColor $C
        return ' '
    }
}

function Get-Path {
    [CmdLetBinding()]
    Param(
        [ValidateSet(
            "Machine",
            "User"
        )]$Context = "User",
        [Switch]$Raw
    )
    If ($IsMacOS) {
        $PathFiles = @()
        $PathFiles = Get-ChildItem -Path /private/etc/paths.d | Select-Object -Expand FullName
        $PathFiles += '/etc/paths'
        $PathFiles | ForEach-Object {
            Get-Content -Path $PSItem | ForEach-Object {
                $_
            }
        }
        $Paths
    } else {
        If ($Context -eq "Machine") {
            $Root = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        } else {
            $Root = 'HKCU:'
        }
        If ($Raw){
            Get-ItemPropertyValue -Path "$Root\Environment" -Name Path
        } Else {
            Try {
                (Get-ItemPropertyValue -Path "$Root\Environment" -Name Path -EA SilentlyContinue) -split ';'
            } Catch {
                Write-Warning "No user environment variables found"
            }
        }
    }
}

function Add-Path {
    Param($Path)
    $env:PATH = "${env:PATH}:$Path"
}

function Update-Environment{
    [CmdLetBinding()]
    Param()
    If ($IsMacOS) {
        $Paths = $env:PATH -split ':'
        Get-Path | ForEach-Object {
            If ($PSItem -notin $Paths) {
                Write-Verbose "Adding $PSItem to Path"
                Add-Path -Path $PSItem
            }
        }
    } else {
        foreach($level in "Machine","User") {
            [Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object {
                # For Path variables, append the new values, if they're not already in there
                if($_.Name -match '^Path$') {
                    $_.Value = ($((Get-Content "Env:$($_.Name)") + ";$($_.Value)") -split ';' | Select -unique) -join ';'
                }
                $_
            } | Where-Object {$_.Name -ne 'USERNAME'} | ForEach-Object {
                If (Test-Path -Path "Env:$($_.Name)") {
                    $_ | Set-Content -Path { "Env:$($_.Name)" }
                } else {
                    New-Item -Path Env:\ -Name $_.Name -ItemType File -Value $_.Value
                }
            }
        }
    }
}

function Invoke-AsAdmin {
    [CmdLetBinding()]
    Param(
    [Parameter(Position=0)]$Command,
    [Parameter(Position=1,ValueFromPipeLine=$True)]$InputObject
    )
    BEGIN{
        If ($IsLinux) {
            $TEMP = '/tmp/'
        } elseif ($IsMacos) {
            $TEMP = '/private/tmp'
        } else {
            $TEMP = $ENV:TEMP
        }
        $RandFile = Join-Path -Path $TEMP -Child (Get-Random)
    }
    PROCESS{
        If ($IsLinux -or $IsMacos) {
            if ($Command) {
                If ($InputObject) {
                    $InputObject | Export-Clixml -Path $RandFile
                    $Xpression = 'Import-Clixml ' + $RandFile + ' | ' + $Command
                    sudo -s pwsh -NoLogo -Command Invoke-Expression $Xpression
                } else {
                    sudo -s pwsh -NoLogo -Command $Command
                }
            } else {
                sudo -s pwsh -NoLogo
            }
        } else {
            $ElevatePath="$env:systemroot\USCTools\elevate.exe"
            $PWSH = If ($PSEdition -eq 'Core') { "C:\pwsh\pwsh.exe" } else {"$env:systemroot\sysnative\WindowsPowershell\v1.0\powershell.exe"}
            If (Test-Path -Path $ElevatePath) {
                Start-Process -FilePath $ElevatePath -ArgumentList $PWSH
            } Else {
                Write-Error "Unable to find exe elevate"
            }
        }
    }
}

function Connect-Win {
    [CmdLetBinding()]
    Param($ComputerName='appdev4',$UserName='adminjpharris')
    $s = New-PSSession -HostName appdev -UserName $UserName
    Invoke-Command -Session $s -ScriptBlock {
        function prompt {'> '}
        Import-Module WindowsCompatibility
        Import-WinModule Microsoft.PowerShell.Management
        Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
        . \\usc.internal\usc\appdev\SCCMPackages\OperatingSystems\USC-WIMMgmt.ps1
    }
    Enter-Pssession -Session $s
}

If ($IsWindows) {
    Set-Alias hv virtmgmt.msc -force
    Set-Alias ln New-SymbolicLink -force
    #    Install-Module WindowsCompatibility -Scope CurrentUser
    # Import-Module WindowsCompatibility
    # Import-WinModule Microsoft.PowerShell.Management
    # Find-Dev
    # cd zigford
    # Import-Module .\USC-SCCM
    # Import-Module .\gh
    # Set-Alias gwmi Get-WmiObject -force
}

function Import-Text {
    [CmdLetBinding()]
    Param([Parameter(ValueFromPipeline=$True)]$Text)

    Begin {$Object = New-Object -TypeName PSCustomObject}

    Process {
        $Line = $Text.Trim()
        If ($Line) {
            $Split = $Line.Split(':')
            $Object | Add-Member -MemberType NoteProperty -Name $Split[0].Trim() -Value $Split[1].Trim()
        } else {
            If ($Object.ComputerName) {$Object}
            $Object = New-Object -TypeName PSCustomObject
        }
    }
}

Set-Alias iaa Invoke-AsAdmin -force

function reboot {shutdown /r /t 0}
#Update-Environment
