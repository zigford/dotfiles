[CmdLetBinding()]
Param()
# Using Pwsh 7 features

function New-SymbolicLink {
    [CmdLetBinding()]
	Param($Target,$Link)

	If (
            (Test-Path -Path $Link) -and
            (Get-Item -Path $Link).PSIsContainer -eq $False
       ) {
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

$ProfileRoot = Split-Path -Path $profile -Parent
$ProfileSource = Join-Path -Path $PSScriptRoot -ChildPath 'Microsoft.PowerShell_profile.ps1'
$ViModeSource = Join-Path -Path $PSScriptRoot -ChildPath 'vimode.ps1'
If (-Not (Test-Path -Path $ProfileRoot)) {
    New-Item -ItemType Directory -Path $ProfileRoot
}

If (-Not (Test-Path -Path $profile)) {
    Write-Verbose "Linking profile"
    New-SymbolicLink $ProfileSource $ProfileRoot
} else {
    Write-Warning "Profile already exists"
}

$ViMode = Join-Path -Path $ProfileRoot -ChildPath vimode.ps1
If (-Not (Test-Path -Path $ViMode)) {
    Write-Verbose "Linking vimode file"
    New-SymbolicLink $ViModeSource $ProfileRoot
} else {
    Write-Warning "ViMode file already exists"
}
