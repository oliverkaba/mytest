<#
    .SYNOPSIS
    Script to configure and install Coriols Workgroup Notebooks PARAM -debug -test
    .DESCRIPTION
    Script to configure some basic stuff based on xml config file

    Author: Markus Muehlbacher / Oliver Kaba / Edin Debelac
    Version 1.0

    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>
    
    <#
    Create a secure string, which can be stored as plain text in the confid
    $SecureString = Read-Host -AsSecureString
    $generic = ConvertFrom-SecureString -SecureString $SecureString -Key (1..16)
    Write-Host $generic
    copy the output of $grneric into the appropriate xml node
    
    #>

    <#
    XML Sample
    <?xml version="1.0" encoding="UTF-8"?>
    <Config>
	    <specific>
		    <newHostName>LPT-GSc-01</newHostName>
		    <newlocalUser>georgschuster</newlocalUser>
		    <newlocalUsersPW>76492d1116743f0423413b16050a5345MgB8AEYAWABDAE0AbABqADUAZQByADEAKwBFAEQAcgBGAE4ATAByAHMAeQA2AEEAPQA9AHwANgA3AGUAOABlADUAMQBkADYAZQBhAD
    EANQBiADMANAA2ADUAZQAzADQANAA1ADYANQA0AGUAMAA3ADkANgA2ADcAZABmAGQAMQBiADYAYwBjAGEAZQA0ADcAMwBkADMAMwAwAGMAMgA1AGQAMQBiADUAMQBiADMAYgBj
    ADQANwA=</newlocalUsersPW>
	    </specific>
	    <common>
		    <newWorkgroup>WGCPR</newWorkgroup>
		    <genericadmin>adminit</genericadmin>
		    <genericadminsPW>76492d1116743f0423413b16050a5345MgB8AEYAWABDAE0AbABqADUAZQByADEAKwBFAEQAcgBGAE4ATAByAHMAeQA2AEEAPQA9AHwANgA3AGUAOABlADUAMQBkADYAZQBhAD
    EANQBiADMANAA2ADUAZQAzADQANAA1ADYANQA0AGUAMAA3ADkANgA2ADcAZABmAGQAMQBiADYAYwBjAGEAZQA0ADcAMwBkADMAMwAwAGMAMgA1AGQAMQBiADUAMQBiADMAYgBj
    ADQANwA=</genericadminsPW>
		    <installsourcespath>Software</installsourcespath>
		    <bitlocker set="no">Config</bitlocker>
		    <softwareinstall set="no"/>
		    <securityconfig set="yes">
			    <rememberlastpwd>net accounts /uniquepw:12</rememberlastpwd>
			    <minpwdlength>net accounts /minpwlen:8</minpwdlength>
			    <changepwsrule>net accounts /maxpwage:90</changepwsrule>
			    <lockoutthreshold>net accounts /lockoutthreshold:10</lockoutthreshold>
			    <lockoutwindow>net accounts /lockoutwindow:15</lockoutwindow>
			    <lockoutduration>net accounts /lockoutduration:15</lockoutduration>
			    <disablebulitinadminadguest set="yes"/>
			    <importbaselinesecurity set="yes"/> 
		    </securityconfig>
		    <generalpreferences set="yes">
			    <SemiAnnualChannel keyname="BranchReadinessLevel" value="32">HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings</SemiAnnualChannel>
			    <WaitforRollout keyname="DeferFeatureUpdatesPeriodInDays" value="90">HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings</WaitforRollout>
			    <DisableCortana keyname="AllowCortana" value="0">HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search</DisableCortana>
			    <DeactiveTelemetry keyname="AllowTelemetry" value="0">HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection</DeactiveTelemetry>
			    <DisableTelemetrieExperience keyname="Start" value="4">HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack</DisableTelemetrieExperience>
		    </generalpreferences>
	    </common>
    </Config>
    #>

 Param (
    [switch]$Debug = $false,
    [switch]$test = $false,
    [String]$configfile

)

$version = "0.12"

if ($Debug)
{
    $DebugPreference = "Continue"
    Write-Debug "Script runs in debug mode"
}


Write-host "Scriptversion: $version" -ForegroundColor Magenta
#Generic Variables
$ScriptDir = $PSScriptRoot
$ScriptDrive = $PSScriptRoot.Substring(0,2)
$ScriptName = $MyInvocation.MyCommand.Name.TrimEnd(".ps1")
$logfile = "$ScriptDrive\logs\$scriptname$(get-date -format `"yyyyMMdd_hhmmsstt`").txt"

function Write-Message 
{ 
    param ( 
        [string] 
        $sMessage,
       
        $color 

    ) 
    if ($Color -eq $null) {$color = "white"}

    $sMessage = "[$(Get-Date -Format 'dd-MM-yy HH:mm:ss') ]# $sMessage" 
    
    #Write-Host "$sMessage" -ForegroundColor $color 
    Write-Debug $sMessage
	
	if (-not $Debug)
	{
		Write-progress -Activity "Status" -Status $sMessage 
    }
	
	#$sMessage" -ForegroundColor $color -NoNewline
    $sMessage | out-file -Filepath $logfile -append
} 

#$dryrun=$true

if ($test) {
 $dryrun=$true
 Write-Message "Script runs in Testmode -> $dryrun"
 Write-Host "Script runs in Testmode -> $dryrun"
 } else {
 $dryrun=$false
}

Write-Host $ScriptDir -ForegroundColor Green
Write-Host $ScriptDrive -ForegroundColor Green

Write-Message "=============starting actions============="

#$loadingfile = Get-ChildItem -Path $ScriptDir -Filter *.xml |  Where-Object {$_.Name -eq "$configfile"}
$loadingfile = Get-ChildItem -Path $ScriptDir -Filter *.xml |  Where-Object {$_.Name -eq "LPT-Conf.xml"}

#$loadingfile.GetType() 
#if ($loadingfile.GetType() -is [System.MarshalByRefObject])


#$loadingfile.Fullname

$xconf = New-Object System.XML.XMLDocument
$xconf.Load($loadingfile.Fullname)

if ($Debug){
    #Write-Host "Begin Config"
    $xconf.Config.common
    #Write-Host "-"
    $xconf.Config.specific
    #Write-Host "End Config"
}


#Vars to set
$newWorkgroup = $xconf.Config.common.newWorkgroup
$genericadmin = $xconf.Config.common.genericadmin
$genericadminsPW = ConvertTo-SecureString -string $xconf.Config.common.genericadminsPW -Key (1..16) #-AsPlainText -force
$installsourcespath =  $xconf.Config.common.installsourcespath
$newHostName = $xconf.Config.specific.newHostName
$newlocalUser = $xconf.Config.specific.newlocalUser
$newlocalUsersPW = ConvertTo-SecureString -string $xconf.Config.specific.newlocalUsersPW -Key (1..16) # -AsPlainText -force
$installsourcespath = $xconf.Config.common.installsourcespath
$bitlocker = $xconf.Config.common.bitlocker
$setbitlocker = $xconf.Config.common.bitlocker.set
$setsoftwareinstall = $xconf.Config.common.softwareinstall.set
$setsecurityconfig = $xconf.Config.common.securityconfig.set
$disablebulitinadminadguest = $xconf.Config.common.securityconfig.disablebulitinadminadguest.set
$importbaselinesecurity = $xconf.Config.common.securityconfig.importbaselinesecurity.set
$setgeneralpreferences = $xconf.Config.common.generalpreferences.set

Write-Host $setsecurityconfig -ForegroundColor Green

#Confiugration of the computer/host
#==================================

#Rename Host
Write-Host "Renaming computer to  + $newHostName  & set Workgroup to $newWorkgroup"

Rename-Computer -NewName $newHostName -force -WhatIf:$dryrun
Write-Message "Rename-Computer -NewName $newHostName -force -WhatIf:$dryrun"

Add-Computer -WorkgroupName $newWorkgroup -WhatIf:$dryrun
Write-Message "Add-Computer -WorkgroupName $newWorkgroup -WhatIf:$dryrun"

Write-Host "finished." 

#Create Local Administrator "adminit"
Write-Host "Creating new local administrator $genericadmin and make it to Administrator "

New-LocalUser $genericadmin -Password $genericadminsPW -FullName $genericadmin -Description 'Local Administrator Account' -Whatif:$dryrun
Write-Message "New-LocalUser $genericadmin -Password $genericadminsPW -FullName $genericadmin -Description 'Local Administrator Account' -Whatif:$dryrun"
Add-LocalGroupMember -Group 'Administratoren' -Member $genericadmin -Whatif:$dryrun
Write-Message "Add-LocalGroupMember -Group 'Administratoren' -Member $genericadmin -Whatif:$dryrun"


#Create Local User Account
Write-Host "Creating new local user  $newlocalUser"
New-LocalUser $newlocalUser -Password $newlocalUsersPW -FullName $newlocalUser -Description $newlocalUser -Whatif:$dryrun
Write-Message "New-LocalUser $newlocalUser -Password $newlocalUsersPW -FullName $newlocalUser -Description $newlocalUser -Whatif:$dryrun"
Add-LocalGroupMember -Group 'Benutzer' -Member $newlocalUser -Whatif:$dryrun
Write-Message "Add-LocalGroupMember -Group 'Benutzer' -Member $newlocalUser -Whatif:$dryrun"


#Activate BitLocker Encryption
if ($setbitlocker -eq "yes") {
    Write-Message "Bitlocker go"
    #Get-BitLockerVolume | Enable-BitLocker -EncryptionMethod Aes128 -RecoveryKeyPath "E:\Recovery\" -RecoveryKeyProtector
    Write-Message "Enable-Bitlocker -MountPoint c: -UsedSpaceOnly -SkipHardwareTest -RecoveryKeyPath '$ScriptDrive\Config\' -RecoveryKeyProtector"
}

#Set general Windows preferences
#===============================

if ($setgeneralpreferences -eq "yes") {
 Write-Message "=================Set general Windows preference======================="   
    
    
    #Set Windows Update to Semi-Annual Channel (not targeted)
    #Nochmal prüfen was das bewirkt
    #Write-Host  "Disable MS Userausth"
    #Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftAccount" -Name DisableUserAuth -Value 1 -WhatIf:$dryrun
    #Write-Host "done."

    #Disable Windows Update
    #noch zu überlegen
    #New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name Start -Value 4 -WhatIf:$dryrun
  
    $xconf.Config.common.generalpreferences.ChildNodes | ForEach-Object {
    #name
    $regkey = $_.keyname
    #value
    $regvalue = $_.value
    #text
    $regpath = $_.'#text'

    #check if key exists, otherwise create it
         if (Test-Path $regpath){
            Write-Message "New-ItemProperty -Path $regpath -Name $regkey -Value $regvalue -Force -ErrorAction SilentlyContinue  -WhatIf:$dryrun"
			New-ItemProperty -Path $regpath -Name $regkey -Value $regvalue -Force -ErrorAction SilentlyContinue  -WhatIf:$dryrun
        } else {
            Write-Message "New-Item $regpath -ErrorAction SilentlyContinue -WhatIf:$dryrun"
			New-Item $regpath -ErrorAction SilentlyContinue -WhatIf:$dryrun
            Write-Message "New-ItemProperty -Path $regpath -Name $regkey -Value $regvalue -Force -ErrorAction SilentlyContinue  -WhatIf:$dryrun"
			New-ItemProperty -Path $regpath -Name $regkey -Value $regvalue -Force -ErrorAction SilentlyContinue  -WhatIf:$dryrun
        }
    }

  Write-Message "Stop-Process -Name explorer -Whatif:$dryrun"
  Stop-Process -Name explorer -Whatif:$dryrun
}

#Set Windows security
#===============================

if ($setsecurityconfig -eq "yes") {
Write-Message "=================Set Windows security======================="
        #Disable local built-in administrator and guest account
        #=====================================================
        if ($disablebulitinadminadguest -eq "yes") {
            Disable-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue  -WhatIf:$dryrun
            Write-Message "Disable-LocalUser -Name 'Administrator' -WhatIf:$dryrun -ErrorAction SilentlyContinue  -WhatIf:$dryrun"
            Disable-LocalUser -Name 'Gast' -ErrorAction SilentlyContinue  -WhatIf:$dryrun
            Write-Message "Disable-LocalUser -Name 'Gast' -ErrorAction SilentlyContinue  -WhatIf:$dryrun"
        } 

        
        $xconf.Config.common.securityconfig.rememberlastpwd
        $xconf.Config.common.securityconfig.minpwdlength
        $xconf.Config.common.securityconfig.changepwsrule
        $xconf.Config.common.securityconfig.lockoutthreshold
        $xconf.Config.common.securityconfig.lockoutwindow
        $xconf.Config.common.securityconfig.lockoutduration
        if ($dryrun) {
            #Remember last passwords
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.rememberlastpwd)"
            #Minimum Password Length
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.minpwdlength)"
            #Force change password after time x
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.changepwsrule)"
            #Lock account for 15 minutes after 10 failed login attempts
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.lockoutthreshold)"
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.lockoutwindow)"
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.lockoutduration)"            
        } else {
            #Remember last passwords
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.rememberlastpwd)"
            cmd /c $xconf.Config.common.securityconfig.rememberlastpwd
            #Minimum Password Length
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.minpwdlength)"
            cmd /c $xconf.Config.common.securityconfig.minpwdlength
            #Force change password after time x
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.changepwsrule)"
            cmd /c $xconf.Config.common.securityconfig.changepwsrule
            #Lock account for 15 minutes after 10 failed login attempts
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.lockoutthreshold)"
            cmd /c $xconf.Config.common.securityconfig.lockoutthreshold
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.lockoutwindow)"
            cmd /c $xconf.Config.common.securityconfig.lockoutwindow
            Write-Message "cmd /c $($xconf.Config.common.securityconfig.lockoutduration)"            
            cmd /c $xconf.Config.common.securityconfig.lockoutduration            
       }

        
        #Import baseline security WKS
        #=====================================================
        if ($importbaselinesecurity -eq "yes") {
            Write-Message "Importing Baseline Security"
            #first of all, get version
            # 1803
            # 1809

            $winver =  (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name ReleaseID).ReleaseId
            
            if (($winver -eq 1809)-or ($winver -eq 1803)) {
             Write-Message "right vesion"
                if (Test-Path -Path $scriptdrive\secbaseline) {
                    if ($winver -eq 1809) {
                        Write-Message "$scriptdrive\secbaseline\1809\Local_Script\BaselineLocalInstall.ps1"
                        if ($dryrun) {
                            Write-Message "Whatif -> cmd /c 'powershell -Executionpolicy Bypass -F $scriptdrive\secbaseline\1809\Local_Script\BaselineLocalInstall.ps1 -Win10NonDomainJoined'"
                        }else {
                             cmd /c "powershell -Executionpolicy Bypass -F $scriptdrive\secbaseline\1809\Local_Script\BaselineLocalInstall.ps1 -Win10NonDomainJoined"
                        }
                    }
                    if ($winver -eq 1803) {
                        Write-Message "cmd /c $scriptdrive\secbaseline\1809\Local_Script\Client_Install_NonDomainJoined.cmd"
                        if ($dryrun) {
                            Write-Message "Whatif -> cmd /c $scriptdrive\secbaseline\1809\Local_Script\Client_Install_NonDomainJoined.cmd"
                        }else {
                            cmd /c $scriptdrive\secbaseline\1809\Local_Script\Client_Install_NonDomainJoined.cmd
                        }
                    }
                }else{ 
                Write-Message "no baseline templates available sikp"
                Write-Error "not baseline templates available"
                }

            } else {
             Write-Message "not supported version for applying template"
             Write-Error "not supported version for applying template  only 1809 and 1803 are supported"

            }
        }
     }


# Install software packages
# =========================
if ($setsoftwareinstall -eq "yes") {
    Write-Message "=============Installing Software============="
   
    <#
    # Veeam Agent for Windows
    Write-Host  "Starting Silent Installation of Veeam Agent for Windows"
    cmd /c "ping 127.0.0.1" 
    
    #cmd /c "$ScriptDrive\$installsourcespath\VeeamAgent\VeeamAgentWindows_2.0.0.700.exe /silent /accepteula"
    Write-Message "cmd /c '$ScriptDrive\$installsourcespath\VeeamAgent\VeeamAgentWindows_2.0.0.700.exe' /silent /accepteula"
    #cmd /c "Veeam.Agent.Configurator.exe -import /f:$ScriptDrive\$installsourcespath\VeeamAgent\veeam_config.xml"
    Write-Host "Installation and confoiguration of Veeam Agent for Windows done."

    # Teamviewer
    Write-Host  "Starting Silent Installation of Team Viewer"
    cmd /c 'ping 127.0.0.1'
    Write-Message "cmd /c '$ScriptDrive\$installsourcespath\TeamViewer\TeamViewer_Host_SetupCPR.exe /S'"
    cmd /c "$ScriptDrive\$installsourcespath\TeamViewer\TeamViewer_Host_SetupCPR.exe /S"

    # Start Silent Installation of FoxItReader
    Write-Host "Starting Silent Installation of FoxItReader"
    cmd /c 'ping 127.0.0.1'
    Write-Message "cmd /c '$ScriptDrive\$installsourcespath\FoxitReader\FoxitReader722.0929_enu_Setup.exe  /ForceInstall /VERYSILENT DESKTOP_SHORTCUT=0 MAKEDEFAULT=0 VIEWINBROWSER=0 LAUNCHCHECKDEFAULT=0 AUTO_UPDATE=0 /passive /norestart'"
    #cmd /c "$ScriptDrive\$installsourcespath\FoxitReader\FoxitReader722.0929_enu_Setup.exe  /ForceInstall /VERYSILENT DESKTOP_SHORTCUT=0 MAKEDEFAULT=0 VIEWINBROWSER=0 LAUNCHCHECKDEFAULT=0 AUTO_UPDATE=0 /passive /norestart"

    # Start Silent Installation of Firfox 67.0
    Write-Host "Starting Silent Installation of Firefox"
    cmd /c 'ping 127.0.0.1'
    Write-Message "cmd /c '$ScriptDrive\$installsourcespath\Firefox\Firefox-Setup-67.exe /S'"
    #cmd /c "$ScriptDrive\$installsourcespath\Firefox\Firefox-Setup-67.exe /S"
    
    #Office installation
    #>
    $xconf.Config.common.softwareinstall.ChildNodes | ForEach-Object {


    #name
    $set = $_.set
    #value
    $keyname = $_.keyname
    #text
    $instcommand = $_.'#text'
    

    if ($set -eq "yes"){
        Write-Message "=============Install $keyname============="
        if ($dryrun) {
            Write-Message "cmd /c '$ScriptDrive\$installsourcespath\$keyname\$instcommand'"
            cmd /c 'ping 127.0.0.1'
        }else {
            Write-Message "hotrun ->  cmd /c '$ScriptDrive\$installsourcespath\$keyname\$instcommand'"
            cmd /c "$ScriptDrive\$installsourcespath\$keyname\$instcommand"
        }
      }
    }#End Foreach
}



Write-Message "=============all actions done============="
#Rename Logfile to new Computernames
Write-Debug "Renaming stuff $newHostName"
#Rename-Item -Path $logfile -NewName "$newHostName.log" -Force -ErrorAction SilentlyContinue
Copy-Item -Path $logfile -Destination $env:USERPROFILE\Desktop\$newHostname.log -Force
#unload XML
$xconf = $null

#End Script
#Read-Host -Prompt "Press Enter to exit"

#EOS