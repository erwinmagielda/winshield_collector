<#
.SYNOPSIS
    WinShield+ baseline collector.

.DESCRIPTION
    Collects host metadata required for Windows/MSRC correlation.
    Resolves operating system identity, architecture, latest MSRC month,
    product name hints, privilege context, and latest cumulative update data.

    Emits a stable JSON object consumed by winshield_scanner.py.

.OUTPUTS
    JSON object written to stdout.
#>

# ------------------------------------------------------------
# MSRC: LATEST MONTH RESOLUTION
# ------------------------------------------------------------

function Get-WinShieldLatestMsrcMonthId {

    try {
        Import-Module MsrcSecurityUpdates -ErrorAction Stop

        $command = Get-Command Get-MsrcCvrfDocument -ErrorAction Stop
        $validateSetAttribute = $command.Parameters['ID'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            Select-Object -First 1

        if (-not $validateSetAttribute -or -not $validateSetAttribute.ValidValues) {
            return $null
        }

        $parsedMonthIds = foreach ($monthId in $validateSetAttribute.ValidValues) {

            if (-not $monthId) {
                continue
            }

            $parts = $monthId -split '-', 2
            if ($parts.Count -ne 2 -or -not $parts[1]) {
                continue
            }

            $normalisedMonth = $parts[1].Substring(0, 1).ToUpper() + $parts[1].Substring(1).ToLower()

            try {
                $date = [datetime]::ParseExact(
                    "$($parts[0])-$normalisedMonth",
                    'yyyy-MMM',
                    [System.Globalization.CultureInfo]::InvariantCulture
                )

                [pscustomobject]@{
                    Id   = $monthId
                    Date = $date
                }
            }
            catch {
                continue
            }
        }

        if (-not $parsedMonthIds) {
            return $null
        }

        return ($parsedMonthIds | Sort-Object Date | Select-Object -Last 1).Id
    }
    catch {
        return $null
    }
}

# ------------------------------------------------------------
# MSRC: PRODUCT RESOLUTION
# ------------------------------------------------------------

function Get-WinShieldProductNameHint {

    param(
        [Parameter(Mandatory = $true)]
        [string]$MonthId
    )

    try {
        Import-Module MsrcSecurityUpdates -ErrorAction Stop

        $operatingSystem = Get-CimInstance Win32_OperatingSystem
        $currentVersion = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

        if ($operatingSystem.Caption -like "*Windows 11*") {
            $windowsFamily = "Windows 11"
        }
        elseif ($operatingSystem.Caption -like "*Windows 10*") {
            $windowsFamily = "Windows 10"
        }
        else {
            return $null
        }

        $displayVersion = $currentVersion.DisplayVersion
        if (-not $displayVersion) {
            $displayVersion = $currentVersion.ReleaseId
        }

        $architectureToken = switch ($env:PROCESSOR_ARCHITECTURE) {
            'AMD64' { 'x64' }
            'ARM64' { 'ARM64' }
            'x86'   { '32-bit' }
            default { 'x64' }
        }

        $document = Get-MsrcCvrfDocument -ID $MonthId -ErrorAction Stop
        $affectedSoftware = Get-MsrcCvrfAffectedSoftware -Vulnerability $document.Vulnerability -ProductTree $document.ProductTree

        if (-not $affectedSoftware) {
            return $null
        }

        $windowsProductNames = $affectedSoftware |
            Select-Object -ExpandProperty FullProductName -Unique |
            Where-Object { $_ -like "Windows *" } |
            Sort-Object

        if (-not $windowsProductNames) {
            return $null
        }

        # Prefer an exact product match before falling back to generic or fuzzy matches.
        if ($displayVersion) {

            $targetProductName = if ($architectureToken -eq '32-bit') {
                "$windowsFamily Version $displayVersion for 32-bit Systems"
            } else {
                "$windowsFamily Version $displayVersion for $architectureToken-based Systems"
            }

            $match = $windowsProductNames |
                Where-Object { $_ -ieq $targetProductName } |
                Select-Object -First 1

            if ($match) {
                return $match
            }
        }

        $targetProductName = if ($architectureToken -eq '32-bit') {
            "$windowsFamily for 32-bit Systems"
        } else {
            "$windowsFamily for $architectureToken-based Systems"
        }

        $match = $windowsProductNames |
            Where-Object { $_ -ieq $targetProductName } |
            Select-Object -First 1

        if ($match) {
            return $match
        }

        if ($architectureToken -eq '32-bit') {
            $match = $windowsProductNames |
                Where-Object { $_ -like "$windowsFamily*32-bit*" } |
                Select-Object -First 1
        }
        else {
            $match = $windowsProductNames |
                Where-Object { $_ -like "$windowsFamily*$architectureToken-based*" } |
                Select-Object -First 1
        }

        if ($match) {
            return $match
        }

        return ($windowsProductNames |
            Where-Object { $_ -like "$windowsFamily*" } |
            Select-Object -First 1)
    }
    catch {
        return $null
    }
}

# ------------------------------------------------------------
# SYSTEM IDENTITY
# ------------------------------------------------------------

$currentVersion = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$operatingSystem = Get-CimInstance Win32_OperatingSystem

$buildString = "$($currentVersion.CurrentBuild).$($currentVersion.UBR)"

$architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x64' }
    'ARM64' { 'ARM64' }
    'x86'   { 'x86' }
    default { $env:PROCESSOR_ARCHITECTURE }
}

# ------------------------------------------------------------
# PRIVILEGE CONTEXT
# ------------------------------------------------------------

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ------------------------------------------------------------
# LCU ANCHOR
# ------------------------------------------------------------

$lcuMonthId = $null
$lcuPackageName = $null
$lcuInstallTime = $null

if ($isAdmin) {
    try {
        $latestCumulativeUpdate = Get-WindowsPackage -Online |
            Where-Object { $_.PackageName -like "*RollupFix*" } |
            Sort-Object InstallTime -Descending |
            Select-Object -First 1

        if ($latestCumulativeUpdate) {
            $lcuPackageName = $latestCumulativeUpdate.PackageName
            $lcuInstallTime = $latestCumulativeUpdate.InstallTime
            $lcuMonthId = (Get-Date $latestCumulativeUpdate.InstallTime).ToString("yyyy-MMM")
        }
    }
    catch {
        $lcuMonthId = $null
        $lcuPackageName = $null
        $lcuInstallTime = $null
    }
}

# ------------------------------------------------------------
# MSRC PRODUCT RESOLUTION
# ------------------------------------------------------------

$msrcLatestMonthId = Get-WinShieldLatestMsrcMonthId

$productNameHint = $null
$resolvedMonthId = $null

if ($msrcLatestMonthId) {

    try {
        $latestMsrcDate = [datetime]::ParseExact(
            $msrcLatestMonthId,
            'yyyy-MMM',
            [System.Globalization.CultureInfo]::InvariantCulture
        )

        # Product names can vary between MSRC documents, so recent months are checked in reverse order.
        for ($i = 0; $i -lt 6; $i++) {

            $monthId = $latestMsrcDate.AddMonths(-$i).ToString("yyyy-MMM")
            $candidateProductName = Get-WinShieldProductNameHint -MonthId $monthId

            if ($candidateProductName) {
                $productNameHint = $candidateProductName
                $resolvedMonthId = $monthId
                break
            }
        }
    }
    catch {
        $productNameHint = $null
        $resolvedMonthId = $null
    }
}

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

[pscustomobject]@{

    OsName                 = $operatingSystem.Caption
    OsEdition              = $currentVersion.EditionID
    DisplayVersion         = $currentVersion.DisplayVersion
    Build                  = $buildString
    Architecture           = $architecture
    IsAdmin                = $isAdmin

    LcuMonthId             = $lcuMonthId
    LcuPackageName         = $lcuPackageName
    LcuInstallTime         = $lcuInstallTime

    MsrcLatestMonthId      = $msrcLatestMonthId
    ResolvedProductMonthId = $resolvedMonthId
    ProductNameHint        = $productNameHint

} | ConvertTo-Json -Depth 4