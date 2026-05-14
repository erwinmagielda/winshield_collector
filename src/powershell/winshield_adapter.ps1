<#
.SYNOPSIS
    WinShield+ MSRC adapter.

.DESCRIPTION
    Aggregates MSRC CVRF data for a specific Windows product across one or more MonthIds.
    Builds KB-to-CVE mappings and supersedence data used by winshield_scanner.py.

.OUTPUTS
    JSON object written to stdout.
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds,

    [Parameter(Mandatory = $true)]
    [string]$ProductNameHint
)

# ------------------------------------------------------------
# INPUT NORMALISATION
# ------------------------------------------------------------

$MonthIds = @(
    $MonthIds |
        ForEach-Object { $_ -split "," } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
) | Sort-Object -Unique

if (-not $MonthIds -or -not $ProductNameHint) {
    [pscustomobject]@{
        Error           = "Invalid arguments"
        MonthIds        = $MonthIds
        ProductNameHint = $ProductNameHint
    } | ConvertTo-Json -Depth 5

    exit 1
}

# ------------------------------------------------------------
# MODULE DEPENDENCY
# ------------------------------------------------------------

try {
    Import-Module MsrcSecurityUpdates -ErrorAction Stop
}
catch {
    [pscustomobject]@{
        Error   = "Failed to load MsrcSecurityUpdates"
        Details = $_.Exception.Message
    } | ConvertTo-Json -Depth 5

    exit 1
}

# ------------------------------------------------------------
# AGGREGATION CONTAINER
# ------------------------------------------------------------

$kbMap = @{}

# ------------------------------------------------------------
# PER-MONTH PROCESSING
# ------------------------------------------------------------

foreach ($monthId in $MonthIds) {

    try {
        $document = Get-MsrcCvrfDocument -ID $monthId -ErrorAction Stop
        $affectedSoftware = Get-MsrcCvrfAffectedSoftware `
            -Vulnerability $document.Vulnerability `
            -ProductTree $document.ProductTree
    }
    catch {
        continue
    }

    if (-not $affectedSoftware) {
        continue
    }

    $productRows = $affectedSoftware | Where-Object { $_.FullProductName -eq $ProductNameHint }
    if (-not $productRows) {
        continue
    }

    foreach ($productRow in $productRows) {
        
        $cveList = @()

        if ($productRow.CVE) {
            $cveList = @(
                @($productRow.CVE) |
                    ForEach-Object { ([string]$_).Trim().ToUpper() } |
                    Where-Object { $_ -like "CVE-*" } |
                    Sort-Object -Unique
            )
        }

        $supersededKbs = @()

        if ($productRow.Supercedence) {
            foreach ($supersedenceEntry in @($productRow.Supercedence)) {
                if ($supersedenceEntry -and $supersedenceEntry -match '(\d{4,7})') {
                    $supersededKbs += "KB$($Matches[1])"
                }
            }
        }

        $supersededKbs = $supersededKbs | Sort-Object -Unique

        foreach ($kbArticle in @($productRow.KBArticle)) {

            if (-not $kbArticle -or -not $kbArticle.ID) {
                continue
            }

            $kb = if ($kbArticle.ID -like 'KB*') {
                $kbArticle.ID
            }
            else {
                "KB$($kbArticle.ID)"
            }

            if (-not $kbMap.ContainsKey($kb)) {
                $kbMap[$kb] = [pscustomobject]@{
                    KB         = $kb
                    Months     = @()
                    Cves       = @()
                    Supersedes = @()
                }
            }

            if ($kbMap[$kb].Months -notcontains $monthId) {
                $kbMap[$kb].Months += $monthId
            }

            foreach ($cve in $cveList) {
                if ($cve -and $cve -like "CVE-*" -and $kbMap[$kb].Cves -notcontains $cve) {
                    $kbMap[$kb].Cves += $cve
                }
            }

            foreach ($supersededKb in $supersededKbs) {
                if ($supersededKb -and $kbMap[$kb].Supersedes -notcontains $supersededKb) {
                    $kbMap[$kb].Supersedes += $supersededKb
                }
            }
        }
    }
}

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

[pscustomobject]@{
    ProductNameHint = $ProductNameHint
    MonthIds        = $MonthIds
    KbEntries       = @(
        $kbMap.GetEnumerator() |
            ForEach-Object { $_.Value } |
            Sort-Object KB
    )
} | ConvertTo-Json -Depth 10