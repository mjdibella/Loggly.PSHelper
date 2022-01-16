Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web

function Connect-Loggly {
    param(
        [Parameter(Mandatory=$true)][string]$tenant
    )
    $securedValue = Read-Host -prompt "token" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
    $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    $logglyConfig.tenant = $tenant
    $logglyConfig.token = $token
    New-ItemProperty -Path $logglyConfig.registryURL -Name tenant -Value $tenant -Force | Out-Null
    New-ItemProperty -Path $logglyConfig.registryURL -Name token -Value $token -Force | Out-Null
    Write-host "Connected to Loggly tenant $($logglyConfig.tenant)`n"
}

function Disconnect-Loggly {
    Remove-ItemProperty -Path $logglyConfig.registryURL -Name tenant | Out-Null
    Remove-ItemProperty -Path $logglyConfig.registryURL -Name token | Out-Null
    $logglyconfig.tenant = $null
    $logglyConfig.token = $null
}

function Get-LogglyEvent {
    param(
        [Parameter(Mandatory=$true,parameterSetName="fromRsid")][string]$rsid,
        [Parameter(Mandatory=$true,parameterSetName="fromParams")][string]$query,
        [Parameter(Mandatory=$false,parameterSetName="fromParams")][string]$from,
        [Parameter(Mandatory=$false,parameterSetName="fromParams")][string]$until,
        [Parameter(Mandatory=$false,parameterSetName="fromParams")][string]$order,
        [Parameter(Mandatory=$false,parameterSetName="fromParams")][string]$size
    )
    <#
    $ curl -H 'Authorization: bearer <token>' "https://<subdomain>.loggly.com/apiv2/events?rsid=728480292"
    #>
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not $rsid) {
        $uri = 'https://' + $logglyConfig.tenant + '/apiv2/search?q=' + $query
        if ($from) {
            $uri = $uri + '&from=' + $from
        }
        if ($until) {
            $uri = $uri + '&until=' + $until
        }
        if ($order) {
            $uri = $uri + '&order=' + $order
        }
        if ($size) {
            $uri = $uri +'&size=' + $size
        }
        $uri = [uri]::EscapeUriString($uri)
        try {
            $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "bearer $($logglyConfig.token)"}
            $response = ConvertFrom-JSON $webresponse.Content
            $rsid = $response.rsid.id
        } catch {
            Set-LogglyRESTErrorResponse
        }
    } 
    $uri = 'https://' + $logglyConfig.tenant + '/apiv2/events?rsid=' + $rsid
    $uri = [uri]::EscapeUriString($uri)
    try {
        $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "bearer $($logglyConfig.token)"}
        $response = ConvertFrom-JSON $webresponse.Content
        $response.events
    } catch {
        Set-LogglyRESTErrorResponse
    }
}

function Get-LogglyEventPage {
    param(
        [Parameter(Mandatory=$true)][string]$query,
        [Parameter(Mandatory=$false)][string]$from,
        [Parameter(Mandatory=$false)][string]$until,
        [Parameter(Mandatory=$false)][string]$order,
        [Parameter(Mandatory=$false)][string]$size,
        [Parameter(Mandatory=$false)][int]$pages
    )
    <#
    $ curl -H 'Authorization: bearer <token>' -XGET 'https://<subdomain>.loggly.com/apiv2/events/iterate?q=*&from=-10m&until=now&size=2' 
    https://<subdomain>.loggly.com/apiv2/events/iterate?next=eea25ee6-0e48-4428-a544-36d6441d132c
    #>
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://' + $logglyConfig.tenant + '/apiv2/events/iterate'
    if ($query) {
        $uri = $uri + '?q=' + $query
    }
    if ($from) {
        $uri = $uri + '&from=' + $from
    }
    if ($until) {
        $uri = $uri + '&until=' + $until
    }
    if ($order) {
        $uri = $uri + '&order=' + $order
    }
    if ($size) {
        $uri = $uri +'&size=' + $size
    }
    $uri = [uri]::EscapeUriString($uri)
    while ($uri) {
        try {
            $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "bearer $($logglyConfig.token)"}
            $response = ConvertFrom-JSON $webresponse.Content
            $response.events
            $uri = $response.next
            $pagesReceived++
            if (($pages -gt 0) -and ($pagesReceived -ge $pages)) {
                break
            }
        } catch {
            Set-LogglyRESTErrorResponse
        }
    } 
}

function Get-LogglyEventCount {
    param(
        [Parameter(Mandatory=$true)][string]$query,
        [Parameter(Mandatory=$false)][string]$from,
        [Parameter(Mandatory=$false)][string]$until
    )
    <#
    $ curl -H 'Authorization: bearer <token>' -XGET 'https://<subdomain>.loggly.com/apiv2/events/count?q=*&from=-10m&until=now'
    #>
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://' + $logglyConfig.tenant + '/apiv2/events/count'
    if ($query) {
        $uri = $uri + '?q=' + $query
    }
    if ($from) {
        $uri = $uri + '&from=' + $from
    }
    if ($until) {
        $uri = $uri + '&until=' + $until
    }
    $uri = [uri]::EscapeUriString($uri)
    try {
        $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "bearer $($logglyConfig.token)"}
        $response = ConvertFrom-JSON $webresponse.Content
        $response
    } catch {
        Set-LogglyRESTErrorResponse
    }
}

function Get-LogglyEventMetric {
    param(
        [Parameter(Mandatory=$true)][string]$from,
        [Parameter(Mandatory=$true)][string]$until,
        [Parameter(Mandatory=$false)][string]$groupBy,
        [Parameter(Mandatory=$false)][string]$host,
        [Parameter(Mandatory=$false)][string]$app,
        [Parameter(Mandatory=$false)][string]$types
    )
    <#
    $ curl -H 'Authorization: bearer <token>' -XGET 'https://<subdomain>.loggly.com/apiv2/volume-metrics?measurement_types=count&from=2018-12-20T21%3A24%3A18.007Zh&until=2018-12-21T21%3A24%3A18.007Z&host=customer_host'
    #>
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://' + $logglyConfig.tenant + '/apiv2/volume-metrics'
    if ($from) {
        $uri = $uri + '?from=' + $from
    }
    if ($until) {
        $uri = $uri + '&until=' + $until
    }
    if ($groupBy) {
            $uri = $uri + '&group_by=' + $groupBy
    }
    if ($host) {
            $uri = $uri + '&host=' + $host
    }
    if ($app) {
            $uri = $uri + '&app=' + $app
    }
    if ($types) {
        if ($uri.IndexOf("?") -gt 0) {
            $uri = $uri + '&measurement_types=' + $types
        } else {
            $uri = $uri + '?measurement_types=' + $types
        }
    }
    $uri = [uri]::EscapeUriString($uri)
    try {
        $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "bearer $($logglyConfig.token)"}
        $response = ConvertFrom-JSON $webresponse.Content
        $response
    } catch {
        Set-LogglyRESTErrorResponse
    }
}

function Find-LogglyEvent {
    param(
        [Parameter(Mandatory=$true)][string]$query,
        [Parameter(Mandatory=$false)][string]$from,
        [Parameter(Mandatory=$false)][string]$until,
        [Parameter(Mandatory=$false)][string]$order,
        [Parameter(Mandatory=$false)][string]$size
    )
    <#
    $ curl -H 'Authorization: bearer <token>' "https://<subdomain>.loggly.com/apiv2/search?q=*&from=-2h&until=now&size=10"
    #>
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://' + $logglyConfig.tenant + '/apiv2/search?q=' + $query
    if ($from) {
        $uri = $uri + '&from=' + $from
    }
    if ($until) {
        $uri = $uri + '&until=' + $until
    }
    if ($order) {
        $uri = $uri + '&order=' + $order
    }
    if ($size) {
        $uri = $uri +'&size=' + $size
    }
    $uri = [uri]::EscapeUriString($uri)
    try {
        $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "bearer $($logglyConfig.token)"}
        $response = ConvertFrom-JSON $webresponse.Content
        $response.rsid
    } catch {
        Set-LogglyRESTErrorResponse
    }
}

function Set-LogglyRESTErrorResponse {
    $logglyRESTErrorResponse.tenant = $logglyConfig.tenant
    $logglyRESTErrorResponse.token = $logglyConfig.token
    $logglyRESTErrorResponse.statusCode = $_.Exception.Response.StatusCode
    $logglyRESTErrorResponse.statusDescription = $_.Exception.Response.StatusDescription
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $logglyRESTErrorResponse.responseBody = $reader.ReadToEnd();
    $logglyRESTErrorResponse.responseError = (ConvertFrom-JSON $logglyRESTErrorResponse.responsebody).message
    $logglyRESTErrorResponse
    break
}

function Format-LogglyTimeStamp {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline)][PSObject[]]$sourceObjects,
        [Parameter(Mandatory=$true)][string[]]$properties,
        [Parameter(Mandatory=$false)][string]$format,
        [Parameter(Mandatory=$false)][int]$offset
    )
    begin {
    }
    process {
        foreach ($sourceObject in $sourceObjects) {
            foreach ($property in $properties) {
                $timestamp = $sourceObject.$property / 1000
                if ($offset) {
                    $timestamp = +$timestamp + (+$offset * 3600)
                }
                $dateTime = (Get-Date '1970-01-01 00:00:00').AddSeconds($timeStamp)
                if ($format) {
                    $dateTime = $dateTime.ToString($format)
                }
                $sourceObject.$property = $dateTime
                $sourceObject
            }
        }
    }
    end {
    }
}

# get values for API access
$logglyConfig = [ordered]@{
    registryUrl = "HKCU:\Software\Loggly\Loggly.PSHelper"
    tenant = $null
    token = $null
}
New-Variable -Name logglyconfig -Value $logglyConfig -Scope script -Force
$logglyRESTErrorResponse = [ordered]@{
    tenant = $null
    token = $null
    statusCode = $null
    statusDescription = $null
    responseBody = $null
    responseError = $null
}
New-Variable -Name logglyRESTErrorResponse -Value $logglyRESTErrorResponse -Scope script -Force
$registryKey = (Get-ItemProperty -Path $logglyConfig.registryURL -ErrorAction SilentlyContinue)
if ($registryKey -eq $null) {
    Write-Warning "Autoconnect failed.  API key not found in registry.  Use Connect-Loggly to connect manually."
} else {
    $logglyconfig.tenant = $registryKey.tenant
    $logglyConfig.token = $registryKey.token
    Write-host "Connected to Loggly tenant $($registryKey.tenant)`n"
}
Write-host "Cmdlets added:`n$(Get-Command | where {$_.ModuleName -eq 'Loggly.PSHelper'})`n"