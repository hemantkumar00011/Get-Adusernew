<#
Name                          : Get-AzureADUserNew
Description                   : This cmdlet is a replacement of the Get-AzureADUSer using the Microsoft Graph API.
                                To use this cmdlet kindly follow the example provided in the SYNOPSIS inside the 
                                function with example 
Version                       : 1.0
Powershell Version            : 5.1
Author                        : 
#>

function Get-AzureADUserNew{
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName="ByAccessToken", Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$MsAccessToken,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($false,$true)]
        $All=$false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Top=$null,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]$ObjectId=$null,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]$SearchString=$null

        <#
            .SYNOPSIS
            Get-AzureADUserNew
            .DESCRIPTION
            This cmdlet is a replacement of the Get-AzureADUSer using the Microsoft Graph API.
            .PARAMETER Name
            Get-AzureADUserNew.ps1
            .PARAMETER Extension
            .ps1
            .INPUTS
            MsAccessToken
            .OUTPUTS
            System.Object
            .EXAMPLE
            PS> Get-AzureADUserNew -MsAccessToken <Token> -All $true
            .EXAMPLE
            PS> Get-AzureADUserNew -MsAccessToken <Token> -Top 5
            .EXAMPLE
            PS> Get-AzureADUserNew -MsAccessToken <Token> -$ObjectId "<userPrincipalName>"
            .EXAMPLE
            PS> Get-AzureADUserNew -MsAccessToken <Token> -$ObjectId "<userPrincipalName>"
            .EXAMPLE
            PS> Get-AzureADUserNew -MsAccessToken <Token> -$SearchString "<String to be searched of userPrincipalName>"
        #>
    )

    begin {
        # Microsoft Graph API endpoint
        $requestUrl = "https://graph.microsoft.com/v1.0/users"
        #$requestUrl = "https://graph.microsoft.com/v1.0/users?$userPrincipalName eq 'Yannik@perennialsys.com'"

    }

    process {
        try{
            # Set the access token in the Authorization header
            $headers = @{
                'Authorization' = "Bearer $MsAccessToken"
                'Content-Type'  = 'application/json'
            }

            # Make API requests using $accessToken and $headers
            # For example:
            $response = Invoke-RestMethod -Uri $requestUrl -Headers $headers -Method Get
            $users = $null
            # Process the response
            $users = $response.value

            # Check if any user is present in the Azure
            if($users -eq $null){
                throw "No Users are present in the AD"
            }
            else{
                # All Parameter : Type Boolean
                if($All){
                    return $users
                }

                # Top Parameter : Type Integer
                if($Top){
                    return $users | Select-Object * -First $Top
                }

                # ObjectId Parameter : Type String
                if($ObjectId){
                    return $users | ?{$_.userPrincipalName.toLower() -eq $ObjectId.toLower()}
                }

                # Search String Parameter : Type String
                if($SearchString){
                    return $users | ?{$_.userPrincipalName.toLower() -like "*$($SearchString.toLower())*"}
                }
                else{
                    return $users
                }
            }
        }
        catch{
            # Exception 
            "Error occured in the Get-AzureADUserNew cmdlet : $_.Exception"
        }
    }
    end {

    }
}