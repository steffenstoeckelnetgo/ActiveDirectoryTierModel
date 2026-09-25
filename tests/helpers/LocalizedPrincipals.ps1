# ---------------------------------------------------------------------------
# Rendering a well-known principal as the name THIS host carries.
#
# NOTE: the ACL fixtures that use this do NOT spell their principals out as
# readable literals, and that is deliberate. Do not "fix" them back.
#
# Active Directory and Windows localize the names of built-in principals. On a
# German host S-1-5-32-544 reads 'VORDEFINIERT\Administratoren', S-1-5-32-545
# reads 'VORDEFINIERT\Benutzer' and S-1-1-0 reads 'Jeder'. An English literal
# does not resolve there at all.
#
# That matters because New-TierModelOuAcl and the MSA/gMSA/dMSA equivalents
# resolve Plan.Actions[].Data.identityreference with the real, unmocked
#
#     New-Object System.Security.Principal.NTAccount($identityReference)
#     $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
#
# (New-TierModelOuAcl.ps1:82-83). NTAccount takes a NAME. A hard-coded English
# literal therefore throws on a German host and the success path the test
# exists to cover is never reached -- which is why 31 ACL tests failed there.
#
# Writing a SID literal into those fixtures does NOT fix it, and the difference
# is easy to miss: where a fixture is read back through
# ConvertTo-TierModelIdentitySid a SID string is passed through unchanged
# (Resolve-TierModelPrincipalSid.ps1:506), which is why commit 4c84f4a could
# use SID literals for the WinLAPS fixtures. Here the value reaches NTAccount
# itself, which would look for an account literally CALLED 'S-1-5-32-544'.
#
# So the fixture holds the invariant SID and asks the host what it calls it.
# The product then translates that name back to the same SID on any host, in
# any language, which is the behaviour these tests are about.
# ---------------------------------------------------------------------------

function Get-TestPrincipalName {
    <#
    .SYNOPSIS
        Returns the account name the local host renders for a well-known SID.

    .DESCRIPTION
        Windows-only by nature: it is the local translation that is under test.
        The round-trip check below is not decoration -- it is what stops a
        fixture from going quietly vacuous. If the name this host produced did
        not translate back to the SID it came from, every test using it would
        be exercising some other principal, and they would still be green.

    .PARAMETER Sid
        The invariant SID, for example 'S-1-5-32-544' (Administrators).

    .EXAMPLE
        Get-TestPrincipalName -Sid 'S-1-5-32-544'
        # BUILTIN\Administrators       on an English host
        # VORDEFINIERT\Administratoren on a German one
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^S-1-\d+(-\d+)+$')]
        [string]$Sid
    )

    try {
        $identifier = [System.Security.Principal.SecurityIdentifier]::new($Sid)
        $name       = $identifier.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        # Say what was being attempted. The raw failure on a non-Windows host is
        # "Windows Principal functionality is not supported on this platform",
        # which tells the next reader nothing about why a test fixture wanted it.
        throw ("Get-TestPrincipalName: this host cannot render '{0}' as an account name. " +
               "The ACL fixtures need the name THIS host uses, because the code under test " +
               "resolves it through NTAccount(...).Translate(). Underlying error: {1}") -f $Sid, $_.Exception.Message
    }

    if ([string]::IsNullOrWhiteSpace($name)) {
        throw "Get-TestPrincipalName: '$Sid' rendered as an empty name on this host."
    }

    $roundTrip = try {
        ([System.Security.Principal.NTAccount]::new($name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw ("Get-TestPrincipalName: '{0}' rendered as '{1}', but that name does not translate " +
               "back to a SID on this host. The fixture would be meaningless. Underlying error: {2}") -f $Sid, $name, $_.Exception.Message
    }

    if ($roundTrip -ne $Sid) {
        throw ("Get-TestPrincipalName: '{0}' rendered as '{1}', which translates back to '{2}'. " +
               "The fixture would silently exercise a different principal.") -f $Sid, $name, $roundTrip
    }

    return $name
}
