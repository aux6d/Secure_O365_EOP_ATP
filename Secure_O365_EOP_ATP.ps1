<#	
	.NOTES
	===========================================================================
	 Created on:   	21/04/2023
	 Created by:   	Auxence REMOND
	 Filename:     	Secure_O365_EOP_ATP.ps1
	===========================================================================
	.DESCRIPTION
		Sécurisation messagerie O365 (Exchange Online Protection et Advance Threat Protection) avec configuration strict selon le best-practise Microsoft.
		Génération d'un rapport avant et après actions menées sur le tenant.
#>

$version = "1.0.0"

Install-Module -Name MSOnline
Import-Module -Name MSOnline
Install-Module -Name ExchangeOnlineManagement
Import-Module -Name ExchangeOnlineManagement
Install-Module -Name ORCA
Import-Module -Name ORCA

Connect-ExchangeOnline
Get-ORCAReport

# Activation des journaux d'audit unifié
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

# Paramètres de stratégie de courrier indésirable sortant EOP
Set-HostedOutboundSpamFilterPolicy -Identity Default -RecipientLimitExternalPerHour 500 -RecipientLimitInternalPerHour 1000 -RecipientLimitPerDay 1000 -ActionWhenThresholdReached BlockUser

# Paramètres de stratégie de courrier indésirable entrant EOP
Set-HostedContentFilterPolicy -Identity Default -BulkThreshold 6 -HighConfidenceSpamAction Quarantine -HighConfidenceSpamQuarantineTag DefaultFullAccessWithNotificationPolicy -PhishSpamAction Quarantine -PhishQuarantineTag DefaultFullAccessWithNotificationPolicy -QuarantineRetentionPeriod 30

# Paramètres d'emprunt d'identité dans les stratégies anti-hameçonnage dans Microsoft Defender pour Office 365
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -PhishThresholdLevel 3 -EnableTargetedUserProtection $true -ImpersonationProtectionState Automatic -EnableOrganizationDomainsProtection $true -EnableMailboxIntelligenceProtection $true -TargetedUserProtectionAction Quarantine -TargetedUserQuarantineTag DefaultFullAccessWithNotificationPolicy -TargetedDomainProtectionAction Quarantine -TargetedDomainQuarantineTag DefaultFullAccessWithNotificationPolicy -MailboxIntelligenceProtectionAction MoveToJmf -EnableSimilarUsersSafetyTips $true -EnableSimilarDomainsSafetyTips $true -EnableUnusualCharactersSafetyTips $true

# Paramètres de stratégie anti-programme malveillant EOP
Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true -FileTypeAction Reject -ZapEnabled $true

# Activer Defender pour Office 365 pour SharePoint, OneDrive et Microsoft Teams
Set-AtpPolicyForO365 -Identity Default -EnableATPForSPOTeamsODB $true -EnableSafeDocs $true

# Paramètres de stratégie pièces jointes fiables
Set-SafeAttachmentPolicy -Identity "Built-In Protection Policy" -Enable $true -Action Block

# Activation bandeau utilisateurs extrernes.
Set-ExternalInOutlook -Enable $true

# Désactivation de l'auto-forwarding.
Set-RemoteDomain -Identity default -AutoForwardEnabled $False

Get-ORCAReport

Disconnect-ExchangeOnline -Confirm:$false
