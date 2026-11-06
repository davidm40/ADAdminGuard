#Requires -Version 5.1
<#
    Fonctions communes à Invoke-ADAdminGuard.ps1 (contrôle) et Show-ADAdminGuardConfig.ps1 (configurateur).
    Fichiers gérés, tous à la racine du dossier du script :
      config.json   : paramètres (groupes, OU de quarantaine, mail, secrets chiffrés DPAPI machine)
      whitelist.txt : comptes autorisés, une ligne « sAMAccountName;SID » par compte
      state.json    : état entre deux exécutions (dernier événement traité, liste blanche vue), propre au DC
#>

Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Security

$script:Root          = $PSScriptRoot
$script:ConfigPath    = Join-Path $PSScriptRoot 'config.json'
$script:WhitelistPath = Join-Path $PSScriptRoot 'whitelist.txt'
$script:StatePath     = Join-Path $PSScriptRoot 'state.json'
$script:TaskName      = 'ADAdminGuard'
$script:EventSource   = 'ADAdminGuard'
# Entropie ajoutée au chiffrement DPAPI : le secret ne se déchiffre pas par un simple appel sans elle
$script:Entropy       = [Text.Encoding]::UTF8.GetBytes('ADAdminGuard/DPAPI')

# Groupes surveillés : groupes protégés de l'AD (Microsoft, « Appendix C: Protected Accounts and Groups in Active
# Directory ») et DnsAdmins. Désignés par SID quand il est fixe : indépendant de la langue de l'AD.
#   Scope Domain  : SID du domaine + RID       Scope Forest : SID du domaine racine de la forêt + RID
#   Scope Builtin : S-1-5-32-RID (groupe intégré, local au domaine : ajout = événement 4732)
#   Scope Name    : recherché par sAMAccountName (DnsAdmins n'a pas de RID fixe ; absent sans DNS intégré à l'AD)
# AllowedIn : groupes surveillés où ce groupe est imbriqué par défaut (Admins du domaine et de l'entreprise sont membres
# des Administrateurs intégrés). Cette imbrication est admise sans être parcourue : le groupe est contrôlé pour lui-même.
$script:GroupDefinitions = [ordered]@{
    DomainAdmins        = @{ Rid = 512; Scope = 'Domain';  Short = 'Admins du domaine'; Label = 'Admins du domaine (Domain Admins)'; AllowedIn = @('Administrators') }
    EnterpriseAdmins    = @{ Rid = 519; Scope = 'Forest';  Short = "Admins de l'entreprise"; Label = "Administrateurs de l'entreprise (Enterprise Admins)"; AllowedIn = @('Administrators') }
    SchemaAdmins        = @{ Rid = 518; Scope = 'Forest';  Short = 'Admins du schéma'; Label = 'Administrateurs du schéma (Schema Admins)'; AllowedIn = @() }
    Administrators      = @{ Rid = 544; Scope = 'Builtin'; Short = 'Administrateurs'; Label = 'Administrateurs intégrés (Administrators)'; AllowedIn = @() }
    AccountOperators    = @{ Rid = 548; Scope = 'Builtin'; Short = 'Opérateurs de compte'; Label = 'Opérateurs de compte (Account Operators)'; AllowedIn = @() }
    ServerOperators     = @{ Rid = 549; Scope = 'Builtin'; Short = 'Opérateurs de serveur'; Label = 'Opérateurs de serveur (Server Operators)'; AllowedIn = @() }
    PrintOperators      = @{ Rid = 550; Scope = 'Builtin'; Short = "Opérateurs d'impression"; Label = "Opérateurs d'impression (Print Operators)"; AllowedIn = @() }
    BackupOperators     = @{ Rid = 551; Scope = 'Builtin'; Short = 'Opérateurs de sauvegarde'; Label = 'Opérateurs de sauvegarde (Backup Operators)'; AllowedIn = @() }
    Replicator          = @{ Rid = 552; Scope = 'Builtin'; Short = 'Duplicateurs'; Label = 'Duplicateurs (Replicator)'; AllowedIn = @() }
    KeyAdmins           = @{ Rid = 526; Scope = 'Domain';  Short = 'Admins clés'; Label = 'Administrateurs clés (Key Admins)'; AllowedIn = @() }
    EnterpriseKeyAdmins = @{ Rid = 527; Scope = 'Forest';  Short = 'Admins clés Entreprise'; Label = 'Administrateurs clés Entreprise (Enterprise Key Admins)'; AllowedIn = @() }
    DnsAdmins           = @{ Name = 'DnsAdmins'; Scope = 'Name'; Short = 'DnsAdmins'; Label = 'DnsAdmins (non protégé par l''AD)'; AllowedIn = @() }
}
# Groupes d'origine (v1/v2.0) : une entrée de liste blanche sans liste de groupes (ancien format) y est admise
$script:LegacyGroups = @('DomainAdmins', 'EnterpriseAdmins', 'SchemaAdmins')

# Modèles du message de sensibilisation placé en tête du mail (personnalisable dans le configurateur)
$script:MailTemplates = [ordered]@{
    'Rappel de la politique' = ("Les comptes ci-dessous ont été ajoutés à un groupe d'administration sans respecter la politique " +
        "de l'entreprise relative aux comptes à privilèges. Ils ont été retirés de ce groupe et désactivés automatiquement.`n`n" +
        "Si cet ajout est légitime, contactez l'équipe infrastructure avant toute réactivation : un compte à privilèges " +
        "se crée uniquement selon la procédure de l'entreprise.")
    'Sensibilisation' = ("Rappel : les droits d'administration du domaine (Admins du domaine, de l'entreprise, du schéma) sont " +
        "réservés aux comptes dédiés, créés selon la procédure de l'entreprise. Chaque compte à privilèges supplémentaire " +
        "est une porte d'entrée de plus pour un attaquant.`n`n" +
        "Les comptes suivants ne respectent pas cette politique et ont été désactivés par mesure de sécurité. " +
        "Merci de vérifier l'origine de ces ajouts et de prendre les mesures nécessaires.")
    'Alerte sécurité' = ("ALERTE SÉCURITÉ : les comptes suivants ont obtenu des droits d'administration sans respecter la " +
        "politique de l'entreprise. Ce type d'ajout est une technique classique de persistance après une compromission.`n`n" +
        "Les comptes ont été neutralisés automatiquement. Identifiez immédiatement l'auteur de l'ajout ; s'il n'est pas " +
        "connu ou si l'ajout n'était pas prévu, traitez l'événement comme un incident de sécurité.")
    'Court' = ("Les comptes suivants ne respectent pas la politique de l'entreprise relative aux comptes à privilèges " +
        "et ont été désactivés. Prenez les mesures nécessaires.")
}

function Get-AdagMailTemplate { $script:MailTemplates }
function Get-AdagGroupDefinition { $script:GroupDefinitions }
function Get-AdagRoot { $script:Root }
function Get-AdagWhitelistPath { $script:WhitelistPath }
function Get-AdagTaskName { $script:TaskName }
function Get-AdagEventSource { $script:EventSource }

#region Configuration

function New-AdagDefaultConfig {
    [pscustomobject]@{
        Groups         = @($script:GroupDefinitions.Keys)
        QuarantineOU   = ''
        SimulationMode = $true
        MailMessage    = $script:MailTemplates['Rappel de la politique']
        Mail           = [pscustomobject]@{
            Method                = 'Graph'   # 'Graph' (Microsoft 365) ou 'Smtp'
            TenantId              = ''
            ClientId              = ''
            SecretProtected       = ''
            SmtpServer            = ''
            SmtpPort              = 587
            SmtpSsl               = $true     # STARTTLS
            SmtpUser              = ''        # vide = relais anonyme
            SmtpPasswordProtected = ''
            From                  = ''
            To                    = ''
        }
    }
}

function Get-AdagConfig {
    $default = New-AdagDefaultConfig
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) { return $default }

    $cfg = Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    # Complète les clés absentes (config issue d'une version antérieure). Une config existante garde sa liste de
    # groupes : les nouveaux groupes surveillables s'activent dans le configurateur.
    foreach ($p in $default.PSObject.Properties) {
        if (-not $cfg.PSObject.Properties[$p.Name]) { $cfg | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    }
    foreach ($p in $default.Mail.PSObject.Properties) {
        if (-not $cfg.Mail.PSObject.Properties[$p.Name]) { $cfg.Mail | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    }
    $cfg.Groups  = @($cfg.Groups | Where-Object { $_ })
    $cfg
}

function Save-AdagConfig {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] $Config)
    if ($PSCmdlet.ShouldProcess($script:ConfigPath, 'Enregistrer la configuration')) {
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
    }
}

function Test-AdagConfig {
    # Renvoie la liste des problèmes bloquants (vide si la configuration est utilisable)
    param([Parameter(Mandatory)] $Config)
    $problems = @()
    if (@($Config.Groups).Count -eq 0) { $problems += 'Aucun groupe surveillé.' }
    foreach ($g in @($Config.Groups)) {
        if (-not $script:GroupDefinitions.Contains($g)) { $problems += "Groupe inconnu : $g." }
    }
    if (-not $Config.SimulationMode -and -not $Config.QuarantineOU) {
        $problems += "L'OU de quarantaine est obligatoire hors mode simulation."
    }
    $problems
}

function Test-AdagMailConfigured {
    param([Parameter(Mandatory)] $Config)
    $m = $Config.Mail
    if (-not ($m.From -and $m.To)) { return $false }
    if ($m.Method -eq 'Smtp') {
        # Authentification facultative, mais un utilisateur sans mot de passe est incomplet
        return [bool]($m.SmtpServer -and $m.SmtpPort -and (-not $m.SmtpUser -or $m.SmtpPasswordProtected))
    }
    [bool]($m.TenantId -and $m.ClientId -and $m.SecretProtected)
}

#endregion

#region Liste blanche

function ConvertTo-AdagGroupList {
    # Texte « DomainAdmins,BackupOperators » ou « * » -> tableau de clés ; vide -> groupes d'origine (ancien format)
    param([AllowEmptyString()][string]$Text)
    $keys = @($Text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if (-not $keys.Count) { return $script:LegacyGroups }
    $keys
}

function Format-AdagGroupList {
    # Clés -> libellés courts, pour l'affichage (« Tous les groupes » pour *)
    param([AllowEmptyCollection()][string[]]$Groups = @())
    if ($Groups -contains '*') { return 'Tous les groupes' }
    (@($Groups | ForEach-Object { if ($script:GroupDefinitions.Contains($_)) { $script:GroupDefinitions[$_].Short } else { $_ } })) -join ', '
}

function Get-AdagWhitelist {
    # Entrées { Name; Sid; Groups }. Ligne « nom;SID;Groupes » : Groupes = clés séparées par des virgules, ou * pour tous.
    # Une ligne sans Groupes (format v2.0) vaut pour les trois groupes d'origine. Une ligne sans SID (compte introuvable)
    # est comparée sur le nom seul.
    if (-not (Test-Path -LiteralPath $script:WhitelistPath)) { return @() }
    foreach ($line in Get-Content -LiteralPath $script:WhitelistPath -Encoding UTF8) {
        $line = ($line -replace '#.*$', '').Trim()
        if (-not $line) { continue }
        $parts = $line -split ';', 3
        [pscustomobject]@{
            Name   = $parts[0].Trim()
            Sid    = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
            Groups = @(ConvertTo-AdagGroupList -Text $(if ($parts.Count -gt 2) { $parts[2] } else { '' }))
        }
    }
}

function Save-AdagWhitelist {
    [CmdletBinding(SupportsShouldProcess)]
    param([AllowEmptyCollection()][object[]]$Entry = @())
    $header = @(
        '# Comptes autorisés dans les groupes surveillés par ADAdminGuard : « sAMAccountName;SID;Groupes », # = commentaire.'
        '# Groupes : clés séparées par des virgules (ex. DomainAdmins,BackupOperators), ou * pour tous les groupes surveillés.'
        '# Le SID fait foi : renommer un compte ne permet pas de se faire passer pour un compte autorisé.'
        "# Mis à jour le $(Get-Date -Format 'yyyy-MM-dd HH:mm') par $env:USERDOMAIN\$env:USERNAME"
    )
    $lines = @($Entry | Sort-Object -Property Name -Unique | ForEach-Object { '{0};{1};{2}' -f $_.Name, $_.Sid, (@($_.Groups) -join ',') })
    if ($PSCmdlet.ShouldProcess($script:WhitelistPath, 'Enregistrer la liste blanche')) {
        Set-Content -LiteralPath $script:WhitelistPath -Value ($header + $lines) -Encoding UTF8
    }
}

function Test-AdagAuthorized {
    # Compte admis dans le groupe surveillé GroupKey : Administrateur intégré (RID 500), ou entrée de liste blanche qui
    # désigne ce groupe (ou *). Comparaison sur le SID quand l'entrée en a un, sinon sur le nom.
    param([Parameter(Mandatory)] $Member, [AllowEmptyCollection()][object[]]$Whitelist = @(), [Parameter(Mandatory)][string]$GroupKey)
    if ($Member.Sid -like '*-500') { return $true }
    foreach ($w in $Whitelist) {
        $groups = @($w.Groups)
        if ($groups -notcontains '*' -and $groups -notcontains $GroupKey) { continue }
        if ($w.Sid) { if ($Member.Sid -and $w.Sid -eq $Member.Sid) { return $true } }
        elseif ($Member.SamAccountName -and $w.Name -eq $Member.SamAccountName) { return $true }
    }
    $false
}

#endregion

#region État entre deux exécutions et export / import

function Get-AdagState {
    if (-not (Test-Path -LiteralPath $script:StatePath)) { return $null }
    Get-Content -LiteralPath $script:StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Save-AdagState {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] $State)
    if ($PSCmdlet.ShouldProcess($script:StatePath, "Enregistrer l'état")) {
        $State | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:StatePath -Encoding UTF8
    }
}

function Export-AdagPackage {
    # Configuration et liste blanche dans un fichier, SANS les secrets : à importer sur les autres DC
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)] $Config, [AllowEmptyCollection()][object[]]$Whitelist = @())
    $c = $Config | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    $c.Mail.SecretProtected = ''
    $c.Mail.SmtpPasswordProtected = ''
    [pscustomobject]@{
        Product    = 'ADAdminGuard'
        ExportedAt = (Get-Date).ToString('s')
        ExportedBy = "$env:USERDOMAIN\$env:USERNAME"
        Source     = $env:COMPUTERNAME
        Config     = $c
        Whitelist  = @($Whitelist | Select-Object -Property Name, Sid, @{ n = 'Groups'; e = { @($_.Groups) -join ',' } })
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Import-AdagPackage {
    # Lit un export ; renvoie { Config; Whitelist; Source; ExportedAt }. Les secrets ne sont pas dans l'export.
    param([Parameter(Mandatory)][string]$Path)
    $p = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $p.PSObject.Properties['Product'] -or $p.Product -ne 'ADAdminGuard') { throw "Ce fichier n'est pas un export ADAdminGuard." }
    [pscustomobject]@{
        Config     = $p.Config
        Whitelist  = @($p.Whitelist | Where-Object { $_ } | ForEach-Object {
                $g = if ($_.PSObject.Properties['Groups']) { [string]$_.Groups } else { '' }
                [pscustomobject]@{ Name = [string]$_.Name; Sid = [string]$_.Sid; Groups = @(ConvertTo-AdagGroupList -Text $g) } })
        Source     = [string]$p.Source
        ExportedAt = [string]$p.ExportedAt
    }
}

#endregion

#region Secret (DPAPI portée machine : lisible par SYSTEM sur cette machine uniquement)

function Protect-AdagSecret {
    param([Parameter(Mandatory)][string]$PlainText)
    $bytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
    [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($bytes, $script:Entropy, 'LocalMachine'))
}

function Unprotect-AdagSecret {
    param([Parameter(Mandatory)][string]$Protected)
    try {
        $bytes = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($Protected), $script:Entropy, 'LocalMachine')
    }
    catch {
        throw "Secret illisible sur $env:COMPUTERNAME : il a été chiffré sur une autre machine. Ressaisissez-le dans le configurateur sur ce serveur."
    }
    [Text.Encoding]::UTF8.GetString($bytes)
}

#endregion

#region Mail : Microsoft Graph (client credentials, permission application Mail.Send) ou SMTP

function Send-AdagMail {
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$HtmlBody
    )
    if ($Config.Mail.Method -eq 'Smtp') {
        if (-not (Test-AdagMailConfigured -Config $Config)) { throw 'Paramètres SMTP incomplets (serveur, port, expéditeur, destinataires, mot de passe si un utilisateur est saisi).' }
        Send-AdagSmtpMail -Mail $Config.Mail -Subject $Subject -HtmlBody $HtmlBody
        return
    }
    if (-not (Test-AdagMailConfigured -Config $Config)) { throw 'Paramètres mail incomplets (tenant, client, secret, expéditeur, destinataires).' }
    $m = $Config.Mail
    $guid = '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$'
    if ($m.ClientId -notmatch $guid) {
        throw ("L'ID d'application (client) doit être un GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx), visible sur la page " +
            "« Vue d'ensemble » de l'application dans Entra ID. La valeur saisie n'en est pas un : ce serait plutôt le secret.")
    }
    if ($m.TenantId -notmatch $guid -and $m.TenantId -notmatch '^[\w-]+(\.[\w-]+)+$') {
        throw "L'ID de locataire doit être un GUID ou un nom de domaine du locataire (ex. contoso.com)."
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $token = Invoke-AdagRestMethod -Step "Obtention du jeton auprès d'Entra ID" -Parameters @{
        Method = 'Post'
        Uri    = "https://login.microsoftonline.com/$($m.TenantId)/oauth2/v2.0/token"
        Body   = @{
            client_id     = $m.ClientId
            client_secret = Unprotect-AdagSecret -Protected $m.SecretProtected
            scope         = 'https://graph.microsoft.com/.default'
            grant_type    = 'client_credentials'
        }
    }

    $recipients = @($m.To -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ } |
        ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    $payload = @{
        message         = @{
            subject      = $Subject
            body         = @{ contentType = 'HTML'; content = $HtmlBody }
            toRecipients = $recipients
            importance   = 'high'
        }
        saveToSentItems = $false
    } | ConvertTo-Json -Depth 6

    Invoke-AdagRestMethod -Step "Envoi du mail depuis $($m.From)" -Parameters @{
        Method      = 'Post'
        Uri         = "https://graph.microsoft.com/v1.0/users/$($m.From)/sendMail"
        Headers     = @{ Authorization = "Bearer $($token.access_token)" }
        ContentType = 'application/json; charset=utf-8'
        Body        = [Text.Encoding]::UTF8.GetBytes($payload)
    } | Out-Null
}

function Send-AdagSmtpMail {
    # Envoi SMTP classique (System.Net.Mail). EnableSsl = STARTTLS, port 587 ou 25 ;
    # le SSL implicite du port 465 n'est pas pris en charge par SmtpClient.
    param([Parameter(Mandatory)] $Mail, [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][string]$HtmlBody)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $client = New-Object Net.Mail.SmtpClient($Mail.SmtpServer, [int]$Mail.SmtpPort)
    $message = New-Object Net.Mail.MailMessage
    try {
        $client.EnableSsl = [bool]$Mail.SmtpSsl
        $client.Timeout = 30000
        $client.UseDefaultCredentials = $false
        if ($Mail.SmtpUser) {
            $client.Credentials = New-Object Net.NetworkCredential($Mail.SmtpUser, (Unprotect-AdagSecret -Protected $Mail.SmtpPasswordProtected))
        }
        $message.From = New-Object Net.Mail.MailAddress($Mail.From)
        foreach ($to in @($Mail.To -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { $message.To.Add($to) }
        $message.Subject = $Subject
        $message.SubjectEncoding = [Text.Encoding]::UTF8
        $message.Body = $HtmlBody
        $message.BodyEncoding = [Text.Encoding]::UTF8
        $message.IsBodyHtml = $true
        $message.Priority = 'High'
        $client.Send($message)
    }
    catch {
        throw "Envoi SMTP via $($Mail.SmtpServer):$($Mail.SmtpPort) : $($_.Exception.GetBaseException().Message)"
    }
    finally {
        $message.Dispose()
        $client.Dispose()
    }
}

function ConvertTo-AdagMailBanner {
    # Message de sensibilisation (config.json) encadré en tête du mail ; chaîne vide si aucun message
    param([AllowEmptyString()][string]$Message)
    $text = ($Message -replace "`r", '').Trim()
    if (-not $text) { return '' }
    '<div style="border-left:4px solid #d9822b;background:#fdf3e7;padding:10px 14px;margin:0 0 14px 0">{0}</div>' -f `
        ([Net.WebUtility]::HtmlEncode($text) -replace "`n", '<br>')
}

function Invoke-AdagRestMethod {
    # Invoke-RestMethod qui remonte le motif renvoyé par Entra ID (AADSTSxxxx) ou Graph au lieu du seul code HTTP
    param([Parameter(Mandatory)][string]$Step, [Parameter(Mandatory)][hashtable]$Parameters)
    try { Invoke-RestMethod @Parameters }
    catch {
        $err = $_
        $detail = if ($err.ErrorDetails) { [string]$err.ErrorDetails.Message } else { '' }
        try {
            $j = $detail | ConvertFrom-Json
            if ($j.PSObject.Properties['error_description']) { $detail = ($j.error_description -split '\r?\n')[0] }
            elseif ($j.PSObject.Properties['error'] -and $j.error.PSObject.Properties['message']) { $detail = "$($j.error.code) : $($j.error.message)" }
        }
        catch { }
        throw "$Step : $($err.Exception.Message)$(if ($detail) { "`r`n$detail" })"
    }
}

#endregion

#region Active Directory

function Get-AdagDomainFromDN {
    # CN=x,OU=y,DC=contoso,DC=local -> contoso.local (domaine à interroger pour cet objet)
    param([Parameter(Mandatory)][string]$DistinguishedName)
    (@($DistinguishedName -split '(?<!\\),' | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) })) -join '.'
}

function Test-AdagInContainer {
    param([Parameter(Mandatory)][string]$DistinguishedName, [AllowEmptyCollection()][string[]]$Container = @())
    foreach ($c in $Container) {
        if ($c -and $DistinguishedName.EndsWith(",$c", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

function Get-AdagGroup {
    # Renvoie les groupes surveillés : clé, libellé, SID, objet ADGroup (avec member) et serveur à interroger.
    # Un groupe recherché par nom (DnsAdmins) et absent du domaine est ignoré avec un avertissement.
    param([Parameter(Mandatory)][string[]]$Key)
    $domain = Get-ADDomain
    $forest = Get-ADForest
    $rootDomain = if ($forest.RootDomain -eq $domain.DNSRoot) { $domain } else { Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain }

    foreach ($k in $Key) {
        if (-not $script:GroupDefinitions.Contains($k)) { throw "Groupe inconnu dans la configuration : $k" }
        $def = $script:GroupDefinitions[$k]
        $d = if ($def.Scope -eq 'Forest') { $rootDomain } else { $domain }
        $group = switch ($def.Scope) {
            'Builtin' { Get-ADGroup -Identity "S-1-5-32-$($def.Rid)" -Server $d.DNSRoot -Properties member }
            'Name' {
                $n = [string]$def.Name
                Get-ADGroup -Filter "sAMAccountName -eq '$n'" -Server $d.DNSRoot -Properties member | Select-Object -First 1
            }
            default { Get-ADGroup -Identity "$($d.DomainSID.Value)-$($def.Rid)" -Server $d.DNSRoot -Properties member }
        }
        if (-not $group) { Write-Warning "Groupe $($def.Label) introuvable dans $($d.DNSRoot) : ignoré."; continue }
        [pscustomobject]@{
            Key    = $k
            Label  = $def.Label
            Sid    = [string]$group.SID.Value
            Server = $d.DNSRoot
            Group  = $group
        }
    }
}

function Get-AdagDefaultNesting {
    # SID des groupes surveillés imbriqués par défaut dans le groupe Key (ex. Admins du domaine dans Administrateurs) :
    # à passer à Get-AdagEffectiveMember -NoDescendSid. Seuls les groupes eux-mêmes surveillés sont concernés : sinon
    # leurs membres doivent être contrôlés au titre du groupe qui les contient.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$GroupInfo, [Parameter(Mandatory)][string]$Key)
    $h = @{}
    foreach ($gi in $GroupInfo) {
        if ($gi.Sid -and @($script:GroupDefinitions[$gi.Key].AllowedIn) -contains $Key) { $h[$gi.Sid] = $gi.Key }
    }
    $h
}

function ConvertTo-AdagMember {
    # Lit un objet AD par son DN et le normalise (objet non résolu : ObjectClass « inconnu »)
    param([Parameter(Mandatory)][string]$DistinguishedName)
    try {
        $o = Get-ADObject -Identity $DistinguishedName -Server (Get-AdagDomainFromDN -DistinguishedName $DistinguishedName) `
            -Properties sAMAccountName, objectSid, description, member
        $get = { param($n) $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } }
        $sid = & $get 'objectSid'
        [pscustomobject]@{
            DistinguishedName = [string]$o.DistinguishedName
            SamAccountName    = [string](& $get 'sAMAccountName')
            Sid               = if ($sid) { $sid.Value } else { '' }
            ObjectClass       = [string]$o.ObjectClass
            Description       = [string](& $get 'description')
            Members           = if ($o.ObjectClass -eq 'group') { @(& $get 'member' | ForEach-Object { [string]$_ }) } else { @() }
        }
    }
    catch {
        [pscustomobject]@{ DistinguishedName = $DistinguishedName; SamAccountName = ''; Sid = ''; ObjectClass = 'inconnu'; Description = ''; Members = @() }
    }
}

function Get-AdagEffectiveMember {
    # Membres directs et imbriqués d'un groupe surveillé. Chaque objet est renvoyé avec le groupe qui le contient
    # directement (Parent*, celui dont il faut le retirer) et son chemin d'appartenance depuis le groupe surveillé.
    # Un groupe déjà parcouru n'est pas relu : les imbrications circulaires ne bouclent pas.
    # -NoDescendSid : SID de groupes à ne pas parcourir (groupes surveillés imbriqués par défaut, ex. Admins du domaine
    # dans Administrateurs) ; ils sont renvoyés comme membres, avec DefaultNesting = $true.
    param([Parameter(Mandatory)] $GroupInfo, [hashtable]$NoDescendSid = @{})
    $rootDN  = [string]$GroupInfo.Group.DistinguishedName
    $rootSid = $GroupInfo.Group.PSObject.Properties['SID']
    $rootSid = if ($rootSid -and $rootSid.Value) { [string]$rootSid.Value } else { '' }
    $visited = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    [void]$visited.Add($rootDN)
    $pending = New-Object System.Collections.Queue
    $pending.Enqueue([pscustomobject]@{
        DN = $rootDN; Sid = $rootSid; Name = $GroupInfo.Label; Server = $GroupInfo.Server; Path = $GroupInfo.Label
        Members = @($GroupInfo.Group.member | ForEach-Object { [string]$_ })
    })

    while ($pending.Count) {
        $parent = $pending.Dequeue()
        foreach ($dn in $parent.Members) {
            $m = ConvertTo-AdagMember -DistinguishedName $dn
            $default = $parent.DN -eq $rootDN -and $m.Sid -and $NoDescendSid.ContainsKey($m.Sid)
            [pscustomobject]@{
                Member         = $m
                ParentDN       = $parent.DN
                ParentSid      = $parent.Sid
                ParentName     = $parent.Name
                ParentServer   = $parent.Server
                Path           = $parent.Path
                Nested         = $parent.DN -ne $rootDN
                DefaultNesting = [bool]$default
            }
            if ($m.ObjectClass -eq 'group' -and -not $default -and $visited.Add($m.DistinguishedName)) {
                $name = if ($m.SamAccountName) { $m.SamAccountName } else { $m.DistinguishedName }
                $pending.Enqueue([pscustomobject]@{
                    DN = $m.DistinguishedName; Sid = $m.Sid; Name = $name; Path = "$($parent.Path) > $name"; Members = $m.Members
                    Server = Get-AdagDomainFromDN -DistinguishedName $m.DistinguishedName
                })
            }
        }
    }
}

function Get-AdagAddEvent {
    # Ajouts à un groupe de sécurité global (4728), local de domaine ou intégré (4732) ou universel (4756) dans le
    # journal Sécurité de ce serveur,
    # ou d'un autre DC avec -ComputerName. Lève une erreur si le journal est illisible (droits, RPC) :
    # « aucun événement » et « journal inaccessible » ne doivent pas se confondre.
    param([int]$Minutes = 120, [datetime]$Since, [string]$ComputerName)
    $start = if ($PSBoundParameters.ContainsKey('Since')) { $Since } else { (Get-Date).AddMinutes(-$Minutes) }
    $target = @{}
    if ($ComputerName) { $target.ComputerName = $ComputerName }
    $where = if ($ComputerName) { $ComputerName } else { $env:COMPUTERNAME }
    # Get-WinEvent -FilterHashtable répond « aucun événement » quand l'accès est refusé : on teste l'accès d'abord
    try { [void](Get-WinEvent -ListLog Security @target -ErrorAction Stop) }
    catch { throw "Lecture du journal Sécurité de $where impossible : $($_.Exception.Message)" }

    $query = @{ FilterHashtable = @{ LogName = 'Security'; Id = 4728, 4732, 4756; StartTime = $start } } + $target
    try { $raw = @(Get-WinEvent @query -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw "Lecture du journal Sécurité de $where impossible : $($_.Exception.Message)"
    }
    foreach ($e in $raw) {
        $data = @{}
        foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $data[$d.Name] = $d.InnerText }
        [pscustomobject]@{
            RecordId  = [long]$e.RecordId
            Time      = $e.TimeCreated
            Computer  = ($e.MachineName -split '\.')[0]
            MemberSid = ([string]$data['MemberSid']) -replace '^%\{|\}$', ''
            GroupSid  = [string]$data['TargetSid']
            By        = '{0}\{1}' -f $data['SubjectDomainName'], $data['SubjectUserName']
        }
    }
}

function Get-AdagMembershipOrigin {
    # Date et DC d'origine de l'ajout d'un membre à un groupe, lus dans les métadonnées de réplication de la valeur
    # liée « member ». Disponible depuis n'importe quel DC, contrairement à l'événement 4728/4756.
    param([Parameter(Mandatory)][string]$GroupDN, [Parameter(Mandatory)][string]$MemberDN, [Parameter(Mandatory)][string]$Server)
    try {
        $md = Get-ADReplicationAttributeMetadata -Object $GroupDN -Server $Server -Properties member -ShowAllLinkedValues |
            Where-Object { $_.AttributeValue -eq $MemberDN } | Select-Object -First 1
    }
    catch { return }
    if (-not $md) { return }
    # CN=NTDS Settings,CN=DC02,CN=Servers,... -> DC02
    $origin = [string]$md.LastOriginatingChangeDirectoryServerIdentity
    if ($origin -match '^CN=NTDS Settings,CN=([^,]+),') { $origin = $Matches[1] }
    [pscustomobject]@{ Time = $md.LastOriginatingChangeTime; DC = $origin }
}

function Get-AdagAuditState {
    # Stratégie d'audit effective de la sous-catégorie « Gestion des groupes de sécurité » (source des 4728/4756).
    # Lue par auditpol /backup : la colonne Setting Value (0 aucun, 1 succès, 2 échec, 3 les deux) n'est pas traduite,
    # contrairement à /get. Nécessite une console élevée. Enabled = $null si la lecture est impossible.
    $guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    # Chemins et fichier manipulés en .NET : le fournisseur PowerShell gère mal les noms courts 8.3 de %TEMP%
    $file = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('ADAdminGuard_audit_{0}.csv' -f [guid]::NewGuid()))
    try {
        # En PS 5.1, avec ErrorActionPreference = Stop, la moindre sortie d'erreur d'un exécutable lève une exception
        $ErrorActionPreference = 'Continue'
        # auditpol écrit en UTF-16 : les octets nuls capturés sont retirés avant analyse
        $out =((& auditpol.exe /backup "/file:$file" 2>&1 | Out-String) -replace "`0", '').Trim()
        # Sans le privilège requis, auditpol peut laisser un fichier vide : seul le code retour fait foi
        if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($file) -or -not [IO.File]::ReadAllText($file).Trim()) {
            # 0x522 = ERROR_PRIVILEGE_NOT_HELD
            $reason = if ($LASTEXITCODE -eq 1314 -or $out -match '0x00000522') { 'console non élevée' } else { $out }
            return [pscustomobject]@{ Enabled = $null; Text = "non vérifiable ($reason)" }
        }
        $row = [IO.File]::ReadAllLines($file) | ConvertFrom-Csv -Header Machine, Target, Subcategory, Guid, Inclusion, Exclusion, Value |
            Where-Object { $_.Guid -eq $guid } | Select-Object -First 1
        $value = if ($row) { [int]$row.Value } else { 0 }
        $text = @('aucun audit', 'succès', 'échec seulement', 'succès et échec')[$value]
        [pscustomobject]@{ Enabled = [bool]($value -band 1); Text = $text }
    }
    catch { [pscustomobject]@{ Enabled = $null; Text = "non vérifiable ($($_.Exception.Message))" } }
    finally { if ([IO.File]::Exists($file)) { [IO.File]::Delete($file) } }
}

#endregion

#region Tâche planifiée

function Get-AdagTaskState {
    $t = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    if ($t) { [string]$t.State } else { 'non installée' }
}

function Register-AdagTask {
    # Tâche SYSTEM déclenchée par les événements 4728/4732/4756 + contrôle de rattrapage toutes les heures.
    # Restreint aussi les droits du dossier (SYSTEM et Administrateurs) : le script tourne en SYSTEM sur un DC.
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $scriptPath = Join-Path $script:Root 'Invoke-ADAdminGuard.ps1'

    $eventTrigger = New-CimInstance -CimClass (Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace 'Root/Microsoft/Windows/TaskScheduler') -ClientOnly
    $eventTrigger.Subscription = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4728 or EventID=4732 or EventID=4756)]]</Select></Query></QueryList>'
    $eventTrigger.Enabled = $true
    $sweepTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 1)

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -MultipleInstances Queue -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

    if ($PSCmdlet.ShouldProcess($script:Root, 'Restreindre les droits du dossier à SYSTEM et Administrateurs')) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                (New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $script:Root -AclObject $acl
    }

    if ($PSCmdlet.ShouldProcess('Application', "Créer la source d'événements $script:EventSource")) {
        if (-not [Diagnostics.EventLog]::SourceExists($script:EventSource)) { New-EventLog -LogName Application -Source $script:EventSource }
    }

    if ($PSCmdlet.ShouldProcess($script:TaskName, 'Créer ou mettre à jour la tâche planifiée')) {
        Register-ScheduledTask -TaskName $script:TaskName -TaskPath '\' -Action $action -Trigger @($eventTrigger, $sweepTrigger) `
            -Principal $principal -Settings $settings -Force `
            -Description "Met en quarantaine les comptes hors liste blanche ajoutés aux groupes à privilèges de l'AD (Admins du domaine, de l'entreprise, du schéma, Administrateurs, Opérateurs…)." | Out-Null
    }
}

function Unregister-AdagTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess($script:TaskName, 'Supprimer la tâche planifiée')) {
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false
    }
}

#endregion

Export-ModuleMember -Function *-Adag*
