#Requires -Version 5.1
<#
    Fonctions communes à Invoke-PrivAdminGuard.ps1 (contrôle) et Show-PrivAdminGuardConfig.ps1 (configurateur).
    Fichiers gérés, tous à la racine du dossier du script :
      config.json   : paramètres (pattern, groupes, OU de quarantaine, mail, secret chiffré DPAPI machine)
      whitelist.txt : comptes exclus du contrôle, un sAMAccountName par ligne
#>

Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Security

$script:Root          = $PSScriptRoot
$script:ConfigPath    = Join-Path $PSScriptRoot 'config.json'
$script:WhitelistPath = Join-Path $PSScriptRoot 'whitelist.txt'
$script:TaskName      = 'PrivAdminGuard'
$script:EventSource   = 'PrivAdminGuard'
# Entropie ajoutée au chiffrement DPAPI : le secret ne se déchiffre pas par un simple appel sans elle
$script:Entropy       = [Text.Encoding]::UTF8.GetBytes('PrivAdminGuard/DPAPI')

# Groupes surveillés, désignés par RID : indépendant de la langue de l'AD (« Admins du domaine »…)
$script:GroupDefinitions = [ordered]@{
    DomainAdmins     = @{ Rid = 512; Scope = 'Domain'; Label = 'Admins du domaine (Domain Admins)' }
    EnterpriseAdmins = @{ Rid = 519; Scope = 'Forest'; Label = "Administrateurs de l'entreprise (Enterprise Admins)" }
    SchemaAdmins     = @{ Rid = 518; Scope = 'Forest'; Label = 'Administrateurs du schéma (Schema Admins)' }
}

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

function Get-PagMailTemplate { $script:MailTemplates }
function Get-PagGroupDefinition { $script:GroupDefinitions }
function Get-PagRoot { $script:Root }
function Get-PagWhitelistPath { $script:WhitelistPath }
function Get-PagTaskName { $script:TaskName }
function Get-PagEventSource { $script:EventSource }

#region Configuration

function New-PagDefaultConfig {
    [pscustomobject]@{
        Pattern        = '^adm-'
        Groups         = @('DomainAdmins', 'EnterpriseAdmins', 'SchemaAdmins')
        QuarantineOU   = ''
        SimulationMode = $true
        MailMessage    = $script:MailTemplates['Rappel de la politique']
        Mail           = [pscustomobject]@{
            TenantId        = ''
            ClientId        = ''
            SecretProtected = ''
            From            = ''
            To              = ''
        }
    }
}

function Get-PagConfig {
    $default = New-PagDefaultConfig
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) { return $default }

    $cfg = Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    # Complète les clés absentes (config issue d'une version antérieure)
    foreach ($p in $default.PSObject.Properties) {
        if (-not $cfg.PSObject.Properties[$p.Name]) { $cfg | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    }
    foreach ($p in $default.Mail.PSObject.Properties) {
        if (-not $cfg.Mail.PSObject.Properties[$p.Name]) { $cfg.Mail | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    }
    $cfg.Groups  = @($cfg.Groups | Where-Object { $_ })
    $cfg
}

function Save-PagConfig {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] $Config)
    if ($PSCmdlet.ShouldProcess($script:ConfigPath, 'Enregistrer la configuration')) {
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
    }
}

function Test-PagConfig {
    # Renvoie la liste des problèmes bloquants (vide si la configuration est utilisable)
    param([Parameter(Mandatory)] $Config)
    $problems = @()
    if (-not $Config.Pattern) { $problems += 'Le pattern est vide.' }
    else {
        try { [void][regex]::new($Config.Pattern) }
        catch { $problems += "Pattern invalide : $($_.Exception.GetBaseException().Message)" }
    }
    if (@($Config.Groups).Count -eq 0) { $problems += 'Aucun groupe surveillé.' }
    foreach ($g in @($Config.Groups)) {
        if (-not $script:GroupDefinitions.Contains($g)) { $problems += "Groupe inconnu : $g." }
    }
    if (-not $Config.SimulationMode -and -not $Config.QuarantineOU) {
        $problems += "L'OU de quarantaine est obligatoire hors mode simulation."
    }
    $problems
}

function Test-PagMailConfigured {
    param([Parameter(Mandatory)] $Config)
    $m = $Config.Mail
    [bool]($m.TenantId -and $m.ClientId -and $m.SecretProtected -and $m.From -and $m.To)
}

#endregion

#region Liste blanche

function Get-PagWhitelist {
    if (-not (Test-Path -LiteralPath $script:WhitelistPath)) { return @() }
    @(Get-Content -LiteralPath $script:WhitelistPath -Encoding UTF8 |
        ForEach-Object { ($_ -replace '#.*$', '').Trim() } |
        Where-Object { $_ })
}

function Save-PagWhitelist {
    [CmdletBinding(SupportsShouldProcess)]
    param([AllowEmptyCollection()][string[]]$Name = @())
    $header = @(
        '# Comptes exclus du contrôle PrivAdminGuard : un sAMAccountName par ligne, # = commentaire.'
        "# Mis à jour le $(Get-Date -Format 'yyyy-MM-dd HH:mm') par $env:USERDOMAIN\$env:USERNAME"
    )
    if ($PSCmdlet.ShouldProcess($script:WhitelistPath, 'Enregistrer la liste blanche')) {
        Set-Content -LiteralPath $script:WhitelistPath -Value ($header + @($Name | Sort-Object -Unique)) -Encoding UTF8
    }
}

#endregion

#region Secret (DPAPI portée machine : lisible par SYSTEM sur cette machine uniquement)

function Protect-PagSecret {
    param([Parameter(Mandatory)][string]$PlainText)
    $bytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
    [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($bytes, $script:Entropy, 'LocalMachine'))
}

function Unprotect-PagSecret {
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

#region Mail (Microsoft Graph, flux client credentials, permission application Mail.Send)

function Send-PagMail {
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$HtmlBody
    )
    if (-not (Test-PagMailConfigured -Config $Config)) { throw 'Paramètres mail incomplets (tenant, client, secret, expéditeur, destinataires).' }
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

    $token = Invoke-PagRestMethod -Step "Obtention du jeton auprès d'Entra ID" -Parameters @{
        Method = 'Post'
        Uri    = "https://login.microsoftonline.com/$($m.TenantId)/oauth2/v2.0/token"
        Body   = @{
            client_id     = $m.ClientId
            client_secret = Unprotect-PagSecret -Protected $m.SecretProtected
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

    Invoke-PagRestMethod -Step "Envoi du mail depuis $($m.From)" -Parameters @{
        Method      = 'Post'
        Uri         = "https://graph.microsoft.com/v1.0/users/$($m.From)/sendMail"
        Headers     = @{ Authorization = "Bearer $($token.access_token)" }
        ContentType = 'application/json; charset=utf-8'
        Body        = [Text.Encoding]::UTF8.GetBytes($payload)
    } | Out-Null
}

function ConvertTo-PagMailBanner {
    # Message de sensibilisation (config.json) encadré en tête du mail ; chaîne vide si aucun message
    param([AllowEmptyString()][string]$Message)
    $text = ($Message -replace "`r", '').Trim()
    if (-not $text) { return '' }
    '<div style="border-left:4px solid #d9822b;background:#fdf3e7;padding:10px 14px;margin:0 0 14px 0">{0}</div>' -f `
        ([Net.WebUtility]::HtmlEncode($text) -replace "`n", '<br>')
}

function Invoke-PagRestMethod {
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

function Get-PagDomainFromDN {
    # CN=x,OU=y,DC=contoso,DC=local -> contoso.local (domaine à interroger pour cet objet)
    param([Parameter(Mandatory)][string]$DistinguishedName)
    (@($DistinguishedName -split '(?<!\\),' | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) })) -join '.'
}

function Test-PagInContainer {
    param([Parameter(Mandatory)][string]$DistinguishedName, [AllowEmptyCollection()][string[]]$Container = @())
    foreach ($c in $Container) {
        if ($c -and $DistinguishedName.EndsWith(",$c", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

function Get-PagGroup {
    # Renvoie les groupes surveillés : clé, libellé, objet ADGroup (avec member) et serveur à interroger
    param([Parameter(Mandatory)][string[]]$Key)
    $domain = Get-ADDomain
    $forest = Get-ADForest
    $rootDomain = if ($forest.RootDomain -eq $domain.DNSRoot) { $domain } else { Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain }

    foreach ($k in $Key) {
        if (-not $script:GroupDefinitions.Contains($k)) { throw "Groupe inconnu dans la configuration : $k" }
        $def = $script:GroupDefinitions[$k]
        $d = if ($def.Scope -eq 'Forest') { $rootDomain } else { $domain }
        [pscustomobject]@{
            Key    = $k
            Label  = $def.Label
            Server = $d.DNSRoot
            Group  = Get-ADGroup -Identity "$($d.DomainSID.Value)-$($def.Rid)" -Server $d.DNSRoot -Properties member
        }
    }
}

function ConvertTo-PagMember {
    # Lit un objet AD par son DN et le normalise (objet non résolu : ObjectClass « inconnu »)
    param([Parameter(Mandatory)][string]$DistinguishedName)
    try {
        $o = Get-ADObject -Identity $DistinguishedName -Server (Get-PagDomainFromDN -DistinguishedName $DistinguishedName) `
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

function Get-PagEffectiveMember {
    # Membres directs et imbriqués d'un groupe surveillé. Chaque objet est renvoyé avec le groupe qui le contient
    # directement (Parent*, celui dont il faut le retirer) et son chemin d'appartenance depuis le groupe surveillé.
    # Un groupe déjà parcouru n'est pas relu : les imbrications circulaires ne bouclent pas.
    param([Parameter(Mandatory)] $GroupInfo)
    $rootDN  = [string]$GroupInfo.Group.DistinguishedName
    $visited = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    [void]$visited.Add($rootDN)
    $pending = New-Object System.Collections.Queue
    $pending.Enqueue([pscustomobject]@{
        DN = $rootDN; Name = $GroupInfo.Label; Server = $GroupInfo.Server; Path = $GroupInfo.Label
        Members = @($GroupInfo.Group.member | ForEach-Object { [string]$_ })
    })

    while ($pending.Count) {
        $parent = $pending.Dequeue()
        foreach ($dn in $parent.Members) {
            $m = ConvertTo-PagMember -DistinguishedName $dn
            [pscustomobject]@{
                Member       = $m
                ParentDN     = $parent.DN
                ParentName   = $parent.Name
                ParentServer = $parent.Server
                Path         = $parent.Path
                Nested       = $parent.DN -ne $rootDN
            }
            if ($m.ObjectClass -eq 'group' -and $visited.Add($m.DistinguishedName)) {
                $name = if ($m.SamAccountName) { $m.SamAccountName } else { $m.DistinguishedName }
                $pending.Enqueue([pscustomobject]@{
                    DN = $m.DistinguishedName; Name = $name; Path = "$($parent.Path) > $name"; Members = $m.Members
                    Server = Get-PagDomainFromDN -DistinguishedName $m.DistinguishedName
                })
            }
        }
    }
}

function Get-PagAddEvent {
    # Ajouts à un groupe de sécurité global (4728) ou universel (4756) dans le journal Sécurité de ce serveur,
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

    $query = @{ FilterHashtable = @{ LogName = 'Security'; Id = 4728, 4756; StartTime = $start } } + $target
    try { $raw = @(Get-WinEvent @query -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw "Lecture du journal Sécurité de $where impossible : $($_.Exception.Message)"
    }
    foreach ($e in $raw) {
        $data = @{}
        foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $data[$d.Name] = $d.InnerText }
        [pscustomobject]@{
            Time      = $e.TimeCreated
            Computer  = ($e.MachineName -split '\.')[0]
            MemberSid = ([string]$data['MemberSid']) -replace '^%\{|\}$', ''
            GroupSid  = [string]$data['TargetSid']
            By        = '{0}\{1}' -f $data['SubjectDomainName'], $data['SubjectUserName']
        }
    }
}

function Get-PagMembershipOrigin {
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

function Get-PagAuditState {
    # Stratégie d'audit effective de la sous-catégorie « Gestion des groupes de sécurité » (source des 4728/4756).
    # Lue par auditpol /backup : la colonne Setting Value (0 aucun, 1 succès, 2 échec, 3 les deux) n'est pas traduite,
    # contrairement à /get. Nécessite une console élevée. Enabled = $null si la lecture est impossible.
    $guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    # Chemins et fichier manipulés en .NET : le fournisseur PowerShell gère mal les noms courts 8.3 de %TEMP%
    $file = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('PrivAdminGuard_audit_{0}.csv' -f [guid]::NewGuid()))
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

function Get-PagTaskState {
    $t = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    if ($t) { [string]$t.State } else { 'non installée' }
}

function Register-PagTask {
    # Tâche SYSTEM déclenchée par les événements 4728/4756 + contrôle de rattrapage toutes les heures.
    # Restreint aussi les droits du dossier (SYSTEM et Administrateurs) : le script tourne en SYSTEM sur un DC.
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $scriptPath = Join-Path $script:Root 'Invoke-PrivAdminGuard.ps1'

    $eventTrigger = New-CimInstance -CimClass (Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace 'Root/Microsoft/Windows/TaskScheduler') -ClientOnly
    $eventTrigger.Subscription = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4728 or EventID=4756)]]</Select></Query></QueryList>'
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
            -Description 'Met en quarantaine les comptes hors pattern et hors liste blanche ajoutés aux groupes Admins du domaine / entreprise / schéma.' | Out-Null
    }
}

function Unregister-PagTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess($script:TaskName, 'Supprimer la tâche planifiée')) {
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false
    }
}

#endregion

Export-ModuleMember -Function *-Pag*
