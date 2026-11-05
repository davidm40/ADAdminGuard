#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Met en quarantaine les comptes hors liste blanche ajoutés aux groupes Admins du domaine, de l'entreprise ou du schéma.
.DESCRIPTION
    Lancé par la tâche planifiée « ADAdminGuard » (événements 4728/4756 du journal Sécurité, et toutes les heures).
    Les groupes surveillés (config.json) sont parcourus avec leurs groupes imbriqués, à tous les niveaux.
    Seuls y sont admis l'Administrateur intégré (RID 500) et les comptes de whitelist.txt, reconnus par leur SID.
    Le contrôle porte sur tout le domaine, quel que soit l'emplacement du compte.
    Un compte utilisateur non autorisé est retiré du groupe qui le contient directement (le groupe surveillé ou le
    groupe imbriqué), désactivé, annoté d'une description horodatée et déplacé dans l'OU de quarantaine.
    Un groupe imbriqué présent dans whitelist.txt est autorisé, mais ses membres restent contrôlés un par un ;
    absent de la liste, il est signalé. Ordinateurs, gMSA et objets non résolus hors liste sont seulement signalés.

    Trois mails (Microsoft Graph ou SMTP, selon config.json) :
      - alerte de quarantaine, avec le message de sensibilisation choisi dans le configurateur ;
      - information « liste blanche modifiée » : comptes ajoutés ou retirés de whitelist.txt sur ce DC depuis
        l'exécution précédente ;
      - information « ajout autorisé » : un compte de la liste blanche (ou l'Administrateur intégré) a été ajouté à
        un groupe surveillé ou à un groupe imbriqué, d'après les événements 4728/4756 de ce DC.
    Journal Application, source ADAdminGuard : 1000 quarantaine, 1001 détection sans action, 1002 erreur,
    1003 liste blanche modifiée, 1004 ajout autorisé.
    En mode simulation (config.json) ou avec -WhatIf, rien n'est modifié dans l'AD ; l'alerte est tout de même envoyée.
    Avec -WhatIf, les mails d'information ne sont pas envoyés et state.json n'est pas mis à jour.
    Refuse de s'exécuter si whitelist.txt n'existe pas, pour ne pas mettre en quarantaine les administrateurs en place.
.PARAMETER EventLookbackMinutes
    Fenêtre de lecture des événements 4728/4756 (auteur des ajouts, traçabilité). 120 par défaut.
.PARAMETER LogDir
    Dossier des journaux (un fichier par jour, purge après 90 jours). Par défaut : sous-dossier logs du script.
.EXAMPLE
    .\Invoke-ADAdminGuard.ps1 -WhatIf
    Contrôle sans rien modifier, affiche ce qui serait fait et envoie l'alerte s'il y a lieu.
.NOTES
    Configuration : Show-ADAdminGuardConfig.ps1, à lancer sur chaque contrôleur de domaine.
    Version : 2.0 (2026-11-05) - liste blanche seule (par SID), mails d'information
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(5, 1440)]
    [int]$EventLookbackMinutes = 120,

    [string]$LogDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# $PSScriptRoot peut être vide dans les valeurs par défaut du bloc param en PowerShell 5.1 : dossier résolu ici
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $LogDir) { $LogDir = Join-Path $scriptDir 'logs' }

Import-Module ActiveDirectory -Verbose:$false
Import-Module (Join-Path $scriptDir 'ADAdminGuard.psm1') -Force -Verbose:$false

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -WhatIf:$false
    Write-Host $line -ForegroundColor @{ INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red' }[$Level]
}

function Write-GuardEvent {
    param([int]$EventId, [ValidateSet('Information', 'Warning', 'Error')][string]$EntryType, [string]$Message)
    try {
        $source = Get-AdagEventSource
        if ([Diagnostics.EventLog]::SourceExists($source)) {
            Write-EventLog -LogName Application -Source $source -EventId $EventId -EntryType $EntryType -Message $Message
        }
    }
    catch { Write-Log "Journal Application inaccessible : $($_.Exception.Message)" 'WARN' }
}

function Invoke-GuardAction {
    # Exécute une action AD sous ShouldProcess et note le résultat dans la liste des actions du compte.
    # En mode simulation (config.json), l'action est seulement notée : le mail détaille ce qui aurait été fait.
    param(
        [Parameter(Mandatory)] $Cmdlet,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$ActionList,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    if ($script:Simulation) {
        $ActionList.Add("$Description : non appliqué (simulation)")
        Write-Log "$Target : $Description (simulation)"
        return
    }
    if (-not $Cmdlet.ShouldProcess($Target, $Description)) {
        $ActionList.Add("$Description : non appliqué (WhatIf)")
        return
    }
    try {
        & $Action
        $ActionList.Add("$Description : OK")
        Write-Log "$Target : $Description"
    }
    catch {
        $ActionList.Add("$Description : ÉCHEC ($($_.Exception.Message))")
        Write-Log "$Target : $Description a échoué : $($_.Exception.Message)" 'ERROR'
        $script:HasError = $true
    }
}

function ConvertTo-HtmlCell {
    param($Value)
    [Net.WebUtility]::HtmlEncode([string]$Value) -replace "`n", '<br>'
}

function New-MailBody {
    # Mail d'alerte de quarantaine : message de sensibilisation (orange) + tableau des comptes
    param([Parameter(Mandatory)][object[]]$Finding, [Parameter(Mandatory)][string]$Intro, [string]$Message)
    $banner = ConvertTo-AdagMailBanner -Message $Message
    $td = 'style="border:1px solid #ccc;padding:6px;vertical-align:top"'
    $th = 'style="border:1px solid #ccc;padding:6px;background:#f2f2f2;text-align:left"'
    $rows = foreach ($f in $Finding) {
        "<tr><td $td><b>{0}</b><br><small>{1}</small></td><td $td>{2}</td><td $td>{3}<br><small>{4}</small></td><td $td>{5}</td></tr>" -f `
            (ConvertTo-HtmlCell $f.Compte), (ConvertTo-HtmlCell $f.DN), (ConvertTo-HtmlCell $f.Groupes),
            (ConvertTo-HtmlCell $f.AjoutePar), (ConvertTo-HtmlCell $f.AjouteLe), (ConvertTo-HtmlCell $f.Actions)
    }
    @"
<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px">
$banner
<p>$Intro</p>
<table style="border-collapse:collapse">
<tr><th $th>Compte</th><th $th>Appartenance</th><th $th>Ajouté par</th><th $th>Actions</th></tr>
$($rows -join "`n")
</table>
<p style="color:#666;font-size:12px">Si l'ajout est légitime : ajoutez le compte à la liste blanche (Show-ADAdminGuardConfig.ps1,
sur chaque contrôleur de domaine), puis réactivez-le et remettez-le dans le groupe dont il a été retiré.</p>
</body></html>
"@
}

function New-InfoMailBody {
    # Mail d'information (bandeau bleu, aucune action) : titre, phrase d'introduction, tableau libre
    param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Intro,
        [Parameter(Mandatory)][string[]]$Header, [Parameter(Mandatory)][object[]]$Row)
    $td = 'style="border:1px solid #ccc;padding:6px;vertical-align:top"'
    $th = 'style="border:1px solid #ccc;padding:6px;background:#f2f2f2;text-align:left"'
    $head = ($Header | ForEach-Object { "<th $th>$(ConvertTo-HtmlCell $_)</th>" }) -join ''
    $rows = foreach ($r in $Row) { '<tr>' + (($r | ForEach-Object { "<td $td>$(ConvertTo-HtmlCell $_)</td>" }) -join '') + '</tr>' }
    @"
<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px">
<div style="border-left:4px solid #2b6cb0;background:#ebf4fb;padding:10px 14px;margin:0 0 14px 0"><b>$(ConvertTo-HtmlCell $Title)</b><br>
Message d'information pour traçabilité : aucune action n'a été effectuée sur les comptes.</div>
<p>$Intro</p>
<table style="border-collapse:collapse"><tr>$head</tr>
$($rows -join "`n")
</table>
</body></html>
"@
}

function Send-Notification {
    # Envoi avec journalisation ; un échec est consigné sans interrompre le contrôle
    param([Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][string]$HtmlBody)
    if (-not (Test-AdagMailConfigured -Config $cfg)) {
        Write-Log "Notification mail non configurée : « $Subject » non envoyé" 'WARN'
        return
    }
    try {
        Send-AdagMail -Config $cfg -Subject $Subject -HtmlBody $HtmlBody
        Write-Log "Mail « $Subject » envoyé à $($cfg.Mail.To)"
    }
    catch {
        Write-Log "Échec de l'envoi du mail « $Subject » : $($_.Exception.Message)" 'ERROR'
        Write-GuardEvent -EventId 1002 -EntryType Error -Message "Échec de l'envoi du mail « $Subject » : $($_.Exception.Message)"
        $script:HasError = $true
    }
}

function Get-WhitelistKey {
    # Clé de comparaison d'une entrée : le SID, ou le nom pour une entrée sans SID
    param([Parameter(Mandatory)] $Entry)
    if ($Entry.Sid) { [string]$Entry.Sid } else { "nom:$($Entry.Name.ToLowerInvariant())" }
}

New-Item -ItemType Directory -Path $LogDir -Force -WhatIf:$false | Out-Null
$script:LogFile = Join-Path $LogDir ('ADAdminGuard_{0:yyyyMMdd}.log' -f (Get-Date))
$script:HasError = $false
$script:Simulation = $true   # valeur sûre jusqu'à la lecture de config.json

try {
    Write-Log "Début du contrôle sur $env:COMPUTERNAME"
    Get-ChildItem -LiteralPath $LogDir -Filter '*.log' |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) } |
        Remove-Item -Force -WhatIf:$false

    $cfg = Get-AdagConfig
    $problems = @(Test-AdagConfig -Config $cfg)
    if ($problems.Count) { throw "Configuration invalide : $($problems -join ' ')" }
    if (-not (Test-Path -LiteralPath (Get-AdagWhitelistPath))) {
        throw "whitelist.txt absent : lancez Show-ADAdminGuardConfig.ps1 et importez les membres actuels avant d'activer le contrôle."
    }
    $whitelist  = @(Get-AdagWhitelist)
    $simulation = [bool]$cfg.SimulationMode
    $script:Simulation = $simulation
    $domainName = (Get-ADDomain).DNSRoot
    $state      = Get-AdagState
    Write-Log ("{0} compte(s) en liste blanche, mode {1}" -f $whitelist.Count, $(if ($simulation) { 'simulation' } else { 'application' }))
    $noSid = @($whitelist | Where-Object { -not $_.Sid })
    if ($noSid.Count) {
        Write-Log ("Entrée(s) de liste blanche sans SID, comparées sur le nom seul : {0}. Réenregistrez la liste dans le configurateur pour y ajouter le SID." -f
            (($noSid | Select-Object -ExpandProperty Name) -join ', ')) 'WARN'
    }

    $audit = Get-AdagAuditState
    if ($audit.Enabled -ne $true) {
        Write-Log "Audit « Gestion des groupes de sécurité » : $($audit.Text). Sans succès audité, pas de déclenchement immédiat ni d'auteur de l'ajout." 'WARN'
    }

    $eventsRead = $true
    try {
        $events = @(Get-AdagAddEvent -Minutes $EventLookbackMinutes)
        Write-Log "$($events.Count) ajout(s) à un groupe (4728/4756) dans le journal Sécurité sur les $EventLookbackMinutes dernières minutes"
    }
    catch {
        $events = @()
        $eventsRead = $false
        Write-Log $_.Exception.Message 'WARN'
    }

    # 1. Membres directs et imbriqués de chaque groupe surveillé ; les non autorisés sont retenus
    $allEntries = New-Object System.Collections.Generic.List[object]
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($gi in @(Get-AdagGroup -Key $cfg.Groups)) {
        foreach ($e in @(Get-AdagEffectiveMember -GroupInfo $gi)) {
            $allEntries.Add($e)
            # Un groupe imbriqué n'est jugé que sur la liste blanche ; ses membres sont contrôlés de toute façon
            if (-not (Test-AdagAuthorized -Member $e.Member -Whitelist $whitelist)) { $hits.Add($e) }
        }
    }

    # 2. Traitement, une fois par compte même s'il est atteint par plusieurs chemins
    $findings = @(foreach ($entry in @($hits | Group-Object -Property { $_.Member.DistinguishedName })) {
        $m          = $entry.Group[0].Member
        $label      = if ($m.SamAccountName) { $m.SamAccountName } else { $m.DistinguishedName }
        $parents    = @($entry.Group | Sort-Object -Property ParentDN -Unique)
        # Un chemin par ligne, ex. « Administrateurs de l'entreprise (Enterprise Admins) > G-Tier0-Admins > toto »
        # Select-Object et non ForEach-Object -MemberName : ce dernier respecte -WhatIf et ne renverrait rien
        $groupNames = (@($entry.Group | Select-Object -ExpandProperty Path | Sort-Object -Unique) | ForEach-Object { "$_ > $label" }) -join "`n"
        $actions    = New-Object System.Collections.Generic.List[string]

        # Auteur de l'ajout : événement 4728/4756 récent sur ce DC ; à défaut, date et DC d'origine lus dans les
        # métadonnées de réplication, puis journal Sécurité de ce DC d'origine (distant : lisible seulement si les droits le permettent)
        $addEvent = $events | Where-Object { $m.Sid -and $_.MemberSid -eq $m.Sid } |
            Sort-Object -Property Time -Descending | Select-Object -First 1
        $origin = $null
        if (-not $addEvent) {
            if ($events.Count) {
                Write-Log ("Aucun des {0} événement(s) lus ne concerne {1} ({2}). Membres vus : {3}" -f $events.Count, $label, $m.Sid,
                    ((@($events | Select-Object -ExpandProperty MemberSid) | Sort-Object -Unique) -join ', ')) 'WARN'
            }
            $origin = @($parents | ForEach-Object { Get-AdagMembershipOrigin -GroupDN $_.ParentDN -MemberDN $m.DistinguishedName -Server $_.ParentServer }) |
                Where-Object { $_ } | Sort-Object -Property Time -Descending | Select-Object -First 1
            if ($origin) { Write-Log ("{0} : ajout du {1:dd/MM/yyyy HH:mm:ss} traité par {2} (métadonnées de réplication)" -f $label, $origin.Time, $origin.DC) }
            else { Write-Log "$label : métadonnées de réplication de l'ajout introuvables" 'WARN' }
            if ($origin -and $m.Sid) {
                $remote = if ($origin.DC -and $origin.DC -ne $env:COMPUTERNAME) { $origin.DC } else { '' }
                try {
                    $addEvent = Get-AdagAddEvent -ComputerName $remote -Since $origin.Time.AddMinutes(-5) |
                        Where-Object { $_.MemberSid -eq $m.Sid } | Sort-Object -Property Time -Descending | Select-Object -First 1
                }
                catch { Write-Log $_.Exception.Message 'WARN' }
            }
        }
        if ($addEvent) {
            $addedBy = $addEvent.By
            $addedOn = '{0:dd/MM/yyyy HH:mm:ss} sur {1}' -f $addEvent.Time, $addEvent.Computer
        }
        elseif ($origin) {
            $addedOn = '{0:dd/MM/yyyy HH:mm:ss} sur {1}' -f $origin.Time, $origin.DC
            $addedBy = if ($origin.DC -ne $env:COMPUTERNAME) {
                "inconnu : journal Sécurité de $($origin.DC) illisible depuis $env:COMPUTERNAME (événement 4728/4756 à consulter sur $($origin.DC))"
            }
            else { "inconnu : aucun événement 4728/4756 sur $env:COMPUTERNAME (audit inactif à ce moment-là ?)" }
        }
        else {
            $addedBy = 'inconnu'
            $addedOn = "date d'ajout introuvable"
        }
        Write-Log "$label non autorisé : $($groupNames -replace "`n", ' | ')" 'WARN'

        if ($m.ObjectClass -eq 'group') {
            $actions.Add('Groupe imbriqué absent de la liste blanche : ses membres sont contrôlés, le groupe lui-même est à vérifier manuellement')
        }
        elseif ($m.ObjectClass -notin @('user', 'inetOrgPerson')) {
            $actions.Add("Aucune action automatique sur un objet de type « $($m.ObjectClass) » : vérification manuelle requise")
        }
        else {
            $server = Get-AdagDomainFromDN -DistinguishedName $m.DistinguishedName
            # Retrait du groupe qui contient directement le compte : le retirer du groupe surveillé ne servirait à rien
            # s'il y est par un groupe imbriqué
            foreach ($p in $parents) {
                Invoke-GuardAction -Cmdlet $PSCmdlet -ActionList $actions -Target $label -Description "Retrait du groupe $($p.ParentName)" -Action {
                    Set-ADGroup -Identity $p.ParentDN -Remove @{ member = $m.DistinguishedName } -Server $p.ParentServer -Confirm:$false
                }
            }
            Invoke-GuardAction -Cmdlet $PSCmdlet -ActionList $actions -Target $label -Description 'Désactivation du compte' -Action {
                Disable-ADAccount -Identity $m.DistinguishedName -Server $server -Confirm:$false
            }
            $desc = '[ADAdminGuard {0:yyyy-MM-dd HH:mm}] Quarantaine : compte à privilèges hors liste blanche' -f (Get-Date)
            if ($m.Description) { $desc = "$desc | $($m.Description)" }
            if ($desc.Length -gt 1024) { $desc = $desc.Substring(0, 1024) }
            Invoke-GuardAction -Cmdlet $PSCmdlet -ActionList $actions -Target $label -Description 'Description horodatée' -Action {
                Set-ADObject -Identity $m.DistinguishedName -Server $server -Replace @{ description = $desc } -Confirm:$false
            }
            if (-not $cfg.QuarantineOU) {
                # Possible seulement en simulation : Test-AdagConfig l'exige en mode application
                $actions.Add("Déplacement : OU de quarantaine non définie")
            }
            elseif (Test-AdagInContainer -DistinguishedName $m.DistinguishedName -Container @($cfg.QuarantineOU)) {
                $actions.Add("Déjà dans l'OU de quarantaine")
            }
            else {
                Invoke-GuardAction -Cmdlet $PSCmdlet -ActionList $actions -Target $label -Description "Déplacement vers $($cfg.QuarantineOU)" -Action {
                    Set-ADObject -Identity $m.DistinguishedName -Server $server -ProtectedFromAccidentalDeletion $false -Confirm:$false
                    Move-ADObject -Identity $m.DistinguishedName -TargetPath $cfg.QuarantineOU -Server $server -Confirm:$false
                }
            }
        }

        $actioned = -not $simulation -and $m.ObjectClass -in @('user', 'inetOrgPerson') -and -not $WhatIfPreference
        Write-GuardEvent -EventId $(if ($actioned) { 1000 } else { 1001 }) -EntryType Warning `
            -Message ("Membre non autorisé d'un groupe à privilèges : {0} ({1})`r`nAppartenance :`r`n{2}`r`nActions :`r`n{3}" -f `
                $label, $m.DistinguishedName, ($groupNames -replace "`n", "`r`n"), ($actions -join "`r`n"))

        [pscustomobject]@{
            Compte    = $label
            DN        = $m.DistinguishedName
            Groupes   = $groupNames
            AjoutePar = $addedBy
            AjouteLe  = $addedOn
            Actions   = $actions -join "`n"
        }
    })

    # 3. Alerte de quarantaine
    if ($findings.Count -eq 0) {
        Write-Log 'Aucun compte non autorisé'
    }
    else {
        $prefix = if ($simulation) { '[SIMULATION] ' } elseif ($WhatIfPreference) { '[WHATIF] ' } else { '' }
        $intro = 'Contrôle exécuté sur <b>{0}</b> le {1:dd/MM/yyyy à HH:mm}.' -f $env:COMPUTERNAME, (Get-Date)
        if ($simulation) { $intro += '<br><b>Mode simulation : aucune modification n''a été faite dans l''AD.</b>' }
        Send-Notification -Subject ('{0}[ADAdminGuard] {1} compte(s) à privilèges non autorisé(s) - {2}' -f $prefix, $findings.Count, $domainName) `
            -HtmlBody (New-MailBody -Finding $findings -Intro $intro -Message ([string]$cfg.MailMessage))
    }

    # 4. Information : liste blanche modifiée sur ce DC depuis l'exécution précédente
    $currentKeys = @{}
    foreach ($w in $whitelist) { $currentKeys[(Get-WhitelistKey -Entry $w)] = $w }
    if ($state) {
        $previous = @{}
        foreach ($w in @($state.Whitelist)) { $previous[(Get-WhitelistKey -Entry $w)] = $w }
        $added   = @($currentKeys.Keys | Where-Object { -not $previous.ContainsKey($_) } | ForEach-Object { $currentKeys[$_] })
        $removed = @($previous.Keys | Where-Object { -not $currentKeys.ContainsKey($_) } | ForEach-Object { $previous[$_] })
        if ($added.Count -or $removed.Count) {
            $changes = @(
                $added   | ForEach-Object { , @('Ajouté', $_.Name, $_.Sid) }
                $removed | ForEach-Object { , @('Retiré', $_.Name, $_.Sid) }
            )
            $summary = ($changes | ForEach-Object { "$($_[0]) : $($_[1])" }) -join ', '
            Write-Log "Liste blanche modifiée sur $env:COMPUTERNAME : $summary" 'WARN'
            if ($WhatIfPreference) { Write-Log 'WhatIf : mail « liste blanche modifiée » non envoyé' }
            else {
                Write-GuardEvent -EventId 1003 -EntryType Information -Message "Liste blanche modifiée sur $env:COMPUTERNAME : $summary"
                $intro = ("Le fichier whitelist.txt de <b>{0}</b> a changé depuis le contrôle précédent (constaté le {1:dd/MM/yyyy à HH:mm}). " +
                    "Les comptes ajoutés peuvent désormais être membres des groupes d'administration sans être mis en quarantaine. " +
                    "Vérifiez que la modification est prévue et qu'elle a été reportée sur les autres contrôleurs de domaine.") -f $env:COMPUTERNAME, (Get-Date)
                Send-Notification -Subject "[ADAdminGuard] Information : liste blanche modifiée sur $env:COMPUTERNAME - $domainName" `
                    -HtmlBody (New-InfoMailBody -Title 'Liste blanche modifiée' -Intro $intro -Header @('Modification', 'Compte', 'SID') -Row $changes)
            }
        }
    }

    # 5. Information : ajouts autorisés à un groupe surveillé ou imbriqué, d'après les événements de ce DC
    $lastRecord = if ($state -and $state.PSObject.Properties['LastEventRecordId']) { [long]$state.LastEventRecordId } else { -1 }
    $maxRecord = $lastRecord
    if ($events.Count) { $maxRecord = [math]::Max($lastRecord, [long](($events | Measure-Object -Property RecordId -Maximum).Maximum)) }
    if ($state -and $eventsRead) {
        $privilegedGroups = @{}
        foreach ($e in $allEntries) { if ($e.ParentSid) { $privilegedGroups[$e.ParentSid] = $true } }
        $traces = @(foreach ($ev in @($events | Where-Object { $_.RecordId -gt $lastRecord -and $privilegedGroups.ContainsKey($_.GroupSid) } | Sort-Object -Property Time)) {
            $entry = $allEntries | Where-Object { $_.Member.Sid -eq $ev.MemberSid -and $_.ParentSid -eq $ev.GroupSid } | Select-Object -First 1
            # Ajout non autorisé : déjà traité par l'alerte. Membre retiré depuis : rien à tracer.
            if (-not $entry -or -not (Test-AdagAuthorized -Member $entry.Member -Whitelist $whitelist)) { continue }
            $name = if ($entry.Member.SamAccountName) { $entry.Member.SamAccountName } else { $entry.Member.DistinguishedName }
            , @($name, "$($entry.Path) > $name", $ev.By, ('{0:dd/MM/yyyy HH:mm:ss} sur {1}' -f $ev.Time, $ev.Computer))
        })
        if ($traces.Count) {
            $summary = ($traces | ForEach-Object { "$($_[0]) par $($_[2])" }) -join ', '
            Write-Log "Ajout(s) autorisé(s) : $summary"
            if ($WhatIfPreference) { Write-Log 'WhatIf : mail « ajout autorisé » non envoyé' }
            else {
                Write-GuardEvent -EventId 1004 -EntryType Information -Message "Ajout(s) autorisé(s) à un groupe d'administration : $summary"
                $intro = "Les comptes suivants, présents dans la liste blanche, ont été ajoutés à un groupe d'administration (constaté sur <b>$env:COMPUTERNAME</b>)."
                Send-Notification -Subject "[ADAdminGuard] Information : $($traces.Count) ajout(s) autorisé(s) à un groupe d'administration - $domainName" `
                    -HtmlBody (New-InfoMailBody -Title "Ajout autorisé à un groupe d'administration" -Intro $intro -Header @('Compte', 'Appartenance', 'Ajouté par', 'Date') -Row $traces)
            }
        }
    }

    # 6. État pour l'exécution suivante (premier passage : référence posée sans mail d'information)
    if (-not $state) { Write-Log 'Premier passage : état de référence enregistré (liste blanche, dernier événement), sans mail d''information' }
    if ($WhatIfPreference) { Write-Log 'WhatIf : state.json non mis à jour' }
    else {
        Save-AdagState -State ([pscustomobject]@{
            UpdatedAt         = (Get-Date).ToString('s')
            LastEventRecordId = $maxRecord
            Whitelist         = @($whitelist | Select-Object -Property Name, Sid)
        }) -Confirm:$false
    }

    Write-Log 'Fin du contrôle'
    if ($script:HasError) { exit 1 }
}
catch {
    Write-Log "$($_.Exception.Message) (ligne $($_.InvocationInfo.ScriptLineNumber))" 'ERROR'
    Write-GuardEvent -EventId 1002 -EntryType Error -Message $_.Exception.Message
    exit 1
}
