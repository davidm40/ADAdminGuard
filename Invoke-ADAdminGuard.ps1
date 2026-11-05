#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Met en quarantaine les comptes hors pattern et hors liste blanche ajoutés aux groupes Admins du domaine, de l'entreprise ou du schéma.
.DESCRIPTION
    Lancé par la tâche planifiée « ADAdminGuard » (événements 4728/4756 du journal Sécurité, et toutes les heures).
    Les groupes surveillés (config.json) sont parcourus avec leurs groupes imbriqués, à tous les niveaux.
    Un compte direct ou indirect est ignoré s'il :
      - figure dans whitelist.txt,
      - respecte le pattern (expression régulière, insensible à la casse),
      - est l'Administrateur intégré (RID 500).
    Le contrôle porte sur tout le domaine, quel que soit l'emplacement du compte.
    Sinon, pour un compte utilisateur : retrait du groupe qui le contient directement (le groupe surveillé ou le
    groupe imbriqué), désactivation, description horodatée, déplacement dans l'OU de quarantaine.
    Un groupe imbriqué présent dans whitelist.txt est autorisé, mais ses membres restent contrôlés un par un ;
    absent de la liste, il est signalé. Ordinateurs, gMSA et objets non résolus hors liste sont seulement signalés.
    Un mail récapitulatif est envoyé (Microsoft Graph ou SMTP, selon config.json) et chaque détection est inscrite dans le journal
    Application (source ADAdminGuard, ID 1000 = quarantaine, 1001 = détection sans action, 1002 = erreur).
    En mode simulation (config.json) ou avec -WhatIf, rien n'est modifié dans l'AD ; le mail est tout de même envoyé.
    Refuse de s'exécuter si whitelist.txt n'existe pas, pour ne pas mettre en quarantaine les administrateurs en place.
.PARAMETER EventLookbackMinutes
    Fenêtre de recherche des événements 4728/4756 servant à retrouver l'auteur de l'ajout. 120 par défaut.
.PARAMETER LogDir
    Dossier des journaux (un fichier par jour, purge après 90 jours). Par défaut : sous-dossier logs du script.
.EXAMPLE
    .\Invoke-ADAdminGuard.ps1 -WhatIf
    Contrôle sans rien modifier, affiche ce qui serait fait et envoie le mail.
.NOTES
    Configuration : Show-ADAdminGuardConfig.ps1, à lancer sur chaque contrôleur de domaine.
    Version : 1.0 (2026-11-05) - création
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

function New-MailBody {
    param([Parameter(Mandatory)][object[]]$Finding, [Parameter(Mandatory)][string]$Intro, [string]$Message)
    $enc = { param($s) [Net.WebUtility]::HtmlEncode([string]$s) -replace "`n", '<br>' }
    $banner = ConvertTo-AdagMailBanner -Message $Message
    $td = 'style="border:1px solid #ccc;padding:6px;vertical-align:top"'
    $th = 'style="border:1px solid #ccc;padding:6px;background:#f2f2f2;text-align:left"'
    $rows = foreach ($f in $Finding) {
        "<tr><td $td><b>{0}</b><br><small>{1}</small></td><td $td>{2}</td><td $td>{3}<br><small>{4}</small></td><td $td>{5}</td></tr>" -f `
            (& $enc $f.Compte), (& $enc $f.DN), (& $enc $f.Groupes), (& $enc $f.AjoutePar), (& $enc $f.AjouteLe), (& $enc $f.Actions)
    }
    @"
<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px">
$banner
<p>$Intro</p>
<table style="border-collapse:collapse">
<tr><th $th>Compte</th><th $th>Appartenance</th><th $th>Ajouté par</th><th $th>Actions</th></tr>
$($rows -join "`n")
</table>
<p style="color:#666;font-size:12px">Si l'ajout est légitime : renommez le compte selon le pattern ou ajoutez-le à la liste blanche
(Show-ADAdminGuardConfig.ps1), puis réactivez-le et remettez-le dans le groupe dont il a été retiré.</p>
</body></html>
"@
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
    Write-Log ("Pattern '{0}', {1} compte(s) en liste blanche, mode {2}" -f $cfg.Pattern, $whitelist.Count,
        $(if ($simulation) { 'simulation' } else { 'application' }))

    $audit = Get-AdagAuditState
    if ($audit.Enabled -ne $true) {
        Write-Log "Audit « Gestion des groupes de sécurité » : $($audit.Text). Sans succès audité, pas de déclenchement immédiat ni d'auteur de l'ajout." 'WARN'
    }

    try {
        $events = @(Get-AdagAddEvent -Minutes $EventLookbackMinutes)
        Write-Log "$($events.Count) ajout(s) à un groupe (4728/4756) dans le journal Sécurité sur les $EventLookbackMinutes dernières minutes"
    }
    catch {
        $events = @()
        Write-Log $_.Exception.Message 'WARN'
    }

    # 1. Membres non conformes, directs et imbriqués, groupe surveillé par groupe surveillé
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($gi in @(Get-AdagGroup -Key $cfg.Groups)) {
        foreach ($e in @(Get-AdagEffectiveMember -GroupInfo $gi)) {
            $m = $e.Member
            $label = if ($m.SamAccountName) { $m.SamAccountName } else { $m.DistinguishedName }
            if ($m.Sid -like '*-500') { continue }
            if ($m.SamAccountName -and $whitelist -contains $m.SamAccountName) { continue }
            # Un groupe imbriqué n'est jugé que sur la liste blanche ; ses membres sont contrôlés de toute façon
            if ($m.ObjectClass -ne 'group' -and $m.SamAccountName -and
                [regex]::IsMatch($m.SamAccountName, $cfg.Pattern, 'IgnoreCase')) { continue }
            $hits.Add($e)
        }
    }

    # 2. Traitement, une fois par compte même s'il est atteint par plusieurs chemins
    $findings = @(foreach ($entry in @($hits | Group-Object -Property { $_.Member.DistinguishedName })) {
        $m          = $entry.Group[0].Member
        $label      = if ($m.SamAccountName) { $m.SamAccountName } else { $m.DistinguishedName }
        $parents    = @($entry.Group | Sort-Object -Property ParentDN -Unique)
        # Un chemin par ligne, ex. « Administrateurs de l'entreprise (Enterprise Admins) > G-S-T0-Managers > toto »
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
        Write-Log "$label non conforme : $($groupNames -replace "`n", ' | ')" 'WARN'

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
            $desc = '[ADAdminGuard {0:yyyy-MM-dd HH:mm}] Quarantaine : compte à privilèges hors pattern et hors liste blanche' -f (Get-Date)
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
            -Message ("Membre non conforme d'un groupe à privilèges : {0} ({1})`r`nAppartenance :`r`n{2}`r`nActions :`r`n{3}" -f `
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

    # 3. Notification
    if ($findings.Count -eq 0) {
        Write-Log 'Aucun compte non conforme'
    }
    else {
        $prefix = if ($simulation) { '[SIMULATION] ' } elseif ($WhatIfPreference) { '[WHATIF] ' } else { '' }
        $subject = '{0}[ADAdminGuard] {1} compte(s) à privilèges non autorisé(s) - {2}' -f $prefix, $findings.Count, $domainName
        # Le pattern n'est jamais écrit dans le mail : il ne doit pas circuler hors des contrôleurs de domaine
        $intro = 'Contrôle exécuté sur <b>{0}</b> le {1:dd/MM/yyyy à HH:mm}.' -f $env:COMPUTERNAME, (Get-Date)
        if ($simulation) { $intro += '<br><b>Mode simulation : aucune modification n''a été faite dans l''AD.</b>' }

        if (Test-AdagMailConfigured -Config $cfg) {
            try {
                Send-AdagMail -Config $cfg -Subject $subject -HtmlBody (New-MailBody -Finding $findings -Intro $intro -Message ([string]$cfg.MailMessage))
                Write-Log "Mail envoyé à $($cfg.Mail.To)"
            }
            catch {
                Write-Log "Échec de l'envoi du mail : $($_.Exception.Message)" 'ERROR'
                Write-GuardEvent -EventId 1002 -EntryType Error -Message "Échec de l'envoi du mail : $($_.Exception.Message)"
                $script:HasError = $true
            }
        }
        else {
            Write-Log 'Notification mail non configurée : aucun mail envoyé' 'WARN'
        }
    }

    Write-Log 'Fin du contrôle'
    if ($script:HasError) { exit 1 }
}
catch {
    Write-Log "$($_.Exception.Message) (ligne $($_.InvocationInfo.ScriptLineNumber))" 'ERROR'
    Write-GuardEvent -EventId 1002 -EntryType Error -Message $_.Exception.Message
    exit 1
}
