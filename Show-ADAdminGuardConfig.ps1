#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Configurateur graphique d'ADAdminGuard, en quatre étapes guidées.
.DESCRIPTION
    Ouvre une fenêtre à quatre étapes numérotées, parcourues avec Précédent / Suivant ou directement par les onglets :
      1. Liste blanche  : groupes surveillés, comptes autorisés et leurs groupes (whitelist.txt, avec leur SID),
                          import des membres actuels ;
      2. Message        : message de sensibilisation en tête de l'alerte de quarantaine (modèles ou texte personnalisé) ;
      3. Notification   : envoi par Microsoft 365 (Graph) ou par serveur SMTP, destinataires, mail de test ;
      4. Planification  : OU de quarantaine, audit, installation de la tâche (simulation ou application), tests,
                          journaux, export / import de la configuration vers les autres contrôleurs de domaine.
    Une coche marque chaque étape terminée ; l'installation reste bloquée tant que l'étape 1 ne l'est pas.
    Les secrets (secret client, mot de passe SMTP) sont chiffrés avec DPAPI pour cette machine et ne sont jamais
    exportés : les ressaisir sur chaque contrôleur de domaine après un import.
.EXAMPLE
    .\Show-ADAdminGuardConfig.ps1
.NOTES
    Version : 2.1 (2026-11-06) - groupes protégés de l'AD et DnsAdmins, groupes autorisés par compte
              2.0 (2026-11-05) - liste blanche seule (par SID), export / import
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Import-Module ActiveDirectory -Verbose:$false
Import-Module (Join-Path $PSScriptRoot 'ADAdminGuard.psm1') -Force -Verbose:$false
[Windows.Forms.Application]::EnableVisualStyles()

$cfg       = Get-AdagConfig
$groupDefs = Get-AdagGroupDefinition
$isAdmin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isDC      = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
$script:SimulationMode        = [bool]$cfg.SimulationMode
$script:SecretProtected       = [string]$cfg.Mail.SecretProtected
$script:SmtpPasswordProtected = [string]$cfg.Mail.SmtpPasswordProtected
# Valeur factice affichée en points quand un secret est enregistré (le vrai secret n'est jamais déchiffré dans le GUI).
# Caractère invisible U+2063 : impossible à taper, donc jamais confondu avec un secret saisi.
$script:SecretMask = [string][char]0x2063 * 16

# Conteneurs proposés : toutes les OU + CN=Users (conteneur par défaut des nouveaux comptes)
$containers = @(@((Get-ADDomain).UsersContainer) + @(Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName) | Sort-Object)

$stepTitles = @('1. Liste blanche', '2. Message', '3. Notification', '4. Planification')
$checkMark  = [string][char]0x2713

#region Fonctions d'interface

function Add-Control {
    param(
        [Parameter(Mandatory)] $Parent,
        [Parameter(Mandatory)][string]$Type,
        [int]$X, [int]$Y, [int]$Width, [int]$Height = 23,
        [string]$Text = ''
    )
    $c = New-Object "System.Windows.Forms.$Type"
    $c.Location = New-Object System.Drawing.Point($X, $Y)
    $c.Size = New-Object System.Drawing.Size($Width, $Height)
    if ($Text) { $c.Text = $Text }
    $Parent.Controls.Add($c)
    $c
}

function Add-StepIntro {
    # Bandeau d'explication en haut de chaque étape
    param([Parameter(Mandatory)] $Parent, [Parameter(Mandatory)][string]$Text)
    $l = Add-Control -Parent $Parent -Type Label -X 10 -Y 8 -Width 690 -Height 34 -Text $Text
    $l.ForeColor = 'SteelBlue'
}

function Add-SecretBox {
    # Champ mot de passe : les points factices sont sélectionnés à l'entrée, la saisie les remplace d'un coup
    param([Parameter(Mandatory)] $Parent, [int]$X, [int]$Y, [int]$Width)
    $t = Add-Control -Parent $Parent -Type TextBox -X $X -Y $Y -Width $Width
    $t.UseSystemPasswordChar = $true
    $t.Add_Enter({ if ($this.Text -eq $script:SecretMask) { $this.SelectAll() } })
    $t.Add_MouseUp({ if ($this.Text -eq $script:SecretMask) { $this.SelectAll() } })
    $t
}

function Show-Message {
    param([string]$Text, [ValidateSet('Information', 'Warning', 'Error')][string]$Icon = 'Information')
    [void][Windows.Forms.MessageBox]::Show($Text, 'ADAdminGuard', 'OK', $Icon)
}

function Confirm-Action {
    param([string]$Text)
    [Windows.Forms.MessageBox]::Show($Text, 'ADAdminGuard', 'YesNo', 'Question') -eq 'Yes'
}

function Select-InstallMode {
    # Fenêtre de choix du mode d'installation (une MessageBox ne permet pas de renommer Oui/Non).
    # Renvoie 'Simulation', 'Application' ou $null si annulé.
    $dlg = New-Object Windows.Forms.Form
    $dlg.Text = 'ADAdminGuard'
    $dlg.ClientSize = New-Object Drawing.Size(470, 245)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MinimizeBox = $false
    $dlg.MaximizeBox = $false
    $dlg.ShowInTaskbar = $false
    $dlg.Font = $form.Font
    $dlg.Icon = $form.Icon

    $icon = Add-Control -Parent $dlg -Type PictureBox -X 15 -Y 15 -Width 32 -Height 32
    $icon.Image = [Drawing.SystemIcons]::Question.ToBitmap()
    [void](Add-Control -Parent $dlg -Type Label -X 60 -Y 12 -Width 395 -Height 180 -Text (
        "Dans quel mode installer la tâche ?`r`n`r`n" +
        "Simulation : la tâche détecte et envoie le mail en détaillant ce qu'elle aurait fait, sans modifier l'AD.`r`n`r`n" +
        "Application : les comptes hors liste blanche (l'Administrateur intégré excepté) sont retirés des groupes, désactivés et déplacés.`r`n`r`n" +
        "Les droits du dossier $(Get-AdagRoot) seront restreints à SYSTEM et Administrateurs."))

    $btnSim = Add-Control -Parent $dlg -Type Button -X 120 -Y 205 -Width 110 -Height 28 -Text 'Simulation'
    $btnSim.DialogResult = 'Yes'
    $btnApp = Add-Control -Parent $dlg -Type Button -X 238 -Y 205 -Width 110 -Height 28 -Text 'Application'
    $btnApp.DialogResult = 'No'
    $btnCancel = Add-Control -Parent $dlg -Type Button -X 356 -Y 205 -Width 100 -Height 28 -Text 'Annuler'
    $btnCancel.DialogResult = 'Cancel'
    # Entrée = Simulation (choix sans risque), Échap = Annuler
    $dlg.AcceptButton = $btnSim
    $dlg.CancelButton = $btnCancel

    $result = $dlg.ShowDialog($form)
    $dlg.Dispose()
    switch ([string]$result) {
        'Yes' { 'Simulation' }
        'No'  { 'Application' }
        default { $null }
    }
}

function Get-SelectedGroupKey {
    @($script:GroupChecks.Keys | Where-Object { $script:GroupChecks[$_].Checked })
}

function Get-WhitelistEntry {
    @($lvWhite.Items | ForEach-Object { $_.Tag })
}

function Set-WhitelistItemGroups {
    # Met à jour les groupes d'une ligne de la liste affichée (objet Tag et colonne « Groupes autorisés »)
    param([Parameter(Mandatory)] $Item, [Parameter(Mandatory)][string[]]$Groups)
    $g = if ($Groups -contains '*') { @('*') } else { @($groupDefs.Keys | Where-Object { $Groups -contains $_ }) }
    $Item.Tag.Groups = $g
    $Item.SubItems[1].Text = Format-AdagGroupList -Groups $g
}

function Add-WhitelistEntry {
    # Ajoute une ligne (nom, SID, groupes) à la liste affichée. Si le compte y est déjà, ses groupes sont complétés.
    # Renvoie 'ajouté', 'complété' ou 'inchangé'.
    param([Parameter(Mandatory)][string]$Name, [AllowEmptyString()][string]$Sid, [Parameter(Mandatory)][string[]]$Groups)
    foreach ($item in @($lvWhite.Items)) {
        $w = $item.Tag
        if (($Sid -and $w.Sid -eq $Sid) -or (-not $Sid -and $w.Name -eq $Name)) {
            $union = @(@($w.Groups) + $Groups | Sort-Object -Unique)
            if (@($w.Groups) -contains '*' -or (@($union).Count -eq @($w.Groups).Count)) { return 'inchangé' }
            Set-WhitelistItemGroups -Item $item -Groups $union
            return 'complété'
        }
    }
    $item = New-Object Windows.Forms.ListViewItem($Name)
    [void]$item.SubItems.Add('')
    [void]$item.SubItems.Add($(if ($Sid) { $Sid } else { '(SID inconnu : comparé sur le nom)' }))
    $item.Tag = [pscustomobject]@{ Name = $Name; Sid = $Sid; Groups = @() }
    Set-WhitelistItemGroups -Item $item -Groups $Groups
    [void]$lvWhite.Items.Add($item)
    'ajouté'
}

function Select-WhitelistGroup {
    # Fenêtre de choix des groupes où un compte est autorisé. Renvoie les clés choisies (ou @('*')), ou $null si annulé.
    param([Parameter(Mandatory)][string]$Title, [AllowEmptyCollection()][string[]]$Selected = @())
    $dlg = New-Object Windows.Forms.Form
    $dlg.Text = 'ADAdminGuard'
    $dlg.ClientSize = New-Object Drawing.Size(470, 420)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MinimizeBox = $false; $dlg.MaximizeBox = $false; $dlg.ShowInTaskbar = $false
    $dlg.Font = $form.Font
    $dlg.Icon = $form.Icon
    [void](Add-Control -Parent $dlg -Type Label -X 12 -Y 10 -Width 446 -Height 36 -Text $Title)
    $clb = Add-Control -Parent $dlg -Type CheckedListBox -X 12 -Y 50 -Width 446 -Height 300
    $clb.CheckOnClick = $true
    $all = 'Tous les groupes surveillés, y compris ceux ajoutés plus tard'
    [void]$clb.Items.Add($all, ($Selected -contains '*'))
    foreach ($k in $groupDefs.Keys) { [void]$clb.Items.Add($groupDefs[$k].Label, ($Selected -contains $k)) }
    $hint = Add-Control -Parent $dlg -Type Label -X 12 -Y 352 -Width 446 -Height 30 -Text "Accordez le moins de groupes possible : un compte de service n'a souvent besoin que d'un seul."
    $hint.ForeColor = 'DimGray'
    $ok = Add-Control -Parent $dlg -Type Button -X 248 -Y 385 -Width 100 -Height 28 -Text 'OK'; $ok.DialogResult = 'OK'
    $cancel = Add-Control -Parent $dlg -Type Button -X 358 -Y 385 -Width 100 -Height 28 -Text 'Annuler'; $cancel.DialogResult = 'Cancel'
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    $result = $dlg.ShowDialog($form)
    $keys = @($groupDefs.Keys)
    $chosen = @(for ($i = 1; $i -lt $clb.Items.Count; $i++) { if ($clb.GetItemChecked($i)) { $keys[$i - 1] } })
    $star = $clb.GetItemChecked(0)
    $dlg.Dispose()
    if ([string]$result -ne 'OK') { return $null }
    if ($star) { return , @('*') }
    if (-not $chosen.Count) { Show-Message -Text 'Aucun groupe coché : rien n''est modifié.' -Icon Warning; return $null }
    , $chosen
}

function Get-SecretValue {
    # Secret à enregistrer : nouveau secret chiffré s'il a été saisi, sinon celui déjà enregistré
    param([Parameter(Mandatory)] $Box, [AllowEmptyString()][string]$Stored)
    if ($Box.Text -and $Box.Text -ne $script:SecretMask) { return Protect-AdagSecret -PlainText $Box.Text }
    $Stored
}

function Get-FormConfig {
    $port = 0
    [void][int]::TryParse($txtSmtpPort.Text.Trim(), [ref]$port)
    $smtpUser = $txtSmtpUser.Text.Trim()
    [pscustomobject]@{
        Groups         = @(Get-SelectedGroupKey)
        QuarantineOU   = $cmbQuar.Text.Trim()
        SimulationMode = $script:SimulationMode
        MailMessage    = ($txtMessage.Text -replace "`r", '').Trim()
        Mail           = [pscustomobject]@{
            Method                = if ($rbSmtp.Checked) { 'Smtp' } else { 'Graph' }
            TenantId              = $txtTenant.Text.Trim()
            ClientId              = $txtClient.Text.Trim()
            SecretProtected       = Get-SecretValue -Box $txtSecret -Stored $script:SecretProtected
            SmtpServer            = $txtSmtpServer.Text.Trim()
            SmtpPort              = $port
            SmtpSsl               = $chkSmtpSsl.Checked
            SmtpUser              = $smtpUser
            # Sans utilisateur (relais anonyme), aucun mot de passe n'est conservé
            SmtpPasswordProtected = if ($smtpUser) { Get-SecretValue -Box $txtSmtpPassword -Stored $script:SmtpPasswordProtected } else { '' }
            From                  = $txtFrom.Text.Trim()
            To                    = $txtTo.Text.Trim()
        }
    }
}

function Set-FormFromConfig {
    # Remplit les étapes depuis une configuration (au chargement, ou depuis un export) ; les secrets ne sont pas touchés
    param([Parameter(Mandatory)] $Config, [AllowEmptyCollection()][object[]]$Whitelist = @())
    foreach ($k in $script:GroupChecks.Keys) { $script:GroupChecks[$k].Checked = @($Config.Groups) -contains $k }
    $lvWhite.Items.Clear()
    foreach ($w in $Whitelist) { [void](Add-WhitelistEntry -Name $w.Name -Sid $w.Sid -Groups @($w.Groups)) }
    $cmbQuar.Text = [string]$Config.QuarantineOU
    $script:SimulationMode = [bool]$Config.SimulationMode
    $script:TemplateSync = $true
    $txtMessage.Text = ([string]$Config.MailMessage -replace "`r", '') -replace "`n", "`r`n"
    $script:TemplateSync = $false
    Set-TemplateSelection -Name (Get-MessageTemplateName -Text $txtMessage.Text)
    $m = $Config.Mail
    $rbSmtp.Checked  = $m.Method -eq 'Smtp'
    $rbGraph.Checked = -not $rbSmtp.Checked
    $txtTenant.Text     = [string]$m.TenantId
    $txtClient.Text     = [string]$m.ClientId
    $txtSmtpServer.Text = [string]$m.SmtpServer
    $txtSmtpPort.Text   = [string]$m.SmtpPort
    $chkSmtpSsl.Checked = [bool]$m.SmtpSsl
    $txtSmtpUser.Text   = [string]$m.SmtpUser
    $txtFrom.Text       = [string]$m.From
    $txtTo.Text         = [string]$m.To
    Update-MailMethod
}

function Update-SecretState {
    foreach ($s in @(
            @{ Box = $txtSecret; Label = $lblSecret; Stored = $script:SecretProtected; Name = 'Secret' }
            @{ Box = $txtSmtpPassword; Label = $lblSmtpPassword; Stored = $script:SmtpPasswordProtected; Name = 'Mot de passe' })) {
        if ($s.Stored) {
            $s.Box.Text = $script:SecretMask
            $s.Label.Text = "$($s.Name) enregistré. Saisissez une nouvelle valeur pour le remplacer."
        }
        else {
            $s.Box.Clear()
            $s.Label.Text = "Aucun $($s.Name.ToLower()) enregistré."
        }
    }
}

function Update-MailMethod {
    # Affiche les champs de la méthode d'envoi choisie
    $pnlGraph.Visible = $rbGraph.Checked
    $pnlSmtp.Visible = $rbSmtp.Checked
    $lblMailHint.Text = if ($rbGraph.Checked) {
        "L'application Entra ID doit avoir la permission Microsoft Graph Mail.Send de type Application, avec consentement " +
        "administrateur. Limitez-la à la boîte expéditrice (RBAC for Applications d'Exchange Online), sinon elle peut " +
        "écrire au nom de n'importe quelle boîte.`r`n`r`n" +
        "Le secret est chiffré avec DPAPI pour CETTE machine et n'est jamais exporté : saisissez-le sur chaque contrôleur de domaine."
    }
    else {
        "Relais SMTP interne ou serveur de messagerie. Chiffrement STARTTLS sur les ports 587 ou 25 ; le SSL implicite " +
        "(port 465) n'est pas pris en charge. Laissez « Utilisateur » vide pour un relais anonyme autorisé par adresse IP.`r`n`r`n" +
        "Le mot de passe est chiffré avec DPAPI pour CETTE machine et n'est jamais exporté : saisissez-le sur chaque contrôleur de domaine."
    }
}

function Update-TaskState {
    $state = Get-AdagTaskState
    $script:TaskInstalled = $state -ne 'non installée'
    $lblDeploy.Text = "Dossier : $(Get-AdagRoot)`r`n" +
        "Cette machine : $env:COMPUTERNAME ($(if ($isDC) { 'contrôleur de domaine' } else { 'PAS un contrôleur de domaine' }))" +
        "$(if (-not $isAdmin) { ', console non élevée' })`r`n" +
        "Tâche planifiée « $(Get-AdagTaskName) » : $state`r`n" +
        "Mode enregistré dans config.json : $(if ((Get-AdagConfig).SimulationMode) { 'SIMULATION (aucune modification de l''AD)' } else { 'APPLICATION' })"
}

function Update-AuditState {
    $script:AuditState = Get-AdagAuditState
    $head = "Audit « Gestion des groupes de sécurité » : $($script:AuditState.Text)"
    if ($script:AuditState.Enabled -eq $true) {
        $lblAudit.Text = "$head`r`nLes ajouts aux groupes génèrent bien les événements 4728/4732/4756."
        $lblAudit.ForeColor = 'DarkGreen'
    }
    elseif ($script:AuditState.Enabled -eq $false) {
        $lblAudit.Text = "$head`r`nÀ activer par GPO sur l'OU Domain Controllers : Configuration avancée de la stratégie d'audit > " +
            "Gestion des comptes > Auditer la gestion des groupes de sécurité : Succès."
        $lblAudit.ForeColor = 'Firebrick'
    }
    else {
        $lblAudit.Text = "$head`r`nRelancez le configurateur en tant qu'administrateur pour le vérifier."
        $lblAudit.ForeColor = 'DarkOrange'
    }
}

function Test-MailReady {
    # Champs de l'étape 3 remplis pour la méthode choisie (secret saisi ou déjà enregistré)
    $hasSecret = { param($box, $stored) [bool](($box.Text -and $box.Text -ne $script:SecretMask) -or $stored) }
    if (-not ($txtFrom.Text.Trim() -and $txtTo.Text.Trim())) { return $false }
    if ($rbSmtp.Checked) {
        $port = 0
        return [bool]($txtSmtpServer.Text.Trim() -and [int]::TryParse($txtSmtpPort.Text.Trim(), [ref]$port) -and $port -gt 0 -and
            (-not $txtSmtpUser.Text.Trim() -or (& $hasSecret $txtSmtpPassword $script:SmtpPasswordProtected)))
    }
    [bool]($txtTenant.Text.Trim() -and $txtClient.Text.Trim() -and (& $hasSecret $txtSecret $script:SecretProtected))
}

function Test-StepDone {
    param([int]$Step)
    switch ($Step) {
        1 { return [bool](@(Get-SelectedGroupKey).Count -and $lvWhite.Items.Count) }
        2 { return $true }
        3 { return (Test-MailReady) }
        4 { return [bool]$script:TaskInstalled }
    }
}

function Update-StepState {
    # Coche des étapes terminées, compteur, navigation et blocage de l'installation
    if (-not $script:UiReady) { return }
    $done = 0
    for ($i = 0; $i -lt $stepTitles.Count; $i++) {
        $ok = Test-StepDone -Step ($i + 1)
        if ($ok) { $done++ }
        $title = if ($ok) { "$checkMark $($stepTitles[$i])" } else { $stepTitles[$i] }
        if ($tabs.TabPages[$i].Text -ne $title) { $tabs.TabPages[$i].Text = $title }
    }
    $lblProgress.Text = "$done étape(s) terminée(s) sur $($stepTitles.Count)"
    $btnPrev.Enabled = $tabs.SelectedIndex -gt 0
    $btnNext.Enabled = $tabs.SelectedIndex -lt ($stepTitles.Count - 1)

    $ready = Test-StepDone -Step 1
    $btnInstall.Enabled = $ready
    $lblBlocked.Text = if ($ready) { '' } else { "Installation impossible tant que l'étape 1 n'est pas terminée (au moins un groupe et une liste blanche non vide)." }
}

function Save-FormConfig {
    # Enregistre config.json et whitelist.txt ; renvoie $false si la configuration est refusée
    $c = Get-FormConfig
    $problems = @(Test-AdagConfig -Config $c)
    if ($problems.Count) {
        Show-Message -Text ("Configuration non enregistrée :`r`n- " + ($problems -join "`r`n- ")) -Icon Warning
        return $false
    }
    if ($c.QuarantineOU) {
        try { [void](Get-ADObject -Identity $c.QuarantineOU -Server (Get-AdagDomainFromDN -DistinguishedName $c.QuarantineOU)) }
        catch {
            Show-Message -Text "OU de quarantaine introuvable dans l'AD :`r`n$($c.QuarantineOU)`r`n`r`nConfiguration non enregistrée." -Icon Warning
            return $false
        }
    }

    Save-AdagConfig -Config $c
    Save-AdagWhitelist -Entry @(Get-WhitelistEntry)
    $script:SecretProtected = $c.Mail.SecretProtected
    $script:SmtpPasswordProtected = $c.Mail.SmtpPasswordProtected
    Update-SecretState
    Update-TaskState
    Update-StepState
    $true
}

#endregion

#region Fenêtre

$script:UiReady = $false
$form = New-Object Windows.Forms.Form
$form.Text = 'ADAdminGuard - Configuration'
$form.ClientSize = New-Object Drawing.Size(740, 575)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.Font = New-Object Drawing.Font('Segoe UI', 9)
# Logo dans la barre de titre et la barre des tâches (facultatif : sans le fichier, icône par défaut)
$iconPath = Join-Path $PSScriptRoot 'ADAdminGuard.ico'
if (Test-Path -LiteralPath $iconPath) { $form.Icon = New-Object Drawing.Icon($iconPath) }

$tabs =Add-Control -Parent $form -Type TabControl -X 10 -Y 10 -Width 720 -Height 515
$tabWhite  = New-Object Windows.Forms.TabPage
$tabMsg    = New-Object Windows.Forms.TabPage
$tabMail   = New-Object Windows.Forms.TabPage
$tabDeploy = New-Object Windows.Forms.TabPage
$tabs.TabPages.AddRange(@($tabWhite, $tabMsg, $tabMail, $tabDeploy))
for ($i = 0; $i -lt $stepTitles.Count; $i++) { $tabs.TabPages[$i].Text = $stepTitles[$i] }

#endregion

#region Étape 1 : liste blanche

Add-StepIntro -Parent $tabWhite -Text ("Étape 1 - Cochez les groupes à surveiller et recensez, pour chaque compte autorisé, les groupes où il " +
    "est admis. Tout autre membre, direct ou imbriqué, est mis en quarantaine ; l'Administrateur intégré est toujours autorisé.")

[void](Add-Control -Parent $tabWhite -Type Label -X 10 -Y 46 -Width 300 -Text 'Groupes surveillés :')
$btnImport = Add-Control -Parent $tabWhite -Type Button -X 400 -Y 42 -Width 300 -Height 24 -Text 'Importer les membres actuels des groupes cochés'
$script:GroupChecks = [ordered]@{}
$i = 0
foreach ($k in $groupDefs.Keys) {
    # Deux colonnes de six
    $x = if ($i -lt 6) { 20 } else { 360 }
    $y = 70 + ($i % 6) * 21
    $chk = Add-Control -Parent $tabWhite -Type CheckBox -X $x -Y $y -Width 335 -Text $groupDefs[$k].Label
    $chk.Add_CheckedChanged({ Update-StepState })
    $script:GroupChecks[$k] = $chk
    $i++
}

[void](Add-Control -Parent $tabWhite -Type Label -X 10 -Y 202 -Width 690 -Text 'Comptes autorisés, enregistrés dans whitelist.txt (le SID fait foi, pas le nom) :')
$lvWhite = Add-Control -Parent $tabWhite -Type ListView -X 10 -Y 222 -Width 570 -Height 160
$lvWhite.View = 'Details'
$lvWhite.FullRowSelect = $true
$lvWhite.MultiSelect = $true
$lvWhite.HideSelection = $false
$lvWhite.Sorting = 'Ascending'
[void]$lvWhite.Columns.Add('Compte', 130)
[void]$lvWhite.Columns.Add('Groupes autorisés', 190)
[void]$lvWhite.Columns.Add('SID', 225)
$btnWhiteGroups = Add-Control -Parent $tabWhite -Type Button -X 590 -Y 222 -Width 110 -Text 'Groupes…'
$btnWhiteRemove = Add-Control -Parent $tabWhite -Type Button -X 590 -Y 252 -Width 110 -Text 'Retirer'

$txtWhite = Add-Control -Parent $tabWhite -Type TextBox -X 10 -Y 390 -Width 570
$btnWhiteAdd = Add-Control -Parent $tabWhite -Type Button -X 590 -Y 389 -Width 110 -Text 'Ajouter…'

$lblWhiteHint = Add-Control -Parent $tabWhite -Type Label -X 10 -Y 420 -Width 690 -Height 62 -Text (
    "Un compte n'est admis que dans les groupes de sa ligne : un compte de sauvegarde autorisé dans les Opérateurs de sauvegarde " +
    "ne l'est pas chez les Admins du domaine. Admins du domaine et de l'entreprise, membres par défaut des Administrateurs, y sont admis d'office. " +
    "Toute modification de la liste déclenche un mail d'information. Liste propre à ce DC : Exporter / Importer (étape 4).")
$lblWhiteHint.ForeColor = 'DimGray'

$btnWhiteAdd.Add_Click({
    $n = $txtWhite.Text.Trim()
    if (-not $n) { return }
    $found = @(Get-ADObject -LDAPFilter "(sAMAccountName=$($n -replace '([\\*()])', '\$1'))" -Properties objectSid, sAMAccountName)
    $sid = ''
    if ($found.Count) { $sid = [string]$found[0].objectSid.Value }
    elseif (-not (Confirm-Action -Text ("Aucun objet « $n » trouvé dans le domaine. L'ajouter quand même ?`r`n`r`n" +
            "Sans SID, il sera comparé sur son nom seul : un autre compte renommé ainsi serait aussi autorisé."))) { return }
    $name = if ($found.Count) { [string]$found[0].sAMAccountName } else { $n }
    $groups = Select-WhitelistGroup -Title "Groupes où « $name » est autorisé :" -Selected @(Get-SelectedGroupKey | Select-Object -First 1)
    if (-not $groups) { return }
    $r = Add-WhitelistEntry -Name $name -Sid $sid -Groups $groups
    if ($r -eq 'inchangé') { Show-Message -Text "« $name » est déjà autorisé dans ces groupes." ; return }
    $txtWhite.Clear()
    Update-StepState
})

$btnWhiteGroups.Add_Click({
    $items = @($lvWhite.SelectedItems)
    if (-not $items.Count) { Show-Message -Text 'Sélectionnez un ou plusieurs comptes dans la liste.'; return }
    $title = if ($items.Count -eq 1) { "Groupes où « $($items[0].Text) » est autorisé :" } else { "Groupes où les $($items.Count) comptes sélectionnés sont autorisés :" }
    $groups = Select-WhitelistGroup -Title $title -Selected @($items[0].Tag.Groups)
    if (-not $groups) { return }
    foreach ($item in $items) { Set-WhitelistItemGroups -Item $item -Groups $groups }
    Update-StepState
})
$lvWhite.Add_DoubleClick({ $btnWhiteGroups.PerformClick() })
$txtWhite.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') { $btnWhiteAdd.PerformClick(); $_.SuppressKeyPress = $true } })

$btnWhiteRemove.Add_Click({
    foreach ($item in @($lvWhite.SelectedItems)) { $lvWhite.Items.Remove($item) }
    Update-StepState
})

$btnImport.Add_Click({
    $keys = @(Get-SelectedGroupKey)
    if (-not $keys.Count) { Show-Message -Text 'Cochez au moins un groupe surveillé.' -Icon Warning; return }
    try {
        $form.Cursor = 'WaitCursor'
        $added = @()
        # Membres directs et imbriqués, Administrateur intégré excepté (toujours autorisé) ; chaque compte est autorisé
        # dans le groupe où il a été trouvé. Les groupes imbriqués sont ajoutés aussi, pour autoriser l'imbrication ;
        # l'imbrication par défaut (Admins du domaine dans Administrateurs) n'a pas besoin de l'être.
        $infos = @(Get-AdagGroup -Key $keys -WarningVariable importWarnings -WarningAction SilentlyContinue)
        foreach ($gi in $infos) {
            $noDescend = Get-AdagDefaultNesting -GroupInfo $infos -Key $gi.Key
            foreach ($e in @(Get-AdagEffectiveMember -GroupInfo $gi -NoDescendSid $noDescend)) {
                $m = $e.Member
                if ($e.DefaultNesting -or -not $m.SamAccountName -or $m.Sid -like '*-500') { continue }
                $r = Add-WhitelistEntry -Name $m.SamAccountName -Sid $m.Sid -Groups @($gi.Key)
                if ($r -ne 'inchangé') { $added += "$($m.SamAccountName) : $($groupDefs[$gi.Key].Short)  (via $($e.Path))" }
            }
        }
        Update-StepState
        $msg = if ($added.Count) { "$($added.Count) autorisation(s) ajoutée(s) :`r`n" + ($added -join "`r`n") } else { 'Tous les membres actuels sont déjà autorisés.' }
        if (@($importWarnings).Count) { $msg += "`r`n`r`n" + (@($importWarnings) -join "`r`n") }
        Show-Message -Text "$msg`r`n`r`nCliquez sur Enregistrer pour écrire whitelist.txt."
    }
    catch { Show-Message -Text "Import impossible : $($_.Exception.Message)" -Icon Error }
    finally { $form.Cursor = 'Default' }
})

#endregion

#region Étape 2 : message du mail

# Modèles du module + « Aucun message » ; « Personnalisé » désigne un texte qui ne correspond à aucun modèle.
# Le modèle affiché n'est pas enregistré : il est retrouvé en comparant le message de config.json aux modèles.
$templates = [ordered]@{}
foreach ($k in (Get-AdagMailTemplate).Keys) { $templates[$k] = (Get-AdagMailTemplate)[$k] }
$templates['Aucun message'] = ''
$customLabel = 'Personnalisé'
$script:TemplateSync = $false   # vrai pendant une mise à jour faite par le code (évite les événements en cascade)

function Get-MessageTemplateName {
    param([AllowEmptyString()][string]$Text)
    $norm = ($Text -replace "`r", '').Trim()
    foreach ($k in $templates.Keys) { if ((($templates[$k] -replace "`r", '').Trim()) -eq $norm) { return $k } }
    $customLabel
}

function Set-TemplateSelection {
    param([string]$Name)
    $script:TemplateSync = $true
    $cmbTemplate.SelectedItem = $Name
    $script:TemplateSync = $false
    $script:LastTemplate = $Name
}

Add-StepIntro -Parent $tabMsg -Text ("Étape 2 - Rédigez le message de sensibilisation affiché en tête de l'alerte de quarantaine, " +
    "au-dessus de la liste des comptes.")

[void](Add-Control -Parent $tabMsg -Type Label -X 10 -Y 51 -Width 130 -Text 'Modèle :')
$cmbTemplate = Add-Control -Parent $tabMsg -Type ComboBox -X 140 -Y 48 -Width 300
$cmbTemplate.DropDownStyle = 'DropDownList'
$cmbTemplate.Items.AddRange([object[]]@(@($templates.Keys) + $customLabel))

$txtMessage = Add-Control -Parent $tabMsg -Type TextBox -X 10 -Y 82 -Width 690 -Height 270
$txtMessage.Multiline = $true
$txtMessage.AcceptsReturn = $true
$txtMessage.WordWrap = $true
$txtMessage.ScrollBars = 'Vertical'

$lblMsgHint = Add-Control -Parent $tabMsg -Type Label -X 10 -Y 362 -Width 690 -Height 105 -Text (
    "Laissez vide pour ne pas afficher de message. Le texte est envoyé tel quel, sans mise en forme ; les sauts de ligne sont conservés.`r`n" +
    "En mode simulation, le mail précise en plus qu'aucune modification n'a été faite : évitez d'y affirmer que les comptes ont été désactivés " +
    "si vous testez longtemps en simulation.`r`n" +
    "Les mails d'information (liste blanche modifiée, ajout autorisé) ont un texte fixe. Le mail de test (étape 3) inclut ce message.")
$lblMsgHint.ForeColor = 'DimGray'

# Choix d'un modèle : le texte est remplacé aussitôt. Seul un texte personnalisé demande confirmation avant d'être écrasé.
$cmbTemplate.Add_SelectedIndexChanged({
    if ($script:TemplateSync) { return }
    $name = [string]$cmbTemplate.SelectedItem
    if ($name -eq $customLabel) { $script:LastTemplate = $name; return }
    if ($script:LastTemplate -eq $customLabel -and $txtMessage.Text.Trim() -and
        -not (Confirm-Action -Text "Remplacer votre message personnalisé par le modèle « $name » ?")) {
        Set-TemplateSelection -Name $customLabel
        return
    }
    $script:TemplateSync = $true
    $txtMessage.Text = ($templates[$name] -replace "`r", '') -replace "`n", "`r`n"
    $script:TemplateSync = $false
    $script:LastTemplate = $name
})

# Saisie dans le texte : la liste suit (« Personnalisé » dès que le texte s'écarte d'un modèle)
$txtMessage.Add_TextChanged({
    if ($script:TemplateSync) { return }
    $name = Get-MessageTemplateName -Text $txtMessage.Text
    if ([string]$cmbTemplate.SelectedItem -ne $name) { Set-TemplateSelection -Name $name } else { $script:LastTemplate = $name }
})

#endregion

#region Étape 3 : notification

Add-StepIntro -Parent $tabMail -Text ("Étape 3 - Choisissez comment envoyer les alertes et les mails d'information, puis envoyez " +
    "un mail de test (il inclut le message de l'étape 2).")

$rbGraph = Add-Control -Parent $tabMail -Type RadioButton -X 10 -Y 48 -Width 300 -Text 'Microsoft 365 (Microsoft Graph)'
$rbSmtp  = Add-Control -Parent $tabMail -Type RadioButton -X 320 -Y 48 -Width 300 -Text 'Serveur SMTP'
$rbGraph.Checked = $true

# Microsoft 365
$pnlGraph = Add-Control -Parent $tabMail -Type Panel -X 0 -Y 80 -Width 710 -Height 140
[void](Add-Control -Parent $pnlGraph -Type Label -X 10 -Y 3 -Width 180 -Text 'ID de locataire (tenant)')
$txtTenant = Add-Control -Parent $pnlGraph -Type TextBox -X 195 -Y 0 -Width 505
[void](Add-Control -Parent $pnlGraph -Type Label -X 10 -Y 38 -Width 180 -Text "ID d'application (client)")
$txtClient = Add-Control -Parent $pnlGraph -Type TextBox -X 195 -Y 35 -Width 505
[void](Add-Control -Parent $pnlGraph -Type Label -X 10 -Y 73 -Width 180 -Text 'Secret client')
$txtSecret = Add-SecretBox -Parent $pnlGraph -X 195 -Y 70 -Width 505
$lblSecret = Add-Control -Parent $pnlGraph -Type Label -X 195 -Y 96 -Width 505
$lblSecret.ForeColor = 'DimGray'

# SMTP
$pnlSmtp = Add-Control -Parent $tabMail -Type Panel -X 0 -Y 80 -Width 710 -Height 140
[void](Add-Control -Parent $pnlSmtp -Type Label -X 10 -Y 3 -Width 180 -Text 'Serveur SMTP')
$txtSmtpServer = Add-Control -Parent $pnlSmtp -Type TextBox -X 195 -Y 0 -Width 340
[void](Add-Control -Parent $pnlSmtp -Type Label -X 555 -Y 3 -Width 40 -Text 'Port')
$txtSmtpPort = Add-Control -Parent $pnlSmtp -Type TextBox -X 600 -Y 0 -Width 100
$chkSmtpSsl = Add-Control -Parent $pnlSmtp -Type CheckBox -X 195 -Y 30 -Width 505 -Text 'Chiffrer la connexion (STARTTLS)'
[void](Add-Control -Parent $pnlSmtp -Type Label -X 10 -Y 63 -Width 180 -Text 'Utilisateur (facultatif)')
$txtSmtpUser = Add-Control -Parent $pnlSmtp -Type TextBox -X 195 -Y 60 -Width 505
[void](Add-Control -Parent $pnlSmtp -Type Label -X 10 -Y 98 -Width 180 -Text 'Mot de passe')
$txtSmtpPassword = Add-SecretBox -Parent $pnlSmtp -X 195 -Y 95 -Width 505
$lblSmtpPassword = Add-Control -Parent $pnlSmtp -Type Label -X 195 -Y 121 -Width 505
$lblSmtpPassword.ForeColor = 'DimGray'

# Commun
[void](Add-Control -Parent $tabMail -Type Label -X 10 -Y 238 -Width 180 -Text 'Expéditeur')
$txtFrom = Add-Control -Parent $tabMail -Type TextBox -X 195 -Y 235 -Width 505
[void](Add-Control -Parent $tabMail -Type Label -X 10 -Y 273 -Width 180 -Text 'Destinataires (séparés par ;)')
$txtTo = Add-Control -Parent $tabMail -Type TextBox -X 195 -Y 270 -Width 505

$lblMailHint = Add-Control -Parent $tabMail -Type Label -X 10 -Y 310 -Width 690 -Height 100
$lblMailHint.ForeColor = 'DimGray'

$btnTestMail = Add-Control -Parent $tabMail -Type Button -X 10 -Y 420 -Width 220 -Height 28 -Text 'Envoyer un mail de test'

$btnTestMail.Add_Click({
    try {
        $form.Cursor = 'WaitCursor'
        $c = Get-FormConfig
        # Le message de sensibilisation est inclus : le test sert aussi d'aperçu
        Send-AdagMail -Config $c -Subject '[ADAdminGuard] Mail de test' -HtmlBody ((ConvertTo-AdagMailBanner -Message $c.MailMessage) +
            ("<p>Mail de test envoyé depuis <b>$env:COMPUTERNAME</b> le {0:dd/MM/yyyy à HH:mm}.</p>" -f (Get-Date)))
        Show-Message -Text "Mail envoyé à $($c.Mail.To)."
    }
    catch { Show-Message -Text "Échec de l'envoi : $($_.Exception.Message)" -Icon Error }
    finally { $form.Cursor = 'Default' }
})

#endregion

#region Étape 4 : planification

Add-StepIntro -Parent $tabDeploy -Text ("Étape 4 - Indiquez l'OU de quarantaine, puis installez la tâche planifiée sur ce contrôleur de " +
    "domaine, d'abord en simulation. Exportez la configuration pour l'importer sur les autres DC.")

[void](Add-Control -Parent $tabDeploy -Type Label -X 10 -Y 48 -Width 690 -Text "OU de quarantaine (destination des comptes désactivés, obligatoire pour le mode application) :")
$cmbQuar = Add-Control -Parent $tabDeploy -Type ComboBox -X 10 -Y 68 -Width 690
$cmbQuar.Items.AddRange([object[]]$containers)
$cmbQuar.AutoCompleteMode = 'SuggestAppend'
$cmbQuar.AutoCompleteSource = 'ListItems'

$lblDeploy = Add-Control -Parent $tabDeploy -Type Label -X 10 -Y 102 -Width 690 -Height 92
Update-TaskState

$btnInstall   = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 198 -Width 330 -Height 28 -Text 'Installer / mettre à jour la tâche planifiée'
$btnUninstall = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 231 -Width 330 -Height 28 -Text 'Supprimer la tâche planifiée'
$btnRunTest   = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 264 -Width 330 -Height 28 -Text 'Contrôler maintenant sans rien modifier (-WhatIf)'
$btnRunTask   = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 297 -Width 330 -Height 28 -Text 'Exécuter la tâche maintenant (en SYSTEM)'
$btnLogs      = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 330 -Width 330 -Height 28 -Text 'Ouvrir le dossier des journaux'

$lblAudit = Add-Control -Parent $tabDeploy -Type Label -X 355 -Y 198 -Width 345 -Height 90
$btnAudit = Add-Control -Parent $tabDeploy -Type Button -X 355 -Y 297 -Width 170 -Height 28 -Text "Revérifier l'audit"
$btnExport = Add-Control -Parent $tabDeploy -Type Button -X 355 -Y 330 -Width 170 -Height 28 -Text 'Exporter la configuration'
$btnImportCfg = Add-Control -Parent $tabDeploy -Type Button -X 530 -Y 330 -Width 170 -Height 28 -Text 'Importer une configuration'
Update-AuditState

$lblBlocked = Add-Control -Parent $tabDeploy -Type Label -X 10 -Y 366 -Width 690 -Height 20
$lblBlocked.ForeColor = 'Firebrick'

$lblDeployHint = Add-Control -Parent $tabDeploy -Type Label -X 10 -Y 390 -Width 690 -Height 85 -Text (
    "La tâche s'exécute en SYSTEM à chaque événement 4728, 4732 ou 4756 du journal Sécurité de ce DC, et toutes les heures. " +
    "Installez-la sur chaque contrôleur de domaine ; l'installation restreint les droits du dossier à SYSTEM et Administrateurs.`r`n" +
    "L'export contient la configuration et la liste blanche, jamais les secrets : après un import, ressaisissez le secret " +
    "à l'étape 3, puis Enregistrer.")
$lblDeployHint.ForeColor = 'DimGray'

$btnInstall.Add_Click({
    if (-not $isAdmin) { Show-Message -Text 'Relancez le configurateur en tant qu''administrateur.' -Icon Warning; return }
    if (-not $isDC -and -not (Confirm-Action -Text "$env:COMPUTERNAME n'est pas un contrôleur de domaine : les événements 4728/4732/4756 n'y sont pas journalisés. Installer quand même ?")) { return }
    Update-AuditState
    if ($script:AuditState.Enabled -eq $false -and -not (Confirm-Action -Text ("L'audit « Gestion des groupes de sécurité » n'est pas actif en succès sur $env:COMPUTERNAME : " +
        "la tâche ne se déclenchera qu'au contrôle horaire. Installer quand même ?"))) { return }
    if (-not (Test-MailReady) -and -not (Confirm-Action -Text "La notification (étape 3) n'est pas configurée : aucun mail ne sera envoyé. Installer quand même ?")) { return }
    # Choix explicite du mode à l'installation : la tâche lit config.json à chaque exécution
    $mode = Select-InstallMode
    if (-not $mode) { return }
    if ($mode -eq 'Application' -and -not (Confirm-Action -Text 'Confirmer le mode APPLICATION : les comptes hors liste blanche seront mis en quarantaine automatiquement ?')) { return }
    $previous = $script:SimulationMode
    $script:SimulationMode = $mode -eq 'Simulation'
    if (-not (Save-FormConfig)) { $script:SimulationMode = $previous; return }
    try {
        Register-AdagTask -Confirm:$false
        Update-TaskState
        Update-StepState
        Show-Message -Text ("Tâche planifiée installée en mode $($mode.ToLower()).`r`n" +
            "Pour la tester en SYSTEM : bouton « Exécuter la tâche maintenant », ou ajoutez un compte de test à un groupe surveillé.")
    }
    catch { Show-Message -Text "Installation impossible : $($_.Exception.Message)" -Icon Error }
})

$btnUninstall.Add_Click({
    if (-not $isAdmin) { Show-Message -Text 'Relancez le configurateur en tant qu''administrateur.' -Icon Warning; return }
    if (-not $script:TaskInstalled) { Show-Message -Text 'La tâche n''est pas installée.'; return }
    if (-not (Confirm-Action -Text 'Supprimer la tâche planifiée ? Le contrôle ne sera plus effectué sur ce serveur.')) { return }
    try { Unregister-AdagTask -Confirm:$false; Update-TaskState; Update-StepState }
    catch { Show-Message -Text "Suppression impossible : $($_.Exception.Message)" -Icon Error }
})

$btnRunTest.Add_Click({
    if (-not (Save-FormConfig)) { return }
    $main = Join-Path (Get-AdagRoot) 'Invoke-ADAdminGuard.ps1'
    $arguments = "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$main`" -WhatIf"
    # Lecture du journal Sécurité : nécessite une console élevée
    if ($isAdmin) { Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments }
    else { Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs }
})

$btnRunTask.Add_Click({
    if (-not $isAdmin) { Show-Message -Text 'Relancez le configurateur en tant qu''administrateur.' -Icon Warning; return }
    if (-not $script:TaskInstalled) { Show-Message -Text 'Installez d''abord la tâche planifiée.' -Icon Warning; return }
    try {
        Start-ScheduledTask -TaskName (Get-AdagTaskName)
        Update-TaskState
        Show-Message -Text ("Tâche lancée en SYSTEM, dans le mode enregistré dans config.json.`r`n" +
            "Le résultat est dans le journal du jour (bouton « Ouvrir le dossier des journaux ») et, s'il y a lieu, dans les mails.")
    }
    catch { Show-Message -Text "Lancement impossible : $($_.Exception.Message)" -Icon Error }
})

$btnAudit.Add_Click({ Update-AuditState })

$btnLogs.Add_Click({
    $logs = Join-Path (Get-AdagRoot) 'logs'
    New-Item -ItemType Directory -Path $logs -Force | Out-Null
    Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$logs`""
})

$btnExport.Add_Click({
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'Export ADAdminGuard (*.json)|*.json'
    $dlg.FileName = 'ADAdminGuard-export-{0}-{1:yyyyMMdd}.json' -f $env:COMPUTERNAME, (Get-Date)
    if ($dlg.ShowDialog($form) -ne 'OK') { return }
    try {
        Export-AdagPackage -Path $dlg.FileName -Config (Get-FormConfig) -Whitelist @(Get-WhitelistEntry)
        Show-Message -Text ("Configuration et liste blanche exportées, sans les secrets :`r`n$($dlg.FileName)`r`n`r`n" +
            "Sur chaque autre DC : Importer une configuration, ressaisir le secret à l'étape 3, Enregistrer, puis installer la tâche.")
    }
    catch { Show-Message -Text "Export impossible : $($_.Exception.Message)" -Icon Error }
})

$btnImportCfg.Add_Click({
    $dlg = New-Object Windows.Forms.OpenFileDialog
    $dlg.Filter = 'Export ADAdminGuard (*.json)|*.json'
    if ($dlg.ShowDialog($form) -ne 'OK') { return }
    try {
        $pkg = Import-AdagPackage -Path $dlg.FileName
        if (-not (Confirm-Action -Text ("Remplacer la configuration affichée par celle exportée depuis $($pkg.Source) le $($pkg.ExportedAt) ?`r`n`r`n" +
            "$($pkg.Whitelist.Count) compte(s) en liste blanche. Les secrets de ce DC sont conservés."))) { return }
        Set-FormFromConfig -Config $pkg.Config -Whitelist $pkg.Whitelist
        Update-StepState
        Show-Message -Text ("Configuration importée, pas encore enregistrée.`r`nVérifiez les étapes, saisissez le secret à l'étape 3 " +
            "si aucun n'est enregistré sur ce DC, puis cliquez sur Enregistrer.")
    }
    catch { Show-Message -Text "Import impossible : $($_.Exception.Message)" -Icon Error }
})

#endregion

#region Navigation et boutons du bas

$btnPrev = Add-Control -Parent $form -Type Button -X 10 -Y 537 -Width 110 -Height 28 -Text '< Précédent'
$btnNext = Add-Control -Parent $form -Type Button -X 125 -Y 537 -Width 110 -Height 28 -Text 'Suivant >'
$lblProgress = Add-Control -Parent $form -Type Label -X 245 -Y 543 -Width 265
$lblProgress.ForeColor = 'DimGray'
$btnSave  = Add-Control -Parent $form -Type Button -X 520 -Y 537 -Width 100 -Height 28 -Text 'Enregistrer'
$btnClose = Add-Control -Parent $form -Type Button -X 630 -Y 537 -Width 100 -Height 28 -Text 'Fermer'

$btnPrev.Add_Click({ if ($tabs.SelectedIndex -gt 0) { $tabs.SelectedIndex-- } })
$btnNext.Add_Click({ if ($tabs.SelectedIndex -lt $tabs.TabCount - 1) { $tabs.SelectedIndex++ } })
$tabs.Add_SelectedIndexChanged({ Update-StepState })
$btnSave.Add_Click({
    if (Save-FormConfig) { Show-Message -Text 'Configuration et liste blanche enregistrées.' }
})
$btnClose.Add_Click({ $form.Close() })
$form.CancelButton = $btnClose

if (-not $isAdmin) {
    $form.Add_Shown({ Show-Message -Text "Console non élevée : l'installation de la tâche et le contrôle immédiat demanderont une élévation." -Icon Warning })
}

#endregion

#region Chargement de la configuration enregistrée

Set-FormFromConfig -Config $cfg -Whitelist @(Get-AdagWhitelist)
Update-SecretState
$rbGraph.Add_CheckedChanged({ Update-MailMethod; Update-StepState })
foreach ($box in @($txtTenant, $txtClient, $txtSecret, $txtSmtpServer, $txtSmtpPort, $txtSmtpUser, $txtSmtpPassword, $txtFrom, $txtTo)) {
    $box.Add_TextChanged({ Update-StepState })
}
$script:UiReady = $true
Update-StepState

#endregion

[void]$form.ShowDialog()
$form.Dispose()
