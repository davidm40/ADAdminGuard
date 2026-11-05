#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Configurateur graphique de ADAdminGuard, en cinq étapes guidées.
.DESCRIPTION
    Ouvre une fenêtre à cinq étapes numérotées, parcourues avec Précédent / Suivant ou directement par les onglets :
      1. Liste blanche  : groupes surveillés, comptes exclus (whitelist.txt), import des membres actuels ;
      2. Pattern        : convention de nommage des comptes à privilèges (avec test), OU de quarantaine ;
      3. Message        : message de sensibilisation en tête du mail (modèles ou texte personnalisé) ;
      4. Notification   : envoi par Microsoft 365 (Graph) ou par serveur SMTP, destinataires, mail de test ;
      5. Planification  : audit, installation de la tâche (simulation ou application), tests, journaux.
    Une coche marque chaque étape terminée ; l'installation reste bloquée tant que les étapes 1 et 2 ne le sont pas.
    Les secrets (secret client, mot de passe SMTP) sont chiffrés avec DPAPI pour cette machine : lancer le
    configurateur sur chaque contrôleur de domaine où la tâche doit tourner.
.EXAMPLE
    .\Show-ADAdminGuardConfig.ps1
.NOTES
    Version : 1.1 (2026-11-05) - étapes guidées, envoi SMTP
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

$stepTitles = @('1. Liste blanche', '2. Pattern', '3. Message', '4. Notification', '5. Planification')
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

    $icon = Add-Control -Parent $dlg -Type PictureBox -X 15 -Y 15 -Width 32 -Height 32
    $icon.Image = [Drawing.SystemIcons]::Question.ToBitmap()
    [void](Add-Control -Parent $dlg -Type Label -X 60 -Y 12 -Width 395 -Height 180 -Text (
        "Dans quel mode installer la tâche ?`r`n`r`n" +
        "Simulation : la tâche détecte et envoie le mail en détaillant ce qu'elle aurait fait, sans modifier l'AD.`r`n`r`n" +
        "Application : les comptes hors pattern ET hors liste blanche sont retirés des groupes, désactivés et déplacés.`r`n`r`n" +
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
        Pattern        = $txtPattern.Text.Trim()
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
        "Le secret est chiffré avec DPAPI pour CETTE machine : enregistrez la configuration sur chaque contrôleur de domaine."
    }
    else {
        "Relais SMTP interne ou serveur de messagerie. Chiffrement STARTTLS sur les ports 587 ou 25 ; le SSL implicite " +
        "(port 465) n'est pas pris en charge. Laissez « Utilisateur » vide pour un relais anonyme autorisé par adresse IP.`r`n`r`n" +
        "Le mot de passe est chiffré avec DPAPI pour CETTE machine : enregistrez la configuration sur chaque contrôleur de domaine."
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
        $lblAudit.Text = "$head`r`nLes ajouts aux groupes génèrent bien les événements 4728/4756."
        $lblAudit.ForeColor = 'DarkGreen'
    }
    elseif ($script:AuditState.Enabled -eq $false) {
        $lblAudit.Text = "$head`r`nSans succès audité, la tâche ne réagit qu'au contrôle horaire et l'auteur de l'ajout reste inconnu.`r`n" +
            "À activer par GPO liée à l'OU Domain Controllers : Configuration ordinateur > Stratégies > Paramètres Windows > " +
            "Paramètres de sécurité > Configuration avancée de la stratégie d'audit > Gestion des comptes > " +
            "Auditer la gestion des groupes de sécurité : Succès."
        $lblAudit.ForeColor = 'Firebrick'
    }
    else {
        $lblAudit.Text = "$head`r`nRelancez le configurateur en tant qu'administrateur pour le vérifier."
        $lblAudit.ForeColor = 'DarkOrange'
    }
}

function Test-PatternValid {
    $p = $txtPattern.Text.Trim()
    if (-not $p) { return $false }
    try { [void][regex]::new($p); $true } catch { $false }
}

function Test-MailReady {
    # Champs de l'étape 4 remplis pour la méthode choisie (secret saisi ou déjà enregistré)
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
        1 { return [bool](@(Get-SelectedGroupKey).Count -and $lstWhite.Items.Count) }
        2 { return [bool]((Test-PatternValid) -and $cmbQuar.Text.Trim()) }
        3 { return $true }
        4 { return (Test-MailReady) }
        5 { return [bool]$script:TaskInstalled }
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

    $missing = @()
    if (-not (Test-StepDone -Step 1)) { $missing += 'étape 1 (au moins un groupe et une liste blanche non vide)' }
    if (-not (Test-PatternValid)) { $missing += 'étape 2 (pattern valide)' }
    $btnInstall.Enabled = $missing.Count -eq 0
    $lblBlocked.Text = if ($missing.Count) { "Installation impossible tant que ne sont pas terminées : $($missing -join ', ')." } else { '' }
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
    Save-AdagWhitelist -Name @($lstWhite.Items | ForEach-Object { [string]$_ })
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

$tabs = Add-Control -Parent $form -Type TabControl -X 10 -Y 10 -Width 720 -Height 515
$tabWhite  = New-Object Windows.Forms.TabPage
$tabRules  = New-Object Windows.Forms.TabPage
$tabMsg    = New-Object Windows.Forms.TabPage
$tabMail   = New-Object Windows.Forms.TabPage
$tabDeploy = New-Object Windows.Forms.TabPage
$tabs.TabPages.AddRange(@($tabWhite, $tabRules, $tabMsg, $tabMail, $tabDeploy))
for ($i = 0; $i -lt $stepTitles.Count; $i++) { $tabs.TabPages[$i].Text = $stepTitles[$i] }

#endregion

#region Étape 1 : liste blanche

Add-StepIntro -Parent $tabWhite -Text ("Étape 1 - Recensez les comptes à privilèges existants : ils seront exclus du contrôle. " +
    "Tout compte ajouté ensuite aux groupes surveillés devra respecter le pattern de l'étape 2.")

[void](Add-Control -Parent $tabWhite -Type Label -X 10 -Y 48 -Width 400 -Text 'Groupes surveillés :')
$script:GroupChecks = [ordered]@{}
$y = 68
foreach ($k in $groupDefs.Keys) {
    $chk = Add-Control -Parent $tabWhite -Type CheckBox -X 20 -Y $y -Width 460 -Text $groupDefs[$k].Label
    $chk.Checked = @($cfg.Groups) -contains $k
    $chk.Add_CheckedChanged({ Update-StepState })
    $script:GroupChecks[$k] = $chk
    $y += 22
}
$btnImport = Add-Control -Parent $tabWhite -Type Button -X 500 -Y 66 -Width 200 -Height 60 -Text 'Importer les membres actuels des groupes cochés'

[void](Add-Control -Parent $tabWhite -Type Label -X 10 -Y 140 -Width 690 -Text 'Comptes exclus du contrôle (sAMAccountName), enregistrés dans whitelist.txt :')
$lstWhite = Add-Control -Parent $tabWhite -Type ListBox -X 10 -Y 162 -Width 570 -Height 200
$lstWhite.Sorted = $true
$lstWhite.SelectionMode = 'MultiExtended'
foreach ($n in @(Get-AdagWhitelist)) { [void]$lstWhite.Items.Add($n) }
$btnWhiteRemove = Add-Control -Parent $tabWhite -Type Button -X 590 -Y 162 -Width 110 -Text 'Retirer'

$txtWhite = Add-Control -Parent $tabWhite -Type TextBox -X 10 -Y 372 -Width 570
$btnWhiteAdd = Add-Control -Parent $tabWhite -Type Button -X 590 -Y 371 -Width 110 -Text 'Ajouter'

$lblWhiteHint = Add-Control -Parent $tabWhite -Type Label -X 10 -Y 405 -Width 690 -Height 70 -Text (
    "L'import reprend les membres directs et imbriqués. Un groupe de la liste peut rester imbriqué, mais ses membres sont " +
    "contrôlés un par un. Tenez cette liste courte : chaque entrée échappe au contrôle.`r`n" +
    "Le contrôle refuse de tourner tant que whitelist.txt n'existe pas (bouton Enregistrer).")
$lblWhiteHint.ForeColor = 'DimGray'

$btnWhiteAdd.Add_Click({
    $n = $txtWhite.Text.Trim()
    if (-not $n -or @($lstWhite.Items) -contains $n) { return }
    $found = @(Get-ADObject -LDAPFilter "(sAMAccountName=$($n -replace '([\\*()])', '\$1'))")
    if (-not $found.Count -and -not (Confirm-Action -Text "Aucun objet « $n » trouvé dans le domaine. L'ajouter quand même ?")) { return }
    [void]$lstWhite.Items.Add($n)
    $txtWhite.Clear()
    Update-StepState
})
$txtWhite.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') { $btnWhiteAdd.PerformClick(); $_.SuppressKeyPress = $true } })

$btnWhiteRemove.Add_Click({
    foreach ($item in @($lstWhite.SelectedItems)) { $lstWhite.Items.Remove($item) }
    Update-StepState
})

$btnImport.Add_Click({
    $keys = @(Get-SelectedGroupKey)
    if (-not $keys.Count) { Show-Message -Text 'Cochez au moins un groupe surveillé.' -Icon Warning; return }
    try {
        $form.Cursor = 'WaitCursor'
        $added = @()
        # Membres directs et imbriqués : les groupes imbriqués sont ajoutés aussi, pour autoriser l'imbrication
        foreach ($gi in @(Get-AdagGroup -Key $keys)) {
            foreach ($e in @(Get-AdagEffectiveMember -GroupInfo $gi)) {
                $n = $e.Member.SamAccountName
                if ($n -and @($lstWhite.Items) -notcontains $n) {
                    [void]$lstWhite.Items.Add($n)
                    $added += "$n  (via $($e.Path))"
                }
            }
        }
        Update-StepState
        $msg = if ($added.Count) { "$($added.Count) compte(s) ajouté(s) :`r`n" + ($added -join "`r`n") } else { 'Tous les membres actuels sont déjà dans la liste.' }
        Show-Message -Text "$msg`r`n`r`nCliquez sur Enregistrer pour écrire whitelist.txt."
    }
    catch { Show-Message -Text "Import impossible : $($_.Exception.Message)" -Icon Error }
    finally { $form.Cursor = 'Default' }
})

#endregion

#region Étape 2 : pattern et quarantaine

Add-StepIntro -Parent $tabRules -Text ("Étape 2 - Définissez la convention de nommage des nouveaux comptes à privilèges, " +
    "et l'OU où seront déplacés les comptes non conformes.")

[void](Add-Control -Parent $tabRules -Type Label -X 10 -Y 48 -Width 690 -Text 'Pattern que doivent respecter les comptes à privilèges (expression régulière sur le sAMAccountName, insensible à la casse) :')
$txtPattern = Add-Control -Parent $tabRules -Type TextBox -X 10 -Y 70 -Width 690 -Text $cfg.Pattern
$txtPattern.Font = New-Object Drawing.Font('Consolas', 10)

[void](Add-Control -Parent $tabRules -Type Label -X 10 -Y 106 -Width 100 -Text 'Tester un nom :')
$txtTest = Add-Control -Parent $tabRules -Type TextBox -X 110 -Y 103 -Width 200
$lblTest = Add-Control -Parent $tabRules -Type Label -X 320 -Y 106 -Width 380

$updateTest = {
    if (-not $txtTest.Text) { $lblTest.Text = ''; return }
    try {
        $ok = [regex]::IsMatch($txtTest.Text, $txtPattern.Text, 'IgnoreCase')
        $lblTest.Text = if ($ok) { 'Conforme : aucune action' } else { 'Hors pattern : serait mis en quarantaine' }
        $lblTest.ForeColor = if ($ok) { 'DarkGreen' } else { 'Firebrick' }
    }
    catch {
        $lblTest.Text = 'Pattern invalide'
        $lblTest.ForeColor = 'DarkOrange'
    }
}
$txtPattern.Add_TextChanged($updateTest)
$txtPattern.Add_TextChanged({ Update-StepState })
$txtTest.Add_TextChanged($updateTest)

[void](Add-Control -Parent $tabRules -Type Label -X 10 -Y 150 -Width 690 -Text 'OU de quarantaine (destination des comptes désactivés) :')
$cmbQuar = Add-Control -Parent $tabRules -Type ComboBox -X 10 -Y 172 -Width 690 -Text $cfg.QuarantineOU
$cmbQuar.Items.AddRange([object[]]$containers)
$cmbQuar.AutoCompleteMode = 'SuggestAppend'
$cmbQuar.AutoCompleteSource = 'ListItems'
$cmbQuar.Add_TextChanged({ Update-StepState })

$lblScope = Add-Control -Parent $tabRules -Type Label -X 10 -Y 215 -Width 690 -Height 60 -Text (
    "Le contrôle porte sur tout le domaine, quel que soit l'emplacement du compte : les exceptions passent " +
    "uniquement par le pattern et la liste blanche.`r`n" +
    "L'OU de quarantaine est obligatoire pour le mode application ; son existence est vérifiée à l'enregistrement.")
$lblScope.ForeColor = 'DimGray'

#endregion

#region Étape 3 : message du mail

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

Add-StepIntro -Parent $tabMsg -Text ("Étape 3 - Rédigez le message de sensibilisation affiché en tête du mail d'alerte, " +
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
$script:TemplateSync = $true
$txtMessage.Text = ([string]$cfg.MailMessage -replace "`r", '') -replace "`n", "`r`n"
$script:TemplateSync = $false
Set-TemplateSelection -Name (Get-MessageTemplateName -Text $txtMessage.Text)

$lblMsgHint = Add-Control -Parent $tabMsg -Type Label -X 10 -Y 362 -Width 690 -Height 105 -Text (
    "Laissez vide pour ne pas afficher de message. Le texte est envoyé tel quel, sans mise en forme ; les sauts de ligne sont conservés.`r`n" +
    "En mode simulation, le mail précise en plus qu'aucune modification n'a été faite : évitez d'y affirmer que les comptes ont été désactivés " +
    "si vous testez longtemps en simulation.`r`n" +
    "Le mail de test (étape 4) inclut ce message : il sert d'aperçu.")
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

#region Étape 4 : notification

Add-StepIntro -Parent $tabMail -Text ("Étape 4 - Choisissez comment envoyer les alertes, puis envoyez un mail de test " +
    "(il inclut le message de l'étape 3).")

$rbGraph = Add-Control -Parent $tabMail -Type RadioButton -X 10 -Y 48 -Width 300 -Text 'Microsoft 365 (Microsoft Graph)'
$rbSmtp  = Add-Control -Parent $tabMail -Type RadioButton -X 320 -Y 48 -Width 300 -Text 'Serveur SMTP'
$rbSmtp.Checked  = $cfg.Mail.Method -eq 'Smtp'
$rbGraph.Checked = -not $rbSmtp.Checked

# Microsoft 365
$pnlGraph = Add-Control -Parent $tabMail -Type Panel -X 0 -Y 80 -Width 710 -Height 140
[void](Add-Control -Parent $pnlGraph -Type Label -X 10 -Y 3 -Width 180 -Text 'ID de locataire (tenant)')
$txtTenant = Add-Control -Parent $pnlGraph -Type TextBox -X 195 -Y 0 -Width 505 -Text $cfg.Mail.TenantId
[void](Add-Control -Parent $pnlGraph -Type Label -X 10 -Y 38 -Width 180 -Text "ID d'application (client)")
$txtClient = Add-Control -Parent $pnlGraph -Type TextBox -X 195 -Y 35 -Width 505 -Text $cfg.Mail.ClientId
[void](Add-Control -Parent $pnlGraph -Type Label -X 10 -Y 73 -Width 180 -Text 'Secret client')
$txtSecret = Add-SecretBox -Parent $pnlGraph -X 195 -Y 70 -Width 505
$lblSecret = Add-Control -Parent $pnlGraph -Type Label -X 195 -Y 96 -Width 505
$lblSecret.ForeColor = 'DimGray'

# SMTP
$pnlSmtp = Add-Control -Parent $tabMail -Type Panel -X 0 -Y 80 -Width 710 -Height 140
[void](Add-Control -Parent $pnlSmtp -Type Label -X 10 -Y 3 -Width 180 -Text 'Serveur SMTP')
$txtSmtpServer = Add-Control -Parent $pnlSmtp -Type TextBox -X 195 -Y 0 -Width 340 -Text $cfg.Mail.SmtpServer
[void](Add-Control -Parent $pnlSmtp -Type Label -X 555 -Y 3 -Width 40 -Text 'Port')
$txtSmtpPort = Add-Control -Parent $pnlSmtp -Type TextBox -X 600 -Y 0 -Width 100 -Text ([string]$cfg.Mail.SmtpPort)
$chkSmtpSsl = Add-Control -Parent $pnlSmtp -Type CheckBox -X 195 -Y 30 -Width 505 -Text 'Chiffrer la connexion (STARTTLS)'
$chkSmtpSsl.Checked = [bool]$cfg.Mail.SmtpSsl
[void](Add-Control -Parent $pnlSmtp -Type Label -X 10 -Y 63 -Width 180 -Text 'Utilisateur (facultatif)')
$txtSmtpUser = Add-Control -Parent $pnlSmtp -Type TextBox -X 195 -Y 60 -Width 505 -Text $cfg.Mail.SmtpUser
[void](Add-Control -Parent $pnlSmtp -Type Label -X 10 -Y 98 -Width 180 -Text 'Mot de passe')
$txtSmtpPassword = Add-SecretBox -Parent $pnlSmtp -X 195 -Y 95 -Width 505
$lblSmtpPassword = Add-Control -Parent $pnlSmtp -Type Label -X 195 -Y 121 -Width 505
$lblSmtpPassword.ForeColor = 'DimGray'

# Commun
[void](Add-Control -Parent $tabMail -Type Label -X 10 -Y 238 -Width 180 -Text 'Expéditeur')
$txtFrom = Add-Control -Parent $tabMail -Type TextBox -X 195 -Y 235 -Width 505 -Text $cfg.Mail.From
[void](Add-Control -Parent $tabMail -Type Label -X 10 -Y 273 -Width 180 -Text 'Destinataires (séparés par ;)')
$txtTo = Add-Control -Parent $tabMail -Type TextBox -X 195 -Y 270 -Width 505 -Text $cfg.Mail.To

$lblMailHint = Add-Control -Parent $tabMail -Type Label -X 10 -Y 310 -Width 690 -Height 100
$lblMailHint.ForeColor = 'DimGray'

$btnTestMail = Add-Control -Parent $tabMail -Type Button -X 10 -Y 420 -Width 220 -Height 28 -Text 'Envoyer un mail de test'

Update-SecretState
Update-MailMethod
$rbGraph.Add_CheckedChanged({ Update-MailMethod; Update-StepState })
foreach ($box in @($txtTenant, $txtClient, $txtSecret, $txtSmtpServer, $txtSmtpPort, $txtSmtpUser, $txtSmtpPassword, $txtFrom, $txtTo)) {
    $box.Add_TextChanged({ Update-StepState })
}

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

#region Étape 5 : planification

Add-StepIntro -Parent $tabDeploy -Text ("Étape 5 - Installez la tâche planifiée sur ce contrôleur de domaine, d'abord en simulation, " +
    "puis en application une fois les résultats vérifiés.")

$lblDeploy = Add-Control -Parent $tabDeploy -Type Label -X 10 -Y 48 -Width 690 -Height 92
Update-TaskState

$btnInstall   = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 145 -Width 330 -Height 28 -Text 'Installer / mettre à jour la tâche planifiée'
$btnUninstall = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 180 -Width 330 -Height 28 -Text 'Supprimer la tâche planifiée'
$btnRunTest   = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 215 -Width 330 -Height 28 -Text 'Contrôler maintenant sans rien modifier (-WhatIf)'
$btnRunTask   = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 250 -Width 330 -Height 28 -Text 'Exécuter la tâche maintenant (en SYSTEM)'
$btnLogs      = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 285 -Width 330 -Height 28 -Text 'Ouvrir le dossier des journaux'

$lblAudit = Add-Control -Parent $tabDeploy -Type Label -X 355 -Y 145 -Width 345 -Height 135
$btnAudit = Add-Control -Parent $tabDeploy -Type Button -X 355 -Y 285 -Width 200 -Height 28 -Text "Revérifier l'audit"
Update-AuditState

$lblBlocked = Add-Control -Parent $tabDeploy -Type Label -X 10 -Y 322 -Width 690 -Height 20
$lblBlocked.ForeColor = 'Firebrick'

$lblDeployHint = Add-Control -Parent $tabDeploy -Type Label -X 10 -Y 348 -Width 690 -Height 125 -Text (
    "La tâche s'exécute en SYSTEM à chaque événement 4728 ou 4756 (ajout à un groupe global ou universel) du journal " +
    "Sécurité de ce DC, et toutes les heures pour rattraper un ajout fait ailleurs. Installez-la sur chaque contrôleur de domaine.`r`n`r`n" +
    "L'installation restreint les droits du dossier à SYSTEM et Administrateurs : un script modifiable par un tiers et exécuté " +
    "en SYSTEM sur un DC serait une élévation de privilèges.`r`n`r`n" +
    "Le contrôle « -WhatIf » ne modifie pas l'AD mais envoie le mail s'il trouve un compte hors pattern et hors liste blanche.")
$lblDeployHint.ForeColor = 'DimGray'

$btnInstall.Add_Click({
    if (-not $isAdmin) { Show-Message -Text 'Relancez le configurateur en tant qu''administrateur.' -Icon Warning; return }
    if (-not $isDC -and -not (Confirm-Action -Text "$env:COMPUTERNAME n'est pas un contrôleur de domaine : les événements 4728/4756 n'y sont pas journalisés. Installer quand même ?")) { return }
    Update-AuditState
    if ($script:AuditState.Enabled -eq $false -and -not (Confirm-Action -Text ("L'audit « Gestion des groupes de sécurité » n'est pas actif en succès sur $env:COMPUTERNAME : " +
        "la tâche ne se déclenchera qu'au contrôle horaire. Installer quand même ?"))) { return }
    if (-not (Test-MailReady) -and -not (Confirm-Action -Text "La notification (étape 4) n'est pas configurée : aucune alerte ne sera envoyée. Installer quand même ?")) { return }
    # Choix explicite du mode à l'installation : la tâche lit config.json à chaque exécution
    $mode = Select-InstallMode
    if (-not $mode) { return }
    if ($mode -eq 'Application' -and -not (Confirm-Action -Text 'Confirmer le mode APPLICATION : les comptes hors pattern et hors liste blanche seront mis en quarantaine automatiquement ?')) { return }
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
            "Le résultat est dans le journal du jour (bouton « Ouvrir le dossier des journaux ») et, s'il y a un compte hors pattern et hors liste blanche, dans le mail.")
    }
    catch { Show-Message -Text "Lancement impossible : $($_.Exception.Message)" -Icon Error }
})

$btnAudit.Add_Click({ Update-AuditState })

$btnLogs.Add_Click({
    $logs = Join-Path (Get-AdagRoot) 'logs'
    New-Item -ItemType Directory -Path $logs -Force | Out-Null
    Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$logs`""
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

$script:UiReady = $true
Update-StepState

#endregion

[void]$form.ShowDialog()
$form.Dispose()
