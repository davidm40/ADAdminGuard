#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Configurateur graphique de PrivAdminGuard (pattern, groupes, OU, liste blanche, mail, tâche planifiée).
.DESCRIPTION
    Ouvre une fenêtre à quatre onglets :
      - Règles        : pattern à respecter (avec test), groupes surveillés, OU de quarantaine, mode simulation ;
      - Liste blanche : comptes exclus (whitelist.txt à la racine du script), import des membres actuels des groupes ;
      - Notification  : application M365 (tenant, client, secret), expéditeur, destinataires, mail de test ;
      - Déploiement   : installation de la tâche planifiée, contrôle immédiat en -WhatIf, journaux.
    Le secret est chiffré avec DPAPI pour cette machine : lancer le configurateur sur chaque contrôleur de domaine
    où la tâche doit tourner.
.EXAMPLE
    .\Show-PrivAdminGuardConfig.ps1
.NOTES
    Version : 1.0 (2026-11-05) - création
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Import-Module ActiveDirectory -Verbose:$false
Import-Module (Join-Path $PSScriptRoot 'PrivAdminGuard.psm1') -Force -Verbose:$false
[Windows.Forms.Application]::EnableVisualStyles()

$cfg       = Get-PagConfig
$groupDefs = Get-PagGroupDefinition
$isAdmin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isDC      = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
$script:SecretProtected = [string]$cfg.Mail.SecretProtected
# Valeur factice affichée en points quand un secret est enregistré (le vrai secret n'est jamais déchiffré dans le GUI).
# Caractère invisible U+2063 : impossible à taper, donc jamais confondu avec un secret saisi.
$script:SecretMask = [string][char]0x2063 * 16

# Conteneurs proposés : toutes les OU + CN=Users (conteneur par défaut des nouveaux comptes)
$containers = @(@((Get-ADDomain).UsersContainer) + @(Get-ADOrganizationalUnit -Filter * | ForEach-Object -MemberName DistinguishedName) | Sort-Object)

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

function Show-Message {
    param([string]$Text, [ValidateSet('Information', 'Warning', 'Error')][string]$Icon = 'Information')
    [void][Windows.Forms.MessageBox]::Show($Text, 'PrivAdminGuard', 'OK', $Icon)
}

function Confirm-Action {
    param([string]$Text)
    [Windows.Forms.MessageBox]::Show($Text, 'PrivAdminGuard', 'YesNo', 'Question') -eq 'Yes'
}

function Select-InstallMode {
    # Fenêtre de choix du mode d'installation (une MessageBox ne permet pas de renommer Oui/Non).
    # Renvoie 'Simulation', 'Application' ou $null si annulé.
    $dlg = New-Object Windows.Forms.Form
    $dlg.Text = 'PrivAdminGuard'
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
        "Les droits du dossier $(Get-PagRoot) seront restreints à SYSTEM et Administrateurs."))

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

function Get-FormConfig {
    $secret = $script:SecretProtected
    if ($txtSecret.Text -and $txtSecret.Text -ne $script:SecretMask) { $secret = Protect-PagSecret -PlainText $txtSecret.Text }
    [pscustomobject]@{
        Pattern        = $txtPattern.Text.Trim()
        Groups         = @(Get-SelectedGroupKey)
        QuarantineOU   = $cmbQuar.Text.Trim()
        SimulationMode = $chkSim.Checked
        MailMessage    = ($txtMessage.Text -replace "`r", '').Trim()
        Mail           = [pscustomobject]@{
            TenantId        = $txtTenant.Text.Trim()
            ClientId        = $txtClient.Text.Trim()
            SecretProtected = $secret
            From            = $txtFrom.Text.Trim()
            To              = $txtTo.Text.Trim()
        }
    }
}

function Update-SecretState {
    if ($script:SecretProtected) {
        $txtSecret.Text = $script:SecretMask
        $lblSecret.Text = 'Secret enregistré. Saisissez une nouvelle valeur pour le remplacer.'
    }
    else {
        $txtSecret.Clear()
        $lblSecret.Text = 'Aucun secret enregistré.'
    }
}

function Update-TaskState {
    $lblDeploy.Text = "Dossier : $(Get-PagRoot)`r`n" +
        "Cette machine : $env:COMPUTERNAME ($(if ($isDC) { 'contrôleur de domaine' } else { 'PAS un contrôleur de domaine' }))" +
        "$(if (-not $isAdmin) { ', console non élevée' })`r`n" +
        "Tâche planifiée « $(Get-PagTaskName) » : $(Get-PagTaskState)`r`n" +
        "Mode enregistré dans config.json : $(if ((Get-PagConfig).SimulationMode) { 'SIMULATION (aucune modification de l''AD)' } else { 'APPLICATION' })"
}

function Update-AuditState {
    $script:AuditState = Get-PagAuditState
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

function Save-FormConfig {
    # Enregistre config.json et whitelist.txt ; renvoie $false si la configuration est refusée
    $c = Get-FormConfig
    $problems = @(Test-PagConfig -Config $c)
    if ($problems.Count) {
        Show-Message -Text ("Configuration non enregistrée :`r`n- " + ($problems -join "`r`n- ")) -Icon Warning
        return $false
    }
    if ($c.QuarantineOU) {
        try { [void](Get-ADObject -Identity $c.QuarantineOU -Server (Get-PagDomainFromDN -DistinguishedName $c.QuarantineOU)) }
        catch {
            Show-Message -Text "OU de quarantaine introuvable dans l'AD :`r`n$($c.QuarantineOU)`r`n`r`nConfiguration non enregistrée." -Icon Warning
            return $false
        }
    }

    Save-PagConfig -Config $c
    Save-PagWhitelist -Name @($lstWhite.Items | ForEach-Object { [string]$_ })
    $script:SecretProtected = $c.Mail.SecretProtected
    Update-SecretState
    $true
}

#endregion

#region Fenêtre

$form = New-Object Windows.Forms.Form
$form.Text = 'PrivAdminGuard - Configuration'
$form.ClientSize = New-Object Drawing.Size(740, 560)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.Font = New-Object Drawing.Font('Segoe UI', 9)

$tabs = Add-Control -Parent $form -Type TabControl -X 10 -Y 10 -Width 720 -Height 500
$tabRules  = New-Object Windows.Forms.TabPage; $tabRules.Text  = 'Règles'
$tabWhite  = New-Object Windows.Forms.TabPage; $tabWhite.Text  = 'Liste blanche'
$tabMail   = New-Object Windows.Forms.TabPage; $tabMail.Text   = 'Notification'
$tabMsg    = New-Object Windows.Forms.TabPage; $tabMsg.Text    = 'Message du mail'
$tabDeploy = New-Object Windows.Forms.TabPage; $tabDeploy.Text = 'Déploiement'
$tabs.TabPages.AddRange(@($tabRules, $tabWhite, $tabMail, $tabMsg, $tabDeploy))

#endregion

#region Onglet Règles

[void](Add-Control -Parent $tabRules -Type Label -X 10 -Y 12 -Width 690 -Text 'Pattern que doivent respecter les comptes à privilèges (expression régulière sur le sAMAccountName, insensible à la casse) :')
$txtPattern = Add-Control -Parent $tabRules -Type TextBox -X 10 -Y 34 -Width 690 -Text $cfg.Pattern
$txtPattern.Font = New-Object Drawing.Font('Consolas', 10)

[void](Add-Control -Parent $tabRules -Type Label -X 10 -Y 70 -Width 100 -Text 'Tester un nom :')
$txtTest = Add-Control -Parent $tabRules -Type TextBox -X 110 -Y 67 -Width 200
$lblTest = Add-Control -Parent $tabRules -Type Label -X 320 -Y 70 -Width 380

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
$txtTest.Add_TextChanged($updateTest)

[void](Add-Control -Parent $tabRules -Type Label -X 10 -Y 105 -Width 690 -Text 'Groupes surveillés :')
$script:GroupChecks = [ordered]@{}
$y = 127
foreach ($k in $groupDefs.Keys) {
    $chk = Add-Control -Parent $tabRules -Type CheckBox -X 20 -Y $y -Width 500 -Text $groupDefs[$k].Label
    $chk.Checked = @($cfg.Groups) -contains $k
    $script:GroupChecks[$k] = $chk
    $y += 24
}

[void](Add-Control -Parent $tabRules -Type Label -X 10 -Y 205 -Width 690 -Text 'OU de quarantaine (destination des comptes désactivés) :')
$cmbQuar = Add-Control -Parent $tabRules -Type ComboBox -X 10 -Y 227 -Width 690 -Text $cfg.QuarantineOU
$cmbQuar.Items.AddRange([object[]]$containers)
$cmbQuar.AutoCompleteMode = 'SuggestAppend'
$cmbQuar.AutoCompleteSource = 'ListItems'

$chkSim = Add-Control -Parent $tabRules -Type CheckBox -X 10 -Y 268 -Width 690 -Text 'Mode simulation : signaler par mail sans rien modifier dans l''AD (recommandé pour démarrer)'
$chkSim.Checked = [bool]$cfg.SimulationMode

$lblScope = Add-Control -Parent $tabRules -Type Label -X 10 -Y 305 -Width 690 -Height 40 -Text (
    "Le contrôle porte sur tout le domaine, quel que soit l'emplacement du compte : les exceptions passent " +
    "uniquement par le pattern et la liste blanche.")
$lblScope.ForeColor = 'DimGray'

#endregion

#region Onglet Liste blanche

# Libellé sur deux lignes : le chemin du fichier peut être long
[void](Add-Control -Parent $tabWhite -Type Label -X 10 -Y 8 -Width 690 -Height 36 -Text "Comptes exclus du contrôle (sAMAccountName), enregistrés dans :`r`n$(Get-PagWhitelistPath)")
$lstWhite = Add-Control -Parent $tabWhite -Type ListBox -X 10 -Y 48 -Width 570 -Height 326
$lstWhite.Sorted = $true
$lstWhite.SelectionMode = 'MultiExtended'
foreach ($n in @(Get-PagWhitelist)) { [void]$lstWhite.Items.Add($n) }

$btnWhiteRemove = Add-Control -Parent $tabWhite -Type Button -X 590 -Y 48 -Width 110 -Text 'Retirer'
$btnImport = Add-Control -Parent $tabWhite -Type Button -X 590 -Y 80 -Width 110 -Height 60 -Text 'Importer les membres actuels'

$txtWhite = Add-Control -Parent $tabWhite -Type TextBox -X 10 -Y 385 -Width 570
$btnWhiteAdd = Add-Control -Parent $tabWhite -Type Button -X 590 -Y 384 -Width 110 -Text 'Ajouter'

$lblWhiteHint = Add-Control -Parent $tabWhite -Type Label -X 10 -Y 415 -Width 690 -Height 55 -Text ("Importez les membres actuels (groupes imbriqués compris) avant d'activer la tâche : un compte hors pattern absent " +
    "de cette liste serait mis en quarantaine. Un groupe de la liste peut rester imbriqué, mais ses membres sont contrôlés un par un. " +
    "Le contrôle refuse de tourner tant que whitelist.txt n'existe pas.")
$lblWhiteHint.ForeColor = 'DimGray'

$btnWhiteAdd.Add_Click({
    $n = $txtWhite.Text.Trim()
    if (-not $n -or @($lstWhite.Items) -contains $n) { return }
    $found = @(Get-ADObject -LDAPFilter "(sAMAccountName=$($n -replace '([\\*()])', '\$1'))")
    if (-not $found.Count -and -not (Confirm-Action -Text "Aucun objet « $n » trouvé dans le domaine. L'ajouter quand même ?")) { return }
    [void]$lstWhite.Items.Add($n)
    $txtWhite.Clear()
})
$txtWhite.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') { $btnWhiteAdd.PerformClick(); $_.SuppressKeyPress = $true } })

$btnWhiteRemove.Add_Click({
    foreach ($item in @($lstWhite.SelectedItems)) { $lstWhite.Items.Remove($item) }
})

$btnImport.Add_Click({
    $keys = @(Get-SelectedGroupKey)
    if (-not $keys.Count) { Show-Message -Text "Cochez au moins un groupe dans l'onglet Règles." -Icon Warning; return }
    try {
        $form.Cursor = 'WaitCursor'
        $added = @()
        # Membres directs et imbriqués : les groupes imbriqués sont ajoutés aussi, pour autoriser l'imbrication
        foreach ($gi in @(Get-PagGroup -Key $keys)) {
            foreach ($e in @(Get-PagEffectiveMember -GroupInfo $gi)) {
                $n = $e.Member.SamAccountName
                if ($n -and @($lstWhite.Items) -notcontains $n) {
                    [void]$lstWhite.Items.Add($n)
                    $added += "$n  (via $($e.Path))"
                }
            }
        }
        $msg = if ($added.Count) { "$($added.Count) compte(s) ajouté(s) :`r`n" + ($added -join "`r`n") } else { 'Tous les membres actuels sont déjà dans la liste.' }
        Show-Message -Text "$msg`r`n`r`nCliquez sur Enregistrer pour écrire whitelist.txt."
    }
    catch { Show-Message -Text "Import impossible : $($_.Exception.Message)" -Icon Error }
    finally { $form.Cursor = 'Default' }
})

#endregion

#region Onglet Notification

$y = 15
$fields = [ordered]@{ Tenant = 'ID de locataire (tenant)'; Client = "ID d'application (client)"; Secret = 'Secret client'; From = 'Boîte expéditrice'; To = 'Destinataires (séparés par ;)' }
$mailBoxes = @{}
foreach ($k in $fields.Keys) {
    [void](Add-Control -Parent $tabMail -Type Label -X 10 -Y ($y + 3) -Width 180 -Text $fields[$k])
    $mailBoxes[$k] = Add-Control -Parent $tabMail -Type TextBox -X 195 -Y $y -Width 505
    $y += if ($k -eq 'Secret') { 55 } else { 35 }
}
$txtTenant = $mailBoxes['Tenant']; $txtTenant.Text = $cfg.Mail.TenantId
$txtClient = $mailBoxes['Client']; $txtClient.Text = $cfg.Mail.ClientId
$txtSecret = $mailBoxes['Secret']; $txtSecret.UseSystemPasswordChar = $true
# Les points factices sont sélectionnés à l'entrée dans le champ : la saisie les remplace d'un coup
$txtSecret.Add_Enter({ if ($txtSecret.Text -eq $script:SecretMask) { $txtSecret.SelectAll() } })
$txtSecret.Add_MouseUp({ if ($txtSecret.Text -eq $script:SecretMask) { $txtSecret.SelectAll() } })
$txtFrom   = $mailBoxes['From'];   $txtFrom.Text = $cfg.Mail.From
$txtTo     = $mailBoxes['To'];     $txtTo.Text = $cfg.Mail.To

$lblSecret = Add-Control -Parent $tabMail -Type Label -X 195 -Y 110 -Width 505
$lblSecret.ForeColor = 'DimGray'
Update-SecretState

$lblMailHint = Add-Control -Parent $tabMail -Type Label -X 10 -Y 210 -Width 690 -Height 95 -Text (
    "L'application Entra ID doit avoir la permission Microsoft Graph Mail.Send de type Application, avec consentement administrateur. " +
    "Limitez-la à la boîte expéditrice (RBAC for Applications d'Exchange Online), sinon elle peut écrire au nom de n'importe quelle boîte.`r`n`r`n" +
    "Le secret est chiffré avec DPAPI pour CETTE machine : enregistrez la configuration sur chaque contrôleur de domaine où la tâche tourne.")
$lblMailHint.ForeColor = 'DimGray'

$btnTestMail = Add-Control -Parent $tabMail -Type Button -X 10 -Y 315 -Width 220 -Height 28 -Text 'Envoyer un mail de test'
$btnTestMail.Add_Click({
    try {
        $form.Cursor = 'WaitCursor'
        $c = Get-FormConfig
        # Le message de sensibilisation est inclus : le test sert aussi d'aperçu
        Send-PagMail -Config $c -Subject '[PrivAdminGuard] Mail de test' -HtmlBody ((ConvertTo-PagMailBanner -Message $c.MailMessage) +
            ("<p>Mail de test envoyé depuis <b>$env:COMPUTERNAME</b> le {0:dd/MM/yyyy à HH:mm}.</p>" -f (Get-Date)))
        Show-Message -Text "Mail envoyé à $($c.Mail.To)."
    }
    catch { Show-Message -Text "Échec de l'envoi : $($_.Exception.Message)" -Icon Error }
    finally { $form.Cursor = 'Default' }
})

#endregion

#region Onglet Message du mail

# Modèles du module + « Aucun message » ; « Personnalisé » désigne un texte qui ne correspond à aucun modèle.
# Le modèle affiché n'est pas enregistré : il est retrouvé en comparant le message de config.json aux modèles.
$templates = [ordered]@{}
foreach ($k in (Get-PagMailTemplate).Keys) { $templates[$k] = (Get-PagMailTemplate)[$k] }
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

[void](Add-Control -Parent $tabMsg -Type Label -X 10 -Y 12 -Width 690 -Text "Message de sensibilisation affiché en tête du mail d'alerte, au-dessus de la liste des comptes :")

[void](Add-Control -Parent $tabMsg -Type Label -X 10 -Y 43 -Width 130 -Text 'Modèle :')
$cmbTemplate = Add-Control -Parent $tabMsg -Type ComboBox -X 140 -Y 40 -Width 300
$cmbTemplate.DropDownStyle = 'DropDownList'
$cmbTemplate.Items.AddRange([object[]]@(@($templates.Keys) + $customLabel))

$txtMessage = Add-Control -Parent $tabMsg -Type TextBox -X 10 -Y 75 -Width 690 -Height 270
$txtMessage.Multiline = $true
$txtMessage.AcceptsReturn = $true
$txtMessage.WordWrap = $true
$txtMessage.ScrollBars = 'Vertical'
$script:TemplateSync = $true
$txtMessage.Text = ([string]$cfg.MailMessage -replace "`r", '') -replace "`n", "`r`n"
$script:TemplateSync = $false
Set-TemplateSelection -Name (Get-MessageTemplateName -Text $txtMessage.Text)

$lblMsgHint = Add-Control -Parent $tabMsg -Type Label -X 10 -Y 355 -Width 690 -Height 105 -Text (
    "Laissez vide pour ne pas afficher de message. Le texte est envoyé tel quel, sans mise en forme ; les sauts de ligne sont conservés.`r`n" +
    "En mode simulation, le mail précise en plus qu'aucune modification n'a été faite : évitez d'y affirmer que les comptes ont été désactivés " +
    "si vous testez longtemps en simulation.`r`n" +
    "Le mail de test (onglet Notification) inclut ce message : il sert d'aperçu.")
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

#region Onglet Déploiement

$lblDeploy = Add-Control -Parent $tabDeploy -Type Label -X 10 -Y 8 -Width 690 -Height 72
Update-TaskState

$btnInstall   = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 85 -Width 330 -Height 28 -Text 'Installer / mettre à jour la tâche planifiée'
$btnUninstall = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 120 -Width 330 -Height 28 -Text 'Supprimer la tâche planifiée'
$btnRunTest   = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 155 -Width 330 -Height 28 -Text 'Contrôler maintenant sans rien modifier (-WhatIf)'
$btnRunTask   = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 190 -Width 330 -Height 28 -Text 'Exécuter la tâche maintenant (en SYSTEM)'
$btnLogs      = Add-Control -Parent $tabDeploy -Type Button -X 10 -Y 225 -Width 330 -Height 28 -Text 'Ouvrir le dossier des journaux'

$lblAudit = Add-Control -Parent $tabDeploy -Type Label -X 355 -Y 85 -Width 345 -Height 150
$btnAudit = Add-Control -Parent $tabDeploy -Type Button -X 355 -Y 240 -Width 200 -Height 28 -Text "Revérifier l'audit"
Update-AuditState

$lblDeployHint = Add-Control -Parent $tabDeploy -Type Label -X 10 -Y 285 -Width 690 -Height 180 -Text (
    "La tâche s'exécute en SYSTEM sur ce contrôleur de domaine :`r`n" +
    "  - à chaque événement 4728 ou 4756 (ajout à un groupe global ou universel) du journal Sécurité de ce DC ;`r`n" +
    "  - toutes les heures, pour rattraper un ajout fait sur un autre DC ou pendant un arrêt.`r`n`r`n" +
    "Installez-la sur chaque contrôleur de domaine : l'événement n'est journalisé que sur le DC qui a traité l'ajout.`r`n`r`n" +
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
    # Choix explicite du mode à l'installation : la tâche lit config.json à chaque exécution
    $mode = Select-InstallMode
    if (-not $mode) { return }
    $chkSim.Checked = ($mode -eq 'Simulation')
    if (-not $chkSim.Checked -and -not (Confirm-Action -Text 'Confirmer le mode APPLICATION : les comptes hors pattern et hors liste blanche seront mis en quarantaine automatiquement ?')) { return }
    if (-not (Save-FormConfig)) { return }
    try {
        Register-PagTask -Confirm:$false
        Update-TaskState
        Show-Message -Text ("Tâche planifiée installée en mode $(if ($chkSim.Checked) { 'simulation' } else { 'application' }).`r`n" +
            "Pour la tester en SYSTEM : bouton « Exécuter la tâche maintenant », ou ajoutez un compte de test à un groupe surveillé.")
    }
    catch { Show-Message -Text "Installation impossible : $($_.Exception.Message)" -Icon Error }
})

$btnUninstall.Add_Click({
    if (-not $isAdmin) { Show-Message -Text 'Relancez le configurateur en tant qu''administrateur.' -Icon Warning; return }
    if ((Get-PagTaskState) -eq 'non installée') { Show-Message -Text 'La tâche n''est pas installée.'; return }
    if (-not (Confirm-Action -Text 'Supprimer la tâche planifiée ? Le contrôle ne sera plus effectué sur ce serveur.')) { return }
    try { Unregister-PagTask -Confirm:$false; Update-TaskState }
    catch { Show-Message -Text "Suppression impossible : $($_.Exception.Message)" -Icon Error }
})

$btnRunTest.Add_Click({
    if (-not (Save-FormConfig)) { return }
    $main = Join-Path (Get-PagRoot) 'Invoke-PrivAdminGuard.ps1'
    $arguments = "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$main`" -WhatIf"
    # Lecture du journal Sécurité : nécessite une console élevée
    if ($isAdmin) { Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments }
    else { Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs }
})

$btnRunTask.Add_Click({
    if (-not $isAdmin) { Show-Message -Text 'Relancez le configurateur en tant qu''administrateur.' -Icon Warning; return }
    if ((Get-PagTaskState) -eq 'non installée') { Show-Message -Text 'Installez d''abord la tâche planifiée.' -Icon Warning; return }
    try {
        Start-ScheduledTask -TaskName (Get-PagTaskName)
        Update-TaskState
        Show-Message -Text ("Tâche lancée en SYSTEM, dans le mode enregistré dans config.json.`r`n" +
            "Le résultat est dans le journal du jour (bouton « Ouvrir le dossier des journaux ») et, s'il y a un compte hors pattern et hors liste blanche, dans le mail.")
    }
    catch { Show-Message -Text "Lancement impossible : $($_.Exception.Message)" -Icon Error }
})

$btnAudit.Add_Click({ Update-AuditState })

$btnLogs.Add_Click({
    $logs = Join-Path (Get-PagRoot) 'logs'
    New-Item -ItemType Directory -Path $logs -Force | Out-Null
    Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$logs`""
})

#endregion

#region Boutons du bas

$btnSave  = Add-Control -Parent $form -Type Button -X 520 -Y 522 -Width 100 -Height 28 -Text 'Enregistrer'
$btnClose = Add-Control -Parent $form -Type Button -X 630 -Y 522 -Width 100 -Height 28 -Text 'Fermer'
$btnSave.Add_Click({
    if (Save-FormConfig) { Show-Message -Text 'Configuration et liste blanche enregistrées.' }
})
$btnClose.Add_Click({ $form.Close() })
$form.CancelButton = $btnClose

if (-not $isAdmin) {
    $form.Add_Shown({ Show-Message -Text "Console non élevée : l'installation de la tâche et le contrôle immédiat demanderont une élévation." -Icon Warning })
}

#endregion

[void]$form.ShowDialog()
$form.Dispose()
