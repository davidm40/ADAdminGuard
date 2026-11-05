# PrivAdminGuard

Garde-fou pour les groupes à privilèges d'Active Directory. Dès qu'un compte est ajouté aux groupes
**Admins du domaine**, **Administrateurs de l'entreprise** ou **Administrateurs du schéma**, directement ou par un
groupe imbriqué, PrivAdminGuard vérifie qu'il respecte la convention de nommage des comptes d'administration
ou qu'il figure dans une liste blanche. Sinon, il le met en quarantaine et prévient par mail.

Le contrôle tourne sur chaque contrôleur de domaine, en tâche planifiée SYSTEM, déclenchée par les événements
de sécurité 4728 / 4756 et rejouée toutes les heures. Un configurateur graphique (WinForms) règle l'ensemble.

> **Ce que PrivAdminGuard est, et n'est pas.** C'est un contrôle de conformité et un détecteur rapide : il fait
> respecter la convention de nommage et signale tout ajout non prévu. Ce n'est pas une barrière contre un
> attaquant déjà administrateur du domaine, qui peut désactiver la tâche ou nommer son compte selon le pattern.
> Il complète le modèle d'administration en tiers, la délégation restreinte et une supervision (SIEM, Defender
> for Identity), sans les remplacer.

---

## Sommaire

- [Fonctionnement](#fonctionnement)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
- [Application Entra ID pour l'envoi des mails](#application-entra-id-pour-lenvoi-des-mails)
- [Mise en service conseillée](#mise-en-service-conseillée)
- [Journalisation](#journalisation)
- [Exécution manuelle](#exécution-manuelle)
- [Sécurité](#sécurité)
- [Limites connues](#limites-connues)
- [Dépannage](#dépannage)
- [Fichiers](#fichiers)

---

## Fonctionnement

### Déclenchement

La tâche planifiée `PrivAdminGuard` s'exécute en **SYSTEM** sur chaque contrôleur de domaine :

| Déclencheur | Rôle |
|---|---|
| Événement **4728** du journal Sécurité | Ajout d'un membre à un groupe de sécurité **global** (ex. Admins du domaine) |
| Événement **4756** du journal Sécurité | Ajout d'un membre à un groupe de sécurité **universel** (ex. Administrateurs de l'entreprise, du schéma) |
| **Toutes les heures** | Rattrapage : ajout traité par un autre DC, DC arrêté, événement manqué |

Tout ajout à un groupe global ou universel déclenche le contrôle, y compris l'ajout à un groupe imbriqué dans un
groupe surveillé.

### Règles

Les groupes surveillés sont identifiés par leur **SID** (RID 512, 519 et 518), pas par leur nom : le contrôle
fonctionne quelle que soit la langue de l'Active Directory.

Chaque groupe surveillé est parcouru **avec ses groupes imbriqués, à tous les niveaux**. Un compte, direct ou
indirect, est ignoré s'il :

- figure dans la **liste blanche** (`whitelist.txt`) ;
- respecte le **pattern** (expression régulière sur le `sAMAccountName`, insensible à la casse) ;
- est l'**Administrateur intégré** (RID 500).

Le contrôle porte sur **tout le domaine**, quel que soit l'emplacement du compte : les seules exceptions sont le
pattern et la liste blanche.

Un **groupe imbriqué** présent dans la liste blanche est autorisé à rester imbriqué, mais **ses membres sont
contrôlés un par un**. Absent de la liste, il est signalé dans le mail ; ses membres sont contrôlés de toute
façon.

### Actions sur un compte non conforme

Pour un compte utilisateur hors pattern **et** hors liste blanche :

1. **Retrait du groupe qui le contient directement** : le groupe surveillé, ou le groupe imbriqué par lequel il
   obtient ses droits (le retirer du seul groupe surveillé ne servirait à rien) ;
2. **Désactivation** du compte ;
3. **Description horodatée** : `[PrivAdminGuard AAAA-MM-JJ HH:mm] Quarantaine : …`, l'ancienne description
   est conservée à la suite ;
4. **Déplacement** dans l'OU de quarantaine.

Les ordinateurs, comptes de service gérés (gMSA), groupes et objets non résolus ne sont jamais modifiés :
ils sont seulement signalés.

### Modes

| Mode | Effet |
|---|---|
| **Simulation** (par défaut) | Détection et mail, **aucune modification de l'AD**. Le mail et le journal détaillent chaque action qui aurait été faite. |
| **Application** | Les actions ci-dessus sont appliquées. |

Le mode est enregistré dans `config.json` et relu à chaque exécution de la tâche.

### Auteur de l'ajout

Le mail indique qui a fait l'ajout et quand :

1. l'événement 4728 / 4756 correspondant est recherché dans le journal Sécurité du DC qui exécute le contrôle ;
2. à défaut, la **date et le DC d'origine** de l'ajout sont lus dans les métadonnées de réplication de l'attribut
   `member`, puis l'événement est recherché dans le journal Sécurité de ce DC d'origine.

Si le journal d'un autre DC n'est pas lisible (cas de SYSTEM, voir [Limites](#limites-connues)), le mail donne au
moins la date et le DC à consulter.

### Mail d'alerte

Un mail récapitulatif est envoyé via **Microsoft Graph** à chaque exécution qui trouve au moins un compte non
conforme. Il contient :

- un **message de sensibilisation** personnalisable, encadré en tête ;
- pour chaque compte : nom, DN, **chemin d'appartenance** (ex. `Administrateurs de l'entreprise > G-Tier0-Admins > jdupont`),
  auteur et date de l'ajout, actions faites ou prévues.

**Le pattern n'apparaît jamais dans le mail** : il ne doit pas circuler hors des contrôleurs de domaine.

---

## Prérequis

| Élément | Exigence |
|---|---|
| Système | Contrôleur de domaine Windows Server 2016 ou plus récent |
| PowerShell | Windows PowerShell 5.1 |
| Module | `ActiveDirectory` (présent sur un DC) |
| Droits | Administrateur du DC pour installer la tâche ; la tâche tourne ensuite en SYSTEM |
| Audit | **Auditer la gestion des groupes de sécurité : Succès** (stratégie d'audit avancée) |
| Mail | Une application Entra ID avec la permission Graph **Mail.Send** (application) et une boîte expéditrice |
| Réseau | Accès HTTPS sortant du DC vers `login.microsoftonline.com` et `graph.microsoft.com` |

### Activer l'audit

Par GPO liée à l'OU **Domain Controllers** :

`Configuration ordinateur > Stratégies > Paramètres Windows > Paramètres de sécurité > Configuration avancée de la
stratégie d'audit > Gestion des comptes > Auditer la gestion des groupes de sécurité` : **Succès**.

Sans cet audit, la tâche ne réagit qu'au contrôle horaire et l'auteur de l'ajout reste inconnu. L'onglet
**Déploiement** du configurateur affiche l'état effectif de l'audit sur le DC.

---

## Installation

1. Copier le dossier sur **chaque contrôleur de domaine**, par exemple dans `C:\Scripts\PrivAdminGuard`.
2. Lancer **`Configurer-PrivAdminGuard.bat`** : il demande l'élévation si nécessaire, puis ouvre le configurateur.
3. Renseigner les onglets (voir [Configuration](#configuration)), puis cliquer sur **Enregistrer**.
4. Onglet **Déploiement** > **Installer / mettre à jour la tâche planifiée**, puis choisir **Simulation** ou
   **Application**.

L'installation :

- crée ou met à jour la tâche planifiée `PrivAdminGuard` ;
- crée la source d'événements `PrivAdminGuard` dans le journal Application ;
- **restreint les droits du dossier à SYSTEM et Administrateurs** (voir [Sécurité](#sécurité)).

La configuration est **propre à chaque DC** : le secret client est chiffré pour la machine (DPAPI). Il faut donc
ouvrir le configurateur et enregistrer sur chaque DC, ou y ressaisir le secret après copie de `config.json`.

---

## Configuration

Le configurateur `Show-PrivAdminGuardConfig.ps1` (lancé par le `.bat`) comporte cinq onglets.

### Règles

| Champ | Description |
|---|---|
| **Pattern** | Expression régulière que doit respecter le `sAMAccountName` des comptes à privilèges, ex. `^adm-t0-`. Un champ de test indique si un nom serait conforme. |
| **Groupes surveillés** | Admins du domaine, Administrateurs de l'entreprise, Administrateurs du schéma. |
| **OU de quarantaine** | Destination des comptes désactivés. Obligatoire en mode application ; son existence est vérifiée à l'enregistrement. |
| **Mode simulation** | Coché : aucune modification de l'AD. |

### Liste blanche

Comptes et groupes exclus du contrôle, un `sAMAccountName` par ligne, enregistrés dans `whitelist.txt`.

**Importer les membres actuels** ajoute tous les membres, directs et imbriqués, des groupes cochés. À faire
**avant toute mise en service** : un compte existant hors pattern et absent de la liste serait mis en quarantaine.
Par sécurité, le contrôle **refuse de s'exécuter tant que `whitelist.txt` n'existe pas**.

### Notification

| Champ | Description |
|---|---|
| **ID de locataire** | GUID du locataire Entra ID, ou son nom de domaine. |
| **ID d'application (client)** | GUID de l'application (page *Vue d'ensemble*). |
| **Secret client** | *Valeur* du secret (pas son ID). Affiché en points une fois enregistré ; saisir une nouvelle valeur pour le remplacer. |
| **Boîte expéditrice** | Adresse de la boîte qui envoie les alertes. |
| **Destinataires** | Adresses séparées par `;`. |

**Envoyer un mail de test** envoie un mail avec le message de sensibilisation, pour aperçu. En cas d'échec, le
message affiche le motif renvoyé par Entra ID ou Graph (`AADSTS…`, permission manquante, boîte introuvable…).

### Message du mail

Texte de sensibilisation affiché en tête du mail d'alerte. Quatre modèles sont proposés : *Rappel de la
politique* (par défaut), *Sensibilisation*, *Alerte sécurité* et *Court*. Choisir un modèle remplace le texte
aussitôt ; *Aucun message* supprime l'encadré ; toute modification à la main fait passer la liste sur
*Personnalisé*. À la réouverture, l'option correspondant au texte enregistré est présélectionnée.

Les modèles affirment que les comptes « ont été désactivés » : en simulation prolongée, adapter le texte (le mail
précise de toute façon qu'aucune modification n'a été faite).

### Déploiement

| Bouton | Effet |
|---|---|
| **Installer / mettre à jour la tâche planifiée** | Enregistre la configuration, demande le mode (Simulation / Application), installe la tâche. |
| **Supprimer la tâche planifiée** | Désinstalle la tâche sur ce DC. |
| **Contrôler maintenant sans rien modifier (-WhatIf)** | Lance le contrôle dans une console, avec le compte courant. Le mail est envoyé s'il y a un compte non conforme. |
| **Exécuter la tâche maintenant (en SYSTEM)** | Lance la vraie tâche planifiée : test le plus fidèle d'un déclenchement automatique. |
| **Ouvrir le dossier des journaux** | Ouvre `logs\`. |
| **Revérifier l'audit** | Relit l'état effectif de l'audit « Gestion des groupes de sécurité ». |

L'onglet affiche aussi l'état de la tâche, le mode enregistré et l'état de l'audit.

### Fichier `config.json`

```json
{
  "Pattern": "^adm-t0-",
  "Groups": ["DomainAdmins", "EnterpriseAdmins", "SchemaAdmins"],
  "QuarantineOU": "OU=Quarantaine,OU=Administration,DC=contoso,DC=local",
  "SimulationMode": true,
  "MailMessage": "Les comptes ci-dessous …",
  "Mail": {
    "TenantId": "00000000-0000-0000-0000-000000000000",
    "ClientId": "00000000-0000-0000-0000-000000000000",
    "SecretProtected": "<secret chiffré DPAPI, propre à la machine>",
    "From": "alertes-ad@contoso.com",
    "To": "secops@contoso.com;admin@contoso.com"
  }
}
```

---

## Application Entra ID pour l'envoi des mails

1. **Entra ID > Inscriptions d'applications > Nouvelle inscription** (compte unique du locataire, sans URI de redirection).
2. **Autorisations de l'API > Ajouter > Microsoft Graph > Autorisations d'application > `Mail.Send`**, puis
   **Accorder le consentement administrateur**.
3. **Certificats et secrets > Nouveau secret client** : copier la **Valeur** (affichée une seule fois).
4. **Restreindre l'application à la boîte expéditrice.** Sans restriction, `Mail.Send` permet d'envoyer au nom de
   n'importe quelle boîte du locataire. Avec Exchange Online (RBAC for Applications) :

```powershell
Connect-ExchangeOnline
New-ServicePrincipal -AppId <ID d'application> -ObjectId <ID d'objet de l'application d'entreprise> -DisplayName 'PrivAdminGuard'
New-ManagementScope -Name 'PrivAdminGuard-Expediteur' -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'alertes-ad@contoso.com'"
New-ManagementRoleAssignment -App <ID d'application> -Role 'Application Mail.Send' -CustomResourceScope 'PrivAdminGuard-Expediteur'
```

Retirer ensuite la permission `Mail.Send` accordée à l'étape 2 dans Entra ID : c'est l'attribution Exchange qui
fait foi, limitée à la boîte expéditrice.

Penser à **renouveler le secret avant son expiration** : un secret expiré fait échouer l'envoi, ce qui est consigné
dans le journal du script et dans le journal Application (ID 1002).

---

## Mise en service conseillée

1. Activer l'audit sur les DC et vérifier qu'il apparaît en vert dans l'onglet **Déploiement**.
2. Sur chaque DC : configurer, **importer les membres actuels** dans la liste blanche, enregistrer.
3. **Envoyer un mail de test.**
4. Installer la tâche en **Simulation**.
5. Ajouter un compte de test hors pattern à *Admins du domaine* : vérifier le mail (chemin d'appartenance,
   auteur, actions prévues) et le journal.
6. Laisser tourner quelques jours en simulation pour repérer les comptes légitimes oubliés.
7. Réinstaller la tâche en **Application**.

---

## Journalisation

| Emplacement | Contenu |
|---|---|
| `logs\PrivAdminGuard_AAAAMMJJ.log` | Un fichier par jour, purgé après 90 jours : configuration lue, état de l'audit, nombre d'événements lus, comptes non conformes, actions, envoi du mail, erreurs. |
| Journal **Application**, source `PrivAdminGuard` | Pour la supervision (SIEM) : |
| — ID **1000** (Avertissement) | Compte mis en quarantaine |
| — ID **1001** (Avertissement) | Compte non conforme détecté sans action (simulation, `-WhatIf`, objet autre qu'un utilisateur) |
| — ID **1002** (Erreur) | Erreur du contrôle ou échec de l'envoi du mail |

Le pattern figure dans le journal du script (dossier réservé à SYSTEM et Administrateurs), jamais dans le mail ni
dans le journal Application.

---

## Exécution manuelle

```powershell
# Contrôle sans rien modifier : affiche les actions prévues et envoie le mail
.\Invoke-PrivAdminGuard.ps1 -WhatIf

# Fenêtre de recherche des événements 4728/4756 (minutes, 120 par défaut) et dossier de journaux
.\Invoke-PrivAdminGuard.ps1 -EventLookbackMinutes 240 -LogDir D:\Logs\PrivAdminGuard
```

À lancer dans une console **élevée** : la lecture du journal Sécurité l'exige.

---

## Sécurité

- **Droits du dossier.** Le script s'exécute en SYSTEM sur un contrôleur de domaine : quiconque pourrait le
  modifier obtiendrait ces droits. L'installation retire l'héritage et limite le dossier à SYSTEM et Administrateurs.
  Ne pas placer le dossier sur un partage.
- **Secret client.** Chiffré avec DPAPI en portée machine : lisible uniquement sur le DC qui l'a enregistré, jamais
  stocké en clair, jamais affiché par le configurateur.
- **Pattern.** Absent du mail et du journal Application. Le connaître facilite le contournement du contrôle.
- **Liste blanche.** À tenir courte et à revoir régulièrement : chaque entrée est un compte qui échappe au contrôle.
- **Mode simulation par défaut**, et refus de fonctionner sans liste blanche : une mauvaise configuration ne peut
  pas mettre en quarantaine les administrateurs en place.

---

## Limites connues

- **Contournable par un administrateur du domaine** : il peut désactiver la tâche ou nommer son compte selon le
  pattern. Superviser les événements 4728 / 4756 et l'ID 1002 dans un SIEM.
- **Journal Sécurité des autres DC.** En SYSTEM, la tâche agit avec le compte ordinateur du DC, qui ne peut pas lire
  par défaut le journal Sécurité d'un autre DC. L'auteur est trouvé quand l'ajout a été traité par le DC qui exécute
  le contrôle, ce qui est le cas des déclenchements par événement. Pour un rattrapage horaire d'un ajout fait
  ailleurs, le mail indique la date et le DC à consulter.
- **Mails en double.** Le contrôle horaire tourne sur chaque DC : une anomalie qui persiste (mode simulation)
  peut être signalée par plusieurs DC.
- **Forêt multi-domaines.** Les groupes Administrateurs de l'entreprise et du schéma sont lus dans le domaine racine
  de la forêt ; le fonctionnement a été conçu et testé pour une forêt à domaine unique.
- **Domaine local.** Les ajouts à un groupe de domaine local (événement 4732, ex. *Administrateurs* intégré) ne
  sont pas surveillés.

---

## Dépannage

| Symptôme | Cause probable |
|---|---|
| `whitelist.txt absent` dans le journal | Importer les membres actuels dans l'onglet Liste blanche, puis Enregistrer. |
| « Ajouté par » inconnu | Audit inactif sur le DC, ajout traité par un autre DC, ou journal Sécurité illisible : le journal du script précise le cas (nombre d'événements lus, DC d'origine, SID vus). |
| `AADSTS7000215` / `invalid_client` | Secret erroné : saisir la *Valeur* du secret, pas son ID. |
| `AADSTS700016` | ID d'application erroné ou application d'un autre locataire. |
| `ErrorAccessDenied` à l'envoi | Permission `Mail.Send` absente, consentement non accordé, ou boîte expéditrice hors du périmètre RBAC. |
| `Secret illisible sur <DC>` | `config.json` copié depuis une autre machine : ressaisir le secret sur ce DC. |
| Audit « non vérifiable » | Configurateur lancé sans élévation : passer par `Configurer-PrivAdminGuard.bat`. |

---

## Fichiers

| Fichier | Rôle |
|---|---|
| `Configurer-PrivAdminGuard.bat` | Lanceur du configurateur, avec élévation automatique. |
| `Show-PrivAdminGuardConfig.ps1` | Configurateur graphique. |
| `Invoke-PrivAdminGuard.ps1` | Contrôle, exécuté par la tâche planifiée. |
| `PrivAdminGuard.psm1` | Fonctions communes : configuration, liste blanche, secret, Graph, AD, tâche planifiée. |
| `config.json` | Configuration, créée par le configurateur (non versionnée). |
| `whitelist.txt` | Liste blanche, créée par le configurateur (non versionnée). |
| `logs\` | Journaux quotidiens (non versionnés). |

Tous les scripts sont compatibles Windows PowerShell 5.1 et encodés en UTF-8 avec BOM.
