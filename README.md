# 🛡️ PowerShell HIDS (Office 365)

## Description
Ce script PowerShell implémente un **Host-based Intrusion Detection System (HIDS)** capable de :
- Surveiller l’intégrité de fichiers via leur empreinte **SHA256**.
- Vérifier la **connectivité réseau (Ping)** d’adresses IP spécifiques.
- Envoyer des **alertes par email via Office 365** lorsqu’un fichier est modifié/supprimé ou lorsqu’un hôte devient injoignable.

---

## ⚙️ Fonctionnalités principales
- Calcul automatique de la somme SHA256 des fichiers à surveiller.  
- Détection de modification ou suppression de fichiers.  
- Vérification de la disponibilité des IP configurées (ping).  
- Envoi automatique d’emails d’alerte via SMTP Office 365.  
- Interface console interactive avec menu.  
- Arrêt du monitoring par touche **ESC**.

---

## 🧩 Prérequis
- **Windows 10/11** ou **Windows Server** avec PowerShell 5.1 ou supérieur.  
- **Compte Office 365** avec SMTP activé.  
- Autorisation d’exécuter des scripts PowerShell :
  ```powershell
  Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

##Lancer le script

- cd "C:\chemin\vers\ton\script"
- .\SimpleHIDS.ps1
 
