# **# Projet Ransomware En C**

&nbsp;

## **## Description**

&nbsp;

Ce projet est une démonstration éducative conçue pour illustrer le fonctionnement d'un ransomware, en mettant l'accent sur les techniques de chiffrement de fichiers, d'exfiltration de données, et de keylogger. Il comprend également une simulation d'interface de rançon. Ce projet vise à augmenter la sensibilisation à la sécurité informatique et à comprendre les mécanismes de défense contre de telles menaces. Il est impératif de ne jamais utiliser ce code à des fins malveillantes ou sans consentement explicite de toutes les parties impliquées.

&nbsp;

## **## Fonctionnalités**

&nbsp;

- ****Chiffrement récursif****: Parcourt récursivement un répertoire cible pour chiffrer tous les fichiers à l'aide de l'algorithme AES-256-CBC.

- ****Exfiltration de fichiers****: Envoie les fichiers à un serveur distant avant leur chiffrement pour simulation d'exfiltration de données.

- ****Keylogger****: Capture et exfiltre les frappes clavier vers un serveur.

- ****Notification de rançon****: Affiche une interface graphique informant l'utilisateur que ses fichiers ont été chiffrés et demande une rançon.

&nbsp;

## **## Composition du Projet**

&nbsp;

Le projet se compose de trois composants principaux :

1. **ransomware.c** - Le script de chiffrement qui inclut également le keylogger et l'interface de rançon.

2. **dechiffrage.c** - Le script de déchiffrement pour restaurer les fichiers chiffrés.

3. **serveur.c** - Un serveur simple pour simuler l'exfiltration de fichiers et de frappes clavier.

&nbsp;

## **## Prérequis**

&nbsp;

- Linux ou un système d'exploitation Windows pour l'exécution du serveur et des scripts.

- **OpenSSL** pour la cryptographie.

- **ncurses** pour le keylogger (uniquement nécessaire sous Unix/Linux).

&nbsp;

## **## Installation**

&nbsp;

1. Installez les dépendances nécessaires (sur un système basé sur Debian/Ubuntu) :

<span style="color: #e03e2d;">**sudo apt-get update**</span>

<span style="color: #e03e2d;">**sudo apt-get install libssl-dev libncurses5-dev libncursesw5-dev**</span>

&nbsp;

<span style="color: #0d0d0d;">Clonez le dépôt et naviguez dans le dossier du projet :</span>  
<br/>**git clone <URL_DU_PROJET>**

**cd <DOSSIER_DU_PROJET>  
<br/>**<span style="color: #0d0d0d;">Compilez les sources :  
</span>  
**gcc ransomware.c -o ransomware -lssl -lcrypto -lncurses**

**gcc dechiffrage.c -o dechiffrage -lssl -lcrypto**

**gcc serveur.c -o serveur**  
**  
<br/>**

### Utilisation

Pour exécuter le serveur d'exfiltration :**  
<br/>**<span style="color: #e03e2d;">./serveur**  
<br/>Pour chiffrer les fichiers :  
Assurez-vous que le serveur d'exfiltration est en cours d'exécution.**  
<br/>**<span style="color: #e03e2d;">./ransomware <chemin_vers_le_dossier_à_chiffrer></span>**  
<br/>Pour déchiffrer les fichiers :**  
<br/>**<span style="color: #e03e2d;">./dechiffrage <chemin_vers_le_dossier_à_déchiffrer>**

### Sécurité et Éthique

Il est essentiel de rappeler que ce projet a été développé à des fins éducatives dans un cadre légal et éthique. L'utilisation de ce code dans un environnement réel sans consentement constitue une violation de la loi et des principes éthiques de la communauté de la cybersécurité.

### **Contribution**

Les contributions à ce projet pour des améliorations éducatives et de sensibilisation à la sécurité sont les bienvenues. Pour toute proposition de modification ou d'ajout, veuillez ouvrir une issue ou un pull request.