# ⚡ Supnum-Bruteforce

> **Framework asynchrone multi-services d’analyse d’authentification, écrit en Rust**

---

## 🔍 Présentation

**Supnum-Bruteforce** est un outil avancé de recherche d’authentification développé en **Rust**, conçu pour analyser la robustesse des mécanismes de connexion sur de nombreux services réseau.

Il repose sur une architecture moderne et performante :
- moteur **asynchrone (Tokio)**,
- **détection automatique des services**,
- modules multi-protocoles,
- gestion fine de la concurrence,
- reprise intelligente après interruption.

Le projet s’inscrit dans une démarche **éducative, expérimentale et défensive** en cybersécurité.

---

## 🚀 Fonctionnalités clés

- 🔎 Détection réelle des services (banner grabbing)
- ⚡ Exécution asynchrone haute performance
- 🧵 Limitation du parallélisme par sémaphore
- 🔁 Reprise automatique via cache
- 🧠 Arrêt immédiat dès succès
- 🌐 Analyse dynamique des formulaires HTTP (GET / POST)
- 🧩 Architecture modulaire et extensible
- 🛡️ Timeouts et gestion des erreurs réseau

---

## 🌐 Services supportés

Supnum-Bruteforce intègre des modules dédiés pour :

- SSH  
- HTTP / HTTPS  
- FTP  
- SMTP  
- POP3  
- IMAP  
- MySQL  
- PostgreSQL  
- MongoDB  
- SMB  
- LDAP  
- Telnet  
- RDP  
- VNC  

Chaque service possède sa propre logique d’authentification, isolée et maintenable.

---

## 🧠 Approche technique

- Détection basée sur le **contenu réel du service**, pas uniquement le port
- Analyse automatique des champs HTML (`name`, `type`)
- Support des formulaires dynamiques
- Utilisation de bibliothèques réseau robustes
- Code Rust typé, sûr et structuré

L’objectif n’est pas la promesse de “puissance”, mais la **compréhension et la fiabilité**.

---

## 🎯 Objectifs du projet

- Étudier les mécanismes d’authentification
- Sensibiliser aux risques des mots de passe faibles
- Tester et renforcer des défenses existantes
- Servir de base pédagogique ou de laboratoire technique
- Approfondir la cybersécurité offensive de manière responsable

---

## ⚠️ Avertissement légal & éthique

> ❗ **Ce projet est strictement destiné à un usage éducatif et autorisé.**

Toute utilisation sur un système sans autorisation explicite est **illégale**.  
L’auteur et les contributeurs déclinent toute responsabilité en cas de mauvaise utilisation.

Utilise cet outil uniquement sur :
- tes propres systèmes,
- des environnements de test,
- des plateformes pour lesquelles tu as une autorisation claire.

---

## 🛠️ Philosophie du projet

> *Comprendre l’attaque pour mieux concevoir la défense.*

Supnum-Bruteforce est pensé comme un **outil d’apprentissage avancé**, pas comme un produit de contournement de sécurité.

---

## 📌 Auteur

- **Cheikh ELghadi**
- GitHub : https://github.com/23092-ctrl

---

## ⭐ Soutenir le projet

Si ce projet t’a aidé :
- laisse une ⭐ sur GitHub
- partage-le à des fins pédagogiques
- propose des améliorations ou des modules

Les contributions constructives sont les bienvenues.
