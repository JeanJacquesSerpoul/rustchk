# RustChk

[English](README.md) · **Français**

Vérifie le checksum d'un fichier téléchargé — et s'assure que le fichier de checksums lui-même est authentique.
Petite application de bureau écrite en Rust avec [Tauri 2](https://tauri.app) et [Leptos 0.8](https://leptos.dev).

[![CI](https://github.com/JeanJacquesSerpoul/rustchk/actions/workflows/ci.yml/badge.svg)](https://github.com/JeanJacquesSerpoul/rustchk/actions/workflows/ci.yml)
[![Licence : MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

## Fonctionnalités

- **MD5, SHA-1, SHA-256, SHA-384 et SHA-512** calculés en une seule lecture du fichier (en parallèle, avec barre de
  progression et bouton d'annulation — environ 3,8 s pour un fichier de 2 Go sur une machine récente).
- **Coller l'empreinte publiée** : l'algorithme est déduit de sa longueur. Formats acceptés : `hash`,
  `hash  fichier`, `sha256:hash`, `SHA256 (fichier) = hash` et la sortie de `certutil` (octets séparés par des espaces).
- **Préremplissage** : si un `fichier.sha256` (ou `.md5`, `.sha1`, `.sha512`…) ou un `SHA256SUMS` se trouve à côté
  du téléchargement, son empreinte est reprise automatiquement.
- **Authentification OpenPGP** de ce fichier de checksums (voir ci-dessous).
- **Signature Authenticode** des exécutables et installeurs (Windows) : qui l'a signé, et s'il a été modifié depuis.
- **Analyse antimalware en ligne** (sur option) : l'empreinte SHA-256 est recherchée sur MalwareBazaar et/ou VirusTotal.
- **Intégration à l'explorateur Windows** : entrée « Vérifier le checksum » dans le menu contextuel de tous les fichiers.
- **Glisser-déposer**, ou ouverture depuis la ligne de commande / le menu contextuel.
- **Mémorise la taille de la fenêtre** (et l'état agrandi) d'un lancement à l'autre.
- Interface en **français et en anglais**, changement à la volée.

## Authentifier le fichier de checksums (OpenPGP)

Un checksum protège d'un téléchargement corrompu, pas d'un fichier remplacé *avec* son checksum.
Quand l'empreinte vient d'un fichier de checksums, RustChk vérifie sa signature OpenPGP avec
[rPGP](https://crates.io/crates/pgp) (Rust pur, GnuPG n'est pas nécessaire) :

- signature détachée voisine : `SHA256SUMS.asc`, `.sig`, `.gpg`, `.sign` ou `.pgp` (binaire ou ASCII-armor) ;
- ou fichier signé en clair (`-----BEGIN PGP SIGNED MESSAGE-----`). Seul le texte à l'intérieur du bloc signé est
  lu ; du texte ajouté avant ou après la signature fait rejeter le fichier entier.

Résultats : **authentique** (signataire, identifiant de clé, date, empreinte de la clé à comparer à celle de
l'éditeur), **clé inconnue**, **signature refusée** (contenu modifié, clé révoquée) ou **aucune signature**.
Une signature refusée l'emporte toujours sur « fichier conforme ».

Seules les clés publiques importées dans le trousseau de l'application (`%APPDATA%\app.rustchk\keys`, section
« Trousseau OpenPGP ») font foi. Rien n'est téléchargé et aucune clé n'est lue dans le dossier du téléchargement :
obtenez la clé sur le site officiel de l'éditeur et comparez son empreinte avant de l'importer.

Limites : pas de toile de confiance ni de serveur de clés ; une clé expirée n'est signalée (avertissement) que si
elle avait déjà expiré à la date de signature.

## Signature de l'éditeur (Authenticode, Windows)

Un checksum et une signature OpenPGP prouvent que vous avez bien le fichier publié par l'éditeur, pas qu'il est
inoffensif. Pour les exécutables, installeurs et scripts (`.exe`, `.msi`, `.dll`, `.ps1`…), RustChk demande aussi
à Windows (`WinVerifyTrust`, comme l'explorateur) de vérifier la signature Authenticode intégrée :

- **signé par …** : signature valide d'une autorité reconnue par Windows, avec le signataire et l'émetteur du
  certificat. Vérifiez que c'est bien l'éditeur attendu ;
- **non signé** : rien n'atteste qui a publié le programme ;
- **refusée** : fichier modifié après signature, certificat révoqué, expiré sans horodatage, ou non délivré par une
  autorité de confiance.

La révocation des certificats est vérifiée : Windows peut donc contacter l'autorité de certification ; hors ligne,
c'est signalé. Limite : seules les signatures intégrées au fichier sont lues, si bien que les fichiers système
Windows signés par catalogue apparaissent non signés. La carte est masquée pour les autres types de fichiers et
sous macOS/Linux.

## Analyse antimalware en ligne (MalwareBazaar, VirusTotal)

Désactivée par défaut. Dans la section « Analyse en ligne », cochez la case et renseignez la clé d'au moins un
service :

- [MalwareBazaar](https://bazaar.abuse.ch) (abuse.ch) : base d'échantillons de malwares, très fournie en
  infostealers (Lumma, RedLine, Vidar…). Auth-Key gratuite sur [auth.abuse.ch](https://auth.abuse.ch).
- [VirusTotal](https://www.virustotal.com) : résultat de la dernière analyse par environ 70 antivirus. Clé
  personnelle gratuite dans votre compte (4 requêtes/minute, usage non commercial). Le fichier est jugé malveillant
  à partir de 3 détections ; en dessous c'est un avertissement, une détection isolée étant souvent un faux positif.

Une fois activée, l'**empreinte SHA-256 de chaque fichier vérifié** est envoyée à ces services, jamais le fichier
ni son nom. Un fichier que les services n'ont jamais vu est signalé *inconnu*, ce qui ne veut pas dire sain.
Les clés sont enregistrées dans `%APPDATA%\app.rustchk\reputation.json`, chiffrées avec la protection de données
de Windows (DPAPI) : seul votre compte Windows sur cette machine peut les déchiffrer ; une copie du fichier est
inutilisable ailleurs, et les clés sont alors à ressaisir. Des clés enregistrées en clair par une version
précédente sont chiffrées au lancement suivant. Sous macOS et Linux, elles restent en clair.

## Intégration à l'explorateur (Windows)

Ajoute « Vérifier le checksum (RustChk) » au menu contextuel de tous les fichiers, clé
`HKCU\Software\Classes\*\shell\RustChk` (sans droits administrateur). Sous Windows 11, l'entrée se trouve dans
« Afficher plus d'options » (Maj+F10).

- Case à cocher en bas de l'application, ou
- `rustchk.exe --register-shell [--lang fr|en]` / `rustchk.exe --unregister-shell`, ou
- automatiquement par l'installeur NSIS (`src-tauri/windows/hooks.nsh`), retirée à la désinstallation.

Le libellé du menu suit la langue de l'interface.

## Langues

Sélecteur **FR | EN** en haut à droite, mémorisé. Au premier lancement, la langue du système est utilisée
(français si c'est la sienne, anglais sinon). Tous les textes sont dans [`src/i18n.rs`](src/i18n.rs) ; le backend
renvoie des erreurs structurées que l'interface traduit. Pour ajouter une langue, ajouter une variante à `Lang`
dans `core/` : le compilateur signale chaque texte manquant.

## Compiler depuis les sources

Prérequis : [Rust](https://rustup.rs), la cible `wasm32-unknown-unknown`, [Trunk](https://trunkrs.dev),
la [CLI Tauri](https://tauri.app/start/prerequisites/) et les prérequis Tauri de votre plateforme
(WebView2 et les outils de build MSVC sous Windows).

```bash
rustup target add wasm32-unknown-unknown
cargo install trunk tauri-cli
cargo tauri dev        # lance trunk serve + l'application
cargo tauri build      # installeur dans target/release/bundle/nsis
cargo test --workspace # tests unitaires
```

Sous PowerShell, si `trunk` échoue avec `invalid value '1' for '--no-color'`, définir `NO_COLOR=true` avant.

## Construire un installeur

Mêmes prérequis que ci-dessus. Chaque script construit l'interface et l'application en release, les empaquette,
puis copie le résultat dans `release/` avec un fichier `.sha256` (que RustChk sait vérifier lui-même).

| Plateforme | Commande | Résultat |
| --- | --- | --- |
| Windows | `.\scripts\build-installer.ps1 [-OutDir DIR] [-RunTests]` | Installeur NSIS `RustChk_<version>_x64-setup.exe` |
| Linux | `scripts/build-appimage.sh [--out DIR] [--test]` | `RustChk_<version>_amd64.AppImage` |

Sous Linux, installer d'abord les bibliothèques système (Debian/Ubuntu) :
`sudo apt install build-essential curl wget file libwebkit2gtk-4.1-dev libgtk-3-dev libxdo-dev libssl-dev librsvg2-dev patchelf`.
Les installeurs ne sont pas signés.

## Intégration continue

[GitHub Actions](.github/workflows/ci.yml) s'exécute à chaque push sur `main` et à chaque pull request :

| Job | Vérification |
| --- | --- |
| **Format** | `cargo fmt --check` |
| **Linux** (Ubuntu 22.04) · **macOS** · **Windows** | construit l'interface avec Trunk, `clippy -D warnings`, `cargo test --workspace`, puis empaquète l'application (AppImage / `.app` / installeur NSIS, les deux premiers via les scripts ci-dessus) et la publie en artefact conservé 7 jours |

L'intégration au menu contextuel de l'explorateur n'existe que sous Windows ; sous Linux et macOS l'application
se compile et fonctionne sans elle. Les paquets ne sont pas signés.

## Structure du projet

| Chemin | Contenu |
| --- | --- |
| `core/` | Types et analyse des checksums partagés entre l'interface et le backend (Rust pur) |
| `src-tauri/` | Hachage, recherche du checksum voisin, OpenPGP, Authenticode, analyse en ligne, intégration explorateur, commandes Tauri |
| `src/` | Interface Leptos et traductions |
| `src-tauri/tests/fixtures/` | Clés publiques jetables et signatures générées avec GnuPG (aucune clé privée) |

## Licence

[MIT](LICENSE) © 2026 Jean-Jacques Serpoul
