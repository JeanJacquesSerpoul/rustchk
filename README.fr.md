# RustChk

[English](README.md) · **Français**

Vérifie le checksum d'un fichier téléchargé — et s'assure que le fichier de checksums lui-même est authentique.
Petite application de bureau écrite en Rust avec [Tauri 2](https://tauri.app) et [Leptos 0.8](https://leptos.dev).

[![Licence : MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

## Fonctionnalités

- **MD5, SHA-1, SHA-256, SHA-384 et SHA-512** calculés en une seule lecture du fichier (en parallèle, avec barre de
  progression et bouton d'annulation — environ 3,8 s pour un fichier de 2 Go sur une machine récente).
- **Coller l'empreinte publiée** : l'algorithme est déduit de sa longueur. Formats acceptés : `hash`,
  `hash  fichier`, `sha256:hash`, `SHA256 (fichier) = hash` et la sortie de `certutil` (octets séparés par des espaces).
- **Préremplissage** : si un `fichier.sha256` (ou `.md5`, `.sha1`, `.sha512`…) ou un `SHA256SUMS` se trouve à côté
  du téléchargement, son empreinte est reprise automatiquement.
- **Authentification OpenPGP** de ce fichier de checksums (voir ci-dessous).
- **Intégration à l'explorateur Windows** : entrée « Vérifier le checksum » dans le menu contextuel de tous les fichiers.
- **Glisser-déposer**, ou ouverture depuis la ligne de commande / le menu contextuel.
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

## Structure du projet

| Chemin | Contenu |
| --- | --- |
| `core/` | Types et analyse des checksums partagés entre l'interface et le backend (Rust pur) |
| `src-tauri/` | Hachage, recherche du checksum voisin, OpenPGP, intégration explorateur, commandes Tauri |
| `src/` | Interface Leptos et traductions |
| `src-tauri/tests/fixtures/` | Clés publiques jetables et signatures générées avec GnuPG (aucune clé privée) |

## Licence

[MIT](LICENSE) © 2026 Jean-Jacques Serpoul
