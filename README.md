# Le projet est déployé sur vercel :
https://dh-and-aes.vercel.app/

# Lancer l’application web (DH + AES)

## Prérequis

- **Node.js** installé (pour `npm` et `npx`).
- Un **navigateur récent** (Chrome, Firefox, Edge…).

L’API **Web Crypto** (`crypto.subtle`) ne fonctionne pas en ouvrant le fichier en `file://`. Il faut servir la page en **HTTP(S)** sur **`localhost`** ou en **HTTPS**.

---

## Méthode recommandée (npm)

Dans un terminal :

```bash
cd web
npm start
```

_(Le script utilise `npx serve` ; une connexion réseau peut être nécessaire la première fois pour télécharger `serve`.)_

Puis ouvre dans le navigateur :

**http://localhost:3333**

Le port **3333** est celui défini dans `package.json` (`serve … -l 3333`). Si le port est occupé, modifie le script ou lance manuellement :

```bash
cd web
npx --yes serve . -l 8080
```

et ouvre **http://localhost:8080**.

---

## Arrêter le serveur

Dans le terminal où il tourne : **Ctrl+C**.

---

## Sans npm (alternative)

Depuis le dossier `web` :

```bash
cd web
python3 -m http.server 3333
```

Puis ouvre **http://localhost:3333** (choisis `index.html` si le serveur liste les fichiers, ou va directement sur **http://localhost:3333/index.html**).

---

## Utilisation rapide

1. **Générer les clés** (bouton 1) — peut prendre quelques secondes (DH 2048 bits).
2. Saisir un **message** côté Alice, **Chiffrer**.
3. **Déchiffrer** côté Bob.

Le diagramme de séquence et les infobulles s’actualisent après ces actions.
