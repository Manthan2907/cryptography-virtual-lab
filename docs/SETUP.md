# Setup Guide

## Prerequisites

- Git
- Python 3, or another static HTTP server
- A modern browser
- Write access to the GitHub repository for integration work

## Clone the Repository

```bash
git clone https://github.com/Manthan2907/cryptography-virtual-lab.git
cd cryptography-virtual-lab
```

## Run Locally

From the repository root:

```bash
python3 -m http.server 8000
```

Open `http://localhost:8000`. Stop the server with `Ctrl+C`.

On Windows, `py -m http.server 8000` can be used when `python3` is not available.

## Branch Structure

The integration branch is `main`. Experiment branches are isolated by group:

```text
group-md5
group-sha1
group-rsa
group-mac
group-hmac
group-kerberos
group-needham-schroeder
group-bcrypt
group-argon2
group-argon2id
group-classical-encryption
group-extended-euclidean
group-brute-force
group-dictionary-attack
group-frequency-analysis
group-ssl-tls
```

Start work from the matching branch and never develop directly on `main`:

```bash
git checkout group-md5
```

## GitHub Pages

In the repository, open **Settings > Pages**, choose **Deploy from a branch**, select `main`, select `/ (root)`, and save. GitHub will publish the root `index.html` at the repository Pages URL.
