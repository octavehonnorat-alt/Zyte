# Scrapy spider - commerces sans site web

Ce projet Scrapy est prêt pour Zyte Cloud (Scrapy Cloud) avec une architecture standard:
- `scrapy_no_website_business/items.py`
- `scrapy_no_website_business/spiders/no_website_directory_spider.py`
- `scrapy_no_website_business/settings.py`

## Objectif
- Cibler des pages publiques de résultats/annuaires.
- Filtrer les commerces sans site web.
- Rechercher des emails publics dans la fiche (description/champs contact/json-ld).

## Exécution locale
```bash
pip install -r requirements.txt
scrapy crawl no_website_directory \
  -a start_urls='https://example.com/directory?q=plombier' \
  -O output.json
```

Paramètres utiles:
- `start_urls` (obligatoire): URLs de départ, séparées par des virgules.
- `allowed_domains` (optionnel): domaines autorisés, séparés par des virgules.
- `max_pages` (optionnel, défaut: `20`): pagination maximale.

## Déploiement Zyte Cloud
Le fichier `scrapy.cfg` est inclus. Depuis ce dossier:
```bash
shub deploy
```

## Notes
- Le spider respecte `robots.txt` (`ROBOTSTXT_OBEY = True`).
- Aucune API tierce payante / Zyte API n'est utilisée.
