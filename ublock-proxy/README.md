# ubproxy — proxy transparent avec filtrage type uBlock Origin

Un proxy HTTP(S) transparent qui applique les **listes de filtrage uBlock Origin /
Adblock Plus** (EasyList, EasyPrivacy, uAssets…) à tout le trafic d'une machine
ou d'un réseau — sans extension à installer dans les navigateurs, et donc aussi
pour les applications mobiles, les TV connectées ou les objets qui n'en
acceptent pas.

Écrit en Python 3.11+, sans dépendance en dehors de `cryptography` (utilisée
uniquement pour le mode déchiffrement HTTPS).

```
                  ┌──────────────────── ubproxy ────────────────────┐
 client   TCP/80  │  :8080  parse HTTP → moteur de filtres → amont  │   site
   ●───────────▶  │           ↳ bloqué : pixel/CSS/JS vide, 403     │ ────▶
   │      TCP/443 │  :8443  ClientHello → SNI → moteur              │
   └───────────▶  │           ↳ autorisé : tunnel TLS opaque        │ ────▶
     (REDIRECT    │           ↳ mitm=true : déchiffre, filtre l'URL │
      netfilter)  │             complète et injecte le CSS cosmétique│
                  └────────────────────────────────────────────────┘
```

## Ce qui est réellement filtré

| | sans `mitm` (défaut) | avec `mitm = true` |
|---|---|---|
| HTTP en clair | URL complète, type de ressource, `$domain`, `$third-party` | idem |
| HTTPS | **nom d'hôte (SNI)** uniquement | URL complète, en-têtes, type de ressource |
| Masquage cosmétique (`##.pub`) | pages HTTP seulement | pages HTTP **et** HTTPS |

En pratique, le mode par défaut supprime déjà l'essentiel des régies et des
traqueurs (ils vivent sur des domaines dédiés : `doubleclick.net`,
`googlesyndication.com`, `criteo.com`…). Le mode `mitm` est nécessaire pour les
publicités servies depuis le domaine du site lui-même et pour le masquage
cosmétique des pages en HTTPS ; il exige d'installer une autorité de
certification locale sur chaque appareil client.

## Syntaxe de filtres supportée

Réseau : `||domaine^`, `|préfixe`, `suffixe|`, `*`, `^`, `/regexp/`,
exceptions `@@`, et les options `script, image, stylesheet, xmlhttprequest,
subdocument, document, media, font, websocket, ping, object, other` (avec leur
négation `~`), `third-party`/`3p`, `first-party`/`1p`, `domain=a|~b`,
`denyallow=`, `important`, `match-case`, `all`, `badfilter`.
Les fichiers au format `hosts` (`0.0.0.0 pub.example`) et les listes de simples
noms de domaine sont également acceptés.

Cosmétique : `##sélecteur`, `domaine##sélecteur`, `domaine,~sous.domaine##sél`,
exceptions `#@#`.

**Non supporté, et volontairement ignoré** (les lignes sont comptées, jamais
devinées) : `$redirect`, `$csp`, `$removeparam`, `$replace`, les scriptlets
(`#%#`, `#$#`) et les filtres cosmétiques procéduraux (`#?#`, `:has-text()`,
`:xpath()`, `:style()`…). `ubproxy stats` affiche combien de lignes ont été
écartées et un échantillon.

## Installation

```sh
cd ublock-proxy
python3 -m pip install -r requirements.txt      # cryptography
python3 -m pip install -r requirements-dev.txt  # pytest, pour les tests
```

## Essai en 30 secondes (mode proxy explicite, sans root)

```sh
python3 -m ubproxy -l filters/sample.txt run --http-port 8080 --log-allowed
# dans un autre terminal :
curl -x http://127.0.0.1:8080 https://exemple.test/     # via CONNECT
curl -x http://127.0.0.1:8080 http://exemple.test/
```

Le proxy accepte indifféremment les requêtes en forme absolue
(`GET http://site/… `), les `CONNECT` d'un proxy classique et les connexions
redirigées par netfilter : la même instance sert donc de proxy explicite et de
proxy transparent.

Vérifier une décision sans lancer le proxy :

```sh
python3 -m ubproxy -l filters/sample.txt check \
    https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js --doc lemonde.fr
# BLOCKED  type=script  third-party=True
# rule: ||googlesyndication.com^

python3 -m ubproxy -l filters/sample.txt cosmetics www.lemonde.fr --generic
python3 -m ubproxy stats          # ce qui a été chargé, et ce qui a été ignoré
python3 -m ubproxy update-lists   # force le rafraîchissement du cache
```

## Mode transparent (Linux, netfilter)

Le proxy écoute sur deux ports non privilégiés et netfilter y redirige le
trafic. Il récupère la destination réelle via `SO_ORIGINAL_DST`, donc rien n'est
à configurer côté client.

Sur un routeur / une passerelle, pour filtrer le réseau derrière lui :

```sh
sudo LAN_IF=eth1 scripts/ubproxy-redirect.sh up
sudo -u ubproxy python3 -m ubproxy --config /etc/ubproxy/config.toml run
```

Pour filtrer uniquement la machine locale :

```sh
sudo MODE=local PROXY_USER=ubproxy scripts/ubproxy-redirect.sh up
```

`scripts/ubproxy-redirect.sh down` retire exactement ce qui a été ajouté (tout
est isolé dans une chaîne `UBPROXY`). Le script rejette aussi l'UDP/443 : sans
cela les navigateurs passent en HTTP/3 (QUIC) et contournent complètement le
proxy ; refusé, le trafic retombe sur TLS/TCP.

Un service systemd d'exemple est fourni : `scripts/ubproxy.service`.

## Déchiffrement HTTPS (optionnel)

```sh
python3 -m ubproxy gen-ca      # crée ~/.local/state/ubproxy/ca/ubproxy-ca.crt
python3 -m ubproxy run --mitm
```

Installez `ubproxy-ca.crt` comme autorité de confiance sur les clients (Android :
*Paramètres → Sécurité → Chiffrement → Installer un certificat* ; Firefox a son
propre magasin). Les certificats de site sont signés à la volée et mis en cache
dans le répertoire d'état.

Points à connaître :

* les hôtes listés dans `mitm_bypass_hosts` (Apple, mises à jour système,
  messageries…) sont tunnelisés sans déchiffrement : leurs applications
  épinglent leur certificat et échoueraient sinon ;
* le proxy n'annonce que `http/1.1` en ALPN, les navigateurs redescendent donc
  de HTTP/2 vers HTTP/1.1 pendant l'interception ;
* le certificat présenté au client est signé par votre CA : ne l'installez que
  sur des appareils dont vous êtes responsable, et gardez `ubproxy-ca.key`
  privée (mode 600). Déchiffrer le trafic d'autrui sans son accord n'est ni
  légal ni acceptable.

## Configuration

Toutes les clés sont optionnelles, voir `config.example.toml` :

| clé | défaut | rôle |
|---|---|---|
| `http_port` / `tls_port` | `8080` / `8443` | ports d'écoute (cibles du REDIRECT) |
| `lists` | EasyList, EasyPrivacy, uAssets | URL ou chemins locaux |
| `list_refresh_hours` | `24` | âge maximal du cache avant re-téléchargement |
| `extra_rules` | `[]` | règles ajoutées à la main, syntaxe uBlock |
| `allow_hosts` | `[]` | hôtes jamais filtrés (banque, outils métier…) |
| `cosmetic_filtering` | `true` | injection du CSS de masquage dans le HTML |
| `generic_cosmetic_filtering` | `false` | règles `##` génériques (plus lourdes, plus de casse) |
| `mitm` | `false` | déchiffrement HTTPS |
| `mitm_bypass_hosts` | Apple, Mozilla, Signal… | jamais déchiffrés |
| `upstream_verify` | `true` | vérifie le certificat du site amont |
| `log_level`, `log_allowed`, `stats_interval` | `info`, `false`, `0` | journalisation |

Si une liste ne peut pas être téléchargée, la copie en cache est réutilisée et
un avertissement est journalisé — le proxy démarre quand même.

## Organisation du code

```
ubproxy/
  filters/parser.py   syntaxe Adblock → règles (patrons, options, cosmétique)
  filters/rules.py    NetworkRule / CosmeticRule / Request, tokenisation
  filters/engine.py   index par token + précédence bloc/exception/important
  filters/lists.py    téléchargement et cache des listes
  filtering.py        typage des requêtes, verdicts, CSS cosmétique
  net/http1.py        parsing HTTP/1.x, cadrage des corps (chunked, longueur…)
  net/tlsinfo.py      lecture du ClientHello (SNI, ALPN)
  net/origdst.py      SO_ORIGINAL_DST (destination réelle avant REDIRECT)
  net/mitm.py         autorité locale, certificats à la volée, terminaison TLS
  net/proxy.py        boucle de connexion : blocage, relais, tunnel, injection
  blockpage.py        réponses de remplacement (pixel, CSS/JS vide, page 403)
  inject.py           insertion du <style> cosmétique dans le HTML
  cli.py              run / check / cosmetics / stats / update-lists / gen-ca
```

Choix de conception notables :

* **Index par token le plus rare.** Chaque règle est indexée sous une de ses
  sous-chaînes littérales ; le moteur retient la plus rare de la liste plutôt
  que la plus longue, sans quoi un mot fréquent (`example`, `static`) ferait
  parcourir des milliers de règles à chaque URL. Sur une liste synthétique de
  132 000 lignes : chargement en 4,4 s, ~158 000 décisions/s.
* **Expressions régulières compilées à la demande.** La grande majorité des
  règles sont des `||hôte^` traités par comparaison de suffixe, sans regex.
* **Réponses de remplacement plutôt qu'erreurs.** Une image bloquée renvoie un
  GIF 1×1, un script un corps vide : beaucoup moins de pages cassées qu'une
  erreur réseau (c'est ce que font les redirections `noop` d'uBlock).
* **Filtrage SNI conservateur.** Sans déchiffrement, seules les règles
  indépendantes du type de ressource peuvent bloquer un hôte entier :
  `||traqueur.example^` coupe la connexion, `||site.example/pub.js$script` non.

## Tests

```sh
python3 -m pytest -q      # 60 tests
```

Ils couvrent la syntaxe des filtres, la précédence des règles, le parsing
HTTP/1.x, la lecture d'un vrai ClientHello produit par OpenSSL, l'autorité de
certification, et des scénarios de bout en bout : blocage et injection
cosmétique sur une connexion keep-alive, réponse *chunked* relayée, `CONNECT`
vers un hôte bloqué, blocage TLS par SNI, et filtrage à l'intérieur d'une
session HTTPS déchiffrée.

Le mode transparent lui-même a été validé avec de vraies règles
`iptables -t nat … REDIRECT` (HTTP filtré, TLS tunnelisé ou bloqué par SNI,
HTTPS déchiffré puis filtré).

## Limites connues

* **HTTP/3 (QUIC)** contourne le proxy : il faut le bloquer (le script
  netfilter le fait).
* **HTTP/2 en clair** n'est pas géré (inutilisé en pratique) ; en interception
  TLS, l'ALPN force HTTP/1.1.
* **ECH (Encrypted Client Hello)** chiffre le SNI : le filtrage par nom d'hôte
  devient aveugle sur ces connexions.
* **DNS-over-HTTPS** des navigateurs ne change rien au filtrage (il porte sur
  les connexions, pas sur le DNS), mais empêche un éventuel filtrage DNS
  complémentaire.
* Les **scriptlets** et **filtres procéduraux** d'uBlock ne sont pas exécutés :
  quelques anti-adblock ne seront pas contournés.
* Le masquage cosmétique demande de bufferiser le HTML (limite
  `max_html_rewrite_bytes`, 4 Mio par défaut) et retire `Accept-Encoding` sur
  les documents pour pouvoir les modifier.
