# Universe server

Layer centrale di instradamento comandi (FastAPI). In produzione resta in dry-run finché `UNIVERSE_ALLOW_LIVE` non viene acceso con un ok esplicito.

## Hook anti-segreti

Prima di ogni commit e di ogni push uno script locale (`scripts/secret_scan.py`) cerca token, chiavi e password. Se trova qualcosa, blocca l'operazione e stampa file, riga, tipo di pattern e un valore mascherato (mai il segreto intero).

Dopo un clone nuovo, una volta sola:

```sh
git config core.hooksPath .githooks
```

Oppure: `make hooks`. Lo stesso comando è il target `hooks` del `Makefile`.

La GitHub Action `.github/workflows/secret-scan.yml` esegue lo stesso controllo su push e pull request: è il backstop se qualcuno usa `--no-verify`. I hook locali da soli si possono bypassare.

Per un controllo manuale:

```sh
python3 scripts/secret_scan.py --ci
```

I file `.env.example` con placeholder sono ammessi. Per un falso positivo su una riga precisa, aggiungi il commento `# secret-scan: allow`.
