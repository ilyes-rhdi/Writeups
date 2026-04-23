# babygame03 - Write-up detaille (ret2win via stack OOB)

## 1. Objectif
Le but est de forcer l'execution de `win()` dans le binaire `g`.

## 2. Triage initial
Commandes utilisees:

```bash
file g
pwn checksec g
nm -n g
objdump -d -Mintel g
strings g
```

Constats:
- ELF 32-bit
- `NX` active
- `Canary` absent
- `PIE` desactive (adresses code fixes)
- symbole `win` present a `0x080497bc`

## 3. Comprendre le flux du programme
Fonctions importantes:
- `main`
- `move_player`
- `win`

Dans `main`:
- `player` est sur la stack
- `level` est sur la stack
- `map` (30 x 90) est sur la stack
- la boucle lit un caractere (`getchar`) puis appelle `move_player`

Condition legitime pour appeler `win` (dans `main`):
- position joueur = `(29, 89)`
- `level == 5`
- compteur interne des rounds = `4`

Puis `main` fait `win(&level)`.

## 4. Pourquoi la voie legitime est piegee
Le code de progression de niveau bloque la montee normale vers 5:
- quand tu termines un niveau, il y a un cas special sur `level == 4`
- resultat: en pratique le flux normal ne permet pas d'atteindre `level == 5` proprement

Donc il faut exploitation memoire.

## 5. Vuln exploitable
Dans `move_player`, l'index map est calcule comme:

```c
idx = 90 * x + y;
map[idx] = ...
```

Il n'y a pas de check de bornes sur `x` / `y`.
Donc on obtient un **out-of-bounds read/write** sur la stack de `main` (car `map` est aussi sur la stack).

## 6. Calcul des offsets utiles
Base map (dans `main`):
- `map_base = &map[0][0] = [ebp - 0xa99]`

Variables cibles:
- `level` est a `[ebp - 0xaac]`
- ecart: `(-0xaac) - (-0xa99) = -0x13 = -19`
- donc le byte LSB de `level` est a `map_base - 19`

Retour de `move_player` (saved EIP dans sa frame):
- observe en debug: `saved ret = 0x0804992c`
- adresse correspondant a `map_base - 51`
- donc en ecrivant a l'index `-51`, on controle le LSB du retour

Pourquoi un LSB overwrite suffit:
- `0x0804992c` -> `0x080499fe` en changeant seulement `0x2c` vers `0xfe`
- `0x080499fe` est juste avant:
  - `push &level`
  - `call win`

Donc si on patch le LSB du retour a `0xfe`, au `ret` de `move_player` on saute directement vers le bloc d'appel `win`.

## 7. Primitive d'ecriture d'un byte arbitraire
Dans `move_player`:
- si input == `'l'`, le programme lit encore un byte via `getchar()` et le stocke dans `player_tile`
- ensuite ce `player_tile` est ecrit dans la case courante de la map

Donc:
1. se deplacer sur la case cible (meme si hors map)
2. envoyer `l<BYTE>` pour choisir le byte a ecrire

## 8. Comment les commandes du solve ont ete construites
### 8.1 Finir vite les 3 premiers niveaux
Payload repete 3 fois:

```text
aaaaawwwaaaawsddddp
```

Interpretation:
- `a` / `w` / `s` / `d`: mouvements
- `p`: lance l'auto-solver interne (`solve_round`) pour terminer le niveau

On l'envoie 3 fois pour arriver au contexte du niveau 4.

### 8.2 Premiere phase OOB (payload stable)
Payload:

```python
b"aaaaawwwaaaawsddddaa" + (b"aaaa" * 12) + b"l\x70w"
```

Idee:
- la premiere partie place le joueur pres de la zone utile
- la longue serie de `a` deplace la position vers la zone stack qui contient le saved return address de `move_player`
- `l\x70` ecrit `0x70` sur le LSB du retour: `0x0804992c -> 0x08049970`
- le `ret` de `move_player` saute alors dans le bloc `main+0xff` ("Next level starting")
- ce bloc incremente `level`, donc on passe de 4 a 5

### 8.3 Ecraser le LSB du retour de `move_player`
Payload:

```python
b"aaaaawwwaaaawsddddaa" + (b"aaaa" * 16) + b"l\xfew"
```

- meme principe de positionnement OOB
- `l\xfe` ecrit `0xfe` sur le byte de poids faible du saved return address
- au retour de `move_player`, execution redirigee vers `0x080499fe` (`0x0804992c -> 0x080499fe`)
- `main` enchaine alors sur `push &level; call win`

## 9. Script final
Fichier: `solve.py`

Lancement local:

```bash
python3 solve.py
```

Lancement remote:

```bash
python3 solve.py REMOTE=1 HOST=<host> PORT=<port>
```

## 10. Verification
Sur ma validation locale (avec un `flag.txt` de test), la sortie contient:
- `You win!`
- puis le contenu de `flag.txt`

## 11. Resume exploitation
1. Reverse pour trouver `win` et les conditions d'appel.
2. Identifier la primitive OOB dans `move_player`.
3. Convertir les offsets stack en offsets relatifs a `map_base` (`-19`, `-51`).
4. Utiliser `l<BYTE>` pour ecrire sur stack.
5. Forcer le retour de `move_player` vers `main+0x18d` (`0x80499fe`) afin d'executer le `call win`.
