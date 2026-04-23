# tinyball write-up

## Résumé

Le challenge utilise `TinyMT32` pour générer des tirages de loterie.  
On voit 27 tirages d'archive de 6 valeurs chacun, avec les 17 premiers censurés via des emojis et les 10 derniers affichés en clair.  
Le but est de prédire le tirage du lendemain, c'est-à-dire les 6 sorties suivantes du PRNG.

Le solveur final est dans [solve.py](/home/ilyes/Downloads/Tamu/tinyball/solve.py) et le flag récupéré est :

```text
gigem{t1ny_l34ks_4_b1g_W1N5!11!!1!11!!eleven!1}
```

## Code du challenge

Le serveur fait essentiellement ceci :

```python
rng = TinyMT32(0xf10c70)
new_state = tuple(int.from_bytes(os.urandom(4), 'little') for _ in range(4)) + (rng.getstate()[4], )
rng.setstate(new_state)

archive = [make_draw(rng) for _ in range(27)]
today = make_draw(rng)
answer = make_draw(rng)
```

Chaque tirage vaut :

```python
[rng.raw() % m for m in [25, 48, 60, 75, 96, 120]]
```

Important :

- l'état interne n'est pas dérivé du seed initial, il est écrasé par 4 mots aléatoires ;
- `setstate()` force le bit de poids fort de `s0` à `0`, donc l'état effectif fait `127` bits ;
- on observe `27 * 6 = 162` sorties modulo de `rng.raw()`.

## Pourquoi les emojis suffisent déjà à fuiter de l'information

Les 17 premiers tirages sont affichés comme :

```python
EMOJIS[n % 8]
```

avec `n = rng.raw() % m`.

Donc pour ces tirages on connaît :

```text
(rng.raw() % m) % 8
```

Pour les modules pairs `48`, `60`, `96`, `120`, la parité de `rng.raw() % m` est exactement la parité de `rng.raw()`, car soustraire un multiple pair de `m` ne change pas le bit faible.

Autrement dit, sur chaque sortie associée à un module pair, on récupère directement le bit 0 de la sortie brute.

Comme il y a 4 modules pairs par tirage et 27 tirages, on obtient :

```text
27 * 4 = 108
```

équations linéaires sur l'état interne.

## La propriété clé de TinyMT32

La transition d'état de `TinyMT32` est linéaire sur `GF(2)` :

```python
x = ((s0 & 0x7fffffff) ^ s1 ^ s2)
x ^= x << 1
y = s3 ^ (s3 >> 1) ^ x
...
```

La sortie est :

```python
t1 = s0 + (s2 >> 8)
t0 = s3 ^ t1
if t1 & 1:
    t0 ^= TMAT
```

Le point important est que :

```text
((s2 >> 8) & 1) = 0
```

donc :

```text
t1 & 1 = s0 & 1
```

et le bit faible de la sortie devient :

```text
out_0 = s3_0
```

après la transition courante.

Donc pour toutes les sorties modulo un nombre pair, la parité observée nous donne directement un bit linéaire de l'état.

## Reconstruction de l'état

### 1. Symboliser l'état initial

On représente les 127 bits libres de l'état initial comme des variables de base.

- `s0` apporte 31 bits libres ;
- `s1`, `s2`, `s3` apportent 32 bits chacun.

### 2. Propager ces bits à travers TinyMT

Comme la transition est linéaire sur `GF(2)`, chaque bit de chaque état futur peut être représenté comme XOR de bits de l'état initial.

Dans le solveur, chaque bit est représenté par un entier Python dont les bits indiquent quelles variables initiales participent à ce XOR.

### 3. Extraire les équations

Pour chaque observation avec module pair :

- on avance l'état symbolique d'un pas ;
- on prend `state[3][0]`, qui correspond au bit faible de la sortie brute ;
- on l'égale à la parité observée.

On obtient ainsi un système linéaire de 108 équations en 127 inconnues.

### 4. Résoudre le système

Une élimination de Gauss sur `GF(2)` donne :

- une solution particulière ;
- une base de l'espace des solutions.

Sur les instances du challenge, le rang est `108`, donc il reste :

```text
127 - 108 = 19
```

bits libres.

### 5. Bruteforce final

On énumère les `2^19` états compatibles avec les parités, puis on rejoue le PRNG et on vérifie toutes les contraintes :

- sorties complètes sur les 10 tirages visibles ;
- sorties censurées modulo 8 sur les 17 premiers tirages.

En pratique, le bon état arrive vite et le solveur prend quelques secondes.

## Pourquoi c'est suffisamment rapide

Le gros gain vient du fait qu'on ne résout pas directement toutes les contraintes modulo avec un SMT/SAT solver.

On fait plutôt :

1. une récupération linéaire très bon marché sur 108 bits d'information ;
2. un bruteforce sur seulement 19 dimensions ;
3. une validation ultra rapide avec l'implémentation Python de TinyMT.

Sur mes tests synthétiques, le solveur tourne généralement entre moins d'une seconde et quelques secondes.  
Sur l'instance distante résolue, il a trouvé la réponse en environ `1.31s` après le PoW.

## Utilisation

### Test local

```bash
python3 solve.py --self-test 5
```

### Résoudre une transcription

```bash
python3 solve.py --stdin < transcript.txt
```

### Exploit remote complet

```bash
python3 solve.py --remote
```

Le script :

- résout le proof-of-work ;
- parse les tirages affichés ;
- reconstruit l'état interne ;
- calcule le tirage du lendemain ;
- envoie automatiquement la réponse.

## Fichiers utiles

- [server.py](/home/ilyes/Downloads/Tamu/tinyball/server.py) : logique du challenge.
- [tinymt32.py](/home/ilyes/Downloads/Tamu/tinyball/tinymt32.py) : implémentation du PRNG.
- [solve.py](/home/ilyes/Downloads/Tamu/tinyball/solve.py) : solveur final.

## Conclusion

Le challenge fuit une information très précieuse : le bit faible de nombreuses sorties brutes, à cause des modules pairs et de la structure de sortie de `TinyMT32`.  
Cette fuite donne un grand système linéaire sur l'état initial. Une fois ce système résolu, il ne reste qu'un petit bruteforce, ce qui rend l'attaque largement faisable dans la fenêtre de temps du service distant.
