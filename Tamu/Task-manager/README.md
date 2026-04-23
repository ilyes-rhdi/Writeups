# Task Manager - Write-up detaille

## TL;DR

- **Bug principal**: overflow heap dans `create_tasks()`.
- `read(0, temp->task, 88)` ecrit **88 octets** dans un buffer de **80 octets**.
- Cela ecrase `temp->next` (8 octets) et permet une corruption de pointeur.
- Avec les structures de meme taille (`Tasks` et `TaskHead`, 0x58), on obtient une **type confusion** utile pour leak + write-what-where.
- Enchainement final: leak stack -> leak PIE -> leak libc -> overwrite `main` saved RIP avec ROP -> overwrite `size` pour skipper cleanup -> shell -> flag.

Flag:

```text
gigem{f4s7b1N5_0f_5p141t_hAuN7_8s_d1A593c6CeF}
```

---

## 1. Analyse du code vulnerable

Dans [`task-manager.c`](./task-manager.c), la fonction `create_tasks()` contient:

```c
read(0, temp->task, 88);
```

Alors que `task` vaut:

```c
char task[80];
```

Et la structure est:

```c
typedef struct Tasks {
  char task[80];
  struct Tasks* next;
} Tasks;
```

Donc les 8 octets de trop ecrasent `next`.

### Important

Ce n'est pas un UAF pur en root cause.
La primitive initiale est un **heap overflow** sur pointeur de chainage (`next`), ensuite exploitee pour creer une chaine de pointeurs arbitraire.

---

## 2. Protections et impact

Le binaire est protege (canary, PIE, NX, full RELRO), donc pas de shellcode direct, pas de GOT overwrite facile.

Strategie retenue:

- construire des leaks fiables (stack, PIE, libc),
- poser un ROP libc sur le retour de `main`,
- eviter le crash dans `cleanup` en forcant `size = 0` juste avant `Exit`.

---

## 3. Point cle de design: tailles identiques

`sizeof(Tasks) == sizeof(TaskHead) == 0x58`.

Quand `A->next` est redirige vers `taskPointer` (objet `TaskHead`), le programme traite `TaskHead` comme un `Tasks`.

Cela donne:

- `taskPointer` interprete comme `task[80] + next`,
- ecritures et leaks sur la memoire de `TaskHead` et sur des adresses choisies via `next`.

C'est la base de toute la chaine.

---

## 4. Plan d'exploitation

### Etape A - Calibration low16 pour pointer vers `taskPointer`

On ajoute une tache de 80 `A`, puis on lit le leak du pointeur `next` imprime par `%s`.

On ajuste les 2 octets faibles:

- `orig_low16 = leaked_next_low16`
- `target_low16 = orig_low16 - 0xc0`

Pourquoi seulement low16:

- les chunks sont dans la meme zone ASLR,
- modifier low16 suffit pour passer de `B` vers `taskPointer`.

### Etape B - Leak stack (`&tasks`)

Avec `A->next -> taskPointer`, un `add` suivant ecrit/lit dans `TaskHead`.

Le champ `head` de `TaskHead` contient `&tasks` (sur la stack).
On recupere:

- `stack_tasks = &tasks`
- `saved_rip = stack_tasks + 0xb0`

### Etape C - Leak PIE

On redirige `taskPointer->next` vers une adresse stack contenant un pointeur code (`main`) dans le frame startup.

Dans ce challenge, l'adresse utilisee est:

- `ptr_main_addr = stack_tasks + 0xc0`

On lit `main_ptr`, puis:

- `pie_base = main_ptr - elf.sym['main']`
- `size_addr = pie_base + elf.sym['size']`

### Etape D - Leak libc

On redirige un maillon vers `saved_rip` et on lit l'adresse de retour libc.

Le delta observe avec la libc fournie:

- `RET_DELTA = 0x27268`

Donc:

- `libc_base = leaked_ret - 0x27268`

On en deduit:

- `system`,
- `"/bin/sh"`,
- gadgets `ret` et `pop rdi; ret`.

### Etape E - Ecriture ROP

Le ROP ecrit sur `saved_rip`:

```text
ret
pop rdi ; ret
/bin/sh
system
```

### Etape F - Bypass cleanup avec `size`

Le chemin `Exit` fait:

```c
while (size > 0) cleanup(&tasks);
```

Si on sort avec une liste corrompue, `cleanup` crash.

Solution:

- ecrire `size = 0xffffffffffffffff`,
- puis le `size += 1` de `ADD_TASK` remet `size` a `0` (wrap unsigned),
- ensuite option `5` (`Exit`) saute la boucle cleanup.

`main` retourne alors directement dans notre ROP.

---

## 5. Stabilisation (points qui font echouer sinon)

1. **Sync I/O**
- Eviter un pilotage de menu desynchronise.
- Le script final envoie `sendline()` quand le prompt est deja consomme.

2. **Noeuds stack qui se chevauchent**
- Reutiliser une meme adresse stack comme noeud a plusieurs profondeurs cree des cycles et casse la traversal.
- Un `delete()` intermediaire (`size 5 -> 4`) est necessaire pour faire de `saved_rip` le `spare` proprement avant l'ecriture ROP.

3. **Le bon delta libc**
- `0x27268` avec la libc fournie.

---

## 6. Script de solve

Exploit final:

- [`final_solve.py`](./final_solve.py)

Lancer:

```bash
python3 final_solve.py
```

Le script:

- construit les leaks,
- pose le ROP,
- force `size=0`,
- envoie `cat flag*`.

---

## 7. Resultat final

Sortie obtenue sur le remote:

```text
gigem{f4s7b1N5_0f_5p141t_hAuN7_8s_d1A593c6CeF}
```

---

## 8. Conclusion

Le challenge est un bon cas d'ecole de:

- overflow de pointeur de chainage,
- type confusion par collision de tailles de structures,
- exploitation robuste sous PIE+NX+RELRO+canary,
- et orchestration fine de l'etat interne (`size`, liste, cleanup).

