# T2 Computação Paralela - Coodenador/Trabalhor MPI

### Transformação de texto.txt em hash
```
make -f Makefile.hash
```

### Compilação
```
make -f Makefile.mpi
```
### Execução
```
make -f Makefile.mpi run THREADS=<num_threads> 
```
---
## Automatizar execução:
Estando na pasta raíz, manter a estrutura de pastas:
```
.
├── Makefile.auto
├── Makefile.hash
├── Makefile.mpi
├── sha512.c
├── hash.txt
├── texto.txt
├── listas/
|   ...
│   ├── lista_N2_T2.txt
│   ├── lista_N2_T8.txt
│   ├── lista_N2_T16.txt
    ...

```

Em `/listas`, os arquivos `.txt` devem conter as palavras-alvo a serem utilizadas na execução do `sha512.c`. Por exemplo:

```
teste
java
senha
```

Para executar a automação, devemos executar na pasta raiz:

```
make -f Makefile.auto
```

Os arquivos de resultado serão salvos na pasta `results`