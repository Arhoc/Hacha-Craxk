# Hacha-Craxk
Hacha-Craxk es una herramienta de fuerza bruta de contraseñas escrita en C usando OpenSSL que permite a los usuarios probar todas las combinaciones posibles de contraseñas para un hash determinado.

## Uso
```
./Hacha-Craxk --wlist <wordlist_file_path_1> <wordlist_file_path_2> --hash <hash_name>
```
Los argumentos son los siguientes:
- --hash: El tipo de hash a atacar (MD5, SHA1, etc.)
- --wlist: La lista de palabras a usar para el ataque. Se puede especificar más de una lista separando cada ruta de archivo con un espacio
- --list: Muestra los hashes compatibles.

## Algoritmos de Hash compatibles

Hacha-Craxk admite los siguientes algoritmos de hash:

- MD4
- MD5
- SHA1
- SHA224
- SHA256
- SHA384
- SHA512
- RIPEMD160

## Important
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">
  <img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/80x15.png" />
</a>
<br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a>.
