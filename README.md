# Hacha-Craxk
Este repositorio contiene un programa de línea de comandos que permite realizar ataques de fuerza bruta para encontrar contraseñas a partir de hashes. El programa utiliza una variedad de algoritmos de hash, como MD5, SHA1 y SHA256, entre otros.

El programa permite especificar el tipo de hash que se está atacando, así como la lista de posibles contraseñas en archivos de texto plano. El programa también cuenta con una opción para listar los tipos de hash compatibles.

Este programa es útil para los investigadores de seguridad y los profesionales de la informática que necesitan encontrar contraseñas perdidas o recuperar claves olvidadas. También puede ser utilizado para fines maliciosos, por lo que se recomienda que sólo se utilice con fines éticos y legales.

## Instrucciones de compilacion
Este código es una implementación de un programa para realizar ataques de fuerza bruta a hashes de contraseñas. Para compilarlo, es necesario tener el compilador de GCC instalado y los paquetes de desarrollo de OpenSSL. Para compilar, se debe ejecutar el siguiente comando en la terminal:
```
gcc -o Hacha-Craxk main.c -lcrypto -lssl -DOPENSSL_API_COMPAT=0x10100000L
```

Este programa depende de la biblioteca OpenSSL, por lo que debes asegurarte de tenerla instalada en tu sistema antes de compilar y ejecutar el programa. Puedes instalarlo, según tu distribución, de la siguiente manera:

### Ubuntu/Debian
```
sudo apt-get update
sudo apt-get install openssl libssl-dev
```

### Fedora
```
sudo dnf update
sudo dnf install openssl openssl-devel
```

### CentOS
```
sudo yum update
sudo yum install openssl openssl-devel
```

### Archlinnux
```
sudo pacman -Syu
sudo pacman -S openssl
``` 

### OpenSUSE
```
sudo zypper update
sudo zypper install openssl libopenssl-devel
```


## Uso
```
./Hacha-Craxk --wlist <wordlist_file_path_1> <wordlist_file_path_2> --hash <hash_name>
```
Los argumentos son los siguientes:
- --hash: El tipo de hash a atacar (MD5, SHA1, etc.)
- --wlist: La lista de palabras a usar para el ataque. Se puede especificar más de una lista separando cada ruta de archivo con un espacio
- --list: Muestra los hashes compatibles.

### Ejemplos
```
./Hacha-Craxk --wlist=wlist.txt,/usr/share/dict/rockyou.txt --hash SHA256 d577adc54e95f42f15de2e7c134669888b7d6fb74df97bd62cb4f5b73c281db4
``` 
```
./Hacha-Craxk --wlist rockyou.txt /abs/path/passwords.txt --hash=RIPEMD160 13bdc6e4f3bccec5c62764a55de6c9748c9f2beb
``` 

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

## Dependencias

El programa depende de la biblioteca OpenSSL, que debe estar instalada en su sistema para que el programa pueda compilar y ejecutarse correctamente. Además, el programa utiliza las bibliotecas estándar de C, como stdio.h y stdlib.h, entre otras.

## Autor

Este programa fue creado por Arhoc como un proyecto personal. Si tiene alguna pregunta o comentario, no dude en ponerse en contacto conmigo, no me hago responsable de cualquier uso no 

## Important
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">
  <img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/80x15.png" />
</a>
<br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a>.
