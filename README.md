# Projet inferno
Il faudra rentrer dans le dossier inferno-os dedans vous êtes censé trouver :

- server : le fichier censé lancer un server tcp sans chiffrement
- client _tcp: le fichier censé lancer un client tcp sans chiffrement
- server_tls : le fichier censé lancer un server tcp avec chiffrement
- client_tls : le fichier censé lancer un client tcp avec chiffrement

- Portable/ : correspond à l'importation de libressl
- Le fichier ./emu/port/devtls.c qui est le device avec libressl codé à partir de devssl et de l'IA
- Et tout ce qui existait déjà sur inferno modifié afin qu'il puisse être compilé sur un linux ubuntu et émulé sur ce meme systeme. 