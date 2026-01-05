# Projet inferno
Il faudra rentrer dans le dossier inferno-os dedans vous êtes censé trouver :

- server : le fichier censé lancer un server tcp sans chiffrement
- client : le fichier censé lancer un client tcp sans chiffrement
- server_tls : le fichier censé lancer un server tcp avec chiffrement
- client_tls : le fichier censé lancer un client tcp avec chiffrement

- portable/ : correspond à l'importation de libressl
- le fichier devtls.c placé à la source pour plus de lisibilité ,il existe une copie dans ./emu/port/ car c'est là que sont placés les devices
- Et tout ce qui existait déjà sur inferno modifié afin qu'il puisse être compilé sur un linux ubuntu et émulé sur ce meme systeme. 
- 