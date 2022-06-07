# SEC - Labo 03

> Auteur : Robin Gaudin
>
> Date : 19.06.2022

## Modifications

- Création des certificats
- Modification de la version de TLS utilisée (v1.2)
- Modification du message d'erreur en cas de mauvais identifiants lors de la connexion pour qu'on ne sache pas si c'est le mot de passe ou le nom d'utilisateur qui est faux
- Validation des inputs côté serveur
- Changement de stockage du mot de passe en dur dans la base de donnée, remplacemant par un hash du mot de passe
- Logging avec la crate `simplelog`
- 

