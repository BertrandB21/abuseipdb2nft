Abuseipdb2nft a pour objectif de tnir à jour chaque jour table d'exclusion des adresses IP en provenance d'abuseipdb.

Ce petit bout de code est mon premier programme "utile" en go il est imparfait et construit à partir de morceaux glanés sur Internet et même un peu de chat GPT donc la licence ... et bien elle doit être GPL non ?

Clairement il n'est pas encore beau mais ça fonctionne !

TODO :
- Déjà permettre de diminuer le volume de tranfert par passage du paramètre limit à abuseipdb
- revoir l'ajout des ips dans les ipset un appel à la commande nft par ip est franchement pas la bonne manière de faire
- investiguer du côté de knftables pour ne plus charger dépendre de la commande nft


voili voilou ...
