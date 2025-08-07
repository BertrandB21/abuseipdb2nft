Abuseipdb2nft a pour objectif de tenir à jour chaque jour une table d'exclusion des adresses IP en provenance d'abuseipdb avec l'API Blacklist.

Ce petit bout de code est mon premier programme "utile" en go il est imparfait et construit à partir de morceaux glanés sur Internet et même un peu de chat GPT donc la licence ... et bien elle doit être GPL non ?

Clairement il n'est pas encore beau mais ça fonctionne !

TODO :
- mettre un numéro de version et ajouet les paramètres -h et -v 
- investiguer du côté de knftables pour ne plus charger dépendre de la commande nft

NB :
- le paramètre categories ne sert pratiquement à rien il est en atente d'une éventuelle modification de l'API dit monsieur anuseipdb ce serait sympa

INSTALL

Compiler "go build abuseipdb2nftable.go"
installer l'exécutable "mv abusipdb2nftable /usr/sbin"
installer le fichier de configuration "mkdir /etc/abuseipdb; cp abuseipdb.yaml /etc/abuseipdb/; chown -R root:root /etc/abuseipdb"
installerla partie systemd "cp abuseipdb2nftable.timer abuseipdb2nftable.service /etc/systemd/system; chown root:root /etc/systemd/system/abuseipdb*"
activer : systemctl enable abuseipdb2nftable.timer

voili voilou ...
