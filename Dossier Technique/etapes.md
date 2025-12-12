# Découpage des tâches
- Analyser la structure du fichier de configuration pour:
-- WatchGuard
-- OPNSense
- Déterminer la méthode de parsing XML
- Déterminer la méthode de génération de page web
- Déterminer la méthode de gestion du formulaire
- Déterminer la méthode de génération du tableau récapitulatif



# Analyse des fichiers de conf
### Méthode simple
Exporter la conf par défaut.
Configurer des interfaces (interne/externe, VLAN...).
Exporter la conf.
diff des deux fichiers.
Ajouter quelques règles de pare-feu.
diff des deux dernier fichiers.
Rince.
Repeat.

Quelques idées:
- Créer une règle de pare-feu sans alias et l'analyser.
- Créer une règle de pare-feu avec alias et l'analyser. Observer la différence entre le fichier de base et le fichier avec à la fois l'ajout de l'alias et de la règle.



### Méthode compliquée, peut être plus exhaustive
Aller à la main à travers les 1k+ lignes du XML.
Pour avoir une vision complète des éléments du fichier utiles, configurer toutes les fonctionalités voulues avant d'exporter la conf pour analyse.



