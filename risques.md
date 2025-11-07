Risques

===

Risques techniques
===

1. Compatibilité XML entre fabricants
 
- Chaque marque (Fortinet, WatchGuard, OPNsense) utilise un format XML différent, avec sa propre hiérarchie et ses balises spécifiques.

- Risque : mauvaise interprétation de certaines balises ou perte d’éléments lors de la conversion.

- Mesure : création d’un parseur XML modulaire capable de lire plusieurs structures et de s’adapter aux différences.

<br>

2. Coût de maintenance du moteur XML

- Le suivi des versions et tests peut être chronophage.

- Mesure : automatisation des tests unitaires sur plusieurs jeux de fichiers XML.

