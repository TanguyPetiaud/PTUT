Risques
<br>
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


<br>

3. Revenus incertains au lancement

- La niche XML peut limiter le volume initial d’utilisateurs.
- Mesure : cibler les intégrateurs et prestataires dès la première version.

<br>

Risques de sécurité
===

1. Fichiers XML contenant des données sensibles
- Les fichiers peuvent contenir des IP internes, règles ou tunnels VPN.
2. Injection XML (XXE)
- Risque d’exploitation si l’analyse XML n’est pas sécurisée.
- Mesure : désactiver les entités externes et utiliser un parser sécurisé.
3. Corruption du fichier exporté
- Mauvaise fermeture de balises ou caractères non échappés.
- Mesure : validation systématique du XML généré avant téléchargement.
<br>

Synthèse
===
| Type de risque | Impact | Probabilité | Niveau global | Mesure principale |
|----------------|---------|--------------|----------------|------------------|
| Incompatibilité XML | Élevé | Moyen | **Haut** | Parseur XML modulaire |
| Évolution schémas XSD | Moyen | Élevé | **Haut** | Veille et mise à jour |
| Injection XML (XXE) | Élevé | Faible | **Moyen** | Parser sécurisé |

