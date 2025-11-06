Marché cible
===

Le projet vise le marché de la cybersécurité, et plus précisément celui des pare-feu d’entreprise (Next-Generation Firewalls, NGFW).
L’objectif est de faciliter la migration de configurations entre différents constructeurs, en commençant par WatchGuard et OPNsense.

Ce besoin est concret : les migrations manuelles sont longues, risquées et sources d’erreurs.
Les outils existants (comme FortiConverter) ne couvrent que les migrations vers Fortinet, jamais l’inverse.


Contexte et croissance du marché
===

Le marché mondial des pare-feu d’entreprise représente environ 13,7 milliards $ en 2025, avec une croissance annuelle moyenne de 10 %.
En Europe, il atteint environ 4,7 milliards $, et pourrait dépasser 8 milliards $ d’ici 2031.

- Les tendances actuelles :

- Adoption massive des pare-feu nouvelle génération (NGFW).

- Passage progressif vers des solutions open source (comme OPNsense) pour réduire les coûts.

- Hausse des besoins en migration et automatisation lors de changements d’infrastructure.


Concurrence
===

| Nom de la solution | Type / Positionnement | Points forts | Limites / Manques | Source |
|--------------------|-----------------------|---------------|--------------------|--------|
| **FortiConverter** (Fortinet) | Outil propriétaire de migration *vers* FortiGate | Conversion fiable depuis plusieurs marques (Cisco, Palo Alto, etc.) | Aucun support pour conversion *depuis* Fortinet vers une autre marque | [Fortinet](https://www.fortinet.com/products/next-generation-firewall/forticonverter?) |
| **Tufin SecureTrack / SecureChange** | Plateforme de gestion multi-pare-feu | Automatisation des politiques et conformité | Produit coûteux, destiné aux grandes entreprises, pas de conversion directe de fichiers | [Tufin](https://www.tufin.com/solutions/firewall-management/migration?) |
| **AlgoSec Firewall Analyzer** | Gestion centralisée des politiques de sécurité | Audit et optimisation multi-marques | Ne réalise pas de migration de fichiers, complexité d’usage | [AlgoSec](https://www.algosec.com/?) |
| **FireMon Security Manager** | Supervision et audit de pare-feu | Bon reporting et conformité | Pas de fonction de conversion automatique | [FireMon](https://www.firemon.com/?) |
| **Communauté WatchGuard / OPNsense** | Aide communautaire / scripts manuels | Support de la communauté, documentation ouverte | Aucune automatisation, tout se fait manuellement | [WatchGuard Community](https://community.watchguard.com/watchguard-community/discussion/3823/migration-from-fortinet-to-watchguard?) |
