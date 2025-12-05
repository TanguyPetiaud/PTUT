# Consignes
3 minutes.
Dans ce laps de temps, on doit:
- captiver l'attention de l'audience
- expliquer le problème
- présenter notre solution
- exprimer ce qu'on attend de l'audience


Dans un second temps, nous répondrons aux questions de l'audience.


# Plan
Intro c'est pas sorcier: Tanguy et Nicolas, présents physiquement, introduisent brièvement le problème. Ils posent une question à Ilyesse, qui répond à travers une vidéo pré-enregistrée.

Dans cette section, T et N peuvent soit présenter le problème en entier, puis demander à I de présenter la solution, soit (tenter) un échange avec I, en questions réponses rapid-fire.

On enchaîne sur une présentation plus technique, en expliquant clairement les attendus en terme de capacités (marques, modèles, éléments de configuration traités...) et d'expérience utilisaateur (logiciel à lancer en local, utilisation à travers une page web locale...).

Enfin, présentation de notre modèle de distribution (finances, open-source...).



🎬 [Vidéo : apparition d’Ilyesse (Fred dans “C’est pas sorcier”)]
===

## 🎤 Nicolas (Jamy) : 
« Bonjour à tous ! Avez-vous déjà configuré un pare-feu ? Non ? Laissez-moi vous dire une chose : c'est long, c'est pénible, et ça peut rendre fou ! Tanguy, ce travail de recopie manuelle des règles de sécurité, c'est horriblement chiant, non ? »


## 🎤 Tanguy : 
« Horriblement chiant, Nicolas, c'est le mot ! C'est le genre de tâche qui prend des jours, qui accumule la dette technique, et qu'on ne fait jamais correctement... N'est-ce pas, Ilyesse ? »

## Ilyesse (vidéo – Fred énervé/fatigué) : 
C'est une horreur ! Regardez ! (Montre un écran ou un tableau blanc) Ça fait trois mois ! À cause des recommandations ANSSI et des enjeux de souveraineté, on est obligés de migrer ces configurations vers des solutions auditables ! Mais le problème, c'est qu'on a plus de 1 500 règles à refaire. On a même oublié de créer des alias pour les serveurs critiques ! Quand l'entreprise change de matériel, les techniciens doivent tout refaire à la main : WatchGuard a son concept, Stormshield le sien... On est bloqués par la complexité ! C'est une perte de temps massive !

## 🎤 Nicolas (sur scène – Jamy) :
« Et oui Ilyesse ! Effectivement, aujourd’hui. La contrainte de souveraineté se heurte à la réalité technique. Quand une entreprise change de marque de pare-feu, ses techniciens doivent tout refaire à la main : règles, objets, adresses, NAT… C’est long, c’est risqué, et ça coûte cher. Mais une solution est en cours de developpement et elle s'appel NETMORPH !


## 🎤 Tanguy (sur scène) :
« Et l'équipe netmorph c'est nous
Notre objectif, c’est de réduire ce temps de migration de 60 à 80 %, tout en garantissant que les politiques de sécurité restent cohérentes et sans erreur de traductions. Et pour ça, on développe une application web locale capable de :

Lire un fichier de configuration XML d’un pare-feu,

et en connaissant la marque au préalable,

Et générer une configuration équivalente pour un autre constructeur. »


## 🎬 [Vidéo : Ilyesse / Fred]
« En gros, vous lui donnez un fichier WatchGuard… et hop ! Il vous sort un fichier compatible OPNsense ou vice-versa. Et bientôt, d’autres marques. L’idée, c’est d’aider les techniciens à éviter les copier-coller interminables et les erreurs humaines. »


## 🎤 Nicolas (Jamy) :
« Techniquement, l’outil propose trois briques :

La création de fichiers de configuration propres, via un formulaire complet qu'il faut remplir.

L’analyse automatique de fichiers existants. Vous rentrez un fichier et une description vous est affichée.

Et surtout, le convertisseur inter-marques, le cœur du projet qui regroupe les deux briques du dessus.

## 🎤 Tanguy :
« Et ce n’est pas seulement un outil sympa : c’est un véritable gain de productivité pour les ESN, les intégrateurs, ou les équipes IT.
Notre modèle :

un logiciel open-source gratuit,

et une option payante pour les fonctionnalités avancées comme la gestion des sauvegardes ou du support. »


## 🎬 [Vidéo : Ilyesse / Fred]
« Bien sûr, tout ça ne se fait pas en claquant des doigts. Les formats XML changent, certaines licences coûtent cher, et on a parfois du mal à avoir du matériel pour tester. Mais regardez, ils ont tout prévu ! »


## 🎤 Nicolas (Jamy) :
« Niveau budget, l’essentiel est humain, avec environ 150 heures de travail sur l’année. Les licences et le matériel haut de gamme peuvent coûter cher, parfois plusieurs dizaines de miliers d'euros pans ans, mais l’IUT nous fournit WatchGuard, Stormshield et de quoi tester. »


## 🎤 Tanguy :
« Les risques ? Format XML instable, compatibilité entre marques, et une petite équipe. Mais on a un planning sur 30 semaines, des phases de tests réelles, et un prototype fonctionnel en développement. »


## 🎬 [Vidéo : Ilyesse / Fred – conclusion]
« En résumé : un projet utile, faisable, et qui répond à un vrai besoin dans le monde pro. On automatise une tâche pénible, on limite les erreurs, et on aide les entreprises à passer d’un pare-feu à un autre sans galérer. »


## 🎤 Nicolas & Tanguy (ensemble) :
« Merci à tous ! Et on vous donne rendez-vous prochainement pour une démonstration du convertisseur en action. »
