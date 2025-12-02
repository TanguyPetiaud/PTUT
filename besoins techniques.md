But final
===
L'application est capable de lire un fichier .xml, de l'interpréter (en reconnaissant le fabricant), et d'écrire (ou modifier) un fichier de configuration pour le fabricant choisi.

Une interface graphique permet de choisir les éléments de configuration voulus, après analyse d'un fichier existant ou à partir de zéro.



Fonctionnement
===
1. L'utilisateur ouvre un navigateur web et charge la page.

2. Il a le choix de créer une configuration de zéro, ou de charger un fichier.
S'il charge le fichier, skip à l'étape 4.

3. L'utilisateur entre les paramètres systèmes voulus: nombre et adresses IP des interfaces, VLANs, NAT...
Cette partie doit être synthétique, aller le plus vite possible et tenir la main à l'utilisateur pour éviter une perte de temps.

4. L'utilisateur entre les paramètres de sécurité voulus: ce sont les règles de pare-feu.
S'il a analysé un fichier, les règles existantes dans ce fichier sont préentrées, et l'utilisateur a la possibilité de les modifier.

5. L'utilisateur choisit un fabricant (et un modèle) de destination.
Le programme écrit le fichier de configuration final.



Architecture
===
Le programme est constitué d'un executable, qui génère une page web (ou host un serveur local).
En mode génération, cette page web permet à l'utilisateur de remplir des formulaires, que l'application utilisera pour générer une configuration.
En mode conversion, cette page web permet d'"uploader" un fichier de configuration, et permettra de choisir une marque/modèle de destination et exportera un fichier dans la marque choisie.

La page web permettra de remplir des informations, selon les capacités du modèle interne.

Il doit être clair pour l'utilisateur que le logiciel ne fera pas tout pour lui.
De la même manière, la conversion de la configuration ne sera pas en mesure de traiter l'entièreté de la configuration originale.
Les capacités de l'application seront limitées par l'envergure du modèle interne.