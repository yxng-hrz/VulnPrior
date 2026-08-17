# Post LinkedIn - lancement de VulnPrior

🚀 Nouveau projet personnel : **VulnPrior**

Une vulnérabilité avec un CVSS très élevé n’est pas forcément celle qu’une organisation doit corriger en premier.

J’ai donc développé **VulnPrior**, un moteur de priorisation orienté gouvernance qui croise la sévérité technique avec le contexte d’exploitation et la criticité métier.

Le score prend notamment en compte :
- CVSS
- EPSS
- présence dans un catalogue de vulnérabilités exploitées
- criticité de l’actif
- exposition Internet
- sensibilité des données
- environnement de production
- contrôles compensatoires

L’objectif n’est pas de créer un scanner supplémentaire, mais de répondre à une question plus proche du pilotage RSSI :

**quelles vulnérabilités faut-il traiter en premier, sur quels actifs, avec quel délai et pourquoi ?**

Le projet comprend une API FastAPI, un dashboard, un moteur de scoring explicable, des imports CSV, SQLite/PostgreSQL, Docker, des tests automatisés et une CI GitHub Actions.

Le code est disponible sur mon GitHub.

#Cybersecurity #CISO #RSSI #RiskManagement #VulnerabilityManagement #Python #GRC
