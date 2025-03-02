#!/bin/bash
# Parcours des fichiers du répertoire courant
for file in *.exe; do
    # Vérifier si le fichier existe et est un fichier régulier
    if [[ -f "$file" ]]; then
        echo "Traitement de $file :"
        # Exécuter strings et afficher la 9ème ligne
        strings "$file" | sed -n '9p'
        echo "--------------------------"
    fi
done

