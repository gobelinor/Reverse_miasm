PASSWORD="$1"
FOLDER="." # Dossier courant

# Boucle sur toutes les archives .7z du dossier
for file in "$FOLDER"/*.7z; do
    if [ -f "$file" ]; then
        echo "Décompression de : $file"
        7z x -p"$PASSWORD" "$file" -o"${file%.7z}" -y
        if [ $? -eq 0 ]; then
            echo "✅ Décompression réussie : $file"
        else
            echo "❌ Erreur lors de la décompression : $file"
        fi
    fi
done

echo "🎉 Terminé !"
