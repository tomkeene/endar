FILE=/etc/endar-test.txt
if test -f "$FILE"; then
    echo "file already exists!"
    exit 0
fi
echo "file does not exist, enforcement task will run"
exit 1
