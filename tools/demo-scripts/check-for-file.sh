FILE=/etc/endar-test.txt
if test -f "$FILE"; then
    exit 0
fi

exit 1
