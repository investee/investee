#!/usr/bin/env bash

SVC_HANDLER_ADDR=${1:-0x0}

if [ $SVC_HANDLER_ADDR == "0x0" ]; then
    echo "No valid svc-handler address specified!"
    echo "Run 'cat /proc/kallsyms | grep el0t_64_sync_handler' to get address!"
    exit -1
fi

# Create a temporary GDB script file
SCRIPT_FILE=$(mktemp)

# Write the GDB commands to the script file with the variable substituted
cat <<EOF > $SCRIPT_FILE
target remote :1234
b *$SVC_HANDLER_ADDR
commands
printf "Param 1: %#x\\n", *(long long *)(\$sp + 0x0)
printf "Param 2: %#x\\n", *(long long *)(\$sp + 0x8)
printf "Param 3: %#x\\n", *(long long *)(\$sp + 0x10)
printf "Param 4: %#x\\n", *(long long *)(\$sp + 0x18)
printf "Param 5: %#x\\n", *(long long *)(\$sp + 0x20)
printf "Param 6: %#x\\n", *(long long *)(\$sp + 0x28)
printf "Param 7: %#x\\n", *(long long *)(\$sp + 0x30)
printf "Param 8: %#x\\n", *(long long *)(\$sp + 0x38)
continue
end
continue
EOF

rm -f src/svc-gdb.log
touch src/svc-gdb.log
chmod 777 src/svc-gdb.log

# Run GDB with the generated script file
gdb-multiarch -batch -x $SCRIPT_FILE 2>&1 | tee src/svc-gdb.log 

# Clean up the temporary script file
rm $SCRIPT_FILE