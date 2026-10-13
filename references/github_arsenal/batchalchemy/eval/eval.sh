#!/bin/bash

# TODO
for file in ../test-scripts/*O?.bat; do
    if [ -f "$file" ]; then
        echo "========================================"
        echo "Processing file: $file"
        echo "========================================"

        python ./main.py "$file" &
        pid=$!

        for ((i=0; i<30; i++)); do
            if ! ps -p $pid > /dev/null; then
                break
            fi
            sleep 1
        done

        if ps -p $pid > /dev/null; then
            echo "----------------------------------------"
            echo "Process still running, killing..."
            echo "----------------------------------------"
            echo -n "" > "${file%.*}_out.bat"
            kill $pid
        fi

        wait $pid 2>/dev/null

        echo -e "Done processing file: $file\n\n"
    fi
done