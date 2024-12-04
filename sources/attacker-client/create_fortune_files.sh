#!/bin/bash

# Loop to create 10 files
for i in {1..10}
do
    # Generate the filename
    filename="file_$i.txt"
    
    # Write the output of the fortune command to the file
    fortune > "/home/student/test/$filename"
    
    # Confirm creation (optional)
    echo "Created /home/student/test/$filename"
done

