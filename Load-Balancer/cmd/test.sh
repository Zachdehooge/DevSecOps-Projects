command="wget localhost:8000 --delete-after"
num_times=20

for ((i = 1; i <= num_times; i++)); do
    echo "Running command ($i/$num_times): $command"
    eval $command
done
