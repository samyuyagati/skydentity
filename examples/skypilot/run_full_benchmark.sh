FIREBASE_CREDS=$1
NUM_JOBS=$2

# Cleanup from old runs
mkdir -p logs/with_skydentity_10/run0
mv logs/with_skydentity_10/*.txt logs/with_skydentity_10/run0

# Run 1: with Skydentity
./skypilot_benchmark.sh "$FIREBASE_CREDS" $NUM_JOBS "logs/with_skydentity_batch10_run1.out"

mkdir -p logs/with_skydentity_10/run1
mv logs/with_skydentity_10/*.txt logs/with_skydentity_10/run1

sky down -a -y

sleep 30

# Run 1: Baseline
mkdir -p logs/baseline_10/run0
mv logs/baseline_10/*.txt logs/baseline_10/run0

./skypilot_baseline $NUM_JOBS logs/baseline_batch10_run1.out

mkdir -p logs/baseline_10/run1
mv logs/baseline_10/*.txt logs/baseline_10/run1

sky down -a -y

sleep 30

# Run 2: with Skydentity
./skypilot_benchmark.sh "$FIREBASE_CREDS" $NUM_JOBS "logs/with_skydentity_batch10_run2.out"

mkdir -p logs/with_skydentity_10/run2
mv logs/with_skydentity_10/*.txt logs/with_skydentity_10/run2

sky down -a -y

sleep 30

# Run 2: Baseline
./skypilot_baseline $NUM_JOBS logs/baseline_batch10_run2.out

mkdir -p logs/baseline_10/run2
mv logs/baseline_10/*.txt logs/baseline_10/run2

sky down -a -y

sleep 30

# Run 3: with Skydentity
./skypilot_benchmark.sh "$FIREBASE_CREDS" $NUM_JOBS "logs/with_skydentity_batch10_run3.out"

mkdir -p logs/with_skydentity_10/run3
mv logs/with_skydentity_10/*.txt logs/with_skydentity_10/run3

sky down -a -y

sleep 30

# Run 3: Baseline
./skypilot_baseline $NUM_JOBS logs/baseline_batch10_run3.out

mkdir -p logs/baseline_10/run3
mv logs/baseline_10/*.txt logs/baseline_10/run3

sky down -a -y