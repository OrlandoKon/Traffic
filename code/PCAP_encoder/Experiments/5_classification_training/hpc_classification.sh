#EXPERIMENT MACRO-DATA
TASK="supervised"
LOG_LEVEL="info"
OUTPUT_PATH="./results/"

#Model info
FINETUNED_PATH_MODEL="./"
MODEL_NAME="T5-base"
TOKENIZER_NAME="T5-base" #if you use a finetuned tokenizer, specify the path
GPU=(0) #CHOOSE GPUs HERE. Elements in bash lists shall look like `(GPU1 GPU2 ...)`
GPU_STRING="$(IFS=, ; echo "${GPU[*]}"),"
PORT=2950"${GPU[0]}"

BOTTLENECK="mean"

#Training details
BATCH_SIZE=24
EPOCHS=20 #Training epochs
LR=0.001 #0. 0001 for unfrozen
MAX_QST_LENGTH=512
MAX_ANS_LENGTH=32
PERC=100   # value between [1,100]
SEED=43
LOSS="normal"
PKT_REPR_DIM=768


export GPUS_PER_NODE=1

export SCRIPT=../../2.Training/classification/classification.py
for i in 1
do
    TRAINING_DATA="/root/Traffic/code/PCAP_encoder/1.Datasets/Classification/without_IP/vpn-app/train_val_split_${i}/train.parquet"
    VAL_DATA="/root/Traffic/code/PCAP_encoder/1.Datasets/Classification/without_IP/vpn-app/train_val_split_${i}/val.parquet"
    TEST_DATA="/root/Traffic/code/PCAP_encoder/1.Datasets/Classification/without_IP/vpn-app/test.parquet"

    EXPERIMENT="Task3__DNS__NOIP" 
    IDENTIFIER="lr${LR}_seed${SEED}_loss${LOSS}_batch24_frozen_ver${i}"

    export SCRIPT_ARGS=" \
    --identifier $IDENTIFIER --experiment $EXPERIMENT --task $TASK --clean_start\
    --tokenizer_name $TOKENIZER_NAME --lr $LR --loss $LOSS --fix_encoder\
    --model_name $MODEL_NAME --log_level $LOG_LEVEL --output_path $OUTPUT_PATH\
    --training_data $TRAINING_DATA --validation_data $VAL_DATA --testing_data $TEST_DATA --epochs $EPOCHS --batch_size $BATCH_SIZE \
    --seed $SEED --bottleneck $BOTTLENECK --max_qst_length $MAX_QST_LENGTH\
    --max_ans_length $MAX_ANS_LENGTH --percentage $PERC --gpu $GPU_STRING\
    --finetuned_path_model $FINETUNED_PATH_MODEL --testing_data $TEST_DATA\
    "
    
    accelerate launch --num_processes=1 $SCRIPT $SCRIPT_ARGS
done
