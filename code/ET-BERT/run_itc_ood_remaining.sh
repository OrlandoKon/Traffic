#!/usr/bin/env zsh
set -euo pipefail

cd /root/Repository/Traffic/code/ET-BERT

PY=/root/.local/share/mamba/envs/etbert/bin/python
DATASET=ITC-Net-Blend-60
LOG_DIR=logs
RESULT_DIR=results/${DATASET}
RUN_LOG=${LOG_DIR}/itc_ood_remaining_runner.log

mkdir -p "${LOG_DIR}" "${RESULT_DIR}"

echo "[$(date -Is)] runner started" >> "${RUN_LOG}"

for F in A B C D; do
  RESULT_FILE="${RESULT_DIR}/${F}_6e-05_False_results.json"

  if [[ -f "${RESULT_FILE}" ]] && grep -q '"epoch": "test"' "${RESULT_FILE}"; then
    echo "[$(date -Is)] fold_${F} already has test result; skip" >> "${RUN_LOG}"
    continue
  fi

  if [[ -f "${RESULT_FILE}" ]]; then
    PARTIAL="${RESULT_FILE}.partial_$(date +%Y%m%d_%H%M%S)"
    mv "${RESULT_FILE}" "${PARTIAL}"
    echo "[$(date -Is)] fold_${F} partial result moved to ${PARTIAL}" >> "${RUN_LOG}"
  fi

  echo "[$(date -Is)] start fold_${F}" >> "${RUN_LOG}"
  CUDA_VISIBLE_DEVICES=0 "${PY}" fine-tuning/run_classifier_ori.py \
    --pretrained_model_path models/pre-trained_model.bin \
    --vocab_path models/encryptd_vocab.txt \
    --train_path datasets/${DATASET}/fold_${F} \
    --dev_path datasets/${DATASET}/fold_${F} \
    --test_path datasets/${DATASET}/fold_${F} \
    --epochs_num 10 --batch_size 32 \
    --embedding word pos seg \
    --encoder transformer --mask fully_visible \
    --seq_length 512 --learning_rate 6e-5 \
    --dropout 0.5 \
    --dataset "${DATASET}" \
    --output_model_path outputs/${DATASET}/fold_${F} \
    > "${LOG_DIR}/itc_ood_fold_${F}_10epoch.log" 2>&1
  status=$?
  echo "[$(date -Is)] done fold_${F} status=${status}" >> "${RUN_LOG}"
  [[ "${status}" -eq 0 ]]
done

echo "[$(date -Is)] runner finished" >> "${RUN_LOG}"
