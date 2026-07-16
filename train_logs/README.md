# 训练日志归档

这个目录用于在多台机器之间同步实验产物。

目录结构：

```text
train_logs/
  <模型>/
    <数据集>/
      Result.md
      log_files/
      result_files/
```

这里使用 `log_files/` 和 `result_files/`，而不是 `logs/` 和 `results/`，因为仓库的 `.gitignore` 会忽略名为 `logs/` 和 `results/` 的目录。
