
data = [
    {"ACC": 0.2060, "Pre": 0.2101, "Rec": 0.2075, "F1": 0.1278, "Inference time": 0.0276},
    {"ACC": 0.2060, "Pre": 0.1797, "Rec": 0.1659, "F1": 0.1117, "Inference time": 0.0275},
    {"ACC": 0.2563, "Pre": 0.2653, "Rec": 0.1929, "F1": 0.1452, "Inference time": 0.0294}
]

keys = ["ACC", "Pre", "Rec", "F1", "Inference time"]
averages = {key: 0.0 for key in keys}

for row in data:
    for key in keys:
        averages[key] += row[key]

for key in keys:
    averages[key] /= len(data)

# Format the output as a markdown table row
output_row = "| Average |"
for key in keys:
    output_row += f" {averages[key]:.4f} |"

print("Calculated Averages:")
for key in keys:
    print(f"{key}: {averages[key]:.4f}")

print("\nMarkdown Row:")
print(output_row)
