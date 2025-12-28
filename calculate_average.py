
data = [
    {"ACC": 0.0888, "Pre": 0.0654, "Rec": 0.0803, "F1": 0.0445, "Inference time": 1.5463},
    {"ACC": 0.0931, "Pre": 0.0618, "Rec": 0.0826, "F1": 0.0465, "Inference time": 1.5793},
    {"ACC": 0.0911, "Pre": 0.0833, "Rec": 0.0823, "F1": 0.0462, "Inference time": 1.5485}
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
