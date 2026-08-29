import io
import pickle
import joblib
import struct

print("=== CHECKING FTTRANSFORMER PTH WEIGHT KEYS ===")
import torch
sd1 = torch.load("FTTransformer_cicids2017.pth", map_location="cpu")
sd2 = torch.load("ft_transformer_cicids2017.pth", map_location="cpu")
print("FTTransformer_cicids2017.pth keys:", list(sd1.keys())[:10])
print("ft_transformer_cicids2017.pth keys:", list(sd2.keys())[:10])

# Check if weights are identical or different
diffs = 0
for k in sd1:
    if not torch.equal(sd1[k], sd2[k]):
        diffs += 1
print(f"Weight differences between FTTransformer and ft_transformer: {diffs} out of {len(sd1)}")

print("\n=== CHECKING RTDL MODULE ===")
import rtdl_revisiting_models as rtdl
print("dir(rtdl):", [x for x in dir(rtdl) if not x.startswith("_")])

# Check if rtdl package is available or if we can construct the exact PyTorch architecture matching sd1 keys
print("\n=== MATCHING SD1 KEYS TO PYTORCH ARCHITECTURE ===")
for k, v in sd1.items():
    print(f"  {k}: {v.shape}")

