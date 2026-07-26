"""FP sentinel for the weights_only flag.

Two shapes must stay silent: torch.load with the safe default, and PyTorch
Lightning's save_checkpoint, which uses the SAME keyword to mean "save the whole
model rather than just weights" -- harmless, and the reason the rule is anchored
on the torch.load callee instead of matching the keyword alone.
"""
import torch


def load_trusted(path):
    return torch.load(path, weights_only=True)


def save(trainer, ckpt_path):
    trainer.save_checkpoint(ckpt_path, weights_only=False)
