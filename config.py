from dataclasses import dataclass

@dataclass
class SentinelConfig:
    vocab_size: int = 7053
    hidden_size: int = 768
    num_layers: int = 12
    num_heads: int = 12
    intermediate_size: int = 3072
    max_position_embeddings: int = 768
    dropout: float = 0.1
    pad_token_id: int = 0
    unk_token_id: int = 1
    bos_token_id: int = 2
    eos_token_id: int = 3
