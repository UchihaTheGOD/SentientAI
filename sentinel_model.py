try:
    import torch
    import torch.nn as nn
    _TORCH_AVAILABLE = True
except ImportError:  # Phase 0: torch not installed — keep import safe
    torch = None  # type: ignore
    nn = None  # type: ignore
    _TORCH_AVAILABLE = False
try:
    from model.config import SentinelConfig  # when run as package with model/ layout (backup)
except ModuleNotFoundError:
    from config import SentinelConfig  # project root layout

if _TORCH_AVAILABLE:
    _Base = nn.Module
else:
    class _Base:  # type: ignore
        def __init__(self, *a, **kw): pass
class SentinelModel(_Base):
    def __init__(self, config=None):
        super().__init__()
        self.config = config or SentinelConfig()
        self.token_embedding = nn.Embedding(self.config.vocab_size, self.config.hidden_size, padding_idx=self.config.pad_token_id)
        self.position_embedding = nn.Embedding(self.config.max_position_embeddings, self.config.hidden_size)
        layer = nn.TransformerEncoderLayer(
            d_model=self.config.hidden_size, nhead=self.config.num_heads,
            dim_feedforward=self.config.intermediate_size, dropout=self.config.dropout,
            activation="gelu", batch_first=True, norm_first=True
        )
        self.transformer = nn.TransformerEncoder(layer, num_layers=self.config.num_layers)
        self.norm = nn.LayerNorm(self.config.hidden_size)
        self.lm_head = nn.Linear(self.config.hidden_size, self.config.vocab_size, bias=False)
        self.lm_head.weight = self.token_embedding.weight
        self.apply(self._init_weights)

    def _init_weights(self, module):
        if isinstance(module, nn.Linear):
            nn.init.normal_(module.weight, mean=0.0, std=0.02)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            nn.init.normal_(module.weight, mean=0.0, std=0.02)

    def forward(self, input_ids, labels=None):
        _, seq_len = input_ids.shape
        if seq_len > self.config.max_position_embeddings:
            raise ValueError(f"Sequence length {seq_len} exceeds context length {self.config.max_position_embeddings}")
        pos = torch.arange(seq_len, device=input_ids.device).unsqueeze(0)
        x = self.token_embedding(input_ids) + self.position_embedding(pos)
        causal = torch.triu(torch.ones(seq_len, seq_len, device=input_ids.device, dtype=torch.bool), diagonal=1)
        padding = input_ids.eq(self.config.pad_token_id)
        x = self.transformer(x, mask=causal, src_key_padding_mask=padding)
        logits = self.lm_head(self.norm(x))
        loss = None
        if labels is not None:
            loss = nn.CrossEntropyLoss(ignore_index=self.config.pad_token_id)(
                logits[:, :-1, :].contiguous().view(-1, self.config.vocab_size),
                labels[:, 1:].contiguous().view(-1)
            )
        return {"logits": logits, "loss": loss}
