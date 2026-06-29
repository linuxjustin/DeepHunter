# Dataset Specification

## Format

Datasets are stored as JSONL (JSON Lines) files — one JSON object per line.

## Sample Structure

```json
{
  "instruction": "Summarize the following security knowledge",
  "input": "JWT (JSON Web Tokens) are commonly used for authentication...",
  "output": "Common JWT attacks including alg confusion and key confusion.",
  "source": "https://example.com/jwt",
  "metadata": {
    "sko_id": "sko-abc123",
    "type": "summarization"
  }
}
```

## Sample Types

| Type | Instruction | Output |
|---|---|---|
| `summarization` | "Summarize the following security knowledge" | SKO summary |
| `bug_classification` | "Identify bug classes in this security context" | Comma-separated bug classes |
| `hypothesis` | "Generate a hypothesis for {context}" | Structured hypothesis |
| `text` | "" (empty) | Raw content for continued pre-training |

## Usage

Datasets can be used for:
- Fine-tuning LLMs on security knowledge
- Training classification models for bug class detection
- Evaluating RAG pipeline quality