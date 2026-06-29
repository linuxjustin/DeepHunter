"""Token budget management for the Context Engine."""

from __future__ import annotations

from deephunter.context.models import Context, ContextBlock, ContextBudget, ContextImportance


def estimate_tokens(text: str, method: str = "word_count") -> int:
    """Estimate the number of tokens in a text string.

    Uses a simple heuristic.  'word_count' divides word count by 0.75
    (approx 0.75 words per token).  'character_count' divides characters
    by 4 (approx 4 chars per token).
    """
    if method == "character_count":
        return max(1, len(text) // 4)
    words = len(text.split())
    return max(1, int(words / 0.75))


def apply_budget(
    context: Context,
    budget: ContextBudget | None = None,
    method: str = "word_count",
) -> Context:
    """Trim context blocks to fit within a token budget.

    Removes blocks in order of ascending priority until the total
    estimated tokens fit within the budget.  Blocks marked CRITICAL
    or HIGH importance are protected by ``min_important_tokens``.
    """
    b = budget or context.budget
    available = b.max_tokens - b.reserved_system_tokens - b.reserved_user_tokens

    if available <= 0:
        context.warnings.append("Token budget fully reserved; no tokens available for content.")
        return context

    for section in context.sections:
        for block in section.blocks:
            block.estimated_tokens = estimate_tokens(block.content, method)

    context.recalculate()
    total = context.get_total_tokens()

    if total <= available:
        return context

    # Collect all blocks with their section indices
    all_blocks: list[tuple[int, int, ContextBlock]] = []
    for si, section in enumerate(context.sections):
        for bi, block in enumerate(section.blocks):
            all_blocks.append((si, bi, block))

    protected_tokens = 0
    for _, _, block in all_blocks:
        if block.importance in (ContextImportance.CRITICAL, ContextImportance.HIGH):
            protected_tokens += block.estimated_tokens

    if protected_tokens > available:
        context.warnings.append(
            f"Protected blocks ({protected_tokens} tokens) exceed budget ({available} tokens). "
            "Some critical blocks may still be kept."
        )

    # Sort by priority ascending (lowest priority first), then importance rank
    all_blocks.sort(key=lambda x: (x[2].priority, _importance_value(x[2].importance)))

    blocks_to_remove: list[tuple[int, int]] = []
    running_total = total

    for si, bi, block in all_blocks:
        if running_total <= available:
            break
        # Skip protected blocks unless we have no choice
        is_protected = block.importance in (ContextImportance.CRITICAL, ContextImportance.HIGH)
        remaining_after = running_total - block.estimated_tokens
        if is_protected and remaining_after >= b.min_important_tokens:
            continue
        if is_protected and remaining_after < b.min_important_tokens:
            continue  # keep important blocks above threshold
        if is_protected and running_total > available and remaining_after <= 0:
            blocks_to_remove.append((si, bi))
            running_total -= block.estimated_tokens
            break
        if not is_protected:
            blocks_to_remove.append((si, bi))
            running_total -= block.estimated_tokens

    # Remove blocks in reverse order to maintain indices
    blocks_to_remove.reverse()
    for si, bi in blocks_to_remove:
        if bi < len(context.sections[si].blocks):
            context.sections[si].blocks.pop(bi)

    context.recalculate()

    original_total = total
    trimmed_total = context.get_total_tokens()
    context.statistics.estimated_tokens = trimmed_total

    return context


def _importance_value(importance: ContextImportance) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(importance.value, 0)
