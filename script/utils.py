from typing import List, Any, Callable, Dict, Tuple
import copy

# Type: test_fn takes a list of patches (order preserved) and returns True/False
TestFn = Callable[[List[Any]], bool]

def minimize_greedy(patches: List[Any], test_fn: TestFn, context: Tuple) -> List[Any]:
    """
    Fast heuristic: try removing one patch at a time (left-to-right),
    keep the removal if test_fn still returns True. Repeat until stable.
    """
    cur = list(patches)
    changed = True
    cache: Dict[Tuple[int, ...], bool] = {}

    def cached_test(items: List[Any]) -> bool:
        key = tuple(id(x) for x in items)  # identity-based; avoids equals() surprises
        if key not in cache:
            items_copy = copy.deepcopy(items)
            ctx_copy   = copy.deepcopy(context)
            cache[key] = test_fn(items_copy, *ctx_copy)
        return cache[key]

    while changed:
        changed = False
        i = 0
        while i < len(cur):
            trial = cur[:i] + cur[i+1:]
            if cached_test(trial) == 'trigger_and_fuzzer_build':
                cur = trial
                changed = True
                break
                # do not increment i; the next element shifted into position i
            else:
                i += 1
    return cur


def minimize_ddmin(patches: List[Any], test_fn: TestFn, context: Tuple) -> List[Any]:
    """
    Zeller's ddmin: returns a 1-minimal subset S ⊆ patches such that test_fn(S) is True,
    and for every single element e in S, test_fn(S \ {e}) is False.
    """
    cur = list(patches)
    cache: Dict[Tuple[int, ...], bool] = {}

    def cached_test(items: List[Any]) -> bool:
        key = tuple(id(x) for x in items)
        if key not in cache:
            items_copy = copy.deepcopy(items)
            ctx_copy   = copy.deepcopy(context)
            cache[key] = test_fn(items_copy, *ctx_copy)
        return cache[key]
    
    n = 2
    while len(cur) >= 2:
        chunk_size = max(1, len(cur) // n)
        # Partition cur into n (approximately) equal contiguous chunks
        chunks = [cur[i:i+chunk_size] for i in range(0, len(cur), chunk_size)]
        removed_any = False

        # Try to eliminate whole chunks
        for idx in range(len(chunks)):
            complement = []
            for j, ch in enumerate(chunks):
                if j != idx:
                    complement.extend(ch)
            if cached_test(complement) == 'trigger_and_fuzzer_build':
                cur = complement
                n = max(2, n - 1)  # decrease granularity after success
                removed_any = True
                break  # restart with new partition

        if removed_any:
            continue

        # No chunk removable; increase granularity (finer splits)
        if n >= len(cur):
            break
        n = min(len(cur), n * 2)

    # Optional: final single-removal sweep to ensure 1-minimal
    i = 0
    while i < len(cur):
        trial = cur[:i] + cur[i+1:]
        if cached_test(trial) == 'trigger_and_fuzzer_build':
            cur = trial
        else:
            i += 1

    return cur
