from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class SourceManager:
    """Map JSON paths to local filesystem paths and read code segments."""

    def __init__(self, local_v1_path: str, local_v2_path: str) -> None:
        """Set local repo roots and initialize include resolution caches."""
        self.local_v1_path = Path(local_v1_path).resolve()
        self.local_v2_path = Path(local_v2_path).resolve()
        self._include_cache: Dict[Tuple[str, str], Optional[Path]] = {}
        self._git_file_cache: Dict[Tuple[str, str, str], Optional[str]] = {}
        self._generated_file_cache: Dict[Tuple[str, str], Optional[str]] = {}
        self._include_dirs = {
            "v1": self._default_include_dirs(self.local_v1_path),
            "v2": self._default_include_dirs(self.local_v2_path),
        }

    def _default_include_dirs(self, root: Path) -> List[Path]:
        include_dir = root / "include"
        return [include_dir] if include_dir.is_dir() else [root]

    def _resolve_include(self, header: str, version: str) -> Optional[Path]:
        cache_key = (version, header)
        if cache_key in self._include_cache:
            return self._include_cache[cache_key]
        for inc_dir in self._include_dirs.get(version, []):
            candidate = inc_dir / header
            if candidate.exists():
                self._include_cache[cache_key] = candidate.resolve()
                return self._include_cache[cache_key]
        for path in self._repo_root(version).rglob(header):
            if path.is_file():
                self._include_cache[cache_key] = path.resolve()
                return self._include_cache[cache_key]
        self._include_cache[cache_key] = None
        return None

    @staticmethod
    def _strip_repo_name_prefix(path_s: str, *, repo_name: str = "") -> str:
        s = str(path_s or "").replace("\\", "/").strip()
        repo = str(repo_name or "").strip()
        if not s or not repo:
            return s
        if s == repo:
            return ""
        if s.startswith(repo + "/"):
            return s[len(repo) + 1 :]
        repo_src = f"{repo}-src"
        if s == repo_src:
            return ""
        if s.startswith(repo_src + "/"):
            return s[len(repo_src) + 1 :]
        return s

    @staticmethod
    def _strip_src_repo_prefix(path_s: str, *, repo_name: str = "") -> str:
        s = str(path_s or "").replace("\\", "/").strip()
        if not s:
            return ""
        if s.startswith("/src/"):
            s = s[len("/src/") :]
        elif s == "/src":
            s = ""
        elif s.startswith("src/"):
            s = s[len("src/") :]
        elif s == "src":
            s = ""
        return SourceManager._strip_repo_name_prefix(s, repo_name=repo_name)

    def _repo_relative_path(self, file_path: str, version: str, *, resolved: Optional[Path] = None) -> str:
        root = self._repo_root(version).resolve()
        repo_name = str(root.name or "").strip()

        if resolved is not None:
            try:
                return resolved.resolve().relative_to(root).as_posix()
            except Exception:
                pass

        raw = str(file_path or "").strip()
        if not raw:
            return ""

        if raw.lstrip().startswith("#include") or "#include" in raw:
            after = raw.split("#include", 1)[-1].strip()
            if "<" in after and ">" in after:
                return str(after.split("<", 1)[1].split(">", 1)[0]).strip()
            return str(after).strip().strip('"').strip("<>")

        path = raw.replace("\\", "/")
        if path.startswith("/src") or path.startswith("src/"):
            return self._strip_src_repo_prefix(path, repo_name=repo_name)
        path = path.lstrip("/")
        return self._strip_repo_name_prefix(path, repo_name=repo_name)

    def _repo_relative_candidates(self, file_path: str, version: str, *, resolved: Optional[Path] = None) -> List[str]:
        """Return ordered repo-relative path candidates for fallbacks (git/generated)."""
        root = self._repo_root(version).resolve()
        repo_name = str(root.name or "").strip()
        raw = str(file_path or "").replace("\\", "/").strip()
        raw_rel = raw.lstrip("/")

        candidates: List[str] = []
        seen: set[str] = set()

        def add(path_s: str) -> None:
            rel = str(path_s or "").replace("\\", "/").strip().lstrip("/")
            if not rel:
                return
            if rel in seen:
                return
            seen.add(rel)
            candidates.append(rel)

        # Primary canonical candidate.
        add(self._repo_relative_path(file_path, version, resolved=resolved))

        # Direct raw relative path and repo-name normalization.
        add(raw_rel)
        add(self._strip_repo_name_prefix(raw_rel, repo_name=repo_name))

        if raw_rel.startswith("src/"):
            add(self._strip_src_repo_prefix(raw_rel, repo_name=repo_name))
        else:
            # Many repos nest paths under src/, while diagnostics may omit the prefix.
            add(f"src/{raw_rel}" if raw_rel else "")

        # If we resolved to an absolute path, include the concrete relative path from repo root.
        if resolved is not None:
            try:
                add(resolved.resolve().relative_to(root).as_posix())
            except Exception:
                pass

        return candidates

    @staticmethod
    def _expand_make_vars(text: str, variables: Dict[str, str]) -> str:
        out = str(text or "")
        for _ in range(4):
            updated = re.sub(r"\$\(([^)]+)\)", lambda m: variables.get(str(m.group(1) or "").strip(), m.group(0)), out)
            if updated == out:
                break
            out = updated
        return out

    @staticmethod
    def _parse_echo_recipe_line(line: str) -> Tuple[str, str, str]:
        cmd = str(line or "").strip()
        if cmd.startswith("@"):
            cmd = cmd[1:].lstrip()
        if not cmd.startswith("echo "):
            return "", "", ""
        body = cmd[len("echo ") :].lstrip()
        if not body:
            return "", "", ""

        quote = body[0]
        if quote not in {"'", '"'}:
            return "", "", ""
        i = 1
        payload_chars: List[str] = []
        while i < len(body):
            ch = body[i]
            if quote == '"' and ch == "\\" and i + 1 < len(body):
                payload_chars.append(body[i + 1])
                i += 2
                continue
            if ch == quote:
                break
            payload_chars.append(ch)
            i += 1
        if i >= len(body) or body[i] != quote:
            return "", "", ""

        tail = body[i + 1 :].strip()
        if not tail.startswith(">"):
            return "", "", ""
        redir = ">>" if tail.startswith(">>") else ">"
        out_tail = tail[len(redir) :].strip()
        out = out_tail.split()[0] if out_tail else ""
        if not out:
            return "", "", ""
        return "".join(payload_chars), redir, out

    @staticmethod
    def _make_var_map(lines: List[str]) -> Dict[str, str]:
        vars_map: Dict[str, str] = {}
        assign_re = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*([:+?]?=)\s*(.*?)\s*$")
        for raw in lines:
            line = str(raw or "")
            if not line.strip() or line.lstrip().startswith("#") or line.startswith("\t"):
                continue
            m = assign_re.match(line)
            if not m:
                continue
            name = str(m.group(1) or "").strip()
            op = str(m.group(2) or "").strip()
            value = str(m.group(3) or "").strip()
            if not name:
                continue
            if op == "?=" and name in vars_map:
                continue
            if op == "+=":
                vars_map[name] = (str(vars_map.get(name, "")).strip() + " " + value).strip()
            else:
                vars_map[name] = value
        return vars_map

    def _candidate_makefiles(self, rel_path: str, version: str) -> List[Path]:
        root = self._repo_root(version)
        names = ("Makefile", "makefile", "GNUmakefile")
        candidates: List[Path] = []
        seen: set[Path] = set()

        def add(path: Path) -> None:
            if path in seen:
                return
            seen.add(path)
            if path.is_file():
                candidates.append(path)

        for name in names:
            add(root / name)

        parent = Path(str(rel_path or "")).parent
        while str(parent) not in {"", "."}:
            for name in names:
                add(root / parent / name)
            parent = parent.parent
        return candidates

    @staticmethod
    def _normalize_target_token(token: str) -> str:
        s = str(token or "").strip()
        if s.startswith("./"):
            s = s[2:]
        return s.replace("\\", "/")

    def _synthesize_generated_file(self, rel_path: str, version: str) -> str:
        rel_norm = self._normalize_target_token(rel_path)
        if not rel_norm:
            return ""
        cache_key = (version, rel_norm)
        if cache_key in self._generated_file_cache:
            return self._generated_file_cache[cache_key] or ""

        rel_base = Path(rel_norm).name
        for makefile in self._candidate_makefiles(rel_norm, version):
            try:
                lines = makefile.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue
            vars_map = self._make_var_map(lines)

            i = 0
            while i < len(lines):
                line = str(lines[i] or "")
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or line.startswith("\t") or ":" not in line:
                    i += 1
                    continue

                lhs = line.split(":", 1)[0].strip()
                # Skip variable assignments and special forms that are not target rules.
                if not lhs or any(op in lhs for op in ("=", ":=", "+=", "?=")):
                    i += 1
                    continue
                targets = [self._normalize_target_token(t) for t in lhs.split() if t.strip()]
                if not targets:
                    i += 1
                    continue
                matched_target = ""
                for t in targets:
                    if t == rel_norm or t == rel_base:
                        matched_target = t
                        break
                if not matched_target:
                    i += 1
                    continue

                j = i + 1
                generated_lines: List[str] = []
                while j < len(lines):
                    recipe_line = str(lines[j] or "")
                    if not recipe_line.startswith("\t"):
                        break
                    payload, redir, out = self._parse_echo_recipe_line(recipe_line.lstrip("\t"))
                    if payload and out:
                        out_norm = self._normalize_target_token(out)
                        if out_norm in {"$@", matched_target, rel_norm, rel_base} or out_norm.endswith("/" + rel_norm):
                            expanded = self._expand_make_vars(payload, vars_map)
                            if redir == ">":
                                generated_lines = [expanded]
                            else:
                                generated_lines.append(expanded)
                    j += 1
                if generated_lines:
                    text = "\n".join(generated_lines).rstrip("\n") + "\n"
                    self._generated_file_cache[cache_key] = text
                    return text
                i = j
            # Keep scanning other makefiles.

        self._generated_file_cache[cache_key] = None
        return ""

    def _repo_root(self, version: str) -> Path:
        return self.local_v1_path if version == "v1" else self.local_v2_path

    def _git_commit_hint(self, version: str) -> str:
        name = "REACT_AGENT_V1_SRC_COMMIT" if version == "v1" else "REACT_AGENT_V2_SRC_COMMIT"
        return str(os.environ.get(name, "") or "").strip()

    def _git_show_file(self, rel_path: str, version: str) -> str:
        """Return file content from `git show <commit>:<path>` when the working tree lacks the file."""
        rel = str(rel_path or "").lstrip("/").replace("\\", "/").strip()
        if not rel:
            return ""
        commit = self._git_commit_hint(version)
        if not commit:
            return ""

        repo_root = self._repo_root(version)
        cache_key = (version, commit, rel)
        if cache_key in self._git_file_cache:
            return self._git_file_cache[cache_key] or ""

        try:
            proc = subprocess.run(
                ["git", "-C", str(repo_root), "show", f"{commit}:{rel}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
        except Exception:
            self._git_file_cache[cache_key] = None
            return ""

        if int(proc.returncode) != 0:
            self._git_file_cache[cache_key] = None
            return ""
        text = str(proc.stdout or "")
        self._git_file_cache[cache_key] = text
        return text

    def _resolve_path(self, json_path: str, version: str) -> Optional[Path]:
        """Resolve a JSON path to a local file path."""
        norm_path = str(json_path or "").replace("\\", "/").strip()
        if norm_path.startswith("/src") or norm_path.startswith("src/"):
            rel = norm_path[len("/src") :] if norm_path.startswith("/src") else norm_path[len("src") :]
            rel = rel.lstrip("/")
            repo_root = self._repo_root(version)
            repo_name = repo_root.name
            if repo_name:
                rel = self._strip_src_repo_prefix(rel, repo_name=repo_name)
            if not rel:
                return repo_root

            candidate = repo_root / rel
            if candidate.exists():
                return candidate

            # Fallback: some diagnostics still include an extra "<repo>/" segment after /src stripping.
            rel_wo_repo = self._strip_repo_name_prefix(rel, repo_name=repo_name)
            if rel_wo_repo and rel_wo_repo != rel:
                candidate2 = repo_root / rel_wo_repo
                if candidate2.exists():
                    return candidate2

            # Fallback: the repo may nest sources under src/ (e.g. ndpi/src/include/...),
            # so try the original path relative to repo root before stripping src/.
            candidate_orig = repo_root / norm_path.lstrip("/")
            if candidate_orig.exists():
                return candidate_orig

            # Fallback: prefer a top-level file match when basename is unique at repo root.
            base = Path(rel).name
            if base:
                root_base = repo_root / base
                if root_base.exists():
                    return root_base
            return candidate
        if norm_path.lstrip().startswith("#include") or "#include" in norm_path:
            after = norm_path.split("#include", 1)[-1].strip()
            header = (
                after.split("<")[-1].split(">")[0].strip()
                if "<" in after and ">" in after
                else after.strip().strip('"')
            )
            resolved = self._resolve_include(header, version)
            if resolved is not None:
                return resolved
            # Generated headers (for example, version.h) may not exist before build.
            # Return the expected repo path so later fallbacks can synthesize content.
            if header:
                return self._repo_root(version) / header
            return None
        path = Path(norm_path)
        if path.is_absolute():
            return path
        repo_root = self._repo_root(version)
        candidate = repo_root / norm_path
        if candidate.exists():
            return candidate

        repo_name = repo_root.name
        rel_wo_repo = self._strip_repo_name_prefix(norm_path, repo_name=repo_name)
        if rel_wo_repo and rel_wo_repo != norm_path:
            candidate2 = repo_root / rel_wo_repo
            if candidate2.exists():
                return candidate2
        return candidate

    def get_code_segment(self, file_path: str, start_line: int, end_line: int, version: str) -> str:
        """Read a code segment between start_line and end_line (inclusive)."""
        resolved = self._resolve_path(file_path, version)
        rel_candidates = self._repo_relative_candidates(file_path, version, resolved=resolved)
        text = ""

        # Prefer git-object reads when a commit hint is configured. This avoids subtle mismatches where
        # the configured --v1-src/--v2-src worktrees exist but are checked out at a different revision
        # than the KB JSON (line numbers/extents drift and we extract the wrong lines).
        if self._git_commit_hint(version):
            for rel in rel_candidates:
                if Path(rel).is_absolute():
                    continue
                text = self._git_show_file(rel, version)
                if text:
                    break

        if not text:
            if resolved and resolved.exists():
                text = resolved.read_text(encoding="utf-8", errors="replace")
            else:
                # Fallback: if the file isn't present in the working tree, try reading from git objects
                # using REACT_AGENT_V1_SRC_COMMIT / REACT_AGENT_V2_SRC_COMMIT.
                for rel in rel_candidates:
                    if Path(rel).is_absolute():
                        continue
                    text = self._git_show_file(rel, version)
                    if text:
                        break
                if not text:
                    for rel in rel_candidates:
                        # Generated headers may not exist in either the worktree or git objects.
                        text = self._synthesize_generated_file(rel, version)
                        if text:
                            break
                if not text:
                    return ""
        lines = text.splitlines()
        start = max(start_line - 1, 0)
        end = min(end_line, len(lines))
        return "\n".join(lines[start:end])

    def get_function_code(self, kb_node: dict, version: str) -> str:
        """Return the source code for a node's extent."""
        extent = kb_node.get("extent", {})
        start = extent.get("start", {})
        end = extent.get("end", {})
        file_path = start.get("file") or kb_node.get("location", {}).get("file")
        if not file_path:
            return ""
        start_line = int(start.get("line", 1))
        end_line = int(end.get("line", start_line))
        return self.get_code_segment(file_path, start_line, end_line, version)
