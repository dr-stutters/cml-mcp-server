"""Lab recipes: ready-made `cml_build_lab` specs shipped with the package (`<name>.yaml` here), and from the
directories in CML_RECIPE_DIRS.

A recipe has a `build:` section (exactly the cml_build_lab arguments), a `verify:` contract, and
descriptive fields (summary, address plan, credentials, what to configure on the other product).

`extends: <recipe>` (L40) starts a recipe from another one's build, verify contract and actions and adds to
them (see `_extend`), so recipes that share a block (the SD-WAN fabric) keep it in one place.
"""

from __future__ import annotations

import json
import os
import re
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

import yaml

from cml_mcp._core import InvalidRequest
from cml_mcp.build import UNLICENSED_DEFINITIONS, BuildError, parse_link

RECIPE_DIR = Path(__file__).resolve().parent
# CML_RECIPE_DIRS (L42): more directories of <name>.yaml recipes, set by create_server. They are trusted like
# the package (verify probes and actions run console commands), so only the operator names them; tool callers
# pick recipes by name and never pass recipe YAML.
_EXTRA_DIRS: list[Path] = []


def use_recipe_dirs(value: str | None) -> None:
    """Search the comma- or ':'-separated directories in `value` (CML_RECIPE_DIRS) after the package."""
    _EXTRA_DIRS[:] = [
        Path(os.path.expanduser(p.strip())) for p in re.split(r"[,:]", value or "") if p.strip()
    ]


def _is_recipe(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("extends"), str) and data.get("build") is None:
        return True  # everything from the base recipe, only the descriptive fields change
    return isinstance(data.get("build"), dict)


@cache
def _packaged() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(RECIPE_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        if _is_recipe(data):
            out[str(data.get("name") or path.stem)] = data
    return out


@lru_cache(maxsize=256)
def _parse(path: str, mtime_ns: int, size: int) -> Any:
    """One recipe file's YAML, parsed again only when the file changes."""
    return yaml.safe_load(Path(path).read_text())


def _extras() -> tuple[dict[str, tuple[dict[str, Any], Path]], list[dict[str, str]]]:
    """({name: (recipe, file)} from CML_RECIPE_DIRS, [{file, problem}] skipped). Read on every call, so a
    recipe added to a mounted checkout is there without a restart. A packaged recipe wins over one of the same
    name (an identical copy, e.g. the checkout's own src/cml_mcp/recipes, is skipped silently), and an
    earlier directory over a later one."""
    packaged = _packaged()
    found: dict[str, tuple[dict[str, Any], Path]] = {}
    skipped: list[dict[str, str]] = []
    for d in _EXTRA_DIRS:
        if not d.is_dir():
            skipped.append({"file": str(d), "problem": "not a directory"})
            continue
        for path in sorted(d.glob("*.yaml")):
            try:
                st = path.stat()
                data = _parse(str(path), st.st_mtime_ns, st.st_size)
            except OSError as e:
                skipped.append({"file": str(path), "problem": f"can't be read: {e.strerror or e}"})
                continue
            except UnicodeDecodeError:
                skipped.append({"file": str(path), "problem": "not UTF-8 text"})
                continue
            except yaml.YAMLError as e:  # the line number only: the parser's excerpt could quote a value
                mark = getattr(e, "problem_mark", None)
                where = f" at line {mark.line + 1}" if mark is not None else ""
                skipped.append({"file": str(path), "problem": f"invalid YAML{where}"})
                continue
            if not _is_recipe(data):
                skipped.append({"file": str(path), "problem": "not a recipe (no build: mapping)"})
                continue
            name = str(data.get("name") or path.stem)
            if name in packaged:
                if data != packaged[name]:
                    skipped.append(
                        {
                            "file": str(path),
                            "problem": f"recipe {name!r} is packaged and the packaged one is used; give "
                            "this one another name to build it",
                        }
                    )
                continue
            if name in found:
                skipped.append(
                    {"file": str(path), "problem": f"recipe {name!r} already comes from {found[name][1]}"}
                )
                continue
            found[name] = (data, path)
    return found, skipped


# --- extends: (L40) -------------------------------------------------------------------------------------
class RecipeError(ValueError):
    """A recipe that can't be resolved (unknown base, a cycle, a removal that matches nothing)."""


def _link_ends(spec: Any) -> frozenset[tuple[str, str | None]]:
    try:
        a, b = parse_link(str(spec))
    except BuildError as e:
        raise RecipeError(str(e)) from None
    return frozenset((a, b))


def _merge_links(base: list[Any], child: list[Any]) -> list[Any]:
    """Base links, then the child's. A child link with the same two ends as a base link is that link (kept
    where it was); one that takes an interface a base link uses replaces that link in place (an interface
    has one link); any other is added at the end."""
    out = list(base)
    for link in child:
        ends = _link_ends(link)
        if any(_link_ends(b) == ends for b in out):
            continue
        named = {e for e in ends if e[1]}
        hits = [i for i, b in enumerate(out) if named & _link_ends(b)]
        if hits:
            out[hits[0]] = link
            for i in reversed(hits[1:]):
                del out[i]
        else:
            out.append(link)
    return out


def _merge_nodes(base: list[Any], child: list[Any]) -> list[Any]:
    """Base nodes in order, a child node with a base node's label merged over it (its fields win), new
    labels added at the end."""
    out = [dict(n) for n in base]
    where = {n.get("label"): i for i, n in enumerate(out)}
    for n in child:
        if not isinstance(n, dict):
            raise RecipeError("build.nodes entries must be mappings")
        if n.get("label") in where:
            out[where[n["label"]]] = {**out[where[n["label"]]], **n}
        else:
            where[n.get("label")] = len(out)
            out.append(dict(n))
    return out


def _merge_verify(base: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    """Lists (booted, nodes, targets) are joined without repeats, `addresses` merged by node, `probes` by
    name (a child probe of the same name replaces the base one), anything else replaced."""
    out = dict(base)
    for key, value in child.items():
        old = out.get(key)
        if key == "probes" and isinstance(old, list) and isinstance(value, list):
            names = {p.get("name"): i for i, p in enumerate(old) if isinstance(p, dict)}
            merged = list(old)
            for p in value:
                name = p.get("name") if isinstance(p, dict) else None
                if name is not None and name in names:
                    merged[names[name]] = p
                else:
                    merged.append(p)
            out[key] = merged
        elif isinstance(old, list) and isinstance(value, list):
            out[key] = old + [v for v in value if v not in old]
        elif isinstance(old, dict) and isinstance(value, dict):
            out[key] = {**old, **value}
        else:
            out[key] = value
    return out


def _remove(recipe: dict[str, Any], nodes: list[Any], links: list[Any]) -> dict[str, Any]:
    """`recipe` (resolved, own copies) without the `remove_nodes` (and every link, verify entry and action
    that names them) and the `remove_links`."""
    build = recipe["build"]
    labels = {n.get("label") for n in build.get("nodes") or []}
    if missing := [n for n in nodes if n not in labels]:
        raise RecipeError(f"remove_nodes names node(s) the base doesn't have: {', '.join(map(str, missing))}")
    gone = set(nodes)
    build["nodes"] = [n for n in build.get("nodes") or [] if n.get("label") not in gone]
    kept = []
    for link in build.get("links") or []:
        if not {e[0] for e in _link_ends(link)} & gone:
            kept.append(link)
    drop = [_link_ends(link) for link in links]
    if missing := [str(links[i]) for i, d in enumerate(drop) if not any(_link_ends(k) == d for k in kept)]:
        raise RecipeError(f"remove_links names link(s) the base doesn't have: {', '.join(missing)}")
    build["links"] = [k for k in kept if _link_ends(k) not in drop]
    if gone and isinstance(verify := recipe.get("verify"), dict):
        for key in ("booted", "nodes"):
            if isinstance(verify.get(key), list):
                verify[key] = [v for v in verify[key] if v not in gone]
        if isinstance(verify.get("addresses"), dict):
            verify["addresses"] = {k: v for k, v in verify["addresses"].items() if k not in gone}
        if isinstance(verify.get("probes"), list):
            verify["probes"] = [
                p for p in verify["probes"] if not (isinstance(p, dict) and p.get("node") in gone)
            ]
    if gone and isinstance(recipe.get("actions"), dict):
        recipe["actions"] = {
            k: a for k, a in recipe["actions"].items() if not (isinstance(a, dict) and a.get("node") in gone)
        }
    return recipe


def _extend(base: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    """`child` laid over its resolved `base`: descriptive fields (summary, address_plan, credentials, the
    product sides, boot_minutes) are the child's where it has them, else the base's; build.nodes merge by
    label, build.links by their ends, verify and actions as `_merge_verify` / by action name; then
    build.remove_nodes / build.remove_links drop what the child doesn't want."""
    out: dict[str, Any] = {
        **base,
        **{k: v for k, v in child.items() if k not in ("build", "verify", "actions")},
    }
    cb = child.get("build") or {}
    if not isinstance(cb, dict):
        raise RecipeError("build must be a mapping")
    bb = base["build"]
    build = {
        **bb,
        **{k: v for k, v in cb.items() if k not in ("nodes", "links", "remove_nodes", "remove_links")},
    }
    build["nodes"] = _merge_nodes(bb.get("nodes") or [], cb.get("nodes") or [])
    build["links"] = _merge_links(bb.get("links") or [], cb.get("links") or [])
    out["build"] = build
    if "verify" in child or "verify" in base:
        out["verify"] = _merge_verify(dict(base.get("verify") or {}), dict(child.get("verify") or {}))
    if "actions" in child or "actions" in base:
        if not isinstance(child.get("actions") or {}, dict):
            raise RecipeError("actions must be a mapping")
        out["actions"] = {**(base.get("actions") or {}), **(child.get("actions") or {})}
    remove_nodes, remove_links = cb.get("remove_nodes") or [], cb.get("remove_links") or []
    if not isinstance(remove_nodes, list) or not isinstance(remove_links, list):
        raise RecipeError("build.remove_nodes and build.remove_links must be lists")
    return _remove(out, remove_nodes, remove_links) if remove_nodes or remove_links else out


def _resolve(
    name: str,
    raw: dict[str, dict[str, Any]],
    packaged: set[str],
    done: dict[str, dict[str, Any]],
    chain: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Recipe `name` with its `extends:` chain applied. A packaged recipe extends only packaged ones (the
    release can't depend on what an operator mounts); a CML_RECIPE_DIRS one extends any recipe."""
    if name in done:
        return done[name]
    recipe = raw[name]
    base_name = recipe.get("extends")
    if base_name is None:
        done[name] = recipe
        return recipe
    if not isinstance(base_name, str) or not base_name:
        raise RecipeError("extends must be the name of another recipe")
    if base_name == name or base_name in chain:
        raise RecipeError("extends makes a cycle: " + " -> ".join((*chain, name, base_name)))
    if base_name not in raw or (name in packaged and base_name not in packaged):
        raise RecipeError(
            f"extends names no recipe {base_name!r}"
            + (" (a packaged recipe extends only packaged ones)" if base_name in raw else "")
        )
    try:
        base = _resolve(base_name, raw, packaged, done, (*chain, name))
    except RecipeError as e:
        if str(e).startswith("extends makes a cycle"):
            raise
        raise RecipeError(f"its base {base_name!r} can't be used: {e}") from None
    resolved = _extend(base, recipe)
    resolved["name"], resolved["extends"] = name, base_name
    done[name] = resolved
    return resolved


def _resolved() -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """({name: recipe with extends applied}, {name: why it can't be used}) over every recipe."""
    packaged = _packaged()
    raw = {**packaged, **{name: r for name, (r, _) in _extras()[0].items()}}
    done: dict[str, dict[str, Any]] = {}
    out: dict[str, dict[str, Any]] = {}
    problems: dict[str, str] = {}
    for name in raw:
        try:
            out[name] = _resolve(name, raw, set(packaged), done)
        except RecipeError as e:
            problems[name] = str(e)
    return out, problems


def _load_all() -> dict[str, dict[str, Any]]:
    """Every usable recipe by name (extends applied): the packaged ones, then CML_RECIPE_DIRS'."""
    return _resolved()[0]


def recipe_source(name: str) -> str:
    """'package', or the CML_RECIPE_DIRS file recipe `name` comes from."""
    if name in _packaged():
        return "package"
    extra = _extras()[0].get(name)
    return str(extra[1]) if extra else "package"


def skipped_recipe_files() -> list[dict[str, str]]:
    """Recipe files that are not used, with why (shown by cml_list_recipes): CML_RECIPE_DIRS files that
    can't be read or clash, and recipes whose `extends:` can't be resolved."""
    extras, skipped = _extras()
    unresolved = [
        {"file": str(extras[name][1]) if name in extras else f"package: {name}", "problem": problem}
        for name, problem in _resolved()[1].items()
    ]
    return skipped + unresolved


# Secrets in recipes are references: ${LAB_CLI_PASSWORD} etc., the same names as cml-mcp-server/labs/*.yaml.
PLACEHOLDER = re.compile(r"\$\{(LAB_[A-Z0-9_]+)\}")


def placeholders(value: Any) -> set[str]:
    """Every ${LAB_*} name used anywhere in `value`."""
    if isinstance(value, dict):
        return set().union(*(placeholders(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(placeholders(v) for v in value)) if value else set()
    return set(PLACEHOLDER.findall(value)) if isinstance(value, str) else set()


# A placeholder alone on its line (a multi-line value is filled there, at the line's indent).
PLACEHOLDER_LINE = re.compile(r"^([ \t]*)\$\{(LAB_[A-Z0-9_]+)\}[ \t]*$", re.M)
FILL = re.compile(f"{PLACEHOLDER_LINE.pattern}|{PLACEHOLDER.pattern}", re.M)


def _strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return [value] if isinstance(value, str) else []


def _inline_placeholders(text: str) -> set[str]:
    """${LAB_*} names used somewhere other than alone on their line."""
    return placeholders(PLACEHOLDER_LINE.sub("", text))


def lab_secrets(secrets_file: str | None) -> dict[str, str]:
    """LAB_* values: the dotenv-style `secrets_file` (if given and present), overridden by LAB_* env vars.
    LAB_CA_PEM (the lab CA certificate) can instead come from the file named by LAB_CA_PEM_FILE, as for
    the lab import script; that path is not itself a value."""
    values: dict[str, str] = {}
    if secrets_file:
        path = Path(os.path.expanduser(secrets_file))
        if path.is_file():
            from dotenv import dotenv_values

            values.update({k: v for k, v in dotenv_values(path).items() if k.startswith("LAB_") and v})
    values.update({k: v for k, v in os.environ.items() if k.startswith("LAB_") and v})
    if (ca_file := values.pop("LAB_CA_PEM_FILE", None)) and "LAB_CA_PEM" not in values:
        path = Path(os.path.expanduser(ca_file))
        if path.is_file():
            values["LAB_CA_PEM"] = path.read_text().strip()
    return values


# Values shorter than this are too generic to redact by value (e.g. a vendor default like 'cisco').
MIN_REDACT_LEN = 6


def secret_names_by_value(secrets_file: str | None) -> dict[str, str]:
    """{value: '${LAB_NAME}'} for every LAB_* value long enough to redact by value, longest first."""
    values = lab_secrets(secrets_file)
    pairs = sorted(
        ((v, f"${{{k}}}") for k, v in values.items() if len(v) >= MIN_REDACT_LEN), key=lambda p: -len(p[0])
    )
    return dict(pairs)


def redact_values(value: Any, mapping: dict[str, str]) -> Any:
    """`value` (str/dict/list) with every known lab secret value replaced by its ${LAB_*} reference."""
    if not mapping:
        return value
    if isinstance(value, str):
        for secret, ref in mapping.items():
            if secret in value:
                value = value.replace(secret, ref)
        return value
    if isinstance(value, dict):
        return {k: redact_values(v, mapping) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_values(v, mapping) for v in value]
    return value


def resolve_secrets(value: Any, secrets_file: str | None, *, what: str = "this recipe") -> Any:
    """`value` with every ${LAB_*} placeholder filled in. Raises InvalidRequest naming the missing
    variables (never any value). Only call this on what is sent to CML or used by a probe; previews,
    listings and annotations keep the placeholders.

    A multi-line value (e.g. LAB_CA_PEM, a PEM certificate) is only filled where its placeholder stands
    alone on its line, as inside a YAML block scalar: each of its lines at that line's indent."""
    names = placeholders(value)
    if not names:
        return value
    values = lab_secrets(secrets_file)
    missing = sorted(n for n in names if n not in values)
    if missing:
        raise InvalidRequest(
            f"{what} needs the lab secret(s) {', '.join(missing)}: set them as environment variables of "
            "the cml-mcp-server process or in the file named by CML_LAB_SECRETS_FILE (dotenv format, e.g. "
            "/path/to/lab-secrets.env). Recipes and lab files carry only the ${LAB_*} references."
            + (" LAB_CA_PEM_FILE can name the lab CA's PEM file instead." if "LAB_CA_PEM" in missing else "")
        )
    multiline = {n for n in names if "\n" in values[n] or "\r" in values[n]}
    inline = set().union(*(_inline_placeholders(s) for s in _strings(value)))
    if bad := sorted(multiline & inline):
        raise InvalidRequest(
            f"Lab secret(s) {', '.join(bad)} contain a line break: a multi-line value must stand alone on "
            "its line (inside a YAML block scalar)."
        )

    def fill(m: re.Match[str]) -> str:
        if m.group(2) in multiline:  # alone on its line: every line of the value at that line's indent
            return "\n".join(
                m.group(1) + line.strip() if line.strip() else "" for line in values[m.group(2)].splitlines()
            )
        return PLACEHOLDER.sub(lambda p: values[p.group(1)], m.group(0))

    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str):
            return FILL.sub(fill, v)  # one pass: a filled value is never scanned again
        return v

    return walk(value)


def recipe_names() -> list[str]:
    return list(_load_all())


def get_recipe(name: str) -> dict[str, Any]:
    recipes = _load_all()
    if name not in recipes and (problem := _resolved()[1].get(name)):
        raise InvalidRequest(f"Recipe {name!r} can't be used: {problem}")
    if name not in recipes:
        raise InvalidRequest(f"No recipe {name!r}; available: {', '.join(recipes) or 'none'}")
    return recipes[name]


def recipe_for_lab(title: str) -> str | None:
    """The recipe whose build title is `title`, if any."""
    for name, r in _load_all().items():
        if r["build"].get("title") == title:
            return name
    return None


def recipe_licensed_nodes(recipe: dict[str, Any]) -> int:
    """Licensed nodes the recipe's lab runs (external connectors and unmanaged switches are free)."""
    return sum(
        1 for n in recipe["build"].get("nodes") or [] if n.get("definition") not in UNLICENSED_DEFINITIONS
    )


# Substitutions are for addresses and names (a copy on another IP, another hostname): plain tokens only,
# never secret keywords, so a mapping can't rename e.g. 'secret' to hide a value from the scrubbers or
# smuggle spaces/newlines into probe commands.
SUBST_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}")
SUBST_DENY = re.compile(r"(?i)secret|password|passwd|key|community|psk|cred|token")


def check_substitute(mapping: dict[str, str] | None) -> None:
    """Raise InvalidRequest unless every key and value is a plain address/name token."""
    for k, v in (mapping or {}).items():
        for part in (k, v):
            if not SUBST_TOKEN.fullmatch(part):
                raise InvalidRequest(
                    f"substitute {k!r} -> {v!r}: keys and values must be addresses or names "
                    "(letters, digits, . _ : / -; no spaces), 1-64 characters"
                )
            if SUBST_DENY.search(part) or "LAB_" in part.upper():
                raise InvalidRequest(f"substitute {k!r} -> {v!r}: credential keywords can't be substituted")


def substituted(value: Any, mapping: dict[str, str] | None) -> Any:
    """`value` (a recipe or part of one) with each key of `mapping` replaced by its value in every
    string, in one pass (a replacement is never replaced again) - e.g. {'198.18.128.154':
    '198.18.128.194'} to build or verify a copy of a recipe on another address. Longer keys win."""
    if not mapping:
        return value
    check_substitute(mapping)
    rx = re.compile("|".join(re.escape(k) for k in sorted(mapping, key=len, reverse=True)))

    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str):
            return rx.sub(lambda m: mapping[m.group(0)], v)
        return v

    return walk(value)


# A recipe build records itself in the lab's notes, so cml_verify_recipe can verify a copy with the
# substitutions it was built with (L25). Substitutions are address/name tokens only, never secrets.
RECIPE_MARKER = "cml-mcp-recipe:"
_MARKER_LINE = re.compile(r"^cml-mcp-recipe:\s*(\{.*\})\s*$", re.M)


def recipe_marker(name: str, substitute: dict[str, str] | None) -> str:
    """The notes line a recipe's lab is built with."""
    return f"{RECIPE_MARKER} " + json.dumps({"recipe": name, "substitute": substitute or {}}, sort_keys=True)


def read_recipe_marker(notes: Any) -> dict[str, Any] | None:
    """{'recipe': name, 'substitute': {...}} from a lab's notes, or None."""
    m = _MARKER_LINE.search(notes) if isinstance(notes, str) else None
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except ValueError:
        return None
    sub = data.get("substitute")
    if not isinstance(data.get("recipe"), str) or not isinstance(sub, dict):
        return None
    return {"recipe": data["recipe"], "substitute": {str(k): str(v) for k, v in sub.items()}}


def set_recipe_marker(notes: Any, name: str, substitute: dict[str, str] | None) -> str:
    """`notes` with its recipe marker line replaced by one for `name` (or the line appended)."""
    line = recipe_marker(name, substitute)
    text = notes if isinstance(notes, str) else ""
    if _MARKER_LINE.search(text):
        return _MARKER_LINE.sub(lambda _m: line, text, count=1)
    return f"{text.rstrip()}\n{line}" if text.strip() else line


def recipe_bases(name: str) -> list[str]:
    """The recipes `name` names under `extends:` (a name or a list of names; none when absent)."""
    ext = get_recipe(name).get("extends")
    if isinstance(ext, str):
        return [ext]
    return [str(e) for e in ext] if isinstance(ext, list) else []


def base_relation(target: str, recorded: str) -> str | None:
    """How a lab recorded as built from recipe `recorded` relates to recipe `target` (#67): 'same';
    'extends' when `target` names `recorded` under `extends:`; 'subset' when every node of `recorded`
    (label and definition) is in `target` - a superset recipe for the same lab, grown in place; None
    otherwise (or when `recorded` is not a known recipe)."""
    if recorded == target:
        return "same"
    if recorded in recipe_bases(target):
        return "extends"
    if recorded not in _load_all():
        return None
    want = {str(n.get("label")): n.get("definition") for n in get_recipe(target)["build"].get("nodes") or []}
    have = {
        str(n.get("label")): n.get("definition") for n in get_recipe(recorded)["build"].get("nodes") or []
    }
    if have and all(want.get(label) == d for label, d in have.items()):
        return "subset"
    return None


# Recipe actions (L34): named console commands that change a recipe lab's state the way a
# test needs (e.g. log the 802.1X client in as another user). Callers pick an action by name; the
# command itself always comes from the recipe file (packaged or CML_RECIPE_DIRS), never from tool input.
def recipe_actions(recipe: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """{name: {description, node, command, expect, timeout}} of a recipe, validated."""
    raw = recipe.get("actions") or {}
    if not isinstance(raw, dict):
        raise ValueError(f"recipe {recipe.get('name')!r}: actions must be a mapping")
    labels = {n.get("label") for n in recipe["build"].get("nodes") or []}
    out: dict[str, dict[str, Any]] = {}
    for name, a in raw.items():
        if not isinstance(a, dict) or not isinstance(a.get("command"), str) or not a["command"].strip():
            raise ValueError(f"recipe {recipe.get('name')!r}: action {name!r} needs a command")
        if a.get("node") not in labels:
            raise ValueError(f"recipe {recipe.get('name')!r}: action {name!r} names an unknown node")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in a["command"]):
            raise ValueError(f"recipe {recipe.get('name')!r}: action {name!r} has control characters")
        if PLACEHOLDER.search(a["command"]):  # actions are sent as written: no secrets in them
            raise ValueError(
                f"recipe {recipe.get('name')!r}: action {name!r} must not carry ${{LAB_*}} references"
            )
        if a.get("expect"):
            re.compile(a["expect"])
        timeout = float(a.get("timeout") or 60)
        if not 1 <= timeout <= 600:
            raise ValueError(f"recipe {recipe.get('name')!r}: action {name!r} timeout must be 1-600 s")
        out[str(name)] = {
            "description": str(a.get("description") or ""),
            "node": a["node"],
            "command": a["command"],
            "expect": a.get("expect"),
            "timeout": timeout,
        }
    return out
