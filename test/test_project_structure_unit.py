import importlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_new_package_imports_resolve():
    modules = [
        "honeypots.ssh_honeypot",
        "honeypots.http_honeypot",
        "honeypots.base_honeypot",
        "core.input_normalizer",
        "core.honeypot_utils",
        "llm_providers.llm_utils",
        "llm_providers.llm_usage",
        "logging_pipeline.canonical_log_utils",
        "analysis.attack_classifier",
        "analysis.campaign_detector",
    ]

    for module in modules:
        assert importlib.import_module(module)


def test_project_structure_documentation_exists():
    doc = ROOT / "docs" / "project_structure.md"
    content = doc.read_text()

    assert "src/honeypots/" in content
    assert "src/infra/" in content
    assert "scripts/fakefs/" in content


def test_src_root_has_no_python_modules():
    root_modules = sorted(path.name for path in (ROOT / "src").glob("*.py"))

    assert root_modules == []


def test_fakefs_conversion_scripts_live_under_scripts():
    assert (ROOT / "scripts" / "fakefs" / "convert_fs_txt_to_jsonl_gz.py").exists()
    assert (ROOT / "scripts" / "fakefs" / "fs_json_to_jsonl_gz.py").exists()
    assert not (ROOT / "docs" / "convert_fs_txt_to_jsonl_gz.py").exists()
    assert not (ROOT / "docs" / "fs_json_to_jsonl_gz.py").exists()


def test_markdown_docs_do_not_contain_emoji_characters():
    markdown_files = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
    emoji_pattern = re.compile(
        "["
        "\U0001F300-\U0001FAFF"
        "\U00002600-\U000027BF"
        "\U0001F1E6-\U0001F1FF"
        "]"
    )

    offenders = []
    for path in markdown_files:
        content = path.read_text()
        if emoji_pattern.search(content):
            offenders.append(str(path.relative_to(ROOT)))

    assert offenders == []


def test_gitignore_is_focused_on_local_artifacts():
    content = (ROOT / ".gitignore").read_text()

    assert "config/*.env.list" in content
    assert "config/**" not in content
    assert ".github/hooks/" in content
    assert "*.db" in content
    assert "logs/" in content
