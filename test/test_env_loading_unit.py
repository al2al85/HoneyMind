import logging

import core.honeypot_utils as honeypot_utils


def test_llm_env_list_is_loaded(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "llm.env.list").write_text("OPENAI_API_KEY=llm-key\n")
    monkeypatch.setattr(honeypot_utils, "_PROJECT_FOLDER", tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    honeypot_utils.init_env_from_file()

    assert honeypot_utils.os.environ["OPENAI_API_KEY"] == "llm-key"


def test_dotenv_is_loaded(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".env").write_text("ANTHROPIC_API_KEY=anthropic-key\n")
    monkeypatch.setattr(honeypot_utils, "_PROJECT_FOLDER", tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    honeypot_utils.init_env_from_file()

    assert honeypot_utils.os.environ["ANTHROPIC_API_KEY"] == "anthropic-key"


def test_aws_env_list_still_works(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "aws.env.list").write_text("AWS_REGION=eu-west-1\n")
    monkeypatch.setattr(honeypot_utils, "_PROJECT_FOLDER", tmp_path)
    monkeypatch.delenv("AWS_REGION", raising=False)

    honeypot_utils.init_env_from_file()

    assert honeypot_utils.os.environ["AWS_REGION"] == "eu-west-1"


def test_malformed_env_lines_are_ignored_with_warning(tmp_path, monkeypatch, caplog):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "llm.env.list").write_text(
        "\n# comment\nMALFORMED\nEMPTY = secret-value\nGOOD=value=with=equals\n"
    )
    monkeypatch.setattr(honeypot_utils, "_PROJECT_FOLDER", tmp_path)
    monkeypatch.delenv("GOOD", raising=False)

    with caplog.at_level(logging.WARNING):
        honeypot_utils.init_env_from_file()

    assert honeypot_utils.os.environ["GOOD"] == "value=with=equals"
    assert "Ignoring malformed env line" in caplog.text
    assert "secret-value" not in caplog.text
