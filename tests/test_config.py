from aws_audit.config import load_config


def test_load_config_defaults(tmp_path):
    cfg = load_config(None)
    assert cfg.region
    assert "json" in cfg.formats


def test_load_config_yaml(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("region: eu-west-1\nformats: ['md']\n", encoding="utf-8")
    cfg = load_config(str(p))
    assert cfg.region == "eu-west-1"
    assert cfg.formats == ["md"]
