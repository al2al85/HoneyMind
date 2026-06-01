import os

import pytest

from honeypot_utils import init_env_from_file
from llm_utils import invoke_llm


@pytest.fixture(autouse=True, scope="module")
def set_aws_api_key():
    if os.getenv("RUN_BEDROCK_INTEGRATION", "").lower() not in {"1", "true", "yes"}:
        pytest.skip(
            "Live Bedrock integration tests are optional. Set "
            "RUN_BEDROCK_INTEGRATION=true to run them."
        )
    init_env_from_file()


@pytest.mark.parametrize(
    "model_id",
    [
        "anthropic.claude-3-haiku-20240307-v1:0",
    ],
)
def test_connect_to_bedrock(model_id: str):
    question = "What is the capital of Japan?"
    answer = invoke_llm(
        "you are a helpful assistant who answer questions", question, model_id=model_id
    )
    assert "Tokyo" in answer
