"""LLM backend. Default: Azure GPT-5.4. Fallback: free local HF model.
The gateway is model-agnostic — guardrails are identical regardless of backend."""
import config

_hf_pipe = None


def call_llm(system_prompt, user_prompt):
    if config.LLM_BACKEND == "azure":
        return _call_azure(system_prompt, user_prompt)
    return _call_hf(system_prompt, user_prompt)


def _call_azure(system_prompt, user_prompt):
    from openai import AzureOpenAI
    client = AzureOpenAI(
        azure_endpoint=config.AZURE_OPENAI_ENDPOINT,
        api_key=config.AZURE_OPENAI_API_KEY,
        api_version=config.AZURE_OPENAI_API_VERSION,
    )
    resp = client.chat.completions.create(
        model=config.AZURE_OPENAI_DEPLOYMENT,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
        max_completion_tokens=512,
    )
    return resp.choices[0].message.content


def _call_hf(system_prompt, user_prompt):
    global _hf_pipe
    if _hf_pipe is None:
        from transformers import pipeline
        _hf_pipe = pipeline("text-generation", model=config.HF_GEN_MODEL)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    out = _hf_pipe(messages, max_new_tokens=256, do_sample=False)
    return out[0]["generated_text"][-1]["content"]
