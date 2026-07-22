# Inline Visualizer v2 (vendored)

Upstream: [Classic298/open-webui-plugins/inline-visualizer-v2](https://github.com/Classic298/open-webui-plugins/tree/main/inline-visualizer-v2)

| File | Install in Open WebUI |
|------|------------------------|
| `tool.py` | **Workspace → Tools** (class `Tools`) |
| `SKILL.md` | **Workspace → Skills / Knowledge → Create Skill** — name **`visualize`** |
| `README.md` | Upstream docs (features, CSP, bridges) |

## Setup (this stack)

### Automated (preferred)

From the repo root (Open WebUI must be up; uses `.env` credentials):

```bash
python3 openwebui/install_inline_visualizer.py
python3 scripts/owui_inline_visualizer_test.py
```

This upserts the **tool** + **skill**, enables **Allow iframe same origin**,
adds the LiteLLM OpenAI connection, and creates workspace model **`visualizer`**
with the tool/skill attached. Smoke-test asks for a small dashboard and checks
for `@@@VIZ-START` / `@@@VIZ-END` markers.

Compose note: `AIOHTTP_CLIENT_SESSION_SSL=false` on `open-webui` so lab HTTPS
LiteLLM (self-signed) works.

### Manual

1. Paste `tool.py` into a new Tool; save.
2. Import or paste `SKILL.md` as skill **`visualize`**.
3. Admin → Models → your **general** chat model (not required on `auditor`):
   - enable the Visualizer tool
   - attach the `visualize` skill
   - Function calling: Default or Native (not Legacy)
4. User Settings → Interface → enable **Allow iframe same origin** (required for streaming).

Slash shortcut `/dashboard` (model **Visualizer**): see
[`docs/owui-slash-commands.md`](../../docs/owui-slash-commands.md).

Does not conflict with CIS compliance chart Tool/Filter under `openwebui/functions/`.

To refresh from upstream:

```bash
curl -fsSL -o openwebui/inline-visualizer-v2/tool.py \
  https://raw.githubusercontent.com/Classic298/open-webui-plugins/main/inline-visualizer-v2/tool.py
curl -fsSL -o openwebui/inline-visualizer-v2/SKILL.md \
  https://raw.githubusercontent.com/Classic298/open-webui-plugins/main/inline-visualizer-v2/SKILL.md
curl -fsSL -o openwebui/inline-visualizer-v2/README.md \
  https://raw.githubusercontent.com/Classic298/open-webui-plugins/main/inline-visualizer-v2/README.md
```
