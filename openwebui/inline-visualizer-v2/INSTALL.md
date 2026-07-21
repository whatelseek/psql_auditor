# Inline Visualizer v2 (vendored)

Upstream: [Classic298/open-webui-plugins/inline-visualizer-v2](https://github.com/Classic298/open-webui-plugins/tree/main/inline-visualizer-v2)

| File | Install in Open WebUI |
|------|------------------------|
| `tool.py` | **Workspace → Tools** (class `Tools`) |
| `SKILL.md` | **Workspace → Skills / Knowledge → Create Skill** — name **`visualize`** |
| `README.md` | Upstream docs (features, CSP, bridges) |

## Setup (this stack)

1. Paste `tool.py` into a new Tool; save.
2. Import or paste `SKILL.md` as skill **`visualize`**.
3. Admin → Models → your **general** chat model (not required on `auditor`):
   - enable the Visualizer tool
   - attach the `visualize` skill
   - Function calling: Default or Native (not Legacy)
4. User Settings → Interface → enable **Allow iframe same origin** (required for streaming).

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
