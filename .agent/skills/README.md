# Agent Skills

This directory contains skills that extend the capabilities of the AI agent for this workspace.

## How to add a new skill

1. Create a new directory: `.agent/skills/<my-new-skill>/`
2. Add a `SKILL.md` file inside that directory.
3. Add YAML frontmatter to the top of `SKILL.md`:

```yaml
---
name: my-new-skill
description: A description of what this skill does.
---
```

## Structure

```text
.agent/skills/
├── example/
│   └── SKILL.md
└── <your-skill>/
    ├── SKILL.md
    ├── scripts/    (optional)
    └── examples/   (optional)
```
