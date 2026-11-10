---
name: Vault (secret-broker)
description: Calm, risk-forward admin for a credential vault; values are write-only except a login's password, revealed once behind a button
colors:
  bg: "#f6f5f2"
  bg-2: "#efede8"
  surface: "#fffffe"
  fg: "#1d1b18"
  fg-2: "#45413b"
  muted: "#68625a"
  line: "#e2ded5"
  line-2: "#cfc9be"
  field-border: "#8a8377"
  accent: "#1f6f66"
  accent-soft: "#e3efec"
  danger: "#b3261e"
  danger-soft: "#f9e7e4"
  danger-line: "#e8b4ad"
  warn: "#8a5208"
  warn-soft: "#f6ecd9"
  ok: "#2d6a3e"
  ok-soft: "#e4f0e4"
  dark-bg: "#141412"
  dark-surface: "#1d1c19"
  dark-fg: "#ecebe6"
  dark-muted: "#99938a"
  dark-field-border: "#78746a"
  dark-accent: "#5fb5a8"
  dark-danger: "#f08b80"
typography:
  title:
    fontFamily: "IBM Plex Sans, Segoe UI, system-ui, sans-serif"
    fontSize: "28px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  section:
    fontFamily: "IBM Plex Sans, Segoe UI, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.3
  body:
    fontFamily: "IBM Plex Sans, Segoe UI, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.55
  meta:
    fontFamily: "IBM Plex Sans, Segoe UI, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
  handle:
    fontFamily: "IBM Plex Mono, Cascadia Code, ui-monospace, monospace"
    fontSize: "14px"
    fontWeight: 500
    lineHeight: 1.4
rounded:
  tag: "5px"
  control: "9px"
  container: "12px"
spacing:
  xs: "6px"
  sm: "12px"
  md: "20px"
  lg: "40px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    height: "40px"
  button-danger-confirm:
    backgroundColor: "{colors.danger}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    height: "40px"
  tag-production:
    backgroundColor: "{colors.danger-soft}"
    textColor: "{colors.danger}"
    rounded: "{rounded.tag}"
  card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.container}"
    padding: "20px"
---

# Design System: Vault (secret-broker)

## Overview

A quiet instrument for one operator. Warm paper neutrals and a single deep-teal accent keep routine work calm, so that risk is the loudest thing on any page: production secrets, wildcard hosts, denied events and the frozen state all speak in one red voice. No scripts, no third-party requests; fonts are self-hosted from `/fonts`.

## Colors

### Primary
- **Accent `#1f6f66` (dark `#5fb5a8`)**: primary actions, links, focus rings, the brand mark. Never used to signal state.

### Neutral
- Paper `#f6f5f2` page, `#efede8` table heads and chips, near-white `#fffffe` surfaces; one warm gray family for text (`#1d1b18`, `#45413b`, `#68625a`) and lines (`#e2ded5`, `#cfc9be`). Every text token clears 4.5:1 on every surface in both themes, including placeholders.

### Named Rules
- **Red means risk.** Danger red is reserved for production, wildcard reach, denials, the frozen state and irreversible actions. Never decorative.
- **Amber means caution, not danger**: strict vaults, import-capable tokens, "any subdomain".
- **Green only confirms**: flash messages, "current" version, a recent backup.

## Typography

IBM Plex Sans (variable, self-hosted) for interface text, IBM Plex Mono for anything you would copy: handles, repos, hosts, paths, commands, event names. Mono is for data, never decoration.

### Hierarchy
- Title 28/600, -0.02em. Secret pages set the title in mono because the name is the identity.
- Section 16/600, sentence case. No eyebrows or uppercase labels.
- Body 15/400; meta 13px muted; tabular numerals everywhere.

## Layout

One 960px column with 20px gutters (16px on phones). Sticky top bar on desktop; on phones the bar is static and the nav wraps to a second row so Settings (and Freeze) is always visible. Global status (frozen banner, confirmation flash) sits directly under the bar on every page. Tables become stacked labelled rows below 640px.

## Elevation & Depth

Flat. Elevation is declared once, as a 1px border; no shadows on cards, lists or tables. The only translucency is the top bar's backdrop blur so content scrolling under it stays legible.

## Shapes

Tags 5px, controls 9px, containers 12px. Pills only for the small approvals count.

## Components

### Buttons
Primary teal; secondary outlined; danger outlined red; **confirm** solid red, shown only inside a two-step confirmation. 40px tall (44px on phones).

### Two-step confirm
`<details class="confirm">`: the summary names the action ("Revoke", "Delete forever", "Unfreeze"); opening it reveals a red panel stating the consequence in plain words and the one solid-red button that submits. Used for every irreversible action; reversible ones (move to trash, freeze) stay one click.

### Approval item
A card whose whole surface is the checkbox label. Risky items (production or wildcard host) get a red-tinted card, start unticked and spell out the reach: "Approving lets this repo send it to any subdomain of stripe.com, any path, until you revoke it."

### Row lists
Bordered list with hairline dividers: mono name, tag, one muted meta line (approval count, version, updated), actions on the right (below on phones).

### Navigation
Text links; the current page is a raised chip; Approvals carries a red count when something is waiting.

## Do's and Don'ts

### Do:
- Say exactly what an action does, to which repo, at which host, until when.
- Put confirmation of every POST in the flash strip.
- Keep values write-only: no reveal, no copy, no partial display.

### Don't:
- Don't add a second accent, gradients, glass panels or decorative shadows.
- Don't nest cards; group with a list header instead.
- Don't load anything from another origin or add JavaScript; the CSP forbids it.
- Don't use red for anything that isn't risk.
