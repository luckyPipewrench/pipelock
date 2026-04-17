# Pipelock Badges

Drop-in Markdown for displaying pipelock's security posture on your project's README.

Two badges ship, one for downstream consumers and one reserved for the pipelock repository itself.

## `scanned by pipelock`

Use this badge on any public project where pipelock runs in CI. It signals that your agent traffic or source is inspected by pipelock on every pull request, and links readers back to pipelock so they can evaluate what the badge means.

![scanned by pipelock](https://img.shields.io/badge/scanned%20by-pipelock-00FFC8?style=flat&labelColor=1A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iIzAwRkZDOCIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNWMtMS45MyAwLTMuNSAxLjY2LTMuNSAzLjd2MS4zSDNjLS44MyAwLTEuNSAuNjctMS41IDEuNXY2YzAgLjgzLjY3IDEuNSAxLjUgMS41aDhjLjgzIDAgMS41LS42NyAxLjUtMS41VjdjMC0uODMtLjY3LTEuNS0xLjUtMS41aC0uNVY0LjJjMC0yLjA0LTEuNTctMy43LTMuNS0zLjdabS0yIDVWNC4yYzAtMS40OSAxLjEyLTIuNyAyLjUtMi43czIuNSAxLjIxIDIuNSAyLjd2MS4zSDVaTTIuNSA1aDJ2MS4yaC0yVjVabTcgMGgydjEuMmgtMlY1Wk03IDguMmMtLjY5IDAtMS4yNS41Ni0xLjI1IDEuMjUgMCAuNDQuMjMuODMuNTcgMS4wNXYxLjVoMS4zNnYtMS41Yy4zNC0uMjIuNTctLjYxLjU3LTEuMDUgMC0uNjktLjU2LTEuMjUtMS4yNS0xLjI1WiIvPjwvc3ZnPgo=)

### Requirements

Only display this badge if your project genuinely runs the pipelock GitHub Action on every pull request. The honest CI wiring is the signal; the badge is a surface for that signal. A fake badge is misleading.

The minimum is to run `luckyPipewrench/pipelock` in a `security-scan` (or similar) job in your CI workflow. See the [GitHub Action reference](../action.yml) and [docs/scan-api.md](scan-api.md) for options.

### Markdown

```markdown
[![scanned by pipelock](https://img.shields.io/badge/scanned%20by-pipelock-00FFC8?style=flat&labelColor=1A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iIzAwRkZDOCIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNWMtMS45MyAwLTMuNSAxLjY2LTMuNSAzLjd2MS4zSDNjLS44MyAwLTEuNSAuNjctMS41IDEuNXY2YzAgLjgzLjY3IDEuNSAxLjUgMS41aDhjLjgzIDAgMS41LS42NyAxLjUtMS41VjdjMC0uODMtLjY3LTEuNS0xLjUtMS41aC0uNVY0LjJjMC0yLjA0LTEuNTctMy43LTMuNS0zLjdabS0yIDVWNC4yYzAtMS40OSAxLjEyLTIuNyAyLjUtMi43czIuNSAxLjIxIDIuNSAyLjd2MS4zSDVaTTIuNSA1aDJ2MS4yaC0yVjVabTcgMGgydjEuMmgtMlY1Wk03IDguMmMtLjY5IDAtMS4yNS41Ni0xLjI1IDEuMjUgMCAuNDQuMjMuODMuNTcgMS4wNXYxLjVoMS4zNnYtMS41Yy4zNC0uMjIuNTctLjYxLjU3LTEuMDUgMC0uNjktLjU2LTEuMjUtMS4yNS0xLjI1WiIvPjwvc3ZnPgo=)](https://github.com/luckyPipewrench/pipelock)
```

### HTML

```html
<a href="https://github.com/luckyPipewrench/pipelock">
  <img alt="scanned by pipelock" src="https://img.shields.io/badge/scanned%20by-pipelock-00FFC8?style=flat&labelColor=1A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iIzAwRkZDOCIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNWMtMS45MyAwLTMuNSAxLjY2LTMuNSAzLjd2MS4zSDNjLS44MyAwLTEuNSAuNjctMS41IDEuNXY2YzAgLjgzLjY3IDEuNSAxLjUgMS41aDhjLjgzIDAgMS41LS42NyAxLjUtMS41VjdjMC0uODMtLjY3LTEuNS0xLjUtMS41aC0uNVY0LjJjMC0yLjA0LTEuNTctMy43LTMuNS0zLjdabS0yIDVWNC4yYzAtMS40OSAxLjEyLTIuNyAyLjUtMi43czIuNSAxLjIxIDIuNSAyLjd2MS4zSDVaTTIuNSA1aDJ2MS4yaC0yVjVabTcgMGgydjEuMmgtMlY1Wk03IDguMmMtLjY5IDAtMS4yNS41Ni0xLjI1IDEuMjUgMCAuNDQuMjMuODMuNTcgMS4wNXYxLjVoMS4zNnYtMS41Yy4zNC0uMjIuNTctLjYxLjU3LTEuMDUgMC0uNjktLjU2LTEuMjUtMS4yNS0xLjI1WiIvPjwvc3ZnPgo=">
</a>
```

### Placement

Drop it next to your existing status badges at the top of your README. It reads cleanly alongside CI, codecov, and license badges because it follows the same shields.io layout.

### Link target

Always link the badge to `https://github.com/luckyPipewrench/pipelock` so readers can click through and understand what the badge asserts. If you want to link directly to your own CI run instead (showing the pipelock scan passing in your pipeline), that's also acceptable.

## `pipelock self-scanned`

**Reserved for the pipelock repository itself.** It signals that pipelock runs its own GitHub Action against its own source on every pull request — dogfooding in public.

![pipelock self-scanned](https://img.shields.io/badge/pipelock-self--scanned-00FFC8?style=flat&labelColor=1A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iIzAwRkZDOCIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNWMtMS45MyAwLTMuNSAxLjY2LTMuNSAzLjd2MS4zSDNjLS44MyAwLTEuNSAuNjctMS41IDEuNXY2YzAgLjgzLjY3IDEuNSAxLjUgMS41aDhjLjgzIDAgMS41LS42NyAxLjUtMS41VjdjMC0uODMtLjY3LTEuNS0xLjUtMS41aC0uNVY0LjJjMC0yLjA0LTEuNTctMy43LTMuNS0zLjdabS0yIDVWNC4yYzAtMS40OSAxLjEyLTIuNyAyLjUtMi43czIuNSAxLjIxIDIuNSAyLjd2MS4zSDVaTTIuNSA1aDJ2MS4yaC0yVjVabTcgMGgydjEuMmgtMlY1Wk03IDguMmMtLjY5IDAtMS4yNS41Ni0xLjI1IDEuMjUgMCAuNDQuMjMuODMuNTcgMS4wNXYxLjVoMS4zNnYtMS41Yy4zNC0uMjIuNTctLjYxLjU3LTEuMDUgMC0uNjktLjU2LTEuMjUtMS4yNS0xLjI1WiIvPjwvc3ZnPgo=)

This wording is only honest on the pipelock repo itself. On any other project, use `scanned by pipelock` above.

## Brand notes

Both badges use the official pipelock palette from the brand guidelines:

- Label background: Navy Body `#1A1A2E`
- Message background: Cyan Light `#00FFC8`
- Logo: Cyan Light `#00FFC8`
- Label text: white (rendered by shields.io)
- Message text: dark (rendered by shields.io)

The lock glyph is a monochrome trace of the pipelock padlock silhouette, embedded as an inline SVG data URI. Shields.io renders it verbatim without tinting (unlike Simple Icons entries), so the fill color is baked into the SVG.

Do not modify the colors or swap in a different logo. The consistency is the point.

## Questions or issues

If the badge renders incorrectly in your README, open an issue against [luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock/issues) with the rendered image and your README source. We'll either fix the snippet here or help you diagnose the rendering environment.
