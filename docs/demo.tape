# Renders docs/demo.gif with charmbracelet/vhs (needs vhs, ttyd and ffmpeg on PATH).
# Run from the repo root, with the deps installed in .venv:  vhs docs/demo.tape
# Follows DEMO.md offline path: samples -> deterministic verdicts (--no-llm) -> signal table -> offline tests.
Output docs/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 700
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 40ms

Hide
Type "VIRTUAL_ENV_DISABLE_PROMPT=1 source .venv/bin/activate"
Enter
Wait@120s
Type "rm -rf out"
Enter
Wait@120s
Type "clear"
Enter
Wait@120s
Show
Sleep 500ms

Type "ls samples/"
Sleep 400ms
Enter
Wait@120s
Sleep 1.5s

Type "python -m phish_triage --no-llm samples/*.eml"
Sleep 400ms
Enter
Wait@120s
Sleep 3.5s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type "sed -n '1,26p' out/obvious-phish.report.md | cut -c1-100"
Sleep 400ms
Enter
Wait@120s
Sleep 5s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type "make test"
Sleep 400ms
Enter
Wait@120s
Sleep 2s

Sleep 1s
