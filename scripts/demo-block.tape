# demo-block.tape — reproducible "Shield blocks an irreversible action" GIF
#
# Regenerate:
#   brew install vhs                 # https://github.com/charmbracelet/vhs
#   cargo build --release
#   vhs scripts/demo-block.tape      # writes docs/img/shield-block-demo.gif
#
# The GIF is deterministic: it drives the same binary + fixtures every run,
# so it never drifts from what Shield actually decides.

Output docs/img/shield-block-demo.gif

Set Shell bash
Set FontSize 22
Set Width 1280
Set Height 720
Set Padding 28
Set TypingSpeed 40ms

# Brand-matched dark theme (site navy + emerald). If your VHS version rejects
# an inline JSON theme, replace this line with:  Set Theme "Aardvark Blue"
Set Theme { "name": "shield", "background": "#0f172a", "foreground": "#e2e8f0", "cursor": "#34d399", "black": "#0f172a", "red": "#ef4444", "green": "#34d399", "yellow": "#f59e0b", "blue": "#3b82f6", "magenta": "#8b5cf6", "cyan": "#14b8a6", "white": "#e2e8f0", "brightBlack": "#334155", "brightRed": "#f87171", "brightGreen": "#6ee7b7", "brightYellow": "#fbbf24", "brightBlue": "#60a5fa", "brightMagenta": "#a78bfa", "brightCyan": "#2dd4bf", "brightWhite": "#f8fafc" }

# --- setup (not recorded): put the freshly-built binary first on PATH ---
Hide
Type "export PATH=$PWD/target/release:$PATH" Enter
Type "clear" Enter
Show

# Beat 1 — an AI agent proposes an irreversible action
Type "# an AI coding agent just proposed this tool call:"
Enter
Sleep 900ms
Type "cat demo/drop-db.json"
Enter
Sleep 1800ms

# Beat 2 — Shield evaluates it at the moment it becomes real -> BLOCK
Type "aperion-shield --explain --input demo/drop-db.json"
Enter
Sleep 3400ms

# Beat 3 — the direct-shell reach-around is stopped too
Type "# no reach-around: the same engine guards the shell path -->"
Enter
Sleep 900ms
Type "aperion-shield --explain --input demo/rm-rf.json"
Enter
Sleep 3400ms

# Hold the final frame so the BLOCK verdict is readable in the loop
Sleep 2000ms
