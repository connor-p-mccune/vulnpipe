# Reproducible terminal demo for the README.
#
# Generate the GIF with VHS (https://github.com/charmbracelet/vhs):
#
#   vhs assets/demo.tape        # writes assets/demo.gif
#
# Run it from the repo root with vulnpipe installed and on PATH
# (`pip install -e .`). The demo uses only the bundled sample report, so it
# needs no scanners, no ZAP daemon, and no network.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1280
Set Height 760
Set Padding 20
Set Theme "Dracula"

Type "vulnpipe --help" Sleep 600ms Enter
Sleep 3s

Type "# Render the bundled sample report straight to JSON" Sleep 400ms Enter
Type "vulnpipe report --input examples/sample-report.json --format json | head -n 18" Sleep 600ms Enter
Sleep 3s

Type "# Same findings, prioritized, as a self-contained HTML report" Sleep 400ms Enter
Type "vulnpipe report --input examples/sample-report.json --format html > report.html" Sleep 600ms Enter
Sleep 2s

Type "echo wrote $(wc -c < report.html) bytes to report.html" Sleep 400ms Enter
Sleep 3s
