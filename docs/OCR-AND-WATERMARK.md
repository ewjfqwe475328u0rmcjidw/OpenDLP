# Images (OCR) and screen watermark

## Text in images (OCR)

Screenshots, phone photos of ID cards and scanned forms are images, so plain text rules cannot see inside them.
With OCR the agent reads the text **on the device** and applies the same rules; a hit is reported as
`IMAGE_CONTENT_MATCH` (or `USB_IMAGE_CONTENT` on removable drives) with `source=ocr`. Images are never uploaded.

| Platform | Engine | Setup |
|---|---|---|
| Windows 10 / 11 | built-in Windows OCR | none; uses the OCR languages installed with Windows display languages (Settings → Time & language → Language → *Optical character recognition*) |
| Linux | Tesseract | `sudo apt install tesseract-ocr` (add e.g. `tesseract-ocr-chi-tra` for other languages) |
| macOS | Tesseract | `brew install tesseract tesseract-lang` |

Windows also falls back to Tesseract if it is installed. Without any engine, images are simply skipped.

Policy (on by default):

```json
"ocr": { "enabled": true, "languages": "eng", "maxImageBytes": 20971520, "maxPerMinute": 30 }
```

- `languages`: Tesseract codes joined with `+`, e.g. `eng+chi_tra+jpn` (Windows uses its installed languages).
- `maxPerMinute`: protects the CPU when many images are saved at once; extra images in that minute are skipped.
- Supported files: png, jpg/jpeg, bmp, tif/tiff, gif, webp.

OCR is not perfect: small, blurred or handwritten text may be missed. Payment cards are still validated with the
Luhn check, so misreads rarely cause false alerts.

## Screen watermark (Windows)

A faint text such as `alice · FIN-LAPTOP-07 · 2026-10-13` is tiled across every monitor. It appears in photos of
the screen, screenshots and screen shares, so a leaked image can be traced to a person and machine, and people
think twice before photographing confidential data. The overlay is click-through, never takes focus, is not shown
in Alt-Tab and follows monitor changes.

```json
"watermark": { "enabled": false, "text": "{user} · {host} · {date}", "opacity": 0.08, "fontSize": 16 }
```

- Placeholders: `{user}`, `{host}`, `{date}`, `{time}`; at most 120 characters.
- `opacity` 0.03–0.35 (default 0.08 is visible in photos but does not get in the way).
- Off by default. Typical use: turn it on for one department with a group policy
  ([ENTERPRISE.md](ENTERPRISE.md#department--group-policies)), e.g. `{"watermark": {"enabled": true}}` for Finance.
- It runs in the user-session helper, so it appears for every signed-in user once the policy reaches the device
  (about a minute). macOS and Linux are not supported yet.

Tell employees before enabling it; a visible watermark is usually easier to justify than hidden monitoring, but
it is still a workplace policy decision.
