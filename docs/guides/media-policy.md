<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Media policy

The media policy controls how pipelock handles media responses (image, audio,
video Content-Type). Pipelock is not a multimodal inspector -- it cannot detect
instructions embedded in pixels, audio frames, or video. Instead, the media
policy reduces exposure by stripping unused media types, enforcing size limits,
surgically removing metadata from allowed images, and emitting exposure events
for downstream taint systems.

## When to use

The media policy is enabled by default with secure defaults. You only need to
configure it explicitly when:

- You want to allow audio or video (both stripped by default).
- You want to add image types beyond JPEG and PNG (e.g. WebP, GIF).
- You need to raise or lower the image size limit (default 5 MiB).
- You want to disable metadata stripping for a specific workflow.
- You want to turn off media exposure event emission.

## Configuration

```yaml
media_policy:
  enabled: true
  strip_images: false
  strip_audio: true
  strip_video: true
  allowed_image_types:
    - image/png
    - image/jpeg
  strip_image_metadata: true
  max_image_bytes: 5242880
  log_media_exposure: true
```

All boolean fields use nil-means-security-default semantics: omitting a field
produces the protective default. You only need to set fields you want to
change from the default.

### Minimal config (accept all defaults)

```yaml
# media_policy section omitted entirely -- defaults apply:
# - enabled: true
# - strip_audio: true, strip_video: true
# - allowed images: PNG, JPEG with metadata stripped
# - max_image_bytes: 5 MiB
# - exposure events emitted
```

### Strict config (no media at all)

```yaml
media_policy:
  strip_images: true
  strip_audio: true
  strip_video: true
```

## Field reference

| Field | Default (omitted) | Description |
|-------|-------------------|-------------|
| `enabled` | `true` | Master switch. When false, media passes through unchanged. |
| `strip_images` | `false` | Reject all `image/*` responses. |
| `strip_audio` | `true` | Reject all `audio/*` responses. |
| `strip_video` | `true` | Reject all `video/*` responses. |
| `allowed_image_types` | `[image/png, image/jpeg]` | Image types allowed when `strip_images` is false. |
| `strip_image_metadata` | `true` | Remove EXIF/XMP/IPTC/ICC from allowed images. |
| `max_image_bytes` | `5242880` (5 MiB) | Reject images larger than this before any parsing. |
| `log_media_exposure` | `true` | Emit `media_exposure` events for allowed media. |

## Image metadata stripping

Pipelock performs byte-level surgery on image streams. It never decodes and
re-encodes pixel data, so the forwarded image is pixel-identical to the
original minus metadata segments.

### JPEG

Strips these marker segments:

- **APP1** (0xE1): EXIF metadata, XMP sidecar data
- **APP2** (0xE2): ICC color profiles, FlashPix metadata
- **APP13** (0xED): IPTC/IIM metadata, Photoshop resource blocks

Preserves APP0 (JFIF header) because some viewers require it. All other
markers (SOF, DHT, DQT, SOS, RST, EOI) pass through unchanged. Entropy-coded
scan data is copied byte-for-byte.

### PNG

Strips these chunk types:

- **tEXt**: Latin-1 text metadata
- **iTXt**: International UTF-8 text metadata
- **zTXt**: Compressed Latin-1 text metadata
- **eXIf**: EXIF metadata container (PNG 1.5+)

All other chunks (IHDR, PLTE, tRNS, IDAT, IEND) pass through with their
original CRCs intact.

### Other formats

GIF and WebP are not stripped by default because the metadata parser does not
yet handle their chunk formats. If you add them to `allowed_image_types`, be
aware that XMP in WebP and comment blocks in GIF will pass through unstripped.

## SVG active content hardening

SVG (`image/svg+xml`) is never in the allowed image types list. SVG is active
content, not a static image.

The browser shield pipeline handles SVG separately, stripping:

- `<foreignObject>` elements (HTML embedding, XSS/injection vector)
- `on*` event handler attributes (`onload`, `onclick`, `onerror`, etc.)
- External `xlink:href` and `href` references (beacon/exfiltration)
- Hidden `<text>` elements (invisible prompt injection via `opacity:0`,
  `display:none`, or `visibility:hidden`)
- `<script>` blocks
- Animation injection (`<set>`, `<animate>` targeting href attributes)

Namespace-prefixed variants (e.g. `svg:foreignObject`) are also caught.

## MCP tool-result media

Media policy also enforces on MCP tool results. When an MCP server returns a tool-result `content` block carrying base64 payload in any of the `data`, `blob`, or `raw` fields (plus an `image/*`, `audio/*`, or `video/*` MIME type, or bytes that sniff as such), pipelock evaluates the payload against the same size, type, and image-stripping rules used on HTTP responses.

All three payload slots are evaluated — a malicious tool result cannot stash blocked media in `blob` while keeping a benign value in `data`. Pure-media tool results (no `text` blocks) are routed directly to media policy and are never fed as raw text into response-injection scanning. Content-type sniffing runs when the upstream server advertises a generic type like `application/octet-stream` or `binary/octet-stream`, so untyped binary media is still caught.

Blocked MCP media returns a media-policy-specific JSON-RPC error to the client (distinct from the generic prompt-injection block response) so operators can tell the two enforcement paths apart.

## Decompression bomb protection

The `max_image_bytes` limit is checked on the raw response body before any
parsing begins. This prevents malicious images that decompress to gigabytes
from consuming memory. The default 5 MiB limit handles most legitimate
images. Raise it if your agents work with high-resolution photography or
medical imaging.

## Exposure events

When `log_media_exposure` is true (default), pipelock emits a
`media_exposure` event for every allowed media response. These events feed
into the taint/authority policy system as exposure signals. A downstream
system can use them to escalate scanning when an agent has recently consumed
rich media before attempting a sensitive action.

## Validation rules

- `allowed_image_types` entries must be `image/*` media types with a concrete
  subtype (no wildcards, no whitespace, no nested slashes).
- `image/svg+xml` is rejected in `allowed_image_types`.
- `max_image_bytes` must be non-negative (0 means use the default).
- Validation runs even when `enabled` is false, so toggling the feature on
  via hot-reload cannot introduce malformed values.

## See also

- [Configuration reference](../configuration.md#media-policy-v21) for all fields
- [Bypass resistance](../bypass-resistance.md) for steganography limitations
- [Attacks blocked](../attacks-blocked.md) for SVG and media attack examples
