# EmbedXPL runtime fixes

`embedxpl-runtime-fixes.patch` contains the local changes applied to the upstream
EmbedXPL checkout that this controller uses (`/opt/EmbedXPL-Forge`).

They fix:

- ARP table parsing rejecting invalid MAC values such as `WLAN0`
- missing `callback` argument in `_read_arp_table()`
- slow HTTP banner grabbing on hosts without known web ports
- `DummyFile` missing `flush()` for Rich output during module execution
- duplicated scheme/host in module HTTP requests (`http_request()` and `get_target_url()`)

Apply after cloning/updating upstream EmbedXPL:

```sh
cd /opt/EmbedXPL-Forge
git apply /path/to/RouterXPL-Forge/patches/embedxpl-runtime-fixes.patch
```

If your controller venv has its own installed copy of EmbedXPL, reinstall it or
copy the patched files into that site-packages tree as well.

The controller itself reads EmbedXPL from `EMBEDXPL_ROOT` (default
`/opt/EmbedXPL-Forge`), so these fixes take effect without rebuilding the APK.
