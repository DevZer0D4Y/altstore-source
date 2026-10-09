# DevZer0D4Y's Ports — AltStore source

Every iOS port I publish on GitHub, as one source for AltStore, SideStore,
LiveContainer, Feather and other sideloading apps. It keeps itself up to date:
a GitHub Action reads my repositories every half hour, and any release with an
`.ipa` shows up here, new projects included.

<h3 align="center">
<a href="https://altdirect.app/?url=https://devzer0d4y.github.io/altstore-source/apps.json"><img src="https://altdirect.app/assets/png/AltSource_Blue.png" width="200"></a>
</h3>

Source URL: `https://devzer0d4y.github.io/altstore-source/apps.json`

The games are not included. Each port's page explains how to install your own
copy of the game.

## How it works

- `scripts/build_source.py` lists my public repositories and their releases.
  For every `.ipa` it reads the bundle identifier, version, build number,
  minimum iOS version, entitlements and privacy keys from the IPA itself, so
  the source always matches what the app store downloads. It also takes the
  app icon out of the IPA.
- Repositories with "iOS" in their name or description and no IPA yet are
  announced in the news as being in development.
- `config.json` sets the source's name and colours, and can override any app's
  name, subtitle, description, icon or colour, or leave a repository out.
- `.github/workflows/update-source.yml` runs the script every 30 minutes, when
  `config.json` or the script changes, and on demand (Actions → Update source →
  Run workflow). It commits only what changed; GitHub Pages serves the files.
