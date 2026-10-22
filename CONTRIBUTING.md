# Contributing

Issues and pull requests are welcome. almanac is early, so opening an issue before a large
change saves us both time.

- **Setup:** `python -m pip install -e . pytest`, then `python -m pytest` (all tests must pass).
- **Dependencies:** the stdlib plus `cryptography`. A PR that adds a dependency needs a
  reason the stdlib can't cover.
- **Tests:** a bug fix comes with a test that fails without it. Never commit real exports,
  customer names or secrets in a fixture. Use made-up names like the ones in `almanac/demo.py`.
- **Docs:** if a change makes something in `README.md` or `docs/` untrue, update it in the same PR.
- **Security issues:** see [SECURITY.md](SECURITY.md). Don't file them as public issues.

By contributing you agree your work is released under the [MIT License](LICENSE).
