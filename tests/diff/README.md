# tests/diff -- fixtures for `aperion-shield --diff`

This directory contains the six fixture pairs the v0.6 roadmap calls
out for the native behavior-diff explainer. Each pair is two
minimal shieldset YAML files plus (where useful) a corpus snippet
that exercises the rules under test.

Scenarios:

| Pair | What it tests | Expected `--format json` outcome |
|---|---|---|
| `loosen.{before,after}.yaml`     | Removing `sql.drop_database` | `loosened_count > 0`, flip `block -> allow` |
| `tighten.{before,after}.yaml`    | Swapping `supply.curl_pipe_sh` allowlist for a checksum requirement | `loosened_count == 0`, flip `allow -> approval` |
| `noop.{before,after}.yaml`       | Identical files | Zero flips, all counter deltas zero |
| `added.{before,after}.yaml`      | New rule `company.no_prod_writes` appears | `status: added`, flip `allow -> approval` |
| `removed.{before,after}.yaml`    | Inverse of `added` | `status: removed`, flip `approval -> allow` |
| `modified.{before,after}.yaml`   | Changes `severity` on an existing rule | `status: modified` with YAML diff in the report |

Fixtures are intentionally minimal -- each pair only includes the
rules needed to exercise the scenario, so a single failure points
the eye at the right cause. The full bundled `config/shieldset.yaml`
has 45 rules and isn't suitable as a focused fixture.

To re-record decision counts after editing a fixture:

```bash
cargo build --release
./target/release/aperion-shield --diff \
    --rules-before tests/diff/loosen.before.yaml \
    --rules-after  tests/diff/loosen.after.yaml \
    --corpus       tests/diff/loosen.corpus.jsonl \
    --format json
```

Integration coverage lives in `tests/diff_integration.rs`.
